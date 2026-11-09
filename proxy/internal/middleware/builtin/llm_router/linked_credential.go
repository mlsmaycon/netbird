package llm_router

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/shared/management/proto"
)

const (
	// claudeLoginPathPrefix is reserved even when the linked route is absent.
	claudeLoginPathPrefix = "/claude-login"
	codexLoginPathPrefix  = "/backend-api/codex"
	codexModelListingPath = codexLoginPathPrefix + "/models"

	denyCodeUnsupportedTransport = "llm_policy.unsupported_transport"

	//nolint:gosec // deny code label, not a credential
	denyCodeCredentialNotLinked = "llm_policy.credential_not_linked"
	//nolint:gosec // deny reason label, not a credential
	denyReasonCredentialNotLinked = "credential_not_linked"

	// credentialRPCTimeout bounds the management lookup on the request path.
	credentialRPCTimeout = 5 * time.Second
	// credentialExpirySkew stops serving a cached token this long before it
	// expires, so a request never leaves with a token that dies in flight.
	credentialExpirySkew = time.Minute
	// credentialCacheMaxAge caps how long an answer is reused, so an unlink
	// or a revoked policy takes effect within minutes even for long-lived
	// tokens.
	credentialCacheMaxAge = 5 * time.Minute
	// credentialCacheLimit bounds the cache; expired entries go first.
	credentialCacheLimit = 10000
)

// credentialFailure says why no user credential could be attached.
type credentialFailure string

const (
	credentialNotLinked   credentialFailure = "not_linked"
	credentialNeedsRelink credentialFailure = "needs_relink"
	credentialUnavailable credentialFailure = "unavailable"
)

// CredentialClient is the management call llm_router makes for routes served
// with a linked login. builtin.MgmtClient satisfies it.
type CredentialClient interface {
	GetLLMProviderCredential(ctx context.Context, in *proto.GetLLMProviderCredentialRequest, opts ...grpc.CallOption) (*proto.GetLLMProviderCredentialResponse, error)
}

type credentialKey struct {
	accountID  string
	providerID string
}

type cachedCredential struct {
	headers []middleware.AuthHeader
	until   time.Time
}

// credentialCache holds linked logins' upstream headers across middleware
// rebuilds: the router is rebuilt on every mapping push, and a per-instance
// cache would send every request back to management after each one.
type credentialCache struct {
	mu      sync.Mutex
	entries map[credentialKey]cachedCredential
	flight  singleflight.Group
	now     func() time.Time
}

func newCredentialCache() *credentialCache {
	return &credentialCache{entries: make(map[credentialKey]cachedCredential), now: time.Now}
}

// sharedCredentials is the process-wide cache every router instance uses.
var sharedCredentials = newCredentialCache()

func (c *credentialCache) get(key credentialKey) ([]middleware.AuthHeader, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if !c.now().Before(e.until) {
		delete(c.entries, key)
		return nil, false
	}
	return e.headers, true
}

func (c *credentialCache) put(key credentialKey, headers []middleware.AuthHeader, expiresAt time.Time) {
	now := c.now()
	until := now.Add(credentialCacheMaxAge)
	if limit := expiresAt.Add(-credentialExpirySkew); limit.Before(until) {
		until = limit
	}
	if !until.After(now) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= credentialCacheLimit {
		c.evictLocked(now)
	}
	c.entries[key] = cachedCredential{headers: headers, until: until}
}

// evictLocked drops expired entries, then arbitrary ones until there is room.
func (c *credentialCache) evictLocked(now time.Time) {
	for k, e := range c.entries {
		if !now.Before(e.until) {
			delete(c.entries, k)
		}
	}
	for k := range c.entries {
		if len(c.entries) < credentialCacheLimit {
			return
		}
		delete(c.entries, k)
	}
}

// linkedHeaders returns the upstream headers of the login linked to a
// provider, from cache or management. Anything other than a usable answer is
// a failure; the caller denies on it. No user is needed: the login serves
// every request the route's policies allow, including those from machines
// that belong to nobody.
func (m *Middleware) linkedHeaders(ctx context.Context, accountID, providerID string) ([]middleware.AuthHeader, credentialFailure) {
	if m.credClient == nil || m.creds == nil {
		return nil, credentialUnavailable
	}
	key := credentialKey{accountID: accountID, providerID: providerID}
	if headers, ok := m.creds.get(key); ok {
		return headers, ""
	}

	type result struct {
		headers []middleware.AuthHeader
		failure credentialFailure
	}
	v, _, _ := m.creds.flight.Do(accountID+"\x00"+providerID, func() (any, error) {
		// A previous flight may have filled the cache after this caller's miss.
		if headers, ok := m.creds.get(key); ok {
			return result{headers: headers}, nil
		}
		// Detached from the request so one caller giving up does not fail
		// the others waiting on the same lookup.
		rpcCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), credentialRPCTimeout)
		defer cancel()
		resp, err := m.credClient.GetLLMProviderCredential(rpcCtx, &proto.GetLLMProviderCredentialRequest{
			AccountId:  accountID,
			ProviderId: providerID,
		})
		if err != nil {
			return result{failure: credentialUnavailable}, nil
		}
		headers, failure := headersFromResponse(resp)
		if failure == "" {
			m.creds.put(key, headers, resp.GetExpiresAt().AsTime())
		}
		return result{headers: headers, failure: failure}, nil
	})
	r := v.(result)
	return r.headers, r.failure
}

func headersFromResponse(resp *proto.GetLLMProviderCredentialResponse) ([]middleware.AuthHeader, credentialFailure) {
	switch resp.GetStatus() {
	case proto.GetLLMProviderCredentialResponse_OK:
	case proto.GetLLMProviderCredentialResponse_NOT_LINKED:
		return nil, credentialNotLinked
	case proto.GetLLMProviderCredentialResponse_NEEDS_RELINK:
		return nil, credentialNeedsRelink
	default:
		return nil, credentialUnavailable
	}
	headers := make([]middleware.AuthHeader, 0, len(resp.GetHeaders()))
	for _, h := range resp.GetHeaders() {
		if h.GetName() == "" || h.GetValue() == "" {
			continue
		}
		headers = append(headers, middleware.AuthHeader{Name: h.GetName(), Value: h.GetValue()})
	}
	if len(headers) == 0 || resp.GetExpiresAt() == nil {
		return nil, credentialUnavailable
	}
	return headers, ""
}

// isLinkedCredentialRoute reports whether a route is served with a linked
// login and selected by request path. Such routes are kept out of
// the shared model table so the path selects the credential class.
func isLinkedCredentialRoute(r ProviderRoute) bool {
	return r.LinkedCredential || r.RequestPathPrefix != ""
}

// linkedRoutesFor returns the linked-login routes whose request path prefix
// covers reqPath.
func (m *Middleware) linkedRoutesFor(reqPath string) []ProviderRoute {
	var out []ProviderRoute
	for _, r := range m.linkedRoutes {
		if r.RequestPathPrefix != "" && pathPrefixMatches(r.RequestPathPrefix, reqPath) {
			out = append(out, r)
		}
	}
	return out
}

// routeLinkedCredential serves a request under a user_oauth vendor's path: it
// picks a route by model among those routes only, then attaches the
// provider's linked login. Every failure to obtain it denies.
func (m *Middleware) routeLinkedCredential(ctx context.Context, in *middleware.Input, routes []ProviderRoute, reqPath, surface, model string) *middleware.Output {
	if hasTransportUpgrade(in.Headers) {
		if surface == "" && len(routes) > 0 {
			surface = routes[0].Vendor
		}
		return denySubscriptionUpgrade(surface)
	}
	readPath := linkedReadPath(routes, reqPath, in.Method)
	if isLinkedModelLessPath(readPath) {
		return m.routeLinkedModelless(ctx, in, routes, reqPath, surface)
	}
	detail, _ := modelDetailID(readPath)
	if detail != "" {
		model = detail
	}
	if model == "" {
		return m.routeLinkedModelless(ctx, in, routes, reqPath, surface)
	}

	route, outcome := matchRouteIn(routes, model, surface, reqPath, in.UserGroups)
	switch outcome {
	case matchOutcomeFound:
		out := m.allowLinkedCredential(ctx, in, route, surface)
		if out.Decision != middleware.DecisionAllow {
			return out
		}
		if detail != "" {
			markNonInference(out)
			out.Metadata = append(out.Metadata, middleware.KV{Key: middleware.KeyLLMModel, Value: detail})
		} else if in.Method == http.MethodPost && linkedNativePath(route, reqPath) == "/v1/messages/count_tokens" {
			markNonInference(out)
		}
		return out
	case matchOutcomeUnauthorised:
		return denyNoAuthorisedRoute(surface, model)
	default:
		return denyUnknownModel(surface, model)
	}
}

// linkedNativePath returns the endpoint after a routing namespace is removed.
// Vendor-native prefixes, such as ChatGPT's, have no StripPathPrefix.
func linkedNativePath(route ProviderRoute, reqPath string) string {
	if route.StripPathPrefix != "" && pathPrefixMatches(route.StripPathPrefix, reqPath) {
		return strings.TrimPrefix(reqPath, route.StripPathPrefix)
	}
	return reqPath
}

// linkedReadPath identifies discovery before any caller-supplied body model
// can affect routing or suppress the model-list policy filter.
func linkedReadPath(routes []ProviderRoute, reqPath, method string) string {
	if !isNonInferenceMethod(method) {
		return ""
	}
	for _, route := range routes {
		nativePath := linkedNativePath(route, reqPath)
		if _, detail := modelDetailID(nativePath); detail || isLinkedModelLessPath(nativePath) {
			return nativePath
		}
	}
	return ""
}

func isLinkedModelLessPath(nativePath string) bool {
	return isModelLessPath(nativePath) || nativePath == codexModelListingPath
}

func (m *Middleware) routeLinkedModelless(ctx context.Context, in *middleware.Input, routes []ProviderRoute, reqPath, surface string) *middleware.Output {
	if !isNonInferenceMethod(in.Method) {
		return denyMissingModel(surface)
	}
	for _, route := range routes {
		nativePath := linkedNativePath(route, reqPath)
		if !isLinkedModelLessPath(nativePath) {
			continue
		}
		if !routeAuthorisesGroups(route, in.UserGroups) {
			continue
		}
		var models []string
		if isListingPath(nativePath) || nativePath == codexModelListingPath {
			var bounded bool
			models, bounded = discoverableModels(route, in.UserGroups)
			if bounded && len(models) == 0 {
				continue
			}
		}
		out := m.allowLinkedCredential(ctx, in, route, surface)
		if out.Decision == middleware.DecisionAllow {
			markNonInference(out)
			rewrite := out.Mutations.RewriteUpstream
			rewrite.DiscoveryModels = models
			if len(models) > 0 {
				// The filter reads JSON; preserve native capability fields while
				// preventing client compression negotiation from bypassing it.
				rewrite.StripHeaders = append(rewrite.StripHeaders, "Accept-Encoding")
				rewrite.ExtraAuthHeaders = append(slices.Clone(rewrite.ExtraAuthHeaders), middleware.AuthHeader{Name: "Accept-Encoding", Value: "identity"})
			}
		}
		return out
	}
	return denyNoAuthorisedRoute(surface, "")
}

func hasTransportUpgrade(headers []middleware.KV) bool {
	for _, header := range headers {
		if strings.EqualFold(header.Key, "Upgrade") && strings.TrimSpace(header.Value) != "" {
			return true
		}
		if strings.EqualFold(header.Key, "Connection") {
			for token := range strings.SplitSeq(header.Value, ",") {
				if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
					return true
				}
			}
		}
	}
	return false
}

func denySubscriptionUpgrade(surface string) *middleware.Output {
	return &middleware.Output{
		Decision:   middleware.DecisionDeny,
		DenyStatus: http.StatusBadRequest,
		DenyReason: &middleware.DenyReason{
			Surface: surface,
			Code:    denyCodeUnsupportedTransport,
			Message: "subscription provider WebSocket upgrades are not supported; use HTTP streaming so model policies and usage limits can be enforced",
		},
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMPolicyDecision, Value: "deny"},
			{Key: middleware.KeyLLMPolicyReason, Value: "unsupported_transport"},
		},
	}
}

func (m *Middleware) allowLinkedCredential(ctx context.Context, in *middleware.Input, route ProviderRoute, surface string) *middleware.Output {
	if !route.LinkedCredential {
		return m.allowWithRoute(route, surface, in.UserGroups)
	}
	headers, failure := m.linkedHeaders(ctx, in.AccountID, route.ID)
	if failure != "" {
		return denyCredential(surface, failure)
	}
	out := m.allowWithRoute(route, surface, in.UserGroups)
	if out.Decision != middleware.DecisionAllow || out.Mutations == nil || out.Mutations.RewriteUpstream == nil {
		return out
	}
	// Every header comes from management; the route itself holds no
	// credential, so nothing static may ride along.
	rewrite := out.Mutations.RewriteUpstream
	rewrite.AuthHeader = nil
	rewrite.ExtraAuthHeaders = headers
	// Clear client copies before injecting management's values, including
	// vendor protocol headers required by this particular login profile.
	for _, header := range headers {
		if !slices.ContainsFunc(rewrite.StripHeaders, func(name string) bool { return strings.EqualFold(name, header.Name) }) {
			rewrite.StripHeaders = append(rewrite.StripHeaders, header.Name)
		}
	}
	out.Metadata = append(out.Metadata, middleware.KV{Key: middleware.KeyLLMBillingMode, Value: "subscription"})
	return out
}

// denyCredential refuses a request whose provider has no usable linked login.
// A missing or dead login needs an administrator (403); a management failure
// is transient (503).
func denyCredential(surface string, failure credentialFailure) *middleware.Output {
	statusCode := 403
	message := "no subscription login is linked to this provider; an administrator has to link one on the NetBird dashboard (Agent Network, Providers)"
	switch failure {
	case credentialNeedsRelink:
		message = "the subscription login linked to this provider can no longer be refreshed; an administrator has to link it again on the NetBird dashboard (Agent Network, Providers)"
	case credentialUnavailable:
		statusCode = 503
		message = "could not obtain the subscription credential, try again shortly"
	}
	return &middleware.Output{
		Decision:   middleware.DecisionDeny,
		DenyStatus: statusCode,
		DenyReason: &middleware.DenyReason{
			Surface: surface,
			Code:    denyCodeCredentialNotLinked,
			Message: message,
			Details: map[string]string{"reason": string(failure)},
		},
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMPolicyDecision, Value: "deny"},
			{Key: middleware.KeyLLMPolicyReason, Value: denyReasonCredentialNotLinked},
		},
	}
}

// linkedPathFor returns the request path prefix of a linked-login route that
// would serve model for this caller, so a request on another path can be told
// where the provider is reachable. Empty when no such route exists.
func (m *Middleware) linkedPathFor(model, vendor string, userGroups []string) string {
	for _, r := range m.linkedRoutes {
		if r.RequestPathPrefix == "" || !routeClaimsModel(r, model) || !routeAuthorisesGroups(r, userGroups) {
			continue
		}
		if vendor != "" && !routeSupportsVendor(r, vendor) {
			continue
		}
		return r.RequestPathPrefix
	}
	return ""
}

// denyOnlyOnLinkedPath refuses a request for a model that only a linked-login
// provider serves, on a path that provider does not accept. The message says
// which base URL selects the linked login.
func denyOnlyOnLinkedPath(surface, model, prefix string) *middleware.Output {
	out := denyUnknownModel(surface, model)
	out.DenyReason.Message = fmt.Sprintf(
		"model %s is served by a subscription login provider under %s; point the client's base URL at <endpoint>%s",
		model, prefix, prefix)
	out.DenyReason.Details["path_prefix"] = prefix
	return out
}
