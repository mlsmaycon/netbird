package llm_router

import (
	"context"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/shared/management/proto"
)

const (
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

// CredentialClient is the management call llm_router makes for user_oauth
// routes. builtin.MgmtClient satisfies it.
type CredentialClient interface {
	GetLLMUserCredential(ctx context.Context, in *proto.GetLLMUserCredentialRequest, opts ...grpc.CallOption) (*proto.GetLLMUserCredentialResponse, error)
}

type credentialKey struct {
	accountID  string
	userID     string
	providerID string
}

type cachedCredential struct {
	headers []middleware.AuthHeader
	until   time.Time
}

// credentialCache holds users' upstream headers across middleware rebuilds:
// the router is rebuilt on every mapping push, and a per-instance cache would
// send every user back to management after each one.
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

// userHeaders returns the caller's upstream headers for a user_oauth route,
// from cache or management. Anything other than a usable answer is a
// failure; the caller denies on it.
func (m *Middleware) userHeaders(ctx context.Context, accountID, userID, providerID string) ([]middleware.AuthHeader, credentialFailure) {
	if userID == "" {
		return nil, credentialNotLinked
	}
	if m.credClient == nil || m.creds == nil {
		return nil, credentialUnavailable
	}
	key := credentialKey{accountID: accountID, userID: userID, providerID: providerID}
	if headers, ok := m.creds.get(key); ok {
		return headers, ""
	}

	type result struct {
		headers []middleware.AuthHeader
		failure credentialFailure
	}
	v, _, _ := m.creds.flight.Do(accountID+"\x00"+userID+"\x00"+providerID, func() (any, error) {
		// Detached from the request so one caller giving up does not fail
		// the others waiting on the same lookup.
		rpcCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), credentialRPCTimeout)
		defer cancel()
		resp, err := m.credClient.GetLLMUserCredential(rpcCtx, &proto.GetLLMUserCredentialRequest{
			AccountId:  accountID,
			UserId:     userID,
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

func headersFromResponse(resp *proto.GetLLMUserCredentialResponse) ([]middleware.AuthHeader, credentialFailure) {
	switch resp.GetStatus() {
	case proto.GetLLMUserCredentialResponse_OK:
	case proto.GetLLMUserCredentialResponse_NOT_LINKED:
		return nil, credentialNotLinked
	case proto.GetLLMUserCredentialResponse_NEEDS_RELINK:
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

// isUserCredentialRoute reports whether a route is served with the caller's
// own credential and selected by request path. Such routes are kept out of
// the shared model table: their upstream speaks a different API.
func isUserCredentialRoute(r ProviderRoute) bool {
	return r.UserCredential || r.RequestPathPrefix != ""
}

// userCredentialRoutesFor returns the user-credential routes whose request
// path prefix covers reqPath.
func (m *Middleware) userCredentialRoutesFor(reqPath string) []ProviderRoute {
	var out []ProviderRoute
	for _, r := range m.userRoutes {
		if r.RequestPathPrefix != "" && pathPrefixMatches(r.RequestPathPrefix, reqPath) {
			out = append(out, r)
		}
	}
	return out
}

// routeUserCredential serves a request under a user_oauth vendor's path: it
// picks a route by model among those routes only, then attaches the caller's
// own credential. Every failure to obtain it denies.
func (m *Middleware) routeUserCredential(ctx context.Context, in *middleware.Input, routes []ProviderRoute, reqPath, surface, model string) *middleware.Output {
	if model == "" {
		if !isNonInferenceMethod(in.Method) {
			return denyMissingModel(surface)
		}
		for _, r := range routes {
			if routeAuthorisesGroups(r, in.UserGroups) {
				out := m.allowUserCredential(ctx, in, r, surface)
				if out.Decision == middleware.DecisionAllow {
					markNonInference(out)
				}
				return out
			}
		}
		return denyNoAuthorisedRoute(surface, "")
	}

	route, outcome := matchRouteIn(routes, model, surface, reqPath, in.UserGroups)
	switch outcome {
	case matchOutcomeFound:
		return m.allowUserCredential(ctx, in, route, surface)
	case matchOutcomeUnauthorised:
		return denyNoAuthorisedRoute(surface, model)
	default:
		return denyUnknownModel(surface, model)
	}
}

func (m *Middleware) allowUserCredential(ctx context.Context, in *middleware.Input, route ProviderRoute, surface string) *middleware.Output {
	if !route.UserCredential {
		return m.allowWithRoute(route, surface, in.UserGroups)
	}
	headers, failure := m.userHeaders(ctx, in.AccountID, in.UserID, route.ID)
	if failure != "" {
		return denyCredential(surface, failure)
	}
	out := m.allowWithRoute(route, surface, in.UserGroups)
	if out.Decision != middleware.DecisionAllow || out.Mutations == nil || out.Mutations.RewriteUpstream == nil {
		return out
	}
	// Every header comes from management; the route itself holds no
	// credential, so nothing static may ride along.
	out.Mutations.RewriteUpstream.AuthHeader = nil
	out.Mutations.RewriteUpstream.ExtraAuthHeaders = headers
	out.Metadata = append(out.Metadata, middleware.KV{Key: middleware.KeyLLMBillingMode, Value: "subscription"})
	return out
}

// denyCredential refuses a user_oauth request the caller has no usable login
// for. A missing or dead login is the caller's to fix (403); a management
// failure is transient (503).
func denyCredential(surface string, failure credentialFailure) *middleware.Output {
	statusCode := 403
	message := "link your subscription for this provider on the NetBird dashboard (Agent Network, Connect)"
	switch failure {
	case credentialNeedsRelink:
		message = "your subscription login can no longer be refreshed; link it again on the NetBird dashboard (Agent Network, Connect)"
	case credentialUnavailable:
		statusCode = 503
		message = "could not obtain your subscription credential, try again shortly"
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
