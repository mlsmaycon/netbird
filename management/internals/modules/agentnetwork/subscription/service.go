package subscription

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	cachestore "github.com/eko/gocache/lib/v4/store"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/catalog"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	nbcache "github.com/netbirdio/netbird/management/server/cache"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	// refreshSkew is how close to expiry an access token is refreshed.
	refreshSkew = 5 * time.Minute
	// unreadableExpiryTTL is assumed for an access token whose exp cannot be
	// read, matching the vendor client's own fallback.
	unreadableExpiryTTL = 8 * 24 * time.Hour
	// refreshLease is how long one replica holds the right to redeem a
	// login's refresh token.
	refreshLease = 30 * time.Second
	// leaseWaitStep is how often a replica waiting on another's refresh
	// re-reads the row.
	leaseWaitStep = 250 * time.Millisecond
	// pollLease keeps two replicas from polling the same device code at once.
	pollLease = 30 * time.Second
	// flowResultTTL keeps a finished flow's outcome readable for late polls.
	flowResultTTL = 5 * time.Minute
	// defaultDeviceCodeTTL applies when a profile states none.
	defaultDeviceCodeTTL = 15 * time.Minute

	flowKeyPrefix = "agentnet:sublink:"
)

var (
	// ErrNotLinked means no login is linked to the provider record.
	ErrNotLinked = errors.New("subscription login is not linked")
	// ErrFlowNotFound means the link flow does not exist, expired from the
	// cache, or belongs to someone else.
	ErrFlowNotFound = errors.New("link flow not found")
	// ErrUnsupportedFlow means the catalog profile names a flow this server
	// cannot run.
	ErrUnsupportedFlow = errors.New("unsupported login flow")
	// errNoFlowCache means the shared cache could not be built at startup.
	errNoFlowCache = errors.New("link flows are unavailable: shared cache not configured")
)

// CredentialStore is the slice of the management store the service uses.
type CredentialStore interface {
	GetAgentNetworkProviderCredential(ctx context.Context, accountID, providerID string) (*types.ProviderCredential, error)
	LinkAgentNetworkProviderCredential(ctx context.Context, cred *types.ProviderCredential) error
	CompareAndSwapAgentNetworkProviderCredential(ctx context.Context, cred *types.ProviderCredential, expectedVersion int64) (bool, error)
	DeleteAgentNetworkProviderCredential(ctx context.Context, accountID, providerID string) error
}

// Key identifies the login linked to one provider record.
type Key struct {
	AccountID  string
	ProviderID string
}

// FlowStatus is where a link flow stands.
type FlowStatus string

const (
	FlowPending FlowStatus = "pending"
	FlowLinked  FlowStatus = "linked"
	FlowExpired FlowStatus = "expired"
	FlowFailed  FlowStatus = "failed"
)

// Flow is the caller-visible state of a link flow. It carries the login URL
// or user code to show, never the PKCE verifier or device handle used to poll.
type Flow struct {
	ID               string
	Flow             catalog.OAuthFlow
	AuthorizationURI string
	Status           FlowStatus
	UserCode         string
	VerificationURI  string
	ExpiresAt        time.Time
	Interval         time.Duration
	// JustLinked is true only on the operation that stored the login, so the
	// caller can record the event once.
	JustLinked bool
}

// Header is one header the proxy injects upstream.
type Header struct {
	Name  string
	Value string
}

// Access is what the proxy needs to call the vendor as the user.
type Access struct {
	Headers   []Header
	ExpiresAt time.Time
}

// Service links, refreshes and serves subscription logins.
type Service struct {
	store  CredentialStore
	cache  nbcache.Store
	client *Client
	now    func() time.Time
	locks  keyedMutex
}

// NewService builds a Service. client may be nil for the default HTTP client.
func NewService(credStore CredentialStore, cache nbcache.Store, client *Client) *Service {
	if client == nil {
		client = &Client{}
	}
	return &Service{store: credStore, cache: cache, client: client, now: func() time.Time { return time.Now().UTC() }}
}

type flowState struct {
	Key Key `json:"key"`
	// StartedBy is the user who started the flow. Only they may complete or poll it, and
	// the login it stores is recorded as linked by them.
	StartedBy          string            `json:"started_by"`
	Flow               catalog.OAuthFlow `json:"flow,omitempty"`
	ProviderType       string            `json:"provider_type,omitempty"`
	AuthorizationURI   string            `json:"authorization_uri,omitempty"`
	AuthorizationState string            `json:"authorization_state,omitempty"`
	DeviceAuthID       string            `json:"device_auth_id"`
	UserCode           string            `json:"user_code"`
	IntervalMS         int64             `json:"interval_ms"`
	ExpiresAt          time.Time         `json:"expires_at"`
	NextPollAt         time.Time         `json:"next_poll_at"`
	Verification       string            `json:"verification_uri"`
}

func (f *flowState) view(id string, st FlowStatus) *Flow {
	flow := f.Flow
	if flow == "" {
		// Device flows cached before authorization-code support remain readable.
		flow = catalog.OAuthFlowDevice
	}
	return &Flow{
		ID:               id,
		Flow:             flow,
		AuthorizationURI: f.AuthorizationURI,
		Status:           st,
		UserCode:         f.UserCode,
		VerificationURI:  f.Verification,
		ExpiresAt:        f.ExpiresAt,
		Interval:         time.Duration(f.IntervalMS) * time.Millisecond,
	}
}

// StartLink begins a login for key on behalf of startedBy. Flow secrets stay in
// the shared cache, bound to key and the user, so any replica can complete it.
func (s *Service) StartLink(ctx context.Context, key Key, startedBy string, entry catalog.Provider) (*Flow, error) {
	prof := entry.OAuth
	if _, err := protocolFor(prof); err != nil {
		return nil, err
	}
	if prof.Flow == catalog.OAuthFlowAuthorizationCode {
		return s.startAuthorizationLink(ctx, key, startedBy, entry)
	}
	if prof.Flow != catalog.OAuthFlowDevice || (prof.Protocol != "" && prof.Protocol != catalog.OAuthProtocolOpenAI) {
		return nil, ErrUnsupportedFlow
	}
	if s.cache == nil {
		return nil, errNoFlowCache
	}
	code, err := s.client.RequestDeviceCode(ctx, prof)
	if err != nil {
		return nil, err
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	ttl := prof.DeviceCodeTTL
	if ttl <= 0 {
		ttl = defaultDeviceCodeTTL
	}
	now := s.now()
	state := &flowState{
		Key:          key,
		Flow:         catalog.OAuthFlowDevice,
		ProviderType: entry.ID,
		StartedBy:    startedBy,
		DeviceAuthID: code.DeviceAuthID,
		UserCode:     code.UserCode,
		IntervalMS:   code.Interval.Milliseconds(),
		ExpiresAt:    now.Add(ttl),
		NextPollAt:   now.Add(code.Interval),
		Verification: prof.VerificationURI,
	}
	if err := s.saveFlow(ctx, id, state); err != nil {
		return nil, err
	}
	return state.view(id, FlowPending), nil
}

// PollLink reads a login started by StartLink. Device flows contact the vendor
// at most once per poll interval; authorization-code flows return cached state.
func (s *Service) PollLink(ctx context.Context, key Key, userID, flowID string, entry catalog.Provider) (*Flow, error) {
	if _, err := protocolFor(entry.OAuth); err != nil {
		return nil, err
	}
	if s.cache == nil {
		return nil, errNoFlowCache
	}
	state, err := s.loadFlow(ctx, flowID)
	if err != nil {
		return nil, err
	}
	if state.Key != key || state.StartedBy != userID || (state.ProviderType != "" && state.ProviderType != entry.ID) {
		return nil, ErrFlowNotFound
	}
	if state.view(flowID, FlowPending).Flow != entry.OAuth.Flow {
		return nil, ErrFlowNotFound
	}
	if result, ok := s.flowResult(ctx, flowID); ok {
		return state.view(flowID, result), nil
	}
	now := s.now()
	if !now.Before(state.ExpiresAt) {
		return state.view(flowID, FlowExpired), nil
	}
	if state.Flow == catalog.OAuthFlowAuthorizationCode || now.Before(state.NextPollAt) {
		return state.view(flowID, FlowPending), nil
	}
	acquired, err := s.cache.SetNX(ctx, flowKeyPrefix+flowID+":lease", "1", pollLease)
	if err != nil {
		return nil, fmt.Errorf("claim link flow poll: %w", err)
	}
	if !acquired {
		return state.view(flowID, FlowPending), nil
	}
	defer func() {
		if err := s.cache.Delete(ctx, flowKeyPrefix+flowID+":lease"); err != nil {
			log.WithContext(ctx).Debugf("failed to release link flow poll lease: %v", err)
		}
	}()

	flow := state.view(flowID, s.pollVendor(ctx, flowID, state, entry))
	flow.JustLinked = flow.Status == FlowLinked
	return flow, nil
}

func (s *Service) pollVendor(ctx context.Context, flowID string, state *flowState, entry catalog.Provider) FlowStatus {
	interval := time.Duration(state.IntervalMS) * time.Millisecond
	tokens, err := s.client.PollDeviceCode(ctx, entry.OAuth, &DeviceCode{DeviceAuthID: state.DeviceAuthID, UserCode: state.UserCode, Interval: interval})
	if errors.Is(err, ErrAuthorizationPending) {
		state.NextPollAt = s.now().Add(interval)
		if err := s.saveFlow(ctx, flowID, state); err != nil {
			log.WithContext(ctx).Debugf("failed to record link flow poll time: %v", err)
		}
		return FlowPending
	}
	if err != nil {
		log.WithContext(ctx).Infof("agent network subscription link for provider %s failed: %v", state.Key.ProviderID, err)
		s.setFlowResult(ctx, flowID, FlowFailed)
		return FlowFailed
	}
	if err := s.storeLinked(ctx, state.Key, state.StartedBy, entry.OAuth, tokens); err != nil {
		log.WithContext(ctx).Infof("agent network subscription link for provider %s could not be stored: %v", state.Key.ProviderID, err)
		s.setFlowResult(ctx, flowID, FlowFailed)
		return FlowFailed
	}
	s.setFlowResult(ctx, flowID, FlowLinked)
	return FlowLinked
}

func (s *Service) storeLinked(ctx context.Context, key Key, linkedBy string, prof *catalog.OAuthProfile, tokens *TokenSet) error {
	protocol, err := protocolFor(prof)
	if err != nil {
		return err
	}
	claims, err := protocol.claims(prof, tokens)
	if err != nil {
		return err
	}
	now := s.now()
	cred := &types.ProviderCredential{
		AccountID:         key.AccountID,
		ProviderID:        key.ProviderID,
		LinkedBy:          linkedBy,
		RefreshToken:      tokens.RefreshToken,
		AccessToken:       tokens.AccessToken,
		AccessExpiresAt:   protocol.expiry(tokens, now),
		ExternalAccountID: claims.AccountID,
		PlanType:          claims.PlanType,
		FedRAMP:           claims.FedRAMP,
		Status:            types.CredentialActive,
		CreatedAt:         now,
		UpdatedAt:         now,
		LastRefreshedAt:   &now,
	}
	return s.store.LinkAgentNetworkProviderCredential(ctx, cred)
}

// Unlink forgets the login linked to the provider record.
func (s *Service) Unlink(ctx context.Context, key Key) error {
	return s.store.DeleteAgentNetworkProviderCredential(ctx, key.AccountID, key.ProviderID)
}

// Access returns the headers that let the proxy call the vendor with the
// provider's linked login, refreshing the access token first when it is close
// to expiry. It returns ErrNotLinked or ErrRelinkRequired when there is
// nothing usable to serve.
func (s *Service) Access(ctx context.Context, key Key, entry catalog.Provider) (*Access, error) {
	if _, err := protocolFor(entry.OAuth); err != nil {
		return nil, err
	}
	cred, err := s.load(ctx, key)
	if err != nil {
		return nil, err
	}
	if !cred.AccessValidFor(s.now(), refreshSkew) {
		unlock := s.locks.lock(key)
		cred, err = s.refresh(ctx, key, entry.OAuth)
		unlock()
		if err != nil {
			return nil, err
		}
	}
	return &Access{Headers: accessHeaders(entry, cred), ExpiresAt: cred.AccessExpiresAt}, nil
}

func (s *Service) load(ctx context.Context, key Key) (*types.ProviderCredential, error) {
	cred, err := s.store.GetAgentNetworkProviderCredential(ctx, key.AccountID, key.ProviderID)
	if err != nil {
		if e, ok := status.FromError(err); ok && e.Type() == status.NotFound {
			return nil, ErrNotLinked
		}
		return nil, err
	}
	if cred.Status != types.CredentialActive {
		return nil, ErrRelinkRequired
	}
	return cred, nil
}

// refresh brings the access token up to date. Only the replica whose
// compare-and-swap claims the refresh lease presents the refresh token; the
// vendor kills a login whose refresh token is presented twice, so everyone
// else waits for that replica's result instead.
func (s *Service) refresh(ctx context.Context, key Key, prof *catalog.OAuthProfile) (*types.ProviderCredential, error) {
	protocol, err := protocolFor(prof)
	if err != nil {
		return nil, err
	}
	deadline := s.now().Add(refreshLease + time.Second)
	for {
		cred, err := s.load(ctx, key)
		if err != nil {
			return nil, err
		}
		now := s.now()
		if cred.AccessValidFor(now, refreshSkew) {
			return cred, nil
		}
		if cred.RefreshLeaseUntil != nil && cred.RefreshLeaseUntil.After(now) {
			if cred.AccessValidFor(now, 0) {
				return cred, nil
			}
			if now.After(deadline) {
				return nil, errors.New("refresh of subscription login is held by another replica")
			}
			if err := sleepCtx(ctx, leaseWaitStep); err != nil {
				return nil, err
			}
			continue
		}
		if cred.RefreshLeaseUntil != nil && protocol.uncertainRefreshIsTerminal() {
			// An abandoned holder may have redeemed the token before losing its result.
			next := cred.Copy()
			next.Status = types.CredentialNeedsRelink
			next.AccessToken, next.RefreshToken = "", ""
			next.RefreshLeaseUntil = nil
			ok, err := s.store.CompareAndSwapAgentNetworkProviderCredential(ctx, next, cred.Version)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			return nil, ErrRelinkRequired
		}
		claimed := cred.Copy()
		lease := now.Add(refreshLease)
		claimed.RefreshLeaseUntil = &lease
		ok, err := s.store.CompareAndSwapAgentNetworkProviderCredential(ctx, claimed, cred.Version)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		return s.redeem(ctx, key, prof, claimed)
	}
}

// redeem presents the refresh token of a credential this replica holds the
// lease on, and records the outcome.
func (s *Service) redeem(ctx context.Context, key Key, prof *catalog.OAuthProfile, cred *types.ProviderCredential) (*types.ProviderCredential, error) {
	held := cred.Version
	tokens, err := s.client.Refresh(ctx, prof, cred.RefreshToken)
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), httpTimeout)
	defer cancel()
	ctx = writeCtx
	next := cred.Copy()
	next.RefreshLeaseUntil = nil
	switch {
	case errors.Is(err, ErrRelinkRequired):
		log.WithContext(ctx).Infof("agent network subscription login for provider %s needs relinking: %v", key.ProviderID, err)
		next.Status = types.CredentialNeedsRelink
		next.AccessToken = ""
		next.RefreshToken = ""
		if _, werr := s.store.CompareAndSwapAgentNetworkProviderCredential(ctx, next, held); werr != nil {
			return nil, werr
		}
		return nil, ErrRelinkRequired
	case err != nil:
		if _, werr := s.store.CompareAndSwapAgentNetworkProviderCredential(ctx, next, held); werr != nil {
			log.WithContext(ctx).Debugf("failed to release subscription refresh lease: %v", werr)
		}
		if cred.AccessValidFor(s.now(), 0) {
			return cred, nil
		}
		return nil, fmt.Errorf("refresh subscription login: %w", err)
	}

	if err := applyRefresh(next, prof, tokens, s.now()); err != nil {
		return nil, err
	}
	return s.persistRefresh(ctx, key, next, held)
}

// persistRefresh stores a redeemed token set. The old refresh token is
// already spent, so a failed write is retried rather than given up on.
func (s *Service) persistRefresh(ctx context.Context, key Key, next *types.ProviderCredential, held int64) (*types.ProviderCredential, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		ok, err := s.store.CompareAndSwapAgentNetworkProviderCredential(ctx, next, held)
		if err == nil && ok {
			return next, nil
		}
		if err == nil {
			// The row moved under the lease: unlinked or relinked meanwhile.
			// Whatever is stored now wins; the tokens just redeemed are
			// dropped rather than resurrect a login the user removed.
			return s.load(ctx, key)
		}
		lastErr = err
		if serr := sleepCtx(ctx, leaseWaitStep); serr != nil {
			break
		}
	}
	return nil, fmt.Errorf("store refreshed subscription login: %w", lastErr)
}

func applyRefresh(cred *types.ProviderCredential, prof *catalog.OAuthProfile, tokens *TokenSet, now time.Time) error {
	protocol, err := protocolFor(prof)
	if err != nil {
		return err
	}
	if tokens.AccessToken != "" {
		cred.AccessToken = tokens.AccessToken
		cred.AccessExpiresAt = protocol.expiry(tokens, now)
	}
	if tokens.RefreshToken != "" {
		cred.RefreshToken = tokens.RefreshToken
	}
	if tokens.IDToken != "" || tokens.Account.AccountID != "" {
		if claims, err := protocol.claims(prof, tokens); err == nil {
			cred.ExternalAccountID = claims.AccountID
			cred.PlanType = claims.PlanType
			cred.FedRAMP = claims.FedRAMP
		}
	}
	cred.LastRefreshedAt = &now
	return nil
}

func accessExpiry(accessToken string, now time.Time) time.Time {
	if exp, ok := AccessTokenExpiry(accessToken); ok {
		return exp
	}
	return now.Add(unreadableExpiryTTL)
}

func accessHeaders(entry catalog.Provider, cred *types.ProviderCredential) []Header {
	prof := entry.OAuth
	headers := []Header{{
		Name:  entry.AuthHeaderName,
		Value: strings.ReplaceAll(entry.AuthHeaderTemplate, "${API_KEY}", cred.AccessToken),
	}}
	if prof.AccountIDHeader != "" && cred.ExternalAccountID != "" {
		headers = append(headers, Header{Name: prof.AccountIDHeader, Value: cred.ExternalAccountID})
	}
	if prof.FedRAMPHeader != "" && cred.FedRAMP {
		headers = append(headers, Header{Name: prof.FedRAMPHeader, Value: "true"})
	}
	names := make([]string, 0, len(prof.RequestHeaders))
	for name := range prof.RequestHeaders {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		headers = append(headers, Header{Name: name, Value: prof.RequestHeaders[name]})
	}
	return headers
}

func (s *Service) saveFlow(ctx context.Context, id string, state *flowState) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode link flow: %w", err)
	}
	ttl := time.Until(state.ExpiresAt) + flowResultTTL
	if err := s.cache.Set(ctx, flowKeyPrefix+id, string(raw), cachestore.WithExpiration(ttl)); err != nil {
		return fmt.Errorf("store link flow: %w", err)
	}
	return nil
}

func (s *Service) loadFlow(ctx context.Context, id string) (*flowState, error) {
	if id == "" {
		return nil, ErrFlowNotFound
	}
	raw, err := s.cache.Get(ctx, flowKeyPrefix+id)
	if err != nil {
		if errors.Is(err, cachestore.NotFound{}) {
			return nil, ErrFlowNotFound
		}
		return nil, fmt.Errorf("load link flow: %w", err)
	}
	var state flowState
	if err := json.Unmarshal(cacheBytes(raw), &state); err != nil {
		return nil, fmt.Errorf("decode link flow: %w", err)
	}
	return &state, nil
}

func (s *Service) flowResult(ctx context.Context, id string) (FlowStatus, bool) {
	raw, err := s.cache.Get(ctx, flowKeyPrefix+id+":result")
	if err != nil {
		return "", false
	}
	return FlowStatus(cacheBytes(raw)), true
}

func (s *Service) setFlowResult(ctx context.Context, id string, result FlowStatus) {
	if err := s.cache.Set(ctx, flowKeyPrefix+id+":result", string(result), cachestore.WithExpiration(flowResultTTL)); err != nil {
		log.WithContext(ctx).Debugf("failed to record link flow result: %v", err)
	}
}

func cacheBytes(v any) []byte {
	switch t := v.(type) {
	case string:
		return []byte(t)
	case []byte:
		return t
	default:
		return nil
	}
}

func randomID() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate link flow id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// keyedMutex serialises refreshes of one login inside this process, so
// concurrent requests on one replica wait for a single refresh instead of
// racing each other for the lease.
type keyedMutex struct {
	mu    sync.Mutex
	locks map[Key]*refLock
}

type refLock struct {
	mu   sync.Mutex
	refs int
}

func (k *keyedMutex) lock(key Key) func() {
	k.mu.Lock()
	if k.locks == nil {
		k.locks = make(map[Key]*refLock)
	}
	l, ok := k.locks[key]
	if !ok {
		l = &refLock{}
		k.locks[key] = l
	}
	l.refs++
	k.mu.Unlock()

	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		k.mu.Lock()
		l.refs--
		if l.refs == 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}
