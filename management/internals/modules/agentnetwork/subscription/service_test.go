package subscription

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/catalog"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	nbcache "github.com/netbirdio/netbird/management/server/cache"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/util/crypt"
)

// fakeIssuer imitates the vendor's auth server closely enough to catch the
// failure that matters most: a refresh token presented twice kills the login.
type fakeIssuer struct {
	t   *testing.T
	srv *httptest.Server

	mu           sync.Mutex
	pendingPolls int
	refreshCalls atomic.Int32
	liveRefresh  string
	generation   int
	refreshFail  func(w http.ResponseWriter) bool
	accessTTL    time.Duration
	fedramp      bool
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	f := &fakeIssuer{t: t, liveRefresh: "rt-0", accessTTL: time.Hour}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/accounts/deviceauth/usercode", f.usercode)
	mux.HandleFunc("/api/accounts/deviceauth/token", f.deviceToken)
	mux.HandleFunc("/oauth/token", f.token)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIssuer) entry() catalog.Provider {
	return catalog.Provider{
		ID:                 "chatgpt_codex",
		AuthHeaderName:     "Authorization",
		AuthHeaderTemplate: "Bearer ${API_KEY}",
		CredentialKind:     catalog.CredentialUserOAuth,
		OAuth: &catalog.OAuthProfile{
			Issuer:            f.srv.URL,
			ClientID:          "client-1",
			Flow:              catalog.OAuthFlowDevice,
			DeviceCodeURL:     f.srv.URL + "/api/accounts/deviceauth/usercode",
			DeviceTokenURL:    f.srv.URL + "/api/accounts/deviceauth/token",
			VerificationURI:   f.srv.URL + "/codex/device",
			DeviceRedirectURI: f.srv.URL + "/deviceauth/callback",
			DeviceCodeTTL:     15 * time.Minute,
			TokenURL:          f.srv.URL + "/oauth/token",
			ClaimsNamespace:   "https://api.openai.com/auth",
			AccountIDClaim:    "chatgpt_account_id",
			PlanTypeClaim:     "chatgpt_plan_type",
			FedRAMPClaim:      "chatgpt_account_is_fedramp",
			AccountIDHeader:   "chatgpt-account-id",
			FedRAMPHeader:     "X-OpenAI-Fedramp",
		},
	}
}

func (f *fakeIssuer) usercode(w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	require.NoError(f.t, json.NewDecoder(r.Body).Decode(&body))
	assert.Equal(f.t, "client-1", body["client_id"])
	// The vendor sends interval as a string and the code as "usercode".
	_ = json.NewEncoder(w).Encode(map[string]string{"device_auth_id": "dev-1", "usercode": "ABCD-1234", "interval": "1"})
}

func (f *fakeIssuer) deviceToken(w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	require.NoError(f.t, json.NewDecoder(r.Body).Decode(&body))
	assert.Equal(f.t, "dev-1", body["device_auth_id"])
	assert.Equal(f.t, "ABCD-1234", body["user_code"])
	f.mu.Lock()
	pending := f.pendingPolls > 0
	if pending {
		f.pendingPolls--
	}
	f.mu.Unlock()
	if pending {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"authorization_code": "code-1", "code_challenge": "ch", "code_verifier": "ver-1"})
}

func (f *fakeIssuer) token(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		require.NoError(f.t, r.ParseForm())
		assert.Equal(f.t, "authorization_code", r.PostForm.Get("grant_type"))
		assert.Equal(f.t, "code-1", r.PostForm.Get("code"))
		assert.Equal(f.t, "ver-1", r.PostForm.Get("code_verifier"))
		assert.Equal(f.t, f.srv.URL+"/deviceauth/callback", r.PostForm.Get("redirect_uri"))
		f.writeTokens(w)
		return
	}
	var body map[string]string
	require.NoError(f.t, json.NewDecoder(r.Body).Decode(&body))
	assert.Equal(f.t, "refresh_token", body["grant_type"])
	f.refreshCalls.Add(1)
	if f.refreshFail != nil && f.refreshFail(w) {
		return
	}
	f.mu.Lock()
	if body["refresh_token"] != f.liveRefresh {
		f.mu.Unlock()
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"code":"refresh_token_reused"}}`))
		return
	}
	f.mu.Unlock()
	// Slow enough that concurrent callers overlap with the redemption.
	time.Sleep(50 * time.Millisecond)
	f.writeTokens(w)
}

func (f *fakeIssuer) writeTokens(w http.ResponseWriter) {
	f.mu.Lock()
	f.generation++
	f.liveRefresh = "rt-" + string(rune('0'+f.generation))
	refresh := f.liveRefresh
	f.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]string{
		"access_token":  jwt(map[string]any{"exp": time.Now().Add(f.accessTTL).Unix()}),
		"refresh_token": refresh,
		"id_token": jwt(map[string]any{"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id":         "acct-42",
			"chatgpt_plan_type":          "pro",
			"chatgpt_account_is_fedramp": f.fedramp,
		}}),
	})
}

func jwt(claims map[string]any) string {
	raw, _ := json.Marshal(claims)
	return "e30." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"
}

func newTestStore(t *testing.T, encrypted bool) store.Store {
	t.Helper()
	s, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)
	if encrypted {
		key, err := crypt.GenerateKey()
		require.NoError(t, err)
		enc, err := crypt.NewFieldEncrypt(key)
		require.NoError(t, err)
		s.SetFieldEncrypt(enc)
	}
	return s
}

func newTestCache(t *testing.T) nbcache.Store {
	t.Helper()
	c, err := nbcache.NewStore(context.Background(), time.Hour, time.Minute, 10)
	require.NoError(t, err)
	return c
}

var testKey = Key{AccountID: "acc-1", UserID: "user-1", ProviderID: "prov-1"}

func seedCredential(t *testing.T, s store.Store, accessExpiry time.Time) {
	t.Helper()
	require.NoError(t, s.LinkAgentNetworkUserCredential(context.Background(), &types.UserCredential{
		AccountID:         testKey.AccountID,
		UserID:            testKey.UserID,
		ProviderID:        testKey.ProviderID,
		RefreshToken:      "rt-0",
		AccessToken:       "old-access",
		AccessExpiresAt:   accessExpiry,
		ExternalAccountID: "acct-42",
		Status:            types.UserCredentialActive,
	}))
}

func TestDeviceFlow_LinksAfterApproval(t *testing.T) {
	ctx := context.Background()
	issuer := newFakeIssuer(t)
	issuer.pendingPolls = 1
	s := newTestStore(t, true)
	svc := NewService(s, newTestCache(t), nil)
	clock := time.Now().UTC()
	svc.now = func() time.Time { return clock }

	flow, err := svc.StartLink(ctx, testKey, issuer.entry())
	require.NoError(t, err)
	assert.Equal(t, "ABCD-1234", flow.UserCode, "the vendor's usercode field should be accepted")
	assert.Equal(t, time.Second, flow.Interval, "a string interval should be parsed")
	assert.Equal(t, issuer.srv.URL+"/codex/device", flow.VerificationURI)

	// Polled before the interval elapsed: no vendor call, still pending.
	got, err := svc.PollLink(ctx, testKey, flow.ID, issuer.entry())
	require.NoError(t, err)
	assert.Equal(t, FlowPending, got.Status)

	clock = clock.Add(2 * time.Second)
	got, err = svc.PollLink(ctx, testKey, flow.ID, issuer.entry())
	require.NoError(t, err)
	assert.Equal(t, FlowPending, got.Status, "a 403 from the vendor means the user has not approved yet")

	clock = clock.Add(2 * time.Second)
	got, err = svc.PollLink(ctx, testKey, flow.ID, issuer.entry())
	require.NoError(t, err)
	assert.Equal(t, FlowLinked, got.Status)

	cred, err := s.GetAgentNetworkUserCredential(ctx, testKey.AccountID, testKey.UserID, testKey.ProviderID)
	require.NoError(t, err)
	assert.Equal(t, "rt-1", cred.RefreshToken, "the issued refresh token should be stored")
	assert.Equal(t, "acct-42", cred.ExternalAccountID)
	assert.Equal(t, "pro", cred.PlanType)
	assert.Equal(t, types.UserCredentialActive, cred.Status)

	// A late poll reads the recorded outcome instead of redeeming again.
	got, err = svc.PollLink(ctx, testKey, flow.ID, issuer.entry())
	require.NoError(t, err)
	assert.Equal(t, FlowLinked, got.Status)
}

func TestDeviceFlow_BoundToCaller(t *testing.T) {
	ctx := context.Background()
	issuer := newFakeIssuer(t)
	svc := NewService(newTestStore(t, true), newTestCache(t), nil)

	flow, err := svc.StartLink(ctx, testKey, issuer.entry())
	require.NoError(t, err)

	other := testKey
	other.UserID = "user-2"
	_, err = svc.PollLink(ctx, other, flow.ID, issuer.entry())
	assert.ErrorIs(t, err, ErrFlowNotFound, "another user must not be able to complete someone else's flow")

	_, err = svc.PollLink(ctx, testKey, "unknown", issuer.entry())
	assert.ErrorIs(t, err, ErrFlowNotFound)
}

func TestDeviceFlow_DisabledByVendor(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	entry := newFakeIssuer(t).entry()
	entry.OAuth.DeviceCodeURL = srv.URL + "/usercode"

	svc := NewService(newTestStore(t, true), newTestCache(t), nil)
	_, err := svc.StartLink(context.Background(), testKey, entry)
	assert.ErrorIs(t, err, ErrDeviceLoginDisabled)
}

func TestAccess_ServesValidTokenWithoutRefresh(t *testing.T) {
	issuer := newFakeIssuer(t)
	s := newTestStore(t, true)
	seedCredential(t, s, time.Now().Add(time.Hour))
	svc := NewService(s, newTestCache(t), nil)

	access, err := svc.Access(context.Background(), testKey, issuer.entry())
	require.NoError(t, err)
	assert.Equal(t, []Header{
		{Name: "Authorization", Value: "Bearer old-access"},
		{Name: "chatgpt-account-id", Value: "acct-42"},
	}, access.Headers)
	assert.Zero(t, issuer.refreshCalls.Load(), "a token far from expiry should not be refreshed")
}

func TestAccess_RefreshesNearExpiry(t *testing.T) {
	ctx := context.Background()
	issuer := newFakeIssuer(t)
	issuer.fedramp = true
	s := newTestStore(t, true)
	seedCredential(t, s, time.Now().Add(time.Minute))
	svc := NewService(s, newTestCache(t), nil)

	access, err := svc.Access(ctx, testKey, issuer.entry())
	require.NoError(t, err)
	assert.Equal(t, int32(1), issuer.refreshCalls.Load())
	assert.NotEqual(t, "Bearer old-access", access.Headers[0].Value, "the refreshed token should be served")
	assert.Contains(t, access.Headers, Header{Name: "X-OpenAI-Fedramp", Value: "true"}, "a FedRAMP account should carry the FedRAMP header")
	assert.WithinDuration(t, time.Now().Add(time.Hour), access.ExpiresAt, time.Minute, "expiry should come from the access token")

	cred, err := s.GetAgentNetworkUserCredential(ctx, testKey.AccountID, testKey.UserID, testKey.ProviderID)
	require.NoError(t, err)
	assert.Equal(t, "rt-1", cred.RefreshToken, "the rotated refresh token must be stored")
	assert.Nil(t, cred.RefreshLeaseUntil, "the refresh lease should be released")
}

// Two replicas sharing one database and many concurrent requests must still
// present the refresh token exactly once, or the vendor kills the login.
func TestAccess_ConcurrentReplicasRefreshOnce(t *testing.T) {
	issuer := newFakeIssuer(t)
	s := newTestStore(t, true)
	seedCredential(t, s, time.Now().Add(-time.Minute))
	replicas := []*Service{
		NewService(s, newTestCache(t), nil),
		NewService(s, newTestCache(t), nil),
	}

	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(svc *Service) {
			defer wg.Done()
			_, err := svc.Access(context.Background(), testKey, issuer.entry())
			errs <- err
		}(replicas[i%2])
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.NoError(t, err)
	}
	assert.Equal(t, int32(1), issuer.refreshCalls.Load(), "the refresh token should be redeemed exactly once")
}

func TestAccess_PermanentFailureNeedsRelink(t *testing.T) {
	ctx := context.Background()
	issuer := newFakeIssuer(t)
	issuer.refreshFail = func(w http.ResponseWriter) bool {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return true
	}
	s := newTestStore(t, true)
	seedCredential(t, s, time.Now().Add(-time.Minute))
	svc := NewService(s, newTestCache(t), nil)

	_, err := svc.Access(ctx, testKey, issuer.entry())
	assert.ErrorIs(t, err, ErrRelinkRequired)

	statuses, err := s.GetAccountAgentNetworkUserCredentialStatuses(ctx, testKey.AccountID)
	require.NoError(t, err)
	require.Len(t, statuses, 1)
	assert.Equal(t, types.UserCredentialNeedsRelink, statuses[0].Status)

	_, err = svc.Access(ctx, testKey, issuer.entry())
	assert.ErrorIs(t, err, ErrRelinkRequired)
	assert.Equal(t, int32(1), issuer.refreshCalls.Load(), "a dead login should not be retried upstream")
}

func TestAccess_TransientFailureKeepsUsableToken(t *testing.T) {
	issuer := newFakeIssuer(t)
	issuer.refreshFail = func(w http.ResponseWriter) bool {
		w.WriteHeader(http.StatusBadGateway)
		return true
	}
	s := newTestStore(t, true)
	seedCredential(t, s, time.Now().Add(2*time.Minute))
	svc := NewService(s, newTestCache(t), nil)

	access, err := svc.Access(context.Background(), testKey, issuer.entry())
	require.NoError(t, err, "a token that has not expired yet should still be served")
	assert.Equal(t, "Bearer old-access", access.Headers[0].Value)

	cred, err := s.GetAgentNetworkUserCredential(context.Background(), testKey.AccountID, testKey.UserID, testKey.ProviderID)
	require.NoError(t, err)
	assert.Equal(t, types.UserCredentialActive, cred.Status, "a transient failure must not mark the login dead")
	assert.Nil(t, cred.RefreshLeaseUntil, "the lease should be released for the next attempt")
}

func TestAccess_NotLinked(t *testing.T) {
	issuer := newFakeIssuer(t)
	svc := NewService(newTestStore(t, true), newTestCache(t), nil)
	_, err := svc.Access(context.Background(), testKey, issuer.entry())
	assert.ErrorIs(t, err, ErrNotLinked)
}

func TestStore_RefusesTokensWithoutEncryption(t *testing.T) {
	s := newTestStore(t, false)
	err := s.LinkAgentNetworkUserCredential(context.Background(), &types.UserCredential{
		AccountID: "a", UserID: "u", ProviderID: "p", RefreshToken: "rt", Status: types.UserCredentialActive,
	})
	assert.Error(t, err, "tokens must never be written in plaintext")
}
