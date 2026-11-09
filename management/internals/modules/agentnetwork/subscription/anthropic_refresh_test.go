package subscription

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
)

func anthropicEntry(t *testing.T, endpoint string) catalog.Provider {
	t.Helper()
	entry, ok := catalog.Lookup("anthropic_claude_login")
	require.True(t, ok, "the Claude subscription catalog entry must exist")
	profile := *entry.OAuth
	profile.TokenURL = endpoint
	entry.OAuth = &profile
	return entry
}

func TestAnthropicRefresh_RotatesOnceAcrossReplicas(t *testing.T) {
	var calls atomic.Int32
	var mu sync.Mutex
	liveRefresh := "rt-0"
	generation := 0
	familyRevoked := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var grant map[string]string
		if err := json.NewDecoder(r.Body).Decode(&grant); !assert.NoError(t, err) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		assert.Equal(t, "refresh_token", grant["grant_type"], "the refresh grant must be explicit")
		assert.NotEmpty(t, grant["client_id"], "the built-in public client must be included")
		assert.NotContains(t, grant, "client_secret", "a public client has no secret")
		calls.Add(1)
		mu.Lock()
		defer mu.Unlock()
		if familyRevoked || grant["refresh_token"] != liveRefresh {
			familyRevoked = true
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		generation++
		liveRefresh = fmt.Sprintf("rt-%d", generation)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": fmt.Sprintf("opaque-%d", generation), "refresh_token": liveRefresh,
			"expires_in": 3600, "account": map[string]string{"uuid": "claude-account"},
		})
	}))
	t.Cleanup(srv.Close)
	entry := anthropicEntry(t, srv.URL)
	store := newTestStore(t, true)
	seedCredential(t, store, time.Now().Add(-time.Minute))
	replicas := []*Service{NewService(store, newTestCache(t), nil), NewService(store, newTestCache(t), nil)}
	results := make(chan error, 12)
	var workers sync.WaitGroup
	for i := range 12 {
		workers.Add(1)
		go func(svc *Service) {
			defer workers.Done()
			access, err := svc.Access(context.Background(), testKey, entry)
			if err == nil && (len(access.Headers) == 0 || access.Headers[0].Value != "Bearer opaque-1") {
				err = errors.New("request received a stale token")
			}
			results <- err
		}(replicas[i%2])
	}
	workers.Wait()
	close(results)
	for err := range results {
		require.NoError(t, err)
	}
	assert.Equal(t, int32(1), calls.Load(), "HA replicas must redeem the token only once")
	cred, err := store.GetAgentNetworkProviderCredential(context.Background(), testKey.AccountID, testKey.ProviderID)
	require.NoError(t, err)
	assert.Equal(t, "rt-1", cred.RefreshToken, "the rotated refresh token must be persisted")
	assert.Equal(t, "claude-account", cred.ExternalAccountID, "token-response account metadata should be retained")
	assert.WithinDuration(t, time.Now().Add(time.Hour), cred.AccessExpiresAt, 5*time.Second, "opaque token lifetime must use expires_in")
	access, err := replicas[0].Access(context.Background(), testKey, entry)
	require.NoError(t, err)
	assert.ElementsMatch(t, []Header{
		{Name: "Authorization", Value: "Bearer opaque-1"},
		{Name: "anthropic-version", Value: "2023-06-01"},
		{Name: "anthropic-beta", Value: "oauth-2025-04-20"},
	}, access.Headers, "only the catalog-approved inference headers should be served")

	cred.AccessExpiresAt = time.Now().Add(-time.Minute)
	require.NoError(t, store.LinkAgentNetworkProviderCredential(context.Background(), cred))
	_, err = replicas[0].Access(context.Background(), testKey, entry)
	require.NoError(t, err)
	cred, err = store.GetAgentNetworkProviderCredential(context.Background(), testKey.AccountID, testKey.ProviderID)
	require.NoError(t, err)
	assert.Equal(t, "rt-2", cred.RefreshToken, "the next service refresh must use the rotated value")

	// This issuer revokes the entire token family when any spent token is reused.
	_, err = (&Client{}).Refresh(context.Background(), entry.OAuth, "rt-0")
	assert.ErrorIs(t, err, ErrRelinkRequired, "a repeated refresh token must require linking again")
	cred.AccessExpiresAt = time.Now().Add(-time.Minute)
	require.NoError(t, store.LinkAgentNetworkProviderCredential(context.Background(), cred))
	_, err = replicas[0].Access(context.Background(), testKey, entry)
	assert.ErrorIs(t, err, ErrRelinkRequired, "the service must handle a revoked token family")
}

func TestAnthropicRefresh_FailureDisposition(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		dead   bool
	}{
		{name: "invalid grant", status: 400, body: `{"error":"invalid_grant"}`, dead: true},
		{name: "nested invalid grant", status: 400, body: `{"error":{"type":"invalid_grant"}}`, dead: true},
		{name: "revoked", status: 401, body: `{"error":"authentication_error"}`, dead: true},
		{name: "uncertain server failure", status: 502, body: `{}`, dead: true},
		{name: "malformed successful response", status: 200, body: `not-json-secret`, dead: true},
		{name: "missing expiry", status: 200, body: `{"access_token":"secret"}`, dead: true},
		{name: "rate limited", status: 429, body: `{"error":"rate_limit_error"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(srv.Close)
			entry := anthropicEntry(t, srv.URL)
			store := newTestStore(t, true)
			seedCredential(t, store, time.Now().Add(time.Minute))
			svc := NewService(store, newTestCache(t), nil)
			access, err := svc.Access(context.Background(), testKey, entry)
			cred, loadErr := store.GetAgentNetworkProviderCredential(context.Background(), testKey.AccountID, testKey.ProviderID)
			require.NoError(t, loadErr)
			if !tc.dead {
				require.NoError(t, err)
				assert.Equal(t, "Bearer old-access", access.Headers[0].Value, "an explicit throttle preserves a usable token")
				assert.Equal(t, types.CredentialActive, cred.Status, "throttling must not destroy the login")
				assert.Equal(t, "rt-0", cred.RefreshToken, "throttling does not consume the refresh token")
				return
			}
			assert.ErrorIs(t, err, ErrRelinkRequired, "a dead or uncertain refresh must require relinking")
			assert.Equal(t, types.CredentialNeedsRelink, cred.Status, "failure must be persisted across replicas")
			assert.Empty(t, cred.AccessToken, "dead credentials must not be served")
			assert.Empty(t, cred.RefreshToken, "a possibly spent refresh token must be discarded")
			_, err = svc.Access(context.Background(), testKey, entry)
			assert.ErrorIs(t, err, ErrRelinkRequired, "subsequent requests should see the persisted outcome")
			assert.Equal(t, int32(1), calls.Load(), "there must be no second redemption after an uncertain result")
		})
	}
}

type failedAnthropicTransport struct{ calls atomic.Int32 }

func (transport *failedAnthropicTransport) RoundTrip(*http.Request) (*http.Response, error) {
	transport.calls.Add(1)
	return nil, errors.New("lost response after redemption")
}

func TestAnthropicRefresh_TransportFailureAndAbandonedLease(t *testing.T) {
	for _, abandoned := range []bool{false, true} {
		t.Run(fmt.Sprintf("abandoned=%t", abandoned), func(t *testing.T) {
			store := newTestStore(t, true)
			seedCredential(t, store, time.Now().Add(-time.Minute))
			if abandoned {
				cred, err := store.GetAgentNetworkProviderCredential(context.Background(), testKey.AccountID, testKey.ProviderID)
				require.NoError(t, err)
				expired := time.Now().Add(-time.Second)
				cred.RefreshLeaseUntil = &expired
				ok, err := store.CompareAndSwapAgentNetworkProviderCredential(context.Background(), cred, cred.Version)
				require.NoError(t, err)
				require.True(t, ok, "the simulated crashed replica must own the stored lease")
			}
			transport := &failedAnthropicTransport{}
			svc := NewService(store, newTestCache(t), &Client{HTTP: &http.Client{Transport: transport}})
			_, err := svc.Access(context.Background(), testKey, anthropicEntry(t, "https://issuer.example/token"))
			assert.ErrorIs(t, err, ErrRelinkRequired, "uncertain redemption must not recycle a single-use token")
			cred, err := store.GetAgentNetworkProviderCredential(context.Background(), testKey.AccountID, testKey.ProviderID)
			require.NoError(t, err)
			assert.Equal(t, types.CredentialNeedsRelink, cred.Status, "other replicas must observe the terminal state")
			if abandoned {
				assert.Zero(t, transport.calls.Load(), "an abandoned lease must never redeem the possibly spent token")
			} else {
				assert.Equal(t, int32(1), transport.calls.Load(), "an ambiguous response must not trigger a retry")
			}
		})
	}
}

func TestAnthropicRefresh_MissingReplacementKeepsRefreshToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"new-opaque","expires_in":3600}`))
	}))
	t.Cleanup(srv.Close)
	store := newTestStore(t, true)
	seedCredential(t, store, time.Now().Add(-time.Minute))
	svc := NewService(store, newTestCache(t), nil)
	_, err := svc.Access(context.Background(), testKey, anthropicEntry(t, srv.URL))
	require.NoError(t, err)
	cred, err := store.GetAgentNetworkProviderCredential(context.Background(), testKey.AccountID, testKey.ProviderID)
	require.NoError(t, err)
	assert.Equal(t, "rt-0", cred.RefreshToken, "an omitted refresh token means retain the current value")
}

func TestTokenRequests_DoNotFollowRedirects(t *testing.T) {
	var leaked atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { leaked.Add(1) }))
	t.Cleanup(target.Close)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(srv.Close)
	_, err := (&Client{}).Refresh(context.Background(), anthropicEntry(t, srv.URL).OAuth, "sensitive-refresh")
	require.Error(t, err)
	assert.Zero(t, leaked.Load(), "a redirect must not carry subscription credentials to another endpoint")
}
