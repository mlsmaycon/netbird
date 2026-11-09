package subscription

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
)

type openAIRefreshTransport func(*http.Request) (*http.Response, error)

func (transport openAIRefreshTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return transport(req)
}

func TestOpenAIRefresh_UnknownOutcomeNeverReusesGrant(t *testing.T) {
	var calls atomic.Int32
	client := &Client{HTTP: &http.Client{Transport: openAIRefreshTransport(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("response lost after the issuer rotated the token")
	})}}
	store := newTestStore(t, true)
	seedCredential(t, store, time.Now().Add(-time.Minute))
	entry := newFakeIssuer(t).entry()
	for range 2 {
		svc := NewService(store, newTestCache(t), client)
		_, err := svc.Access(context.Background(), testKey, entry)
		assert.ErrorIs(t, err, ErrRelinkRequired, "later calls and new replicas must not reuse an unresolved refresh token")
	}
	assert.Equal(t, int32(1), calls.Load(), "a lost response must permit only one redemption attempt")
	cred, err := store.GetAgentNetworkProviderCredential(context.Background(), testKey.AccountID, testKey.ProviderID)
	require.NoError(t, err)
	assert.Equal(t, types.CredentialNeedsRelink, cred.Status, "the uncertainty must survive the current replica")
	assert.Empty(t, cred.RefreshToken, "a possibly spent refresh token must be discarded")
}

func TestOpenAIRefresh_RejectsUnusableResponses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "malformed success", status: 200, body: `not-json-sensitive-token`},
		{name: "empty success", status: 200, body: `{}`},
		{name: "missing access", status: 200, body: `{"refresh_token":"rotated","expires_in":3600}`},
		{name: "missing rotation", status: 200, body: `{"access_token":"opaque","expires_in":3600}`},
		{name: "opaque missing expiry", status: 200, body: `{"access_token":"opaque","refresh_token":"rotated"}`},
		{name: "negative expiry", status: 200, body: `{"access_token":"opaque","refresh_token":"rotated","expires_in":-1}`},
		{name: "overflow expiry", status: 200, body: `{"access_token":"opaque","refresh_token":"rotated","expires_in":9223372036854775807}`},
		{name: "unsupported token type", status: 200, body: `{"access_token":"opaque","refresh_token":"rotated","expires_in":3600,"token_type":"mac"}`},
		{name: "unknown throttle outcome", status: 429, body: `{"error":"rate_limit"}`},
		{name: "revoked", status: 400, body: `{"error":"token_revoked"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(srv.Close)
			entry := newFakeIssuer(t).entry()
			entry.OAuth.TokenURL = srv.URL
			store := newTestStore(t, true)
			seedCredential(t, store, time.Now().Add(time.Minute))
			svc := NewService(store, newTestCache(t), nil)
			for range 2 {
				_, err := svc.Access(context.Background(), testKey, entry)
				assert.ErrorIs(t, err, ErrRelinkRequired, "an unusable response must stop further redemption attempts")
				if err != nil {
					assert.NotContains(t, err.Error(), tc.body, "vendor response bodies must not enter diagnostics")
				}
			}
			assert.Equal(t, int32(1), calls.Load(), "neither another request nor an error retry may resend the grant")
		})
	}
}

func TestOpenAIRefresh_ExpiryAndRotation(t *testing.T) {
	for _, explicitExpiry := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy JWT expiry", true: "opaque expires_in"}[explicitExpiry], func(t *testing.T) {
			start := time.Now().UTC().Truncate(time.Second)
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var grant map[string]string
				if err := json.NewDecoder(r.Body).Decode(&grant); !assert.NoError(t, err) {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if calls.Add(1) == 1 {
					assert.Equal(t, "rt-0", grant["refresh_token"], "first redemption must use the linked token")
				} else {
					assert.Equal(t, "rotated-refresh", grant["refresh_token"], "later redemption must use the persisted rotation")
				}
				response := map[string]any{"access_token": jwt(map[string]any{"exp": start.Add(time.Hour).Unix()}), "refresh_token": "rotated-refresh"}
				if explicitExpiry {
					response["access_token"], response["expires_in"] = "opaque-token", 3600
				}
				_ = json.NewEncoder(w).Encode(response)
			}))
			t.Cleanup(srv.Close)
			entry := newFakeIssuer(t).entry()
			entry.OAuth.TokenURL = srv.URL
			store := newTestStore(t, true)
			seedCredential(t, store, start.Add(-time.Minute))
			svc := NewService(store, newTestCache(t), nil)
			svc.now = func() time.Time { return start }
			access, err := svc.Access(context.Background(), testKey, entry)
			require.NoError(t, err)
			assert.Equal(t, start.Add(time.Hour), access.ExpiresAt, "expiry must come from expires_in or the legacy JWT")
			cred, err := store.GetAgentNetworkProviderCredential(context.Background(), testKey.AccountID, testKey.ProviderID)
			require.NoError(t, err)
			assert.Equal(t, "rotated-refresh", cred.RefreshToken, "refresh rotation must be stored before serving access")
			cred.AccessExpiresAt = start.Add(-time.Minute)
			require.NoError(t, store.LinkAgentNetworkProviderCredential(context.Background(), cred))
			_, err = svc.Access(context.Background(), testKey, entry)
			require.NoError(t, err)
			assert.Equal(t, int32(2), calls.Load(), "the subsequent refresh must use the new grant")
		})
	}
}

func TestOpenAIRefresh_CallerCancellationDoesNotLoseRotation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &Client{HTTP: &http.Client{Transport: openAIRefreshTransport(func(req *http.Request) (*http.Response, error) {
		cancel()
		if err := req.Context().Err(); err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: req, Body: io.NopCloser(strings.NewReader(`{"access_token":"opaque-token","refresh_token":"rotated-refresh","expires_in":3600}`))}, nil
	})}}
	store := newTestStore(t, true)
	seedCredential(t, store, time.Now().Add(-time.Minute))
	svc := NewService(store, newTestCache(t), client)
	_, err := svc.Access(ctx, testKey, newFakeIssuer(t).entry())
	require.NoError(t, err)
	assert.ErrorIs(t, ctx.Err(), context.Canceled, "the caller must actually cancel while the issuer is redeeming")
	cred, err := store.GetAgentNetworkProviderCredential(context.Background(), testKey.AccountID, testKey.ProviderID)
	require.NoError(t, err)
	assert.Equal(t, "rotated-refresh", cred.RefreshToken, "cancelling the caller must not discard the returned rotation")
}

func TestOpenAIRefresh_AbandonedLeaseDoesNotRedeem(t *testing.T) {
	store := newTestStore(t, true)
	seedCredential(t, store, time.Now().Add(-time.Minute))
	cred, err := store.GetAgentNetworkProviderCredential(context.Background(), testKey.AccountID, testKey.ProviderID)
	require.NoError(t, err)
	expired := time.Now().Add(-time.Second)
	cred.RefreshLeaseUntil = &expired
	ok, err := store.CompareAndSwapAgentNetworkProviderCredential(context.Background(), cred, cred.Version)
	require.NoError(t, err)
	require.True(t, ok, "the crashed holder must have persisted its lease before redemption")
	var calls atomic.Int32
	client := &Client{HTTP: &http.Client{Transport: openAIRefreshTransport(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("unexpected redemption")
	})}}
	_, err = NewService(store, newTestCache(t), client).Access(context.Background(), testKey, newFakeIssuer(t).entry())
	assert.ErrorIs(t, err, ErrRelinkRequired, "an expired lease is not proof the grant was never consumed")
	assert.Zero(t, calls.Load(), "no replica may reclaim a possibly consumed grant")
}

func TestOpenAIRefresh_ExpiresInTakesPrecedence(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"access_token":  jwt(map[string]any{"exp": time.Now().Add(24 * time.Hour).Unix()}),
		"refresh_token": "rotated", "expires_in": 3600,
	})
	require.NoError(t, err)
	tokens, err := decodeTokens(body)
	require.NoError(t, err)
	now := time.Now().UTC()
	assert.Equal(t, now.Add(time.Hour), (openAIProtocol{}).expiry(tokens, now), "the token endpoint's explicit lifetime takes precedence over a JWT hint")
}

func TestParseIntervalRejectsNonFiniteValue(t *testing.T) {
	assert.Equal(t, defaultPollInterval, parseInterval(json.RawMessage(`"NaN"`)), "nonfinite intervals must not bypass poll throttling")
}
