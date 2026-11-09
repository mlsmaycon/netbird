package subscription

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/catalog"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
)

type authorizationIssuer struct {
	srv       *httptest.Server
	calls     atomic.Int32
	requests  chan map[string]string
	status    int
	accountID string
	entered   chan struct{}
	release   chan struct{}
}

func newAuthorizationIssuer(t *testing.T) *authorizationIssuer {
	t.Helper()
	f := &authorizationIssuer{requests: make(chan map[string]string, 2), status: http.StatusOK}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		assert.Equal(t, "/oauth/token", r.URL.Path, "start and poll must not call the authorization server")
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); !assert.NoError(t, err) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.requests <- body
		if f.entered != nil {
			select {
			case f.entered <- struct{}{}:
			default:
			}
			<-f.release
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.status)
		if f.status != http.StatusOK {
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		response := map[string]any{
			"access_token": "opaque-access-token", "refresh_token": "opaque-refresh-token",
			"expires_in": 3600, "token_type": "Bearer",
		}
		if f.accountID != "" {
			response["account"] = map[string]string{"uuid": f.accountID}
		}
		assert.NoError(t, json.NewEncoder(w).Encode(response))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *authorizationIssuer) entry(t *testing.T) catalog.Provider {
	t.Helper()
	entry, ok := catalog.Lookup("anthropic_claude_login")
	require.True(t, ok)
	profile := *entry.OAuth
	entry.OAuth = &profile
	profile.Issuer = f.srv.URL
	profile.AuthorizeURL = f.srv.URL + "/authorize"
	profile.VerificationURI = profile.AuthorizeURL
	profile.TokenURL = f.srv.URL + "/oauth/token"
	profile.RedirectURI = f.srv.URL + "/callback"
	return entry
}

func authorizationQuery(t *testing.T, flow *Flow) url.Values {
	t.Helper()
	authorize, err := url.Parse(flow.AuthorizationURI)
	require.NoError(t, err)
	query := authorize.Query()
	require.NotEmpty(t, query.Get("state"), "the authorization result must be bound to its flow")
	return query
}

func TestAuthorizationFlow_LinksOpaqueTokens(t *testing.T) {
	for _, tc := range []struct {
		name      string
		accountID string
		callback  bool
	}{
		{name: "code and state without optional account"},
		{name: "registered callback with account", accountID: "claude-account-42", callback: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			issuer := newAuthorizationIssuer(t)
			issuer.accountID = tc.accountID
			entry := issuer.entry(t)
			store := newTestStore(t, true)
			svc := NewService(store, newTestCache(t), nil)
			now := time.Now().UTC().Truncate(time.Second)
			svc.now = func() time.Time { return now }

			flow, err := svc.StartLink(ctx, testKey, testAdmin, entry)
			require.NoError(t, err)
			assert.Equal(t, catalog.OAuthFlowAuthorizationCode, flow.Flow)
			assert.Equal(t, FlowPending, flow.Status)
			assert.Empty(t, flow.UserCode)
			assert.Equal(t, now.Add(entry.OAuth.FlowTTL), flow.ExpiresAt)
			query := authorizationQuery(t, flow)
			assert.Equal(t, entry.OAuth.ClientID, query.Get("client_id"))
			assert.Equal(t, "code", query.Get("response_type"))
			assert.Equal(t, "true", query.Get("code"))
			assert.Equal(t, entry.OAuth.RedirectURI, query.Get("redirect_uri"))
			assert.Equal(t, strings.Join(entry.OAuth.Scopes, " "), query.Get("scope"))
			assert.Equal(t, "S256", query.Get("code_challenge_method"))
			assert.NotEmpty(t, query.Get("code_challenge"))
			assert.Empty(t, query.Get("code_verifier"), "the browser must not receive the PKCE secret")

			pending, err := svc.PollLink(ctx, testKey, testAdmin, flow.ID, entry)
			require.NoError(t, err)
			assert.Equal(t, FlowPending, pending.Status)
			assert.Zero(t, issuer.calls.Load(), "starting and polling a code flow must not redeem anything")

			result := "approved-code#" + query.Get("state")
			if tc.callback {
				result = entry.OAuth.RedirectURI + "?" + url.Values{"code": {"approved-code"}, "state": {query.Get("state")}}.Encode()
			}
			linked, err := svc.CompleteLink(ctx, testKey, testAdmin, flow.ID, result, entry)
			require.NoError(t, err)
			assert.Equal(t, FlowLinked, linked.Status, "opaque access tokens need no ID token")
			assert.True(t, linked.JustLinked, "the completion should record one linking event")
			assert.Equal(t, int32(1), issuer.calls.Load())
			request := <-issuer.requests
			assert.Equal(t, "authorization_code", request["grant_type"])
			assert.Equal(t, entry.OAuth.ClientID, request["client_id"])
			assert.Equal(t, "approved-code", request["code"])
			assert.Equal(t, query.Get("state"), request["state"])
			assert.Equal(t, entry.OAuth.RedirectURI, request["redirect_uri"])
			assert.Len(t, request["code_verifier"], 43, "PKCE must use a fresh 256-bit verifier")
			digest := sha256.Sum256([]byte(request["code_verifier"]))
			assert.Equal(t, query.Get("code_challenge"), base64.RawURLEncoding.EncodeToString(digest[:]), "the exchanged verifier must match the browser's challenge")

			cred, err := store.GetAgentNetworkProviderCredential(ctx, testKey.AccountID, testKey.ProviderID)
			require.NoError(t, err)
			assert.Equal(t, "opaque-access-token", cred.AccessToken)
			assert.Equal(t, "opaque-refresh-token", cred.RefreshToken)
			assert.Equal(t, now.Add(time.Hour), cred.AccessExpiresAt, "opaque token expiry must use expires_in")
			assert.Equal(t, tc.accountID, cred.ExternalAccountID)
			assert.Equal(t, testAdmin, cred.LinkedBy)
			assert.Equal(t, types.CredentialActive, cred.Status)

			_, err = svc.CompleteLink(ctx, testKey, testAdmin, flow.ID, result, entry)
			assert.ErrorIs(t, err, ErrFlowNotFound, "a consumed grant cannot be replayed")
			polled, err := svc.PollLink(ctx, testKey, testAdmin, flow.ID, entry)
			require.NoError(t, err)
			assert.Equal(t, FlowLinked, polled.Status, "the result must remain pollable after grant consumption")
			assert.False(t, polled.JustLinked, "a late poll must not duplicate the linking event")
			assert.Equal(t, int32(1), issuer.calls.Load(), "replay and late polling must not exchange again")
		})
	}
}

func TestAuthorizationFlow_RejectsInvalidCompletionWithoutConsuming(t *testing.T) {
	ctx := context.Background()
	issuer := newAuthorizationIssuer(t)
	entry := issuer.entry(t)
	svc := NewService(newTestStore(t, true), newTestCache(t), nil)
	flow, err := svc.StartLink(ctx, testKey, testAdmin, entry)
	require.NoError(t, err)
	state := authorizationQuery(t, flow).Get("state")
	valid := "approved-code#" + state
	foreignEntry := entry
	foreignEntry.ID = "another-provider-type"
	for _, tc := range []struct {
		name   string
		key    Key
		admin  string
		entry  catalog.Provider
		result string
		want   error
	}{
		{name: "different admin", key: testKey, admin: "other-admin", entry: entry, result: valid, want: ErrFlowNotFound},
		{name: "different account", key: Key{AccountID: "other-account", ProviderID: testKey.ProviderID}, admin: testAdmin, entry: entry, result: valid, want: ErrFlowNotFound},
		{name: "different provider", key: Key{AccountID: testKey.AccountID, ProviderID: "other-provider"}, admin: testAdmin, entry: entry, result: valid, want: ErrFlowNotFound},
		{name: "different catalog entry", key: testKey, admin: testAdmin, entry: foreignEntry, result: valid, want: ErrFlowNotFound},
		{name: "wrong state", key: testKey, admin: testAdmin, entry: entry, result: "approved-code#another-state", want: ErrInvalidAuthorizationCode},
		{name: "bare code", key: testKey, admin: testAdmin, entry: entry, result: "approved-code", want: ErrInvalidAuthorizationCode},
		{name: "foreign callback", key: testKey, admin: testAdmin, entry: entry, result: "https://foreign.example/callback?code=approved-code&state=" + state, want: ErrInvalidAuthorizationCode},
		{name: "wrong callback path", key: testKey, admin: testAdmin, entry: entry, result: issuer.srv.URL + "/other?code=approved-code&state=" + state, want: ErrInvalidAuthorizationCode},
		{name: "duplicate callback state", key: testKey, admin: testAdmin, entry: entry, result: entry.OAuth.RedirectURI + "?code=approved-code&state=" + state + "&state=" + state, want: ErrInvalidAuthorizationCode},
		{name: "extra fragment", key: testKey, admin: testAdmin, entry: entry, result: valid + "#extra", want: ErrInvalidAuthorizationCode},
		{name: "empty code", key: testKey, admin: testAdmin, entry: entry, result: "#" + state, want: ErrInvalidAuthorizationCode},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.CompleteLink(ctx, tc.key, tc.admin, flow.ID, tc.result, tc.entry)
			assert.ErrorIs(t, err, tc.want)
			assert.Zero(t, issuer.calls.Load(), "invalid or foreign completions must not reach the token endpoint")
		})
	}
	_, err = svc.PollLink(ctx, testKey, "other-admin", flow.ID, entry)
	assert.ErrorIs(t, err, ErrFlowNotFound, "only the starter may read the flow result")
	linked, err := svc.CompleteLink(ctx, testKey, testAdmin, flow.ID, valid, entry)
	require.NoError(t, err)
	assert.Equal(t, FlowLinked, linked.Status, "rejected inputs must leave the legitimate grant usable")
	assert.Equal(t, int32(1), issuer.calls.Load())
}

func TestAuthorizationFlow_ExpiredGrantDoesNotExchange(t *testing.T) {
	ctx := context.Background()
	issuer := newAuthorizationIssuer(t)
	entry := issuer.entry(t)
	store := newTestStore(t, true)
	svc := NewService(store, newTestCache(t), nil)
	now := time.Now().UTC()
	svc.now = func() time.Time { return now }
	flow, err := svc.StartLink(ctx, testKey, testAdmin, entry)
	require.NoError(t, err)
	now = flow.ExpiresAt.Add(time.Second)
	result := "approved-code#" + authorizationQuery(t, flow).Get("state")
	expired, err := svc.CompleteLink(ctx, testKey, testAdmin, flow.ID, result, entry)
	require.NoError(t, err)
	assert.Equal(t, FlowExpired, expired.Status)
	polled, err := svc.PollLink(ctx, testKey, testAdmin, flow.ID, entry)
	require.NoError(t, err)
	assert.Equal(t, FlowExpired, polled.Status)
	assert.Zero(t, issuer.calls.Load(), "expired grants must not be sent upstream")
	_, err = store.GetAgentNetworkProviderCredential(ctx, testKey.AccountID, testKey.ProviderID)
	assert.Error(t, err, "an expired grant must not store credentials")
}

func TestAuthorizationFlow_ConcurrentReplicasExchangeOnce(t *testing.T) {
	ctx := context.Background()
	issuer := newAuthorizationIssuer(t)
	issuer.entered = make(chan struct{}, 1)
	issuer.release = make(chan struct{})
	entry := issuer.entry(t)
	store := newTestStore(t, true)
	cache := newTestCache(t)
	first := NewService(store, cache, nil)
	second := NewService(store, cache, nil)
	flow, err := first.StartLink(ctx, testKey, testAdmin, entry)
	require.NoError(t, err)
	result := "approved-code#" + authorizationQuery(t, flow).Get("state")
	type outcome struct {
		flow *Flow
		err  error
	}
	completed := make(chan outcome, 1)
	go func() {
		linked, err := first.CompleteLink(ctx, testKey, testAdmin, flow.ID, result, entry)
		completed <- outcome{flow: linked, err: err}
	}()
	select {
	case <-issuer.entered:
	case <-time.After(5 * time.Second):
		close(issuer.release)
		t.Fatal("first replica did not reach the token endpoint")
	}
	replayed := make(chan outcome, 1)
	go func() {
		linked, err := second.CompleteLink(ctx, testKey, testAdmin, flow.ID, result, entry)
		replayed <- outcome{flow: linked, err: err}
	}()
	select {
	case replay := <-replayed:
		close(issuer.release)
		assert.ErrorIs(t, replay.err, ErrFlowNotFound, "a second replica cannot use an in-flight grant")
	case <-time.After(5 * time.Second):
		close(issuer.release)
		t.Fatal("the second replica did not reject the consumed grant")
	}
	var finished outcome
	select {
	case finished = <-completed:
	case <-time.After(5 * time.Second):
		t.Fatal("the first replica did not finish the exchange")
	}
	require.NoError(t, finished.err)
	assert.Equal(t, FlowLinked, finished.flow.Status)
	assert.Equal(t, int32(1), issuer.calls.Load(), "shared cache consumption must permit one exchange across replicas")
	polled, err := second.PollLink(ctx, testKey, testAdmin, flow.ID, entry)
	require.NoError(t, err)
	assert.Equal(t, FlowLinked, polled.Status, "another replica must observe the stored outcome")
}

func TestAuthorizationFlow_FailedCompletionRemainsPollable(t *testing.T) {
	for _, tc := range []struct {
		name      string
		encrypted bool
		status    int
	}{
		{name: "token exchange rejected", encrypted: true, status: http.StatusBadRequest},
		{name: "encryption unavailable", encrypted: false, status: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			issuer := newAuthorizationIssuer(t)
			issuer.status = tc.status
			entry := issuer.entry(t)
			store := newTestStore(t, tc.encrypted)
			svc := NewService(store, newTestCache(t), nil)
			flow, err := svc.StartLink(ctx, testKey, testAdmin, entry)
			require.NoError(t, err)
			result := "approved-code#" + authorizationQuery(t, flow).Get("state")
			failed, err := svc.CompleteLink(ctx, testKey, testAdmin, flow.ID, result, entry)
			require.NoError(t, err)
			assert.Equal(t, FlowFailed, failed.Status)
			assert.False(t, failed.JustLinked)
			polled, err := svc.PollLink(ctx, testKey, testAdmin, flow.ID, entry)
			require.NoError(t, err)
			assert.Equal(t, FlowFailed, polled.Status, "the UI must be able to observe exchange or persistence failure")
			_, err = svc.CompleteLink(ctx, testKey, testAdmin, flow.ID, result, entry)
			assert.ErrorIs(t, err, ErrFlowNotFound, "a failed exchange must not retry a spent grant")
			assert.Equal(t, int32(1), issuer.calls.Load())
			_, err = store.GetAgentNetworkProviderCredential(ctx, testKey.AccountID, testKey.ProviderID)
			assert.Error(t, err, "failed completion must not write a credential")
		})
	}
}
