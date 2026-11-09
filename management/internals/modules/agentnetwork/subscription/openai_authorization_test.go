package subscription

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
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
)

func TestOpenAIAuthorizationFlow_PastedCallbackUsesPKCE(t *testing.T) {
	ctx := context.Background()
	var calls atomic.Int32
	requests := make(chan url.Values, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"), "OpenAI code exchange must use the documented form encoding")
		if err := r.ParseForm(); !assert.NoError(t, err) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		requests <- r.PostForm
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "opaque-codex-access", "refresh_token": "codex-refresh", "expires_in": 3600,
			"id_token": jwt(map[string]any{"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "codex-account", "chatgpt_plan_type": "pro"}}),
		})
	}))
	t.Cleanup(server.Close)
	entry, ok := catalog.Lookup("chatgpt_codex")
	require.True(t, ok, "the existing ChatGPT entry must remain available")
	profile := *entry.OAuth
	profile.TokenURL = server.URL
	entry.OAuth = &profile
	selected := entry
	selectedProfile := profile
	selectedProfile.Flow = catalog.OAuthFlowAuthorizationCode
	selected.OAuth = &selectedProfile
	store := newTestStore(t, true)
	svc := NewService(store, newTestCache(t), nil)
	now := time.Now().UTC().Truncate(time.Second)
	svc.now = func() time.Time { return now }
	flow, err := svc.StartLink(ctx, testKey, testAdmin, selected)
	require.NoError(t, err)
	query := authorizationQuery(t, flow)
	assert.Equal(t, catalog.OAuthFlowDevice, entry.OAuth.Flow, "selecting browser login must not change the catalog default")
	assert.Equal(t, catalog.OAuthFlowAuthorizationCode, flow.Flow, "the selected flow must survive in the cache")
	assert.Equal(t, "http://localhost:1455/auth/callback", query.Get("redirect_uri"), "self-hosters use the pinned loopback callback without registration")
	assert.Equal(t, "login", query.Get("prompt"), "browser login should request an explicit account login")
	assert.Equal(t, "true", query.Get("id_token_add_organizations"), "account metadata is required for the Codex routing header")
	assert.Equal(t, "true", query.Get("codex_cli_simplified_flow"), "the browser login should use the supported Codex flow")
	assert.Empty(t, query.Get("code"), "Claude's copy-code option must not leak into the OpenAI request")
	assert.Equal(t, strings.Join(profile.Scopes, " "), query.Get("scope"), "the authorization request must use the pinned scope list")
	assert.Equal(t, "S256", query.Get("code_challenge_method"), "the browser flow must use PKCE S256")
	pending, err := svc.PollLink(ctx, testKey, testAdmin, flow.ID, entry)
	require.NoError(t, err)
	assert.Equal(t, FlowPending, pending.Status, "polling with the default profile must resume the selected browser flow")
	assert.Zero(t, calls.Load(), "browser flow polling must not call the device or token endpoints")
	callback := profile.RedirectURI + "?" + url.Values{"code": {"approved-code"}, "state": {query.Get("state")}}.Encode()
	for _, invalid := range []string{
		"approved-code#" + query.Get("state"),
		strings.Replace(callback, "localhost:1455", "localhost:1456", 1),
		strings.Replace(callback, "http://localhost:1455", "https://attacker.example", 1),
		profile.RedirectURI + "?code=approved-code&state=wrong-state",
	} {
		_, err := svc.CompleteLink(ctx, testKey, testAdmin, flow.ID, invalid, entry)
		assert.ErrorIs(t, err, ErrInvalidAuthorizationCode, "only the complete registered callback URL with matching state may finish this login")
	}
	assert.Zero(t, calls.Load(), "invalid callback input must leave the real authorization grant untouched")
	linked, err := svc.CompleteLink(ctx, testKey, testAdmin, flow.ID, callback, entry)
	require.NoError(t, err)
	assert.Equal(t, FlowLinked, linked.Status, "the browser fallback must complete against the default device profile")
	assert.True(t, linked.JustLinked, "successful completion should emit one linking event")
	request := <-requests
	assert.Equal(t, profile.RedirectURI, request.Get("redirect_uri"), "browser code exchange must use the loopback redirect, not the device callback")
	assert.Equal(t, profile.ClientID, request.Get("client_id"), "the public client ID is supplied by the catalog")
	assert.Equal(t, "authorization_code", request.Get("grant_type"), "the submitted callback must exchange an authorization grant")
	assert.Equal(t, "approved-code", request.Get("code"), "only the code belongs in the token request")
	digest := sha256.Sum256([]byte(request.Get("code_verifier")))
	assert.Equal(t, query.Get("code_challenge"), base64.RawURLEncoding.EncodeToString(digest[:]), "only the server-held verifier can redeem this code")
	cred, err := store.GetAgentNetworkProviderCredential(ctx, testKey.AccountID, testKey.ProviderID)
	require.NoError(t, err)
	assert.Equal(t, "codex-account", cred.ExternalAccountID, "the linked account must retain its routing identity")
	assert.Equal(t, now.Add(time.Hour), cred.AccessExpiresAt, "opaque OpenAI tokens must honor expires_in during initial linking too")
	_, err = svc.CompleteLink(ctx, testKey, testAdmin, flow.ID, callback, entry)
	assert.ErrorIs(t, err, ErrFlowNotFound, "the pasted callback cannot be replayed")
	polled, err := svc.PollLink(ctx, testKey, testAdmin, flow.ID, entry)
	require.NoError(t, err)
	assert.Equal(t, FlowLinked, polled.Status, "the completion result must remain readable through the default profile")
	assert.False(t, polled.JustLinked, "polling must not duplicate the linking event")
	assert.Equal(t, int32(1), calls.Load(), "one callback grants exactly one token exchange")
}

func TestOpenAIAuthorizationFlow_CancellationPreservesRedeemedTokens(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	body, err := json.Marshal(map[string]any{
		"access_token": "opaque-access", "refresh_token": "refresh", "expires_in": 3600,
		"id_token": jwt(map[string]any{"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "codex-account"}}),
	})
	require.NoError(t, err)
	client := &Client{HTTP: &http.Client{Transport: openAIRefreshTransport(func(req *http.Request) (*http.Response, error) {
		cancel()
		if err := req.Context().Err(); err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Request: req, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
	})}}
	entry, ok := catalog.Lookup("chatgpt_codex")
	require.True(t, ok)
	selected := entry
	profile := *entry.OAuth
	profile.Flow = catalog.OAuthFlowAuthorizationCode
	selected.OAuth = &profile
	store := newTestStore(t, true)
	svc := NewService(store, newTestCache(t), client)
	flow, err := svc.StartLink(ctx, testKey, testAdmin, selected)
	require.NoError(t, err)
	query := authorizationQuery(t, flow)
	callback := profile.RedirectURI + "?" + url.Values{"code": {"approved"}, "state": {query.Get("state")}}.Encode()
	linked, err := svc.CompleteLink(ctx, testKey, testAdmin, flow.ID, callback, entry)
	require.NoError(t, err)
	assert.ErrorIs(t, ctx.Err(), context.Canceled, "the dashboard must disconnect during token redemption")
	assert.Equal(t, FlowLinked, linked.Status, "consuming the verifier must not lose the login when its caller disconnects")
	cred, err := store.GetAgentNetworkProviderCredential(context.Background(), testKey.AccountID, testKey.ProviderID)
	require.NoError(t, err)
	assert.Equal(t, "refresh", cred.RefreshToken, "the accepted authorization must be persisted after cancellation")
}
