package agentnetwork

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/catalog"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/subscription"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

func TestCodexBrowserLogin_EncryptedCompletionAndDeviceCompatibility(t *testing.T) {
	ctx := context.Background()
	f := newSubscriptionFixture(t, true)
	provider := f.createCodexProvider(t)
	var deviceRequests, exchanges atomic.Int32
	requests := make(chan url.Values, 4)
	claims, err := json.Marshal(map[string]any{"https://api.openai.com/auth": map[string]string{
		"chatgpt_account_id": "browser-account", "chatgpt_plan_type": "plus",
	}})
	require.NoError(t, err)
	idToken := "e30." + base64.RawURLEncoding.EncodeToString(claims) + ".sig"
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/accounts/deviceauth/usercode" {
			deviceRequests.Add(1)
			_, _ = w.Write([]byte(`{"device_auth_id":"device","user_code":"ABCD-1234","interval":1}`))
			return
		}
		exchanges.Add(1)
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		select {
		case requests <- r.PostForm:
		default:
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "opaque-codex-access", "refresh_token": "browser-refresh",
			"id_token": idToken, "expires_in": 3600,
		})
	}))
	t.Cleanup(issuer.Close)
	f.mgr.lookupCatalog = codexEntryAt(issuer.URL)

	device, err := f.mgr.StartProviderLink(ctx, testAccountID, subAdmin, provider.ID)
	require.NoError(t, err)
	assert.Equal(t, catalog.OAuthFlowDevice, device.Flow, "older callers keep the device default")
	flow, err := f.mgr.StartProviderLink(ctx, testAccountID, subAdmin, provider.ID, catalog.OAuthFlowAuthorizationCode)
	require.NoError(t, err)
	assert.Equal(t, catalog.OAuthFlowAuthorizationCode, flow.Flow, "the explicit browser alternative must be honored")
	assert.Equal(t, int32(1), deviceRequests.Load(), "browser login must not need device authorization")
	authorize, err := url.Parse(flow.AuthorizationURI)
	require.NoError(t, err)
	assert.Equal(t, "auth.openai.com", authorize.Host)
	assert.Equal(t, "S256", authorize.Query().Get("code_challenge_method"))
	assert.Equal(t, "login", authorize.Query().Get("prompt"))
	callback, err := url.Parse(authorize.Query().Get("redirect_uri"))
	require.NoError(t, err)
	require.Equal(t, "http://localhost:1455/auth/callback", callback.String())
	callback.RawQuery = url.Values{"code": {"approved"}, "state": {authorize.Query().Get("state")}}.Encode()

	_, err = f.mgr.CompleteProviderLink(ctx, testAccountID, subAdmin2, provider.ID, flow.ID, callback.String())
	assert.Equal(t, status.NotFound, statusType(err), "a different admin cannot complete the attempt")
	for _, invalid := range []string{
		"approved#" + authorize.Query().Get("state"),
		"https://collector.example/auth/callback?" + callback.RawQuery,
		"http://localhost:1455/auth/callback?code=approved&state=wrong",
	} {
		_, err = f.mgr.CompleteProviderLink(ctx, testAccountID, subAdmin, provider.ID, flow.ID, invalid)
		assert.Equal(t, status.InvalidArgument, statusType(err), "only this flow's full registered callback is accepted")
	}
	assert.Zero(t, exchanges.Load(), "rejected callbacks cannot exchange a code")
	completed, err := f.mgr.CompleteProviderLink(ctx, testAccountID, subAdmin, provider.ID, flow.ID, callback.String())
	require.NoError(t, err)
	require.Equal(t, subscription.FlowLinked, completed.Status)
	var form url.Values
	select {
	case form = <-requests:
	case <-time.After(2 * time.Second):
		t.Fatal("the linked login must have exchanged its authorization code")
	}
	assert.Equal(t, "authorization_code", form.Get("grant_type"))
	assert.Equal(t, "http://localhost:1455/auth/callback", form.Get("redirect_uri"), "browser codes cannot use the device redirect")
	digest := sha256.Sum256([]byte(form.Get("code_verifier")))
	assert.Equal(t, authorize.Query().Get("code_challenge"), base64.RawURLEncoding.EncodeToString(digest[:]))
	assert.NotContains(t, flow.AuthorizationURI, form.Get("code_verifier"))

	polled, err := f.mgr.PollProviderLink(ctx, testAccountID, subAdmin, provider.ID, flow.ID)
	require.NoError(t, err)
	assert.Equal(t, subscription.FlowLinked, polled.Status, "polling must resolve the stored alternative despite the device default")
	assert.False(t, polled.JustLinked)
	_, err = f.mgr.CompleteProviderLink(ctx, testAccountID, subAdmin, provider.ID, flow.ID, callback.String())
	assert.Equal(t, status.NotFound, statusType(err))
	assert.Equal(t, int32(1), exchanges.Load(), "a callback is exchanged once")
	cred, err := f.store.GetAgentNetworkProviderCredential(ctx, testAccountID, provider.ID)
	require.NoError(t, err)
	assert.Equal(t, "browser-account", cred.ExternalAccountID)
	assert.WithinDuration(t, time.Now().Add(time.Hour), cred.AccessExpiresAt, 10*time.Second, "opaque access tokens use expires_in")
	var raw types.ProviderCredential
	require.NoError(t, f.store.(*store.SqlStore).GetDB().Where("account_id = ? AND provider_id = ?", testAccountID, provider.ID).Take(&raw).Error)
	assert.NotContains(t, raw.AccessToken, "opaque-codex-access", "browser tokens stay encrypted")
	assert.NotContains(t, raw.RefreshToken, "browser-refresh", "refresh tokens stay encrypted")
	access, err := f.mgr.GetProviderCredentialAccess(ctx, testAccountID, provider.ID)
	require.NoError(t, err)
	assert.Contains(t, access.Headers, subscription.Header{Name: "chatgpt-account-id", Value: "browser-account"})
	var linkEvents int
	for _, event := range *f.events {
		if event == activity.AgentNetworkSubscriptionLinked {
			linkEvents++
		}
	}
	assert.Equal(t, 1, linkEvents, "browser completion should be audited once")
	device, err = f.mgr.StartProviderLink(ctx, testAccountID, subAdmin, provider.ID)
	require.NoError(t, err)
	assert.Equal(t, catalog.OAuthFlowDevice, device.Flow, "choosing a flow cannot mutate the shared catalog")
	_, err = f.mgr.StartProviderLink(ctx, testAccountID, subAdmin, provider.ID, "unsupported")
	assert.Equal(t, status.InvalidArgument, statusType(err))
}
