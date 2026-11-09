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

func (f *subscriptionFixture) createClaudeProvider(t *testing.T) *types.Provider {
	t.Helper()
	p := types.NewProvider(testAccountID)
	p.ProviderID, p.Name = "anthropic_claude_login", "Claude"
	p.UpstreamURL, p.Enabled = "https://api.anthropic.com", true
	created, err := f.mgr.CreateProvider(context.Background(), subAdmin, p)
	require.NoError(t, err)
	require.NoError(t, f.store.SaveAgentNetworkPolicy(context.Background(), newSynthTestPolicy(created.ID, "grp-eng", "")))
	return created
}

func TestClaudeSubscription_CompleteEncryptedLogin(t *testing.T) {
	ctx := context.Background()
	f := newSubscriptionFixture(t, true)
	provider := f.createClaudeProvider(t)
	var exchanges atomic.Int32
	requests := make(chan map[string]string, 2)
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		exchanges.Add(1)
		select {
		case requests <- body:
		default:
			// Let an unexpected replay finish so the exchange-count assertion fails.
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "opaque-claude-access", "refresh_token": "claude-refresh",
			"expires_in": 3600,
			"account":    map[string]string{"uuid": "claude-account", "email_address": "test@example.com"},
		})
	}))
	t.Cleanup(issuer.Close)
	f.mgr.lookupCatalog = func(id string) (catalog.Provider, bool) {
		entry, ok := catalog.Lookup(id)
		if ok && id == "anthropic_claude_login" {
			profile := *entry.OAuth
			profile.TokenURL = issuer.URL + "/token"
			entry.OAuth = &profile
		}
		return entry, ok
	}

	_, err := f.mgr.GetProviderCredentialAccess(ctx, testAccountID, provider.ID)
	assert.ErrorIs(t, err, subscription.ErrNotLinked, "an unlinked provider must refuse access")
	flow, err := f.mgr.StartProviderLink(ctx, testAccountID, subAdmin, provider.ID)
	require.NoError(t, err)
	require.Equal(t, catalog.OAuthFlowAuthorizationCode, flow.Flow, "Claude should use code-paste PKCE")
	authorize, err := url.Parse(flow.AuthorizationURI)
	require.NoError(t, err)
	state := authorize.Query().Get("state")
	require.NotEmpty(t, state, "the authorization URL must bind the result to this attempt")
	code := "approved-code#" + state

	_, err = f.mgr.CompleteProviderLink(ctx, testAccountID, subUser, provider.ID, flow.ID, code)
	assert.Equal(t, status.PermissionDenied, statusType(err), "regular users cannot replace a shared login")
	_, err = f.mgr.CompleteProviderLink(ctx, testAccountID, subAdmin2, provider.ID, flow.ID, code)
	assert.Equal(t, status.NotFound, statusType(err), "another admin cannot consume this flow")
	_, err = f.mgr.CompleteProviderLink(ctx, testAccountID, subAdmin, provider.ID, flow.ID, "approved-code#wrong-state")
	assert.Equal(t, status.InvalidArgument, statusType(err), "a mismatched state must be refused")
	assert.Zero(t, exchanges.Load(), "rejected completions must not contact the issuer")

	completed, err := f.mgr.CompleteProviderLink(ctx, testAccountID, subAdmin, provider.ID, flow.ID, code)
	require.NoError(t, err)
	require.Equal(t, subscription.FlowLinked, completed.Status, "the approved login must be stored")
	assert.Equal(t, int32(1), exchanges.Load(), "the code must be exchanged once")
	exchange := <-requests
	assert.Equal(t, "approved-code", exchange["code"], "the state suffix must not become part of the code")
	assert.Equal(t, state, exchange["state"], "exchange must use the stored flow state")
	assert.Equal(t, authorize.Query().Get("redirect_uri"), exchange["redirect_uri"], "redirect URI must stay pinned")
	challenge := sha256.Sum256([]byte(exchange["code_verifier"]))
	assert.Equal(t, authorize.Query().Get("code_challenge"), base64.RawURLEncoding.EncodeToString(challenge[:]), "the exchanged verifier must match the original challenge")
	assert.NotContains(t, flow.AuthorizationURI, exchange["code_verifier"], "only the challenge may leave management")

	_, err = f.mgr.CompleteProviderLink(ctx, testAccountID, subAdmin, provider.ID, flow.ID, code)
	assert.Error(t, err, "the consumed result cannot be exchanged again")
	assert.Equal(t, int32(1), exchanges.Load(), "a replay must not contact the issuer")
	polled, err := f.mgr.PollProviderLink(ctx, testAccountID, subAdmin, provider.ID, flow.ID)
	require.NoError(t, err)
	assert.Equal(t, subscription.FlowLinked, polled.Status, "completed results remain pollable")
	assert.False(t, polled.JustLinked, "polling cannot emit another link event")

	credential, err := f.store.GetAgentNetworkProviderCredential(ctx, testAccountID, provider.ID)
	require.NoError(t, err)
	assert.Equal(t, "opaque-claude-access", credential.AccessToken, "opaque tokens must survive encrypted storage")
	assert.WithinDuration(t, time.Now().Add(time.Hour), credential.AccessExpiresAt, 10*time.Second, "expiry must come from expires_in")
	var raw types.ProviderCredential
	require.NoError(t, f.store.(*store.SqlStore).GetDB().Where("account_id = ? AND provider_id = ?", testAccountID, provider.ID).Take(&raw).Error)
	assert.NotContains(t, raw.AccessToken, "opaque-claude-access", "access tokens must be encrypted at rest")
	assert.NotContains(t, raw.RefreshToken, "claude-refresh", "refresh tokens must be encrypted at rest")

	access, err := f.mgr.GetProviderCredentialAccess(ctx, testAccountID, provider.ID)
	require.NoError(t, err)
	assert.Contains(t, access.Headers, subscription.Header{Name: "Authorization", Value: "Bearer opaque-claude-access"}, "the proxy receives only short-lived authorization")
	assert.Contains(t, access.Headers, subscription.Header{Name: "anthropic-version", Value: "2023-06-01"}, "the profile pins the version header")
	assert.Contains(t, access.Headers, subscription.Header{Name: "anthropic-beta", Value: "oauth-2025-04-20"}, "the profile pins the OAuth beta header")
	config, err := f.mgr.GetAgentConfigForUser(ctx, testAccountID, subUser)
	require.NoError(t, err)
	require.Len(t, config.Providers, 1, "the policy-covered user should see the shared provider")
	assert.Equal(t, types.SubscriptionLinked, config.Providers[0].SubscriptionLink.Status, "the login serves policy-covered users")
	var linkedEvents int
	for _, event := range *f.events {
		if event == activity.AgentNetworkSubscriptionLinked {
			linkedEvents++
		}
	}
	assert.Equal(t, 1, linkedEvents, "only successful completion should be audited as linked")
	require.NoError(t, f.mgr.UnlinkProvider(ctx, testAccountID, subAdmin, provider.ID))
	_, err = f.mgr.GetProviderCredentialAccess(ctx, testAccountID, provider.ID)
	assert.ErrorIs(t, err, subscription.ErrNotLinked, "unlink must remove access")
}

func TestClaudeSubscription_RequiresEncryptionAndPinnedHost(t *testing.T) {
	f := newSubscriptionFixture(t, false)
	provider := f.createClaudeProvider(t)
	_, err := f.mgr.StartProviderLink(context.Background(), testAccountID, subAdmin, provider.ID)
	assert.Equal(t, status.PreconditionFailed, statusType(err), "linking must fail before authorization without encryption")
	_, err = f.mgr.CompleteProviderLink(context.Background(), testAccountID, subAdmin, provider.ID, "flow", "code#state")
	assert.Equal(t, status.PreconditionFailed, statusType(err), "completion must also refuse to store unencrypted credentials")
	for name, mutate := range map[string]func(*types.Provider){
		"foreign host":   func(p *types.Provider) { p.UpstreamURL = "https://collector.example" },
		"plain HTTP":     func(p *types.Provider) { p.UpstreamURL = "http://api.anthropic.com" },
		"unverified TLS": func(p *types.Provider) { p.SkipTLSVerification = true },
		"extra path":     func(p *types.Provider) { p.UpstreamURL += "/claude-login" },
	} {
		t.Run(name, func(t *testing.T) {
			p := types.NewProvider(testAccountID)
			p.ProviderID, p.Name, p.UpstreamURL, p.Enabled = "anthropic_claude_login", "Claude", "https://api.anthropic.com", true
			mutate(p)
			_, err := f.mgr.CreateProvider(context.Background(), subAdmin, p)
			assert.Equal(t, status.InvalidArgument, statusType(err), "the linked credential must only reach Anthropic over verified TLS")
		})
	}
}
