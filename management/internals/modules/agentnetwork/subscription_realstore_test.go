package agentnetwork

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/catalog"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/subscription"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/store"
	nbtypes "github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
	"github.com/netbirdio/netbird/util/crypt"
)

// fakeOpenAIAuth answers the ChatGPT device login and refresh just enough
// for the manager to link a login end to end.
func fakeOpenAIAuth(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var refreshes atomic.Int32
	jwtOf := func(claims map[string]any) string {
		raw, _ := json.Marshal(claims)
		return "e30." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"
	}
	tokens := func(w http.ResponseWriter) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token":  jwtOf(map[string]any{"exp": time.Now().Add(time.Hour).Unix()}),
			"refresh_token": "rt-next",
			"id_token": jwtOf(map[string]any{"https://api.openai.com/auth": map[string]any{
				"chatgpt_account_id": "acct-42", "chatgpt_plan_type": "plus",
			}}),
		})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/accounts/deviceauth/usercode", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"device_auth_id": "dev-1", "user_code": "WXYZ-0001", "interval": "1"})
	})
	mux.HandleFunc("/api/accounts/deviceauth/token", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"authorization_code": "code", "code_verifier": "ver"})
	})
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			refreshes.Add(1)
		}
		tokens(w)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &refreshes
}

// codexEntryAt is the real chatgpt_codex catalog entry with its login
// endpoints moved onto the fake issuer. Everything else, including the host
// the proxy is pinned to, is the production entry.
func codexEntryAt(issuer string) func(string) (catalog.Provider, bool) {
	return func(id string) (catalog.Provider, bool) {
		entry, ok := catalog.Lookup(id)
		if !ok || id != "chatgpt_codex" {
			return entry, ok
		}
		prof := *entry.OAuth
		prof.DeviceCodeURL = issuer + "/api/accounts/deviceauth/usercode"
		prof.DeviceTokenURL = issuer + "/api/accounts/deviceauth/token"
		prof.TokenURL = issuer + "/oauth/token"
		entry.OAuth = &prof
		return entry, true
	}
}

type subscriptionFixture struct {
	mgr    *managerImpl
	store  store.Store
	events *[]activity.Activity
}

const (
	subAdmin = "admin-1"
	subUser  = "user-1"
	subOther = "user-2"
)

func newSubscriptionFixture(t *testing.T, encrypted bool) *subscriptionFixture {
	t.Helper()
	ctx := context.Background()
	t.Setenv("NETBIRD_STORE_ENGINE", string(nbtypes.SqliteStoreEngine))
	s, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)
	if encrypted {
		key, err := crypt.GenerateKey()
		require.NoError(t, err)
		enc, err := crypt.NewFieldEncrypt(key)
		require.NoError(t, err)
		s.SetFieldEncrypt(enc)
	}

	require.NoError(t, s.SaveAccount(ctx, &nbtypes.Account{Id: testAccountID}))
	require.NoError(t, s.SaveUser(ctx, &nbtypes.User{Id: subAdmin, AccountID: testAccountID, Role: nbtypes.UserRoleAdmin}))
	require.NoError(t, s.SaveUser(ctx, &nbtypes.User{Id: subUser, AccountID: testAccountID, Role: nbtypes.UserRoleUser, AutoGroups: []string{"grp-eng"}}))
	require.NoError(t, s.SaveUser(ctx, &nbtypes.User{Id: subOther, AccountID: testAccountID, Role: nbtypes.UserRoleUser, AutoGroups: []string{"grp-sales"}}))
	require.NoError(t, s.SaveAgentNetworkSettings(ctx, newSynthTestSettings()))

	issuer, _ := fakeOpenAIAuth(t)
	var events []activity.Activity
	ctrl := gomock.NewController(t)
	accounts := account.NewMockManager(ctrl)
	accounts.EXPECT().StoreEvent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Do(func(_ context.Context, _, _, _ string, a activity.ActivityDescriber, _ map[string]any) {
			if act, ok := a.(activity.Activity); ok {
				events = append(events, act)
			}
		}).AnyTimes()
	accounts.EXPECT().UpdateAccountPeers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	accounts.EXPECT().BufferUpdateAccountPeers(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

	mgr := NewManager(s, permissions.NewManager(s), accounts, nil,
		WithModelLister(&stubLister{}),
		WithCatalogLookup(codexEntryAt(issuer.URL)),
	).(*managerImpl)
	return &subscriptionFixture{mgr: mgr, store: s, events: &events}
}

func (f *subscriptionFixture) createCodexProvider(t *testing.T) *types.Provider {
	t.Helper()
	ctx := context.Background()
	p := types.NewProvider(testAccountID)
	p.ProviderID = "chatgpt_codex"
	p.Name = "ChatGPT"
	p.UpstreamURL = "https://chatgpt.com/"
	p.Enabled = true
	created, err := f.mgr.CreateProvider(ctx, subAdmin, p)
	require.NoError(t, err)
	policy := newSynthTestPolicy(created.ID, "grp-eng", "")
	require.NoError(t, f.store.SaveAgentNetworkPolicy(ctx, policy))
	return created
}

func statusType(err error) status.Type {
	if e, ok := status.FromError(err); ok {
		return e.Type()
	}
	return 0
}

func TestSubscription_CreateProviderPinsVendorHost(t *testing.T) {
	f := newSubscriptionFixture(t, true)
	created := f.createCodexProvider(t)
	assert.Equal(t, "https://chatgpt.com", created.UpstreamURL, "the upstream should be normalised to the vendor host")
	assert.Empty(t, created.APIKey, "a user_oauth provider carries no operator key")

	for name, mutate := range map[string]func(p *types.Provider){
		"foreign host": func(p *types.Provider) { p.UpstreamURL = "https://collector.example" },
		"plain http":   func(p *types.Provider) { p.UpstreamURL = "http://chatgpt.com" },
		"extra path":   func(p *types.Provider) { p.UpstreamURL = "https://chatgpt.com/other" },
		"skip tls":     func(p *types.Provider) { p.SkipTLSVerification = true },
	} {
		t.Run(name, func(t *testing.T) {
			p := types.NewProvider(testAccountID)
			p.ProviderID, p.Name, p.UpstreamURL, p.Enabled = "chatgpt_codex", "x", "https://chatgpt.com", true
			mutate(p)
			_, err := f.mgr.CreateProvider(context.Background(), subAdmin, p)
			assert.Equal(t, status.InvalidArgument, statusType(err), "users' tokens must not be sendable anywhere but the vendor")
		})
	}
}

func TestSubscription_LinkServeUnlink(t *testing.T) {
	ctx := context.Background()
	f := newSubscriptionFixture(t, true)
	provider := f.createCodexProvider(t)

	flow, err := f.mgr.StartProviderLink(ctx, testAccountID, subUser, provider.ID)
	require.NoError(t, err)
	assert.Equal(t, "WXYZ-0001", flow.UserCode)
	assert.Equal(t, subscription.FlowPending, flow.Status)

	// The fake issues a one second interval; the service will not poll the
	// vendor sooner.
	time.Sleep(1100 * time.Millisecond)
	flow, err = f.mgr.PollProviderLink(ctx, testAccountID, subUser, provider.ID, flow.ID)
	require.NoError(t, err)
	require.Equal(t, subscription.FlowLinked, flow.Status)
	assert.Contains(t, *f.events, activity.AgentNetworkSubscriptionLinked, "linking should be audited")

	cfg, err := f.mgr.GetAgentConfigForUser(ctx, testAccountID, subUser)
	require.NoError(t, err)
	require.Len(t, cfg.Providers, 1)
	assert.Equal(t, provider.ID, cfg.Providers[0].ID)
	assert.Equal(t, "user_oauth", cfg.Providers[0].CredentialKind)
	require.NotNil(t, cfg.Providers[0].SubscriptionLink)
	assert.Equal(t, types.SubscriptionLinked, cfg.Providers[0].SubscriptionLink.Status)
	assert.Equal(t, "plus", cfg.Providers[0].SubscriptionLink.PlanType)

	access, err := f.mgr.GetUserCredentialAccess(ctx, testAccountID, subUser, provider.ID)
	require.NoError(t, err)
	assert.Contains(t, access.Headers, subscription.Header{Name: "chatgpt-account-id", Value: "acct-42"})

	// The router route carries no credential, only the marker that makes the
	// proxy fetch the user's own, and is pinned to the vendor host.
	services, err := SynthesizeServices(ctx, f.store, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1)
	router := decodeServiceRouterConfig(t, services[0])
	require.Len(t, router.Providers, 1)
	route := router.Providers[0]
	assert.True(t, route.UserCredential)
	assert.Equal(t, "/backend-api/codex", route.RequestPathPrefix)
	assert.Equal(t, "chatgpt.com", route.UpstreamHost)
	assert.Empty(t, route.AuthHeaderValue, "the shared router config must never carry a user's token")

	require.NoError(t, f.mgr.UnlinkProvider(ctx, testAccountID, subUser, provider.ID))
	_, err = f.mgr.GetUserCredentialAccess(ctx, testAccountID, subUser, provider.ID)
	assert.ErrorIs(t, err, subscription.ErrNotLinked)
	cfg, err = f.mgr.GetAgentConfigForUser(ctx, testAccountID, subUser)
	require.NoError(t, err)
	assert.Equal(t, types.SubscriptionNotLinked, cfg.Providers[0].SubscriptionLink.Status)
	assert.Contains(t, *f.events, activity.AgentNetworkSubscriptionUnlinked, "unlinking should be audited")
}

func TestSubscription_CallerScope(t *testing.T) {
	ctx := context.Background()
	f := newSubscriptionFixture(t, true)
	provider := f.createCodexProvider(t)

	_, err := f.mgr.StartProviderLink(ctx, testAccountID, subOther, provider.ID)
	assert.Equal(t, status.NotFound, statusType(err), "a user no policy covers must not be able to link")

	flow, err := f.mgr.StartProviderLink(ctx, testAccountID, subUser, provider.ID)
	require.NoError(t, err)
	_, err = f.mgr.PollProviderLink(ctx, testAccountID, subAdmin, provider.ID, flow.ID)
	assert.Error(t, err, "nobody else may complete a user's flow, not even an admin")

	_, err = f.mgr.ListProviderLinks(ctx, testAccountID, subUser, provider.ID)
	assert.Equal(t, status.PermissionDenied, statusType(err), "listing everyone's links needs the providers read grant")
	links, err := f.mgr.ListProviderLinks(ctx, testAccountID, subAdmin, provider.ID)
	require.NoError(t, err)
	assert.Empty(t, links)

	// Revoking the user's policy access also stops management serving their
	// login to the proxy.
	require.NoError(t, f.store.LinkAgentNetworkUserCredential(ctx, &types.UserCredential{
		AccountID: testAccountID, UserID: subOther, ProviderID: provider.ID,
		RefreshToken: "rt", AccessToken: "at", AccessExpiresAt: time.Now().Add(time.Hour), Status: types.UserCredentialActive,
	}))
	_, err = f.mgr.GetUserCredentialAccess(ctx, testAccountID, subOther, provider.ID)
	assert.ErrorIs(t, err, subscription.ErrNotLinked)
}

func TestSubscription_RetypingProviderDropsLogins(t *testing.T) {
	ctx := context.Background()
	f := newSubscriptionFixture(t, true)
	provider := f.createCodexProvider(t)
	require.NoError(t, f.store.LinkAgentNetworkUserCredential(ctx, &types.UserCredential{
		AccountID: testAccountID, UserID: subUser, ProviderID: provider.ID,
		RefreshToken: "rt", Status: types.UserCredentialActive,
	}))

	update := provider.Copy()
	update.ProviderID = "openai_api"
	update.UpstreamURL = "https://api.openai.com"
	_, err := f.mgr.UpdateProvider(ctx, subAdmin, update)
	assert.Equal(t, status.InvalidArgument, statusType(err), "leaving user_oauth needs an operator key")

	update.APIKey = "sk-operator"
	_, err = f.mgr.UpdateProvider(ctx, subAdmin, update)
	require.NoError(t, err)
	links, err := f.store.GetAccountAgentNetworkUserCredentialStatuses(ctx, testAccountID)
	require.NoError(t, err)
	assert.Empty(t, links, "logins for the old vendor must not survive a retype")
}

func TestSubscription_RequiresEncryptionKey(t *testing.T) {
	f := newSubscriptionFixture(t, false)
	provider := f.createCodexProvider(t)
	_, err := f.mgr.StartProviderLink(context.Background(), testAccountID, subUser, provider.ID)
	assert.Equal(t, status.PreconditionFailed, statusType(err), "linking must be refused up front without an encryption key")
}
