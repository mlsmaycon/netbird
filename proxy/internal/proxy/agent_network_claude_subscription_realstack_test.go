package proxy_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/catalog"
	agentNetworkTypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	mgmtgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server/store"
	nbtypes "github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/middleware/bodytap"
	mwbuiltin "github.com/netbirdio/netbird/proxy/internal/middleware/builtin"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
	nbproxytypes "github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/util/crypt"
)

const (
	claudeStackAccountID = "acct-claude-stack"
	claudeStackUserID    = "user-claude-stack"
	claudeStackGroupID   = "grp-claude-stack"
	claudeStackLoginID   = "prov-claude-login"
	claudeStackAPIID     = "prov-claude-api"
	claudeStackModel     = "claude-sonnet-4-7"
	claudeStackBlocked   = "claude-haiku-4-5"
)

type claudeSubscriptionStack struct {
	store     store.Store
	proxy     *proxy.ReverseProxy
	upstream  *chatgptUpstream
	serviceID nbproxytypes.ServiceID
	domain    string
}

// TestReverseProxy_AgentNetworkClaudeSubscription_FullChain exercises the
// encrypted store, credential RPC, refresh and proxy rewrite with both
// Anthropic sign-in methods configured for the same model and vendor host.
func TestReverseProxy_AgentNetworkClaudeSubscription_FullChain(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sqlite store not supported on Windows")
	}
	entry, ok := catalog.Lookup("anthropic_claude_login")
	require.True(t, ok, "Claude subscription must have a catalog entry")
	require.NotNil(t, entry.OAuth, "Claude subscription must describe its OAuth protocol")

	var refreshes atomic.Int32
	const freshAccess = "opaque-claude-access-token"
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil ||
			r.Method != http.MethodPost || r.URL.Path != "/oauth/token" ||
			r.Header.Get("Content-Type") != "application/json" ||
			body["grant_type"] != "refresh_token" || body["refresh_token"] != "claude-rt-0" ||
			body["client_id"] != entry.OAuth.ClientID || body["client_secret"] != "" {
			http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}
		if refreshes.Add(1) != 1 {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": freshAccess, "refresh_token": "claude-rt-1", "expires_in": 3600,
		})
	}))
	t.Cleanup(issuer.Close)
	stack := newClaudeSubscriptionStack(t, issuer.URL)

	w, _ := stack.send(claudeStackUserID, "/claude-login/v1/messages?beta=true")
	assert.Equal(t, http.StatusForbidden, w.Code, "an unlinked login must fail closed")
	assert.Contains(t, w.Body.String(), "llm_policy.credential_not_linked", "the denial must explain the missing login")
	stack.upstream.mu.Lock()
	assert.Empty(t, stack.upstream.reqs, "the API-key route must not serve an unlinked subscription request")
	stack.upstream.mu.Unlock()

	// The API-key route remains usable even while the subscription is unlinked.
	w, cd := stack.send(claudeStackUserID, "/v1/messages?beta=true")
	require.Equal(t, http.StatusOK, w.Code, "the API-key request should be served: %s", w.Body.String())
	assertClaudeAPIRequest(t, stack.upstream.last(t), cd)
	assert.Zero(t, refreshes.Load(), "API-key requests must not redeem a subscription refresh token")

	ctx := context.Background()
	require.NoError(t, stack.store.LinkAgentNetworkProviderCredential(ctx, &agentNetworkTypes.ProviderCredential{
		AccountID: claudeStackAccountID, ProviderID: claudeStackLoginID, LinkedBy: "admin-claude-stack",
		RefreshToken: "claude-rt-0", AccessToken: "expired-claude-access", AccessExpiresAt: time.Now().Add(-time.Minute),
		Status: agentNetworkTypes.CredentialActive,
	}))

	// Both a user's machine and a setup-key machine use the one provider login.
	for _, userID := range []string{claudeStackUserID, ""} {
		w, cd = stack.send(userID, "/claude-login/v1/messages?beta=true")
		require.Equal(t, http.StatusOK, w.Code, "the linked request should be served: %s", w.Body.String())
		out := stack.upstream.last(t)
		assert.Equal(t, "https", out.URL.Scheme, "subscription tokens require HTTPS")
		assert.Equal(t, "api.anthropic.com", out.URL.Host, "subscription tokens must stay on the pinned vendor host")
		assert.Equal(t, "/v1/messages", out.URL.Path, "the NetBird namespace must be stripped before forwarding")
		assert.Equal(t, "beta=true", out.URL.RawQuery, "rewriting must preserve the query")
		assert.Equal(t, []string{"Bearer " + freshAccess}, out.Header.Values("Authorization"), "the linked bearer must replace client credentials")
		assert.Empty(t, out.Header.Get("X-Api-Key"), "the API-key credential must never cross into a subscription route")
		assert.Equal(t, []string{"2023-06-01"}, out.Header.Values("Anthropic-Version"), "client version header copies must be replaced")
		assert.Equal(t, []string{"oauth-2025-04-20"}, out.Header.Values("Anthropic-Beta"), "client beta header copies must be replaced")
		assert.Empty(t, out.Header.Get("Chatgpt-Account-Id"), "unrelated account headers must be stripped")

		md := cd.GetMetadata()
		assert.Equal(t, claudeStackLoginID, md[middleware.KeyLLMResolvedProviderID], "the namespace must select the subscription provider")
		assert.Equal(t, "anthropic", md[middleware.KeyLLMProvider], "the prefixed path must still select the Anthropic parser")
		assert.Equal(t, claudeStackModel, md["llm.model"], "the parser must preserve the requested model")
		assert.Equal(t, "12", md["llm.input_tokens"], "subscription input usage must still be recorded")
		assert.Equal(t, "30", md["llm.output_tokens"], "subscription output usage must still be recorded")
		assert.Equal(t, "subscription", md["llm.billing_mode"], "the route must mark plan billing")
		assert.Equal(t, "subscription", md["cost.skipped"], "subscription usage must skip API pricing")
		assert.Empty(t, md["cost.usd_total"], "subscription usage must not accrue API cost")
	}
	assert.Equal(t, int32(1), refreshes.Load(), "the cached access token must prevent single-use refresh token replay")
	cred, err := stack.store.GetAgentNetworkProviderCredential(ctx, claudeStackAccountID, claudeStackLoginID)
	require.NoError(t, err)
	assert.Equal(t, "claude-rt-1", cred.RefreshToken, "management must persist the rotated refresh token")
	assert.WithinDuration(t, time.Now().Add(time.Hour), cred.AccessExpiresAt, time.Minute, "opaque access expiry must come from expires_in")

	// Discovery and token counting must honor the same stored model policy.
	for _, tc := range []struct {
		name, method, path, model string
	}{
		{"model detail", http.MethodGet, "/claude-login/v1/models/" + claudeStackBlocked, ""},
		{"token counting", http.MethodPost, "/claude-login/v1/messages/count_tokens", claudeStackBlocked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stack.upstream.mu.Lock()
			before := len(stack.upstream.reqs)
			stack.upstream.mu.Unlock()
			w, _ := stack.sendRequest(claudeStackUserID, tc.method, tc.path, tc.model)
			assert.Equal(t, http.StatusForbidden, w.Code, "the stored allowlist must block the disallowed model: %s", w.Body.String())
			stack.upstream.mu.Lock()
			assert.Len(t, stack.upstream.reqs, before, "disallowed requests must not reach Anthropic")
			stack.upstream.mu.Unlock()
		})
	}

	// Linking must not make bare Anthropic requests start using the subscription.
	w, cd = stack.send(claudeStackUserID, "/v1/messages?beta=true")
	require.Equal(t, http.StatusOK, w.Code, "the API-key request should still be served: %s", w.Body.String())
	assertClaudeAPIRequest(t, stack.upstream.last(t), cd)
	assert.Equal(t, int32(1), refreshes.Load(), "API-key traffic must not refresh the linked login")
}

func assertClaudeAPIRequest(t *testing.T, out *http.Request, cd *proxy.CapturedData) {
	t.Helper()
	assert.Equal(t, "api.anthropic.com", out.URL.Host, "the API-key route should keep its Anthropic upstream")
	assert.Equal(t, "/v1/messages", out.URL.Path, "the bare API-key path should remain unchanged")
	assert.Equal(t, "operator-anthropic-key", out.Header.Get("X-Api-Key"), "the static provider must inject its own API key")
	assert.Empty(t, out.Header.Get("Authorization"), "the linked bearer must never cross into the API-key route")
	assert.Equal(t, []string{"client-version", "shadow-version"}, out.Header.Values("Anthropic-Version"), "API-key requests retain client protocol headers")
	assert.Equal(t, []string{"client-beta", "shadow-beta"}, out.Header.Values("Anthropic-Beta"), "subscription header overrides must not affect the API-key route")
	md := cd.GetMetadata()
	assert.Equal(t, claudeStackAPIID, md[middleware.KeyLLMResolvedProviderID], "the bare path must select the API-key provider")
	assert.Empty(t, md["llm.billing_mode"], "API-key traffic must not be marked as plan billing")
	assert.NotEmpty(t, md["cost.usd_total"], "the API-key route must retain usage pricing")
}

func newClaudeSubscriptionStack(t *testing.T, issuerURL string) *claudeSubscriptionStack {
	t.Helper()
	ctx := context.Background()
	t.Setenv("NETBIRD_STORE_ENGINE", string(nbtypes.SqliteStoreEngine))
	st, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)
	key, err := crypt.GenerateKey()
	require.NoError(t, err)
	enc, err := crypt.NewFieldEncrypt(key)
	require.NoError(t, err)
	st.SetFieldEncrypt(enc)

	require.NoError(t, st.SaveAccount(ctx, &nbtypes.Account{Id: claudeStackAccountID}))
	require.NoError(t, st.SaveUser(ctx, &nbtypes.User{
		Id: claudeStackUserID, AccountID: claudeStackAccountID, Role: nbtypes.UserRoleUser, AutoGroups: []string{claudeStackGroupID},
	}))
	require.NoError(t, st.SaveAgentNetworkSettings(ctx, &agentNetworkTypes.Settings{
		AccountID: claudeStackAccountID, Domain: "claude-sub.test.proxy.local", ProxyAddress: "test.proxy.local", EnableLogCollection: true,
	}))
	for _, p := range []*agentNetworkTypes.Provider{
		{
			ID: claudeStackLoginID, ProviderID: "anthropic_claude_login", Name: "Claude login",
		},
		{
			ID: claudeStackAPIID, ProviderID: "anthropic_api", Name: "Anthropic API", APIKey: "operator-anthropic-key",
		},
	} {
		p.AccountID = claudeStackAccountID
		p.UpstreamURL = "https://api.anthropic.com"
		p.Enabled = true
		p.SessionPrivateKey, p.SessionPublicKey = "priv", "pub"
		p.Models = []agentNetworkTypes.ProviderModel{
			{ID: claudeStackModel, InputPer1k: 0.003, OutputPer1k: 0.015},
			{ID: claudeStackBlocked},
		}
		require.NoError(t, st.SaveAgentNetworkProvider(ctx, p))
	}
	require.NoError(t, st.SaveAgentNetworkGuardrail(ctx, &agentNetworkTypes.Guardrail{
		ID: "guard-claude-stack", AccountID: claudeStackAccountID, Name: "Allowed Claude model",
		Checks: agentNetworkTypes.GuardrailChecks{
			ModelAllowlist: agentNetworkTypes.GuardrailModelAllowlist{Enabled: true, Models: []string{claudeStackModel}},
		},
	}))
	require.NoError(t, st.SaveAgentNetworkPolicy(ctx, &agentNetworkTypes.Policy{
		ID: "pol-claude-stack", AccountID: claudeStackAccountID, Name: "Claude", Enabled: true,
		SourceGroups: []string{claudeStackGroupID}, DestinationProviderIDs: []string{claudeStackLoginID, claudeStackAPIID},
		GuardrailIDs: []string{"guard-claude-stack"},
	}))
	lookup := func(id string) (catalog.Provider, bool) {
		entry, ok := catalog.Lookup(id)
		if ok && id == "anthropic_claude_login" {
			prof := *entry.OAuth
			prof.TokenURL = issuerURL + "/oauth/token"
			entry.OAuth = &prof
		}
		return entry, ok
	}
	anMgr := agentnetwork.NewManager(st, nil, nil, nil, agentnetwork.WithCatalogLookup(lookup))
	server := &mgmtgrpc.ProxyServiceServer{}
	server.SetAgentNetworkLimitsService(anMgr)
	server.SetAgentNetworkCredentialService(anMgr)
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	proto.RegisterProxyServiceServer(srv, server)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///claude-bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	services, err := agentnetwork.SynthesizeServices(ctx, st, claudeStackAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1, "both providers should share one Agent Network endpoint")
	svc := services[0]
	testLogger := log.New()
	testLogger.SetLevel(log.PanicLevel)
	mwbuiltin.Configure(ctx, nil, testLogger, proto.NewProxyServiceClient(conn))
	specs := subscriptionChainSpecs(t, svc)
	mwMetrics, err := middleware.NewMetrics(nil)
	require.NoError(t, err)
	mwMgr := middleware.NewManager(0, mwMetrics, testLogger)
	mwMgr.SetResolver(middleware.NewResolver(mwbuiltin.DefaultRegistry()))
	require.NoError(t, mwMgr.Rebuild(svc.ID, []middleware.PathTargetBinding{{ServiceID: svc.ID, PathID: "/", Specs: specs}}))
	upstream := &chatgptUpstream{body: "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_claude","type":"message","role":"assistant","model":"` + claudeStackModel + `","content":[],"usage":{"input_tokens":12,"output_tokens":1}}}` +
		"\n\nevent: message_delta\n" +
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":30}}` +
		"\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"}
	placeholder, err := url.Parse("https://noop.invalid")
	require.NoError(t, err)
	rp := proxy.NewReverseProxy(upstream, "auto", nil, testLogger, proxy.WithMiddlewareManager(mwMgr))
	rp.AddMapping(proxy.Mapping{
		ID: nbproxytypes.ServiceID(svc.ID), AccountID: nbproxytypes.AccountID(claudeStackAccountID), Host: svc.Domain,
		Paths: map[string]*proxy.PathTarget{"/": {
			URL: placeholder, DirectUpstream: true, AgentNetwork: true, Middlewares: specs,
			CaptureConfig: &bodytap.Config{MaxRequestBytes: 1 << 20, MaxResponseBytes: 1 << 20, ContentTypes: []string{"application/json", "text/event-stream"}},
		}},
	})
	return &claudeSubscriptionStack{store: st, proxy: rp, upstream: upstream, serviceID: nbproxytypes.ServiceID(svc.ID), domain: svc.Domain}
}

func (s *claudeSubscriptionStack) send(userID, path string) (*httptest.ResponseRecorder, *proxy.CapturedData) {
	return s.sendRequest(userID, http.MethodPost, path, claudeStackModel)
}

func (s *claudeSubscriptionStack) sendRequest(userID, method, path, model string) (*httptest.ResponseRecorder, *proxy.CapturedData) {
	body := `{"model":"` + model + `","max_tokens":64,"stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest(method, "https://"+s.domain+path, strings.NewReader(body))
	req.Host = s.domain
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer client-token")
	req.Header.Set("X-Api-Key", "client-key")
	req.Header["Anthropic-Version"] = []string{"client-version", "shadow-version"}
	req.Header["Anthropic-Beta"] = []string{"client-beta", "shadow-beta"}
	req.Header.Set("Chatgpt-Account-Id", "client-account")
	cd := proxy.NewCapturedData("claude-req-" + userID + path)
	cd.SetServiceID(s.serviceID)
	cd.SetAccountID(nbproxytypes.AccountID(claudeStackAccountID))
	if userID != "" {
		cd.SetUserID(userID)
	}
	cd.SetUserGroups([]string{claudeStackGroupID})
	cd.SetAuthMethod("tunnel_peer")
	req = req.WithContext(proxy.WithCapturedData(req.Context(), cd))
	w := httptest.NewRecorder()
	s.proxy.ServeHTTP(w, req)
	return w, cd
}
