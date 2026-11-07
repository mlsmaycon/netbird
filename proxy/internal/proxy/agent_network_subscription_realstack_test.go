package proxy_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
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
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
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

// chatgptUpstream stands in for chatgpt.com. The router pins subscription
// routes to the real vendor host, so the test swaps the proxy's transport
// rather than the route: every request the proxy sends out lands here.
type chatgptUpstream struct {
	mu   sync.Mutex
	reqs []*http.Request
	body string
}

func (u *chatgptUpstream) RoundTrip(r *http.Request) (*http.Response, error) {
	u.mu.Lock()
	u.reqs = append(u.reqs, r.Clone(context.Background()))
	u.mu.Unlock()
	if r.Body != nil {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader(u.body)),
		Request:    r,
	}, nil
}

func (u *chatgptUpstream) last(t *testing.T) *http.Request {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	require.NotEmpty(t, u.reqs, "the upstream should have been called")
	return u.reqs[len(u.reqs)-1]
}

func testJWT(claims map[string]any) string {
	raw, _ := json.Marshal(claims)
	return "e30." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"
}

// TestReverseProxy_AgentNetworkSubscription_FullChain drives Codex requests
// through the real proxy chain against a real management stack. Until a
// ChatGPT login is linked to the provider, requests are refused. Once the
// admin has linked one (stored expired here), management refreshes it against
// the (fake) OpenAI token endpoint and the proxy sends every request the
// policy allows on with that login's token and account header, from a user's
// machine and from a machine that belongs to nobody alike. The client's own
// credentials are stripped and usage is recorded without API pricing.
func TestReverseProxy_AgentNetworkSubscription_FullChain(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sqlite store not supported on Windows")
	}

	const (
		accountID  = "acct-sub-1"
		userID     = "user-sub-1"
		adminID    = "admin-sub-1"
		groupID    = "grp-codex"
		providerID = "prov-chatgpt"
		domain     = "sub.test.proxy.local"
	)
	ctx := context.Background()
	testLogger := log.New()
	testLogger.SetLevel(log.PanicLevel)

	// ---- Fake OpenAI token endpoint. It rotates the refresh token and, like
	// the real one, refuses a refresh token it has already rotated.
	var refreshes atomic.Int32
	freshAccess := testJWT(map[string]any{"exp": time.Now().Add(time.Hour).Unix(), "sub": "fresh"})
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.URL.Path != "/oauth/token" || body["grant_type"] != "refresh_token" || body["refresh_token"] != "rt-0" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"code":"refresh_token_reused"}}`))
			return
		}
		refreshes.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": freshAccess, "refresh_token": "rt-1"})
	}))
	t.Cleanup(issuer.Close)
	lookup := func(id string) (catalog.Provider, bool) {
		entry, ok := catalog.Lookup(id)
		if ok && entry.UsesUserOAuth() {
			prof := *entry.OAuth
			prof.TokenURL = issuer.URL + "/oauth/token"
			entry.OAuth = &prof
		}
		return entry, ok
	}

	// ---- Management: real store with an encryption key, real manager.
	t.Setenv("NETBIRD_STORE_ENGINE", string(nbtypes.SqliteStoreEngine))
	st, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)
	key, err := crypt.GenerateKey()
	require.NoError(t, err)
	enc, err := crypt.NewFieldEncrypt(key)
	require.NoError(t, err)
	st.SetFieldEncrypt(enc)

	require.NoError(t, st.SaveAccount(ctx, &nbtypes.Account{Id: accountID}))
	require.NoError(t, st.SaveUser(ctx, &nbtypes.User{Id: userID, AccountID: accountID, Role: nbtypes.UserRoleUser, AutoGroups: []string{groupID}}))
	require.NoError(t, st.SaveAgentNetworkSettings(ctx, &agentNetworkTypes.Settings{
		AccountID: accountID, Domain: domain, ProxyAddress: "test.proxy.local", EnableLogCollection: true,
	}))
	require.NoError(t, st.SaveAgentNetworkProvider(ctx, &agentNetworkTypes.Provider{
		ID: providerID, AccountID: accountID, ProviderID: "chatgpt_codex", Name: "ChatGPT",
		UpstreamURL: "https://chatgpt.com", Enabled: true, SessionPrivateKey: "priv", SessionPublicKey: "pub",
	}))
	require.NoError(t, st.SaveAgentNetworkPolicy(ctx, &agentNetworkTypes.Policy{
		ID: "pol-codex", AccountID: accountID, Name: "codex", Enabled: true,
		SourceGroups: []string{groupID}, DestinationProviderIDs: []string{providerID},
	}))
	anMgr := agentnetwork.NewManager(st, nil, nil, nil, agentnetwork.WithCatalogLookup(lookup))
	server := &mgmtgrpc.ProxyServiceServer{}
	server.SetAgentNetworkLimitsService(anMgr)
	server.SetAgentNetworkCredentialService(anMgr)
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	proto.RegisterProxyServiceServer(srv, server)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	// ---- Proxy: the chain exactly as synthesised.
	services, err := agentnetwork.SynthesizeServices(ctx, st, accountID)
	require.NoError(t, err)
	require.Len(t, services, 1)
	synthSvc := services[0]
	mwbuiltin.Configure(ctx, nil, testLogger, proto.NewProxyServiceClient(conn))
	specs := subscriptionChainSpecs(t, synthSvc)
	mwMetrics, err := middleware.NewMetrics(nil)
	require.NoError(t, err)
	mwMgr := middleware.NewManager(0, mwMetrics, testLogger)
	mwMgr.SetResolver(middleware.NewResolver(mwbuiltin.DefaultRegistry()))
	require.NoError(t, mwMgr.Rebuild(synthSvc.ID, []middleware.PathTargetBinding{{ServiceID: synthSvc.ID, PathID: "/", Specs: specs}}))

	upstream := &chatgptUpstream{body: "event: response.completed\n" +
		`data: {"type":"response.completed","response":{"id":"resp_1","model":"gpt-5.5","usage":{"input_tokens":12,"input_tokens_details":{"cached_tokens":2},"output_tokens":30,"output_tokens_details":{"reasoning_tokens":5},"total_tokens":42}}}` +
		"\n\n"}
	placeholder, err := url.Parse("https://noop.invalid")
	require.NoError(t, err)
	rp := proxy.NewReverseProxy(upstream, "auto", nil, testLogger, proxy.WithMiddlewareManager(mwMgr))
	rp.AddMapping(proxy.Mapping{
		ID:        nbproxytypes.ServiceID(synthSvc.ID),
		AccountID: nbproxytypes.AccountID(accountID),
		Host:      synthSvc.Domain,
		Paths: map[string]*proxy.PathTarget{"/": {
			URL: placeholder, DirectUpstream: true, AgentNetwork: true, Middlewares: specs,
			CaptureConfig: &bodytap.Config{MaxRequestBytes: 1 << 20, MaxResponseBytes: 1 << 20, ContentTypes: []string{"application/json", "text/event-stream"}},
		}},
	})

	send := func(user string) (*httptest.ResponseRecorder, *proxy.CapturedData) {
		body := `{"model":"gpt-5.5","stream":true,"store":false,"input":[{"role":"user","content":[{"type":"input_text","text":"hi"}]}]}`
		req := httptest.NewRequest("POST", "https://"+synthSvc.Domain+"/backend-api/codex/responses", strings.NewReader(body))
		req.Host = synthSvc.Domain
		req.Header.Set("Content-Type", "application/json")
		// What a client must not be able to choose: its own bearer and the
		// ChatGPT account its request acts for.
		req.Header.Set("Authorization", "Bearer nb-agent-key")
		req.Header.Set("chatgpt-account-id", "someone-elses-account")
		cd := proxy.NewCapturedData("req-" + user)
		cd.SetServiceID(nbproxytypes.ServiceID(synthSvc.ID))
		cd.SetAccountID(nbproxytypes.AccountID(accountID))
		if user != "" {
			cd.SetUserID(user)
		}
		cd.SetUserGroups([]string{groupID})
		cd.SetAuthMethod("tunnel_peer")
		req = req.WithContext(proxy.WithCapturedData(req.Context(), cd))
		w := httptest.NewRecorder()
		rp.ServeHTTP(w, req)
		return w, cd
	}

	// Nothing linked yet: refused before reaching the vendor.
	w, _ := send(userID)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "llm_policy.credential_not_linked")
	upstream.mu.Lock()
	assert.Empty(t, upstream.reqs, "a refused request must not reach the vendor")
	upstream.mu.Unlock()

	// The admin links the provider's login.
	require.NoError(t, st.LinkAgentNetworkProviderCredential(ctx, &agentNetworkTypes.ProviderCredential{
		AccountID: accountID, ProviderID: providerID, LinkedBy: adminID,
		RefreshToken: "rt-0", AccessToken: "expired-access", AccessExpiresAt: time.Now().Add(-time.Minute),
		ExternalAccountID: "acct-42", FedRAMP: true, Status: agentNetworkTypes.CredentialActive,
	}))

	w, cd := send(userID)
	require.Equal(t, http.StatusOK, w.Code, "the request should be served; body=%s", w.Body.String())
	assert.Equal(t, int32(1), refreshes.Load(), "management should have refreshed the expired login once")

	out := upstream.last(t)
	assert.Equal(t, "chatgpt.com", out.URL.Host, "subscription traffic must only go to the vendor")
	assert.Equal(t, "/backend-api/codex/responses", out.URL.Path)
	assert.Equal(t, "Bearer "+freshAccess, out.Header.Get("Authorization"), "the linked login's refreshed token should replace the client's")
	assert.Equal(t, []string{"acct-42"}, out.Header.Values("Chatgpt-Account-Id"), "the account header must be the linked login's")
	assert.Equal(t, "true", out.Header.Get("X-OpenAI-Fedramp"))

	md := cd.GetMetadata()
	assert.Equal(t, "gpt-5.5", md["llm.model"], "the Codex path should be parsed as the Responses API")
	assert.Equal(t, "12", md["llm.input_tokens"], "tokens should still be recorded")
	assert.Equal(t, "30", md["llm.output_tokens"])
	assert.Equal(t, "subscription", md["llm.billing_mode"])
	assert.Equal(t, "subscription", md["cost.skipped"], "subscription usage must not be priced at API rates")
	assert.Empty(t, md["cost.usd_total"])

	cred, err := st.GetAgentNetworkProviderCredential(ctx, accountID, providerID)
	require.NoError(t, err)
	assert.Equal(t, "rt-1", cred.RefreshToken, "the rotated refresh token must be kept")

	// A machine added with a setup key belongs to no user; the shared login
	// serves it too, from the proxy's cache: no second refresh, which the
	// fake issuer would refuse as a reused token anyway.
	w, cd = send("")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "Bearer "+freshAccess, upstream.last(t).Header.Get("Authorization"))
	assert.Equal(t, int32(1), refreshes.Load())
	assert.Equal(t, "subscription", cd.GetMetadata()["llm.billing_mode"])
}

func subscriptionChainSpecs(t *testing.T, svc *rpservice.Service) []middleware.Spec {
	t.Helper()
	require.NotEmpty(t, svc.Targets)
	specs := make([]middleware.Spec, 0, len(svc.Targets[0].Options.Middlewares))
	for _, mw := range svc.Targets[0].Options.Middlewares {
		var slot middleware.Slot
		switch mw.Slot {
		case rpservice.MiddlewareSlotOnRequest:
			slot = middleware.SlotOnRequest
		case rpservice.MiddlewareSlotOnResponse:
			slot = middleware.SlotOnResponse
		case rpservice.MiddlewareSlotTerminal:
			slot = middleware.SlotTerminal
		default:
			t.Fatalf("unknown middleware slot %q on %s", mw.Slot, mw.ID)
		}
		specs = append(specs, middleware.Spec{
			ID: mw.ID, Slot: slot, Enabled: mw.Enabled, FailMode: middleware.FailOpen,
			Timeout: middleware.DefaultTimeout, RawConfig: append([]byte(nil), mw.ConfigJSON...), CanMutate: mw.CanMutate,
		})
	}
	return specs
}
