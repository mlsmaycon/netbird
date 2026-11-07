package llm_router

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type fakeCredentialClient struct {
	calls  atomic.Int32
	status proto.GetLLMProviderCredentialResponse_Status
	err    error
	expiry time.Time
	gotReq *proto.GetLLMProviderCredentialRequest
	mu     sync.Mutex
}

func (f *fakeCredentialClient) GetLLMProviderCredential(_ context.Context, in *proto.GetLLMProviderCredentialRequest, _ ...grpc.CallOption) (*proto.GetLLMProviderCredentialResponse, error) {
	f.calls.Add(1)
	f.mu.Lock()
	f.gotReq = in
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	if f.status != proto.GetLLMProviderCredentialResponse_OK {
		return &proto.GetLLMProviderCredentialResponse{Status: f.status}, nil
	}
	expiry := f.expiry
	if expiry.IsZero() {
		expiry = time.Now().Add(time.Hour)
	}
	return &proto.GetLLMProviderCredentialResponse{
		Status: proto.GetLLMProviderCredentialResponse_OK,
		Headers: []*proto.LLMCredentialHeader{
			{Name: "Authorization", Value: "Bearer linked-" + in.GetProviderId()},
			{Name: "chatgpt-account-id", Value: "acct-42"},
		},
		ExpiresAt: timestamppb.New(expiry),
	}, nil
}

func codexRoute() ProviderRoute {
	return ProviderRoute{
		ID:                "prov-chatgpt",
		Vendor:            "openai",
		Models:            []string{},
		UpstreamScheme:    "https",
		UpstreamHost:      "chatgpt.com",
		AuthHeaderName:    "Authorization",
		AllowedGroupIDs:   []string{defaultTestGroup},
		LinkedCredential:  true,
		RequestPathPrefix: "/backend-api/codex",
	}
}

func openAICatchAll() ProviderRoute {
	return ProviderRoute{
		ID:              "prov-openai",
		Vendor:          "openai",
		Models:          []string{},
		UpstreamScheme:  "https",
		UpstreamHost:    "api.openai.com",
		AuthHeaderName:  "Authorization",
		AuthHeaderValue: "Bearer sk-operator",
		AllowedGroupIDs: []string{defaultTestGroup},
	}
}

func codexInput(model, path string) *middleware.Input {
	in := newInputVendorModelURL("openai", model, path)
	in.Method = "POST"
	in.AccountID = "acc-1"
	in.UserID = "user-1"
	return in
}

func newCodexRouter(client CredentialClient, routes ...ProviderRoute) *Middleware {
	return newWithCredentials(Config{Providers: routes}, client, newCredentialCache())
}

func TestLinkedCredential_InjectsLinkedLoginHeaders(t *testing.T) {
	client := &fakeCredentialClient{status: proto.GetLLMProviderCredentialResponse_OK}
	mw := newCodexRouter(client, openAICatchAll(), codexRoute())

	out, err := mw.Invoke(context.Background(), codexInput("gpt-5.5", "/backend-api/codex/responses"))
	require.NoError(t, err)
	require.Equal(t, middleware.DecisionAllow, out.Decision)
	rw := out.Mutations.RewriteUpstream
	require.NotNil(t, rw)
	assert.Equal(t, "chatgpt.com", rw.Host, "the codex path should reach the subscription route, not the API catch-all")
	assert.Nil(t, rw.AuthHeader, "no static credential may ride along")
	assert.Equal(t, []middleware.AuthHeader{
		{Name: "Authorization", Value: "Bearer linked-prov-chatgpt"},
		{Name: "chatgpt-account-id", Value: "acct-42"},
	}, rw.ExtraAuthHeaders)
	assert.Contains(t, rw.StripHeaders, "chatgpt-account-id", "a client must not choose the account the login acts for")
	assert.Contains(t, rw.StripHeaders, "X-OpenAI-Fedramp")
	mode, _ := metaValue(t, out.Metadata, middleware.KeyLLMBillingMode)
	assert.Equal(t, "subscription", mode)
	assert.Equal(t, "prov-chatgpt", client.gotReq.GetProviderId())
	assert.Equal(t, "acc-1", client.gotReq.GetAccountId())
}

func TestLinkedCredential_RoutesStayApart(t *testing.T) {
	client := &fakeCredentialClient{status: proto.GetLLMProviderCredentialResponse_OK}

	// With only the subscription route configured, a regular API request
	// must not be served from it: chatgpt.com does not speak that API, and
	// the plan would be spent on traffic meant for a key.
	mw := newCodexRouter(client, codexRoute())
	out, err := mw.Invoke(context.Background(), codexInput("gpt-5.5", "/v1/responses"))
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionDeny, out.Decision)
	assert.Equal(t, denyCodeNotRoutable, out.DenyReason.Code)

	// And an API catch-all never serves the codex path.
	mw = newCodexRouter(client, openAICatchAll())
	out, err = mw.Invoke(context.Background(), codexInput("gpt-5.5", "/v1/responses"))
	require.NoError(t, err)
	assert.Equal(t, "api.openai.com", out.Mutations.RewriteUpstream.Host)
	assert.Zero(t, client.calls.Load(), "regular routes never ask for user credentials")
}

func TestLinkedCredential_DeniesWithoutUsableLogin(t *testing.T) {
	cases := []struct {
		name       string
		client     CredentialClient
		userID     string
		wantStatus int
		wantReason string
	}{
		{"not linked", &fakeCredentialClient{status: proto.GetLLMProviderCredentialResponse_NOT_LINKED}, "user-1", 403, "not_linked"},
		{"needs relink", &fakeCredentialClient{status: proto.GetLLMProviderCredentialResponse_NEEDS_RELINK}, "user-1", 403, "needs_relink"},
		{"management unavailable", &fakeCredentialClient{status: proto.GetLLMProviderCredentialResponse_UNAVAILABLE}, "user-1", 503, "unavailable"},
		{"rpc error", &fakeCredentialClient{err: errors.New("boom")}, "user-1", 503, "unavailable"},
		{"unknown status", &fakeCredentialClient{status: proto.GetLLMProviderCredentialResponse_UNSPECIFIED}, "user-1", 503, "unavailable"},
		{"no management client", nil, "user-1", 503, "unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mw := newCodexRouter(tc.client, codexRoute())
			in := codexInput("gpt-5.5", "/backend-api/codex/responses")
			in.UserID = tc.userID
			out, err := mw.Invoke(context.Background(), in)
			require.NoError(t, err)
			require.Equal(t, middleware.DecisionDeny, out.Decision, "every failure must deny")
			assert.Equal(t, tc.wantStatus, out.DenyStatus)
			assert.Equal(t, denyCodeCredentialNotLinked, out.DenyReason.Code)
			assert.Equal(t, tc.wantReason, out.DenyReason.Details["reason"])
			assert.Nil(t, out.Mutations, "a denial must carry no upstream rewrite")
		})
	}
}

func TestLinkedCredential_GroupsStillGate(t *testing.T) {
	client := &fakeCredentialClient{status: proto.GetLLMProviderCredentialResponse_OK}
	mw := newCodexRouter(client, codexRoute())
	in := codexInput("gpt-5.5", "/backend-api/codex/responses")
	in.UserGroups = []string{"grp-other"}

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionDeny, out.Decision)
	assert.Equal(t, denyCodeNoAuthorisedRoute, out.DenyReason.Code)
	assert.Zero(t, client.calls.Load(), "an unauthorised caller must not trigger a credential lookup")
}

func TestLinkedCredential_ModellessListingAndMissingModel(t *testing.T) {
	client := &fakeCredentialClient{status: proto.GetLLMProviderCredentialResponse_OK}
	mw := newCodexRouter(client, codexRoute())

	in := codexInput("", "/backend-api/codex/models?client_version=1")
	in.Method = "GET"
	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.Equal(t, middleware.DecisionAllow, out.Decision)
	nonInference, _ := metaValue(t, out.Metadata, middleware.KeyLLMNonInference)
	assert.Equal(t, "true", nonInference)

	out, err = mw.Invoke(context.Background(), codexInput("", "/backend-api/codex/responses"))
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionDeny, out.Decision, "an inference request without a model cannot be authorised")
}

// The cache lives outside the router, so a rebuilt router (one per mapping
// push) keeps serving cached answers instead of sending every request back to
// management, and answers stop being reused before the token expires.
func TestLinkedCredential_CacheSurvivesRebuildAndHonoursExpiry(t *testing.T) {
	client := &fakeCredentialClient{status: proto.GetLLMProviderCredentialResponse_OK, expiry: time.Now().Add(3 * time.Minute)}
	cache := newCredentialCache()
	now := time.Now()
	cache.now = func() time.Time { return now }

	first := newWithCredentials(Config{Providers: []ProviderRoute{codexRoute()}}, client, cache)
	_, err := first.Invoke(context.Background(), codexInput("gpt-5.5", "/backend-api/codex/responses"))
	require.NoError(t, err)

	rebuilt := newWithCredentials(Config{Providers: []ProviderRoute{codexRoute()}}, client, cache)
	_, err = rebuilt.Invoke(context.Background(), codexInput("gpt-5.5", "/backend-api/codex/responses"))
	require.NoError(t, err)
	assert.Equal(t, int32(1), client.calls.Load(), "a rebuilt router should reuse the cached answer")

	// The login is the provider's, so another user's request shares it.
	in := codexInput("gpt-5.5", "/backend-api/codex/responses")
	in.UserID = "user-2"
	out, err := rebuilt.Invoke(context.Background(), in)
	require.NoError(t, err)
	assert.Equal(t, "Bearer linked-prov-chatgpt", out.Mutations.RewriteUpstream.ExtraAuthHeaders[0].Value)
	assert.Equal(t, int32(1), client.calls.Load(), "every caller of a provider shares one cached answer")

	// The token expires in three minutes; it is not served within the last
	// minute of its life.
	now = now.Add(2*time.Minute + time.Second)
	_, err = rebuilt.Invoke(context.Background(), codexInput("gpt-5.5", "/backend-api/codex/responses"))
	require.NoError(t, err)
	assert.Equal(t, int32(2), client.calls.Load(), "a token close to expiry should be fetched again")
}

// Agents on machines added with a setup key belong to no user; the shared
// login serves them like anyone else the policy covers.
func TestLinkedCredential_ServesRequestsWithoutUser(t *testing.T) {
	client := &fakeCredentialClient{status: proto.GetLLMProviderCredentialResponse_OK}
	mw := newCodexRouter(client, codexRoute())
	in := codexInput("gpt-5.5", "/backend-api/codex/responses")
	in.UserID = ""

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionAllow, out.Decision)
}

func TestLinkedCredential_FailuresAreNotCached(t *testing.T) {
	client := &fakeCredentialClient{status: proto.GetLLMProviderCredentialResponse_NOT_LINKED}
	mw := newCodexRouter(client, codexRoute())
	_, err := mw.Invoke(context.Background(), codexInput("gpt-5.5", "/backend-api/codex/responses"))
	require.NoError(t, err)

	// The user links; the very next request must see it.
	client.status = proto.GetLLMProviderCredentialResponse_OK
	out, err := mw.Invoke(context.Background(), codexInput("gpt-5.5", "/backend-api/codex/responses"))
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionAllow, out.Decision)
}

func TestLinkedCredential_ConcurrentLookupsCollapse(t *testing.T) {
	client := &fakeCredentialClient{status: proto.GetLLMProviderCredentialResponse_OK}
	mw := newCodexRouter(client, codexRoute())
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := mw.Invoke(context.Background(), codexInput("gpt-5.5", "/backend-api/codex/responses"))
			assert.NoError(t, err)
			assert.Equal(t, middleware.DecisionAllow, out.Decision)
		}()
	}
	wg.Wait()
	assert.LessOrEqual(t, client.calls.Load(), int32(2), "concurrent requests should share one management lookup")
}

// A model only a ChatGPT-login route serves, asked for on an API path, must
// say where the provider is reachable instead of claiming no provider exists.
func TestLinkedCredential_APIPathPointsAtCodexPath(t *testing.T) {
	client := &fakeCredentialClient{status: proto.GetLLMProviderCredentialResponse_OK}
	route := codexRoute()
	route.Models = []string{"gpt-5.5"}
	mw := newCodexRouter(client, route)

	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		out, err := mw.Invoke(context.Background(), codexInput("gpt-5.5", path))
		require.NoError(t, err)
		require.Equal(t, middleware.DecisionDeny, out.Decision, path)
		assert.Equal(t, denyCodeNotRoutable, out.DenyReason.Code, "the code stays stable for clients")
		assert.Contains(t, out.DenyReason.Message, "/backend-api/codex", "the message should point at the Codex path for %s", path)
		assert.Equal(t, "/backend-api/codex", out.DenyReason.Details["path_prefix"])
	}

	// No hint for a caller the route does not authorise, or for a model the
	// route does not serve.
	in := codexInput("gpt-5.5", "/v1/chat/completions")
	in.UserGroups = []string{"grp-other"}
	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	assert.NotContains(t, out.DenyReason.Message, "/backend-api/codex")
	out, err = mw.Invoke(context.Background(), codexInput("gpt-4o", "/v1/chat/completions"))
	require.NoError(t, err)
	assert.NotContains(t, out.DenyReason.Message, "/backend-api/codex")
	assert.Zero(t, client.calls.Load(), "a hint never fetches the login")
}
