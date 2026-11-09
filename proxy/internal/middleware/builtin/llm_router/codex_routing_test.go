package llm_router

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestCodexRouting_ReservedNamespace(t *testing.T) {
	mw := newCodexRouter(nil, openAICatchAll())
	for _, path := range []string{"/backend-api/codex", "/backend-api/codex/responses", "/backend-api/codex/models?client_version=0.154.0"} {
		out, err := mw.Invoke(context.Background(), codexInput("gpt-5.5", path))
		require.NoError(t, err)
		assert.Equal(t, middleware.DecisionDeny, out.Decision, "an absent subscription route cannot spend an API key: %s", path)
		assert.Nil(t, out.Mutations, "the reserved namespace must not produce an API-key upstream")
	}
	out, err := mw.Invoke(context.Background(), codexInput("gpt-5.5", "/backend-api/codex-other/responses"))
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionAllow, out.Decision, "the reserved namespace must respect segment boundaries")
}

func TestCodexRouting_DiscoveryPaths(t *testing.T) {
	route := codexRoute()
	route.ModelPolicies = []ModelPolicyRule{{GroupIDs: []string{defaultTestGroup}, Models: []string{"gpt-5.5"}}}
	for _, tc := range []struct {
		name, method, path, model string
		allowed                   bool
	}{
		{"models", http.MethodGet, "/backend-api/codex/models?client_version=0.154.0", "", true},
		{"models with body", http.MethodGet, "/backend-api/codex/models", "gpt-5.4", true},
		{"models HEAD", http.MethodHead, "/backend-api/codex/models", "", true},
		{"models POST", http.MethodPost, "/backend-api/codex/models", "", false},
		{"responses GET", http.MethodGet, "/backend-api/codex/responses", "", false},
		{"unknown GET", http.MethodGet, "/backend-api/codex/private", "", false},
		{"namespace GET", http.MethodGet, "/backend-api/codex", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mw := newCodexRouter(&fakeCredentialClient{status: proto.GetLLMProviderCredentialResponse_OK}, route)
			in := codexInput(tc.model, tc.path)
			in.Method = tc.method
			out, err := mw.Invoke(context.Background(), in)
			require.NoError(t, err)
			if !tc.allowed {
				assert.Equal(t, middleware.DecisionDeny, out.Decision, "only known model-less discovery endpoints may bypass inference checks")
				return
			}
			require.Equal(t, middleware.DecisionAllow, out.Decision, "native model discovery must remain available")
			nonInference, _ := metaValue(t, out.Metadata, middleware.KeyLLMNonInference)
			assert.Equal(t, "true", nonInference, "model discovery does not consume inference budget")
			rw := out.Mutations.RewriteUpstream
			assert.Equal(t, []string{"gpt-5.5"}, rw.DiscoveryModels, "the caller's policy must limit the native picker")
			assert.Empty(t, rw.StripPathPrefix, "the native Codex namespace must reach ChatGPT unchanged")
			assert.Contains(t, rw.ExtraAuthHeaders, middleware.AuthHeader{Name: "Accept-Encoding", Value: "identity"}, "a compressed listing must not bypass filtering")
		})
	}
}

func TestCodexRouting_EmptyModelPolicyDeniesDiscovery(t *testing.T) {
	route := codexRoute()
	route.ModelPolicies = []ModelPolicyRule{{GroupIDs: []string{defaultTestGroup}, Models: []string{}}}
	mw := newCodexRouter(&fakeCredentialClient{status: proto.GetLLMProviderCredentialResponse_OK}, route)
	in := codexInput("", "/backend-api/codex/models")
	in.Method = http.MethodGet
	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionDeny, out.Decision, "an empty policy must not become an unlimited model listing")
}

func TestLinkedCredential_RejectsTransportUpgrades(t *testing.T) {
	for _, route := range []ProviderRoute{codexRoute(), claudeLoginRoute()} {
		for _, headers := range [][]middleware.KV{
			{{Key: "Upgrade", Value: "websocket"}},
			{{Key: "connection", Value: "keep-alive, Upgrade"}},
		} {
			client := &fakeCredentialClient{status: proto.GetLLMProviderCredentialResponse_OK}
			mw := newCodexRouter(client, route)
			in := codexInput("", route.RequestPathPrefix+"/models")
			in.Method = http.MethodGet
			in.Headers = headers
			out, err := mw.Invoke(context.Background(), in)
			require.NoError(t, err)
			require.Equal(t, middleware.DecisionDeny, out.Decision, "subscription transports must not tunnel unmetered frames")
			require.NotNil(t, out.DenyReason, "unsupported transports need an actionable client error")
			assert.Equal(t, "llm_policy.unsupported_transport", out.DenyReason.Code, "clients should distinguish the unsupported transport from missing credentials")
			assert.Equal(t, http.StatusBadRequest, out.DenyStatus, "the proxy must explicitly report unsupported transport")
			assert.Contains(t, out.DenyReason.Message, "HTTP streaming", "the error should describe the supported transport")
			assert.Nil(t, out.Mutations, "a rejected upgrade must not inject credentials")
			assert.Zero(t, client.calls.Load(), "reject before retrieving the subscription login")
		}
	}
}
