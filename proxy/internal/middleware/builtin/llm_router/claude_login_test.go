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

func claudeLoginRoute() ProviderRoute {
	return ProviderRoute{
		ID:                "prov-claude-login",
		Vendor:            "anthropic",
		Models:            []string{"claude-sonnet-4-5", "claude-haiku-4-5"},
		UpstreamScheme:    "https",
		UpstreamHost:      "api.anthropic.com",
		AllowedGroupIDs:   []string{defaultTestGroup},
		LinkedCredential:  true,
		RequestPathPrefix: "/claude-login",
		StripPathPrefix:   "/claude-login",
	}
}

func anthropicKeyRoute() ProviderRoute {
	route := claudeLoginRoute()
	route.ID = "prov-anthropic-key"
	route.LinkedCredential = false
	route.RequestPathPrefix = ""
	route.StripPathPrefix = ""
	route.AuthHeaderName = "x-api-key"
	route.AuthHeaderValue = "operator-key"
	return route
}

func claudeInput(method, model, path string) *middleware.Input {
	in := newInputVendorModelURL("anthropic", model, path)
	in.Method = method
	in.AccountID = "acc-1"
	return in
}

func TestClaudeLogin_RouteIsolation(t *testing.T) {
	client := &fakeCredentialClient{status: proto.GetLLMProviderCredentialResponse_OK}
	cases := []struct {
		name       string
		routes     []ProviderRoute
		path       string
		wantID     string
		wantPrefix string
	}{
		{"login path", []ProviderRoute{anthropicKeyRoute(), claudeLoginRoute()}, "/claude-login/v1/messages?beta=true", "prov-claude-login", "/claude-login"},
		{"API path", []ProviderRoute{claudeLoginRoute(), anthropicKeyRoute()}, "/v1/messages", "prov-anthropic-key", ""},
		{"missing login route", []ProviderRoute{anthropicKeyRoute()}, "/claude-login/v1/messages", "", ""},
		{"missing API route", []ProviderRoute{claudeLoginRoute()}, "/v1/messages", "", ""},
		{"namespace sibling", []ProviderRoute{claudeLoginRoute()}, "/claude-login-other/v1/messages", "", ""},
		{"namespace root", []ProviderRoute{anthropicKeyRoute()}, "/claude-login", "", ""},
		{"encoded namespace", []ProviderRoute{anthropicKeyRoute()}, "/claude%2Dlogin/v1/messages", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mw := newCodexRouter(client, tc.routes...)
			out, err := mw.Invoke(context.Background(), claudeInput(http.MethodPost, "claude-sonnet-4-5", tc.path))
			require.NoError(t, err)
			if tc.wantID == "" {
				require.Equal(t, middleware.DecisionDeny, out.Decision, "request must stay out of the other credential class")
				assert.Nil(t, out.Mutations, "denial must not carry an upstream")
				return
			}
			require.Equal(t, middleware.DecisionAllow, out.Decision, "the selected credential class must be routable")
			id, _ := metaValue(t, out.Metadata, middleware.KeyLLMResolvedProviderID)
			assert.Equal(t, tc.wantID, id, "path selects the credential class despite identical upstreams and models")
			assert.Equal(t, tc.wantPrefix, out.Mutations.RewriteUpstream.StripPathPrefix, "only the NetBird namespace is removed")
		})
	}
}

func TestClaudeLogin_DeniesUnlinked(t *testing.T) {
	client := &fakeCredentialClient{status: proto.GetLLMProviderCredentialResponse_NOT_LINKED}
	mw := newCodexRouter(client, anthropicKeyRoute(), claudeLoginRoute())
	out, err := mw.Invoke(context.Background(), claudeInput(http.MethodPost, "claude-sonnet-4-5", "/claude-login/v1/messages"))
	require.NoError(t, err)
	require.Equal(t, middleware.DecisionDeny, out.Decision, "missing login never falls back to an API key")
	assert.Equal(t, denyCodeCredentialNotLinked, out.DenyReason.Code, "clients receive the link-required error")
}

func TestClaudeLogin_NonInferencePaths(t *testing.T) {
	route := claudeLoginRoute()
	route.ModelPolicies = []ModelPolicyRule{{GroupIDs: []string{defaultTestGroup}, Models: []string{"claude-sonnet-4-5"}}}
	cases := []struct {
		name      string
		method    string
		path      string
		model     string
		wantAllow bool
		wantModel string
	}{
		{"listing", http.MethodGet, "/claude-login/v1/models", "", true, ""},
		{"listing ignores body model", http.MethodGet, "/claude-login/v1/models", "claude-haiku-4-5", true, ""},
		{"detail", http.MethodGet, "/claude-login/v1/models/claude-sonnet-4-5", "", true, "claude-sonnet-4-5"},
		{"unknown detail", http.MethodGet, "/claude-login/v1/models/claude-unknown", "", false, ""},
		{"count tokens", http.MethodPost, "/claude-login/v1/messages/count_tokens", "claude-sonnet-4-5", true, ""},
		{"count missing model", http.MethodPost, "/claude-login/v1/messages/count_tokens", "", false, ""},
		{"warm connection", http.MethodHead, "/claude-login/api/hello", "", true, ""},
		{"unknown GET", http.MethodGet, "/claude-login/api/private", "", false, ""},
		{"POST listing", http.MethodPost, "/claude-login/v1/models", "", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeCredentialClient{status: proto.GetLLMProviderCredentialResponse_OK}
			mw := newCodexRouter(client, anthropicKeyRoute(), route)
			out, err := mw.Invoke(context.Background(), claudeInput(tc.method, tc.model, tc.path))
			require.NoError(t, err)
			if !tc.wantAllow {
				assert.Equal(t, middleware.DecisionDeny, out.Decision, "unrecognized or model-less inference must deny")
				return
			}
			require.Equal(t, middleware.DecisionAllow, out.Decision, "known non-inference path must use the linked login")
			nonInference, _ := metaValue(t, out.Metadata, middleware.KeyLLMNonInference)
			assert.Equal(t, "true", nonInference, "discovery and counting must not consume inference budgets")
			assert.Equal(t, "/claude-login", out.Mutations.RewriteUpstream.StripPathPrefix, "native endpoint must reach Anthropic")
			if tc.path == "/claude-login/v1/models" {
				assert.Equal(t, []string{"claude-sonnet-4-5"}, out.Mutations.RewriteUpstream.DiscoveryModels, "listing is limited to this caller's model policy")
			}
			if tc.wantModel != "" {
				model, _ := metaValue(t, out.Metadata, middleware.KeyLLMModel)
				assert.Equal(t, tc.wantModel, model, "path model must reach downstream guardrails")
			}
		})
	}
}

func TestClaudeLogin_EmptyModelPolicyDeniesListing(t *testing.T) {
	route := claudeLoginRoute()
	route.ModelPolicies = []ModelPolicyRule{{GroupIDs: []string{defaultTestGroup}, Models: []string{}}}
	client := &fakeCredentialClient{status: proto.GetLLMProviderCredentialResponse_OK}
	mw := newCodexRouter(client, route)
	out, err := mw.Invoke(context.Background(), claudeInput(http.MethodGet, "", "/claude-login/v1/models"))
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionDeny, out.Decision, "an empty allowlist must not become an unbounded upstream listing")
}

func TestClaudeLogin_NonInferenceBoundary(t *testing.T) {
	client := &fakeCredentialClient{status: proto.GetLLMProviderCredentialResponse_OK}
	mw := newCodexRouter(client, claudeLoginRoute())
	for _, path := range []string{
		"/claude-login/v1/messages",
		"/claude-login/v1/messages/count_tokens/other",
		"/claude-login/v1/messages/count_tokens-other",
		"/claude-login/v1/models/claude-sonnet-4-5",
	} {
		out, err := mw.Invoke(context.Background(), claudeInput(http.MethodPost, "claude-sonnet-4-5", path))
		require.NoError(t, err)
		require.Equal(t, middleware.DecisionAllow, out.Decision, "a routed request remains subject to inference limits: %s", path)
		nonInference, _ := metaValue(t, out.Metadata, middleware.KeyLLMNonInference)
		assert.Empty(t, nonInference, "only the exact counting endpoint may skip inference limits: %s", path)
	}
}

func TestClaudeLogin_GroupsGateNonInference(t *testing.T) {
	client := &fakeCredentialClient{status: proto.GetLLMProviderCredentialResponse_OK}
	mw := newCodexRouter(client, anthropicKeyRoute(), claudeLoginRoute())
	for _, path := range []string{"/claude-login/v1/models", "/claude-login/v1/models/claude-sonnet-4-5"} {
		in := claudeInput(http.MethodGet, "", path)
		in.UserGroups = []string{"grp-other"}
		out, err := mw.Invoke(context.Background(), in)
		require.NoError(t, err)
		assert.Equal(t, middleware.DecisionDeny, out.Decision, "discovery must not bypass group permissions: %s", path)
	}
	assert.Zero(t, client.calls.Load(), "unauthorized discovery must not fetch a shared credential")
}

func TestClaudeLogin_StripsManagementSuppliedHeaders(t *testing.T) {
	client := &fakeCredentialClient{status: proto.GetLLMProviderCredentialResponse_OK, headers: []*proto.LLMCredentialHeader{
		{Name: "Authorization", Value: "Bearer linked"},
		{Name: "anthropic-beta", Value: "oauth-2025-04-20"},
		{Name: "anthropic-version", Value: "2023-06-01"},
	}}
	mw := newCodexRouter(client, anthropicKeyRoute(), claudeLoginRoute())
	out, err := mw.Invoke(context.Background(), claudeInput(http.MethodPost, "claude-sonnet-4-5", "/claude-login/v1/messages"))
	require.NoError(t, err)
	require.Equal(t, middleware.DecisionAllow, out.Decision, "linked request must obtain management headers")
	for _, name := range []string{"Authorization", "anthropic-beta", "anthropic-version"} {
		assert.Contains(t, out.Mutations.RewriteUpstream.StripHeaders, name, "client copies of injected %s must be removed", name)
	}
	out, err = mw.Invoke(context.Background(), claudeInput(http.MethodPost, "claude-sonnet-4-5", "/v1/messages"))
	require.NoError(t, err)
	require.Equal(t, middleware.DecisionAllow, out.Decision, "API-key provider must still work")
	assert.NotContains(t, out.Mutations.RewriteUpstream.StripHeaders, "anthropic-beta", "static providers preserve SDK-selected betas")
	assert.NotContains(t, out.Mutations.RewriteUpstream.StripHeaders, "anthropic-version", "static providers preserve SDK-selected API version")
}
