package catalog

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// TestClaudeLineupSelectable pins the models Claude Code resolves to by
// default. A model absent from the lineup can't be ticked on a provider
// record, so llm_router denies it as not-routable and the operator has no
// way to authorise the client's own default.
func TestClaudeLineupSelectable(t *testing.T) {
	for providerID, wanted := range map[string][]string{
		"anthropic_api": {"claude-opus-5", "claude-sonnet-5", "claude-haiku-4-5"},
		"bedrock_api":   {"anthropic.claude-opus-5", "anthropic.claude-sonnet-5", "anthropic.claude-haiku-4-5"},
		"vertex_ai_api": {"claude-opus-5", "claude-sonnet-5", "claude-haiku-4-5"},
	} {
		provider, ok := Lookup(providerID)
		require.True(t, ok, "catalog must define %s", providerID)

		selectable := make(map[string]Model, len(provider.Models))
		for _, m := range provider.Models {
			selectable[m.ID] = m
		}
		for _, id := range wanted {
			model, found := selectable[id]
			require.True(t, found, "%s must offer %s", providerID, id)
			assert.NotEmpty(t, model.Label, "%s/%s needs a label for the picker", providerID, id)
			assert.Positive(t, model.InputPer1k, "%s/%s needs an input rate", providerID, id)
			assert.Positive(t, model.OutputPer1k, "%s/%s needs an output rate", providerID, id)
			assert.Positive(t, model.ContextWindow, "%s/%s needs a context window", providerID, id)
		}
	}
}

func TestAgentgatewayCatalogEntry(t *testing.T) {
	entry, ok := Lookup("agentgateway")
	require.True(t, ok, "agentgateway must be available in the provider catalog")

	assert.Equal(t, KindGateway, entry.Kind, "agentgateway must be grouped with AI gateways")
	assert.Empty(t, entry.DefaultHost, "operators must provide their agentgateway proxy URL")
	assert.Equal(t, "Authorization", entry.AuthHeaderName)
	assert.Equal(t, "Bearer ${API_KEY}", entry.AuthHeaderTemplate)
	assert.Equal(t, "application/json", entry.DefaultContentType)
	assert.Empty(t, entry.ParserID, "URL detection must select the OpenAI or Anthropic parser")
	assert.Equal(t, []string{"openai", "anthropic"}, entry.RouterVendors,
		"agentgateway must accept both parser surfaces")
	assert.Equal(t, []string{"openai", "anthropic"}, entry.PricingSurfaces,
		"agentgateway models can use either pricing surface")
	assert.Empty(t, entry.Models, "an empty model list makes agentgateway a catch-all route")
	require.NotNil(t, entry.Discovery)
	assert.Empty(t, entry.Discovery.Host, "discovery must use the configured proxy URL")
	assert.Equal(t, "/v1/models", entry.Discovery.Path)
	assert.Equal(t, ShapeOpenAIData, entry.Discovery.Shape)
	assert.True(t, entry.Discovery.ExactModelsOnly,
		"wildcard model semantics are not supported by NetBird")

	require.NotNil(t, entry.IdentityInjection)
	require.NotNil(t, entry.IdentityInjection.HeaderPair)
	assert.Nil(t, entry.IdentityInjection.JSONMetadata)
	assert.False(t, entry.IdentityInjection.HeaderPair.Customizable,
		"NetBird identity header names are part of the integration contract")
	assert.Equal(t, "x-netbird-user-id", entry.IdentityInjection.HeaderPair.EndUserIDHeader)
	assert.Equal(t, "x-netbird-groups", entry.IdentityInjection.HeaderPair.TagsHeader)
	assert.False(t, entry.IdentityInjection.HeaderPair.EndUserIDInBody)
	assert.False(t, entry.IdentityInjection.HeaderPair.TagsInBody)
}

func TestAgentgatewayCatalogAPIResponse(t *testing.T) {
	entry, ok := Lookup("agentgateway")
	require.True(t, ok)

	resp := entry.ToAPIResponse()
	assert.Equal(t, "agentgateway", resp.Id)
	assert.Equal(t, api.AgentNetworkCatalogProviderKindGateway, resp.Kind)
	assert.Empty(t, resp.Models)
	require.NotNil(t, resp.IdentityInjection)
	require.NotNil(t, resp.IdentityInjection.HeaderPair)
	assert.False(t, resp.IdentityInjection.HeaderPair.Customizable)
	assert.Equal(t, "x-netbird-user-id", resp.IdentityInjection.HeaderPair.EndUserIdHeader)
	assert.Equal(t, "x-netbird-groups", resp.IdentityInjection.HeaderPair.TagsHeader)
}

func TestCredentialKindDefaults(t *testing.T) {
	openai, ok := Lookup("openai_api")
	require.True(t, ok)
	assert.Equal(t, CredentialStaticKey, openai.EffectiveCredentialKind(), "an unset kind should read as a static key")
	assert.False(t, openai.UsesUserOAuth())

	vertex, ok := Lookup("vertex_ai_api")
	require.True(t, ok)
	assert.Equal(t, CredentialGCPServiceAccount, vertex.EffectiveCredentialKind(), "vertex should accept service-account keys")

	// A user_oauth kind without a profile has nothing to log in against, so
	// it must not be treated as a linkable entry.
	assert.False(t, Provider{CredentialKind: CredentialUserOAuth}.UsesUserOAuth(), "user_oauth without a profile should not be linkable")
}

func TestGCPServiceAccountKey(t *testing.T) {
	key, ok := GCPServiceAccountKey("  keyfile:: abc== ")
	assert.True(t, ok)
	assert.Equal(t, "abc==", key, "key material should be trimmed")

	_, ok = GCPServiceAccountKey("sk-plain")
	assert.False(t, ok, "a plain bearer is not a service-account key")
}

func TestChatGPTCodexEntry(t *testing.T) {
	entry, ok := Lookup("chatgpt_codex")
	require.True(t, ok)
	require.True(t, entry.UsesUserOAuth())
	assert.Equal(t, "chatgpt.com", entry.DefaultHost)
	assert.Equal(t, "openai", entry.ParserID, "Codex speaks the Responses API")
	assert.Empty(t, entry.PricingSurfaces, "subscription usage must not be priced at API rates")
	assert.Equal(t, OAuthFlowDevice, entry.OAuth.Flow)
	assert.Equal(t, "/backend-api/codex", entry.OAuth.RequestPathPrefix)

	resp := entry.ToAPIResponse()
	assert.Equal(t, api.AgentNetworkCatalogProviderCredentialKindUserOauth, resp.CredentialKind)
	require.NotNil(t, resp.SubscriptionLogin)
	assert.Equal(t, "https://auth.openai.com/codex/device", resp.SubscriptionLogin.VerificationUri)

	openai, _ := Lookup("openai_api")
	openaiResp := openai.ToAPIResponse()
	assert.Equal(t, api.AgentNetworkCatalogProviderCredentialKindStaticKey, openaiResp.CredentialKind)
	assert.Nil(t, openaiResp.SubscriptionLogin)
}

// The signed NetBird-Anthropic agreement permits this provider-wide login.
// Keep its credential destination and routing namespace fixed in the catalog.
func TestClaudeSubscriptionEntry(t *testing.T) {
	entry, ok := Lookup("anthropic_claude_login")
	require.True(t, ok, "the agreement permits an Anthropic subscription entry")
	require.True(t, entry.UsesUserOAuth(), "Claude must obtain its credential from a linked login")
	assert.Equal(t, "api.anthropic.com", entry.DefaultHost, "the login must only reach Anthropic")
	assert.Equal(t, "anthropic", entry.ParserID, "Claude subscription requests use the Messages parser")
	assert.Equal(t, "Authorization", entry.AuthHeaderName, "OAuth access tokens use bearer authorization")
	assert.Equal(t, "Bearer ${API_KEY}", entry.AuthHeaderTemplate, "the proxy injects the linked token")
	assert.Empty(t, entry.PricingSurfaces, "subscription usage must not be priced at API rates")
	assert.Empty(t, entry.Models, "the subscription catalog must not contribute priced models")
	assert.Equal(t, OAuthFlowAuthorizationCode, entry.OAuth.Flow, "Claude uses an authorization-code flow")
	assert.Equal(t, OAuthProtocolAnthropic, entry.OAuth.Protocol, "Claude token handling must not use OpenAI's protocol")
	assert.Equal(t, "https://claude.ai/oauth/authorize", entry.OAuth.AuthorizeURL, "authorization uses the built-in issuer")
	assert.Equal(t, "https://platform.claude.com/v1/oauth/token", entry.OAuth.TokenURL, "exchange and refresh use the built-in token endpoint")
	assert.Equal(t, "https://platform.claude.com/oauth/code/callback", entry.OAuth.RedirectURI, "self-hosted dashboards use the vendor's code page")
	assert.Equal(t, 15*time.Minute, entry.OAuth.FlowTTL, "unfinished login attempts must expire")
	assert.Equal(t, "/claude-login", entry.OAuth.RequestPathPrefix, "subscription requests must have an exclusive namespace")
	assert.Equal(t, entry.OAuth.RequestPathPrefix, entry.OAuth.StripPathPrefix, "the NetBird namespace must not reach Anthropic")
	assert.NotContains(t, entry.OAuth.Scopes, "org:create_api_key", "inference login does not need API-key creation rights")
	assert.Equal(t, map[string]string{
		"anthropic-version": "2023-06-01",
		"anthropic-beta":    "oauth-2025-04-20",
	}, entry.OAuth.RequestHeaders, "only the catalog's inference headers should be injected")

	resp := entry.ToAPIResponse()
	assert.Equal(t, api.AgentNetworkCatalogProviderCredentialKindUserOauth, resp.CredentialKind, "the UI must offer login instead of API-key entry")
	require.NotNil(t, resp.SubscriptionLogin)
	assert.Equal(t, "authorization_code", string(resp.SubscriptionLogin.Flow), "the UI must show the code-paste flow")
	assert.Nil(t, resp.PricingSurfaces, "API pricing must stay absent on the wire")

	static, ok := Lookup("anthropic_api")
	require.True(t, ok)
	assert.False(t, static.UsesUserOAuth(), "API-key Anthropic remains a separate credential path")
	assert.Equal(t, "x-api-key", static.AuthHeaderName, "existing API-key injection must remain intact")
}
