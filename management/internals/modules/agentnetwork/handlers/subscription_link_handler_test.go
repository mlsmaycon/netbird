package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/catalog"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/util/crypt"
)

func TestCreateProvider_UserOAuthTakesNoAPIKey(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	rec := f.do(t, http.MethodPost, "/agent-network/providers",
		`{"provider_id":"chatgpt_codex","name":"ChatGPT","upstream_url":"https://chatgpt.com","api_key":"sk-operator"}`)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, "an operator key must be refused for a user_oauth entry: %s", rec.Body.String())

	rec = f.do(t, http.MethodPost, "/agent-network/providers",
		`{"provider_id":"chatgpt_codex","name":"ChatGPT","upstream_url":"https://collector.example"}`)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, "a foreign upstream must be refused: %s", rec.Body.String())

	rec = f.do(t, http.MethodPost, "/agent-network/providers",
		`{"provider_id":"chatgpt_codex","name":"ChatGPT","upstream_url":"https://chatgpt.com/"}`)
	require.Equal(t, http.StatusOK, rec.Code, "create without a key should succeed: %s", rec.Body.String())
	var created api.AgentNetworkProvider
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	assert.Equal(t, "https://chatgpt.com", created.UpstreamUrl)

	require.NotNil(t, created.SubscriptionLink, "a ChatGPT provider should report its login state")
	assert.Equal(t, api.AgentNetworkSubscriptionLinkStatusNotLinked, created.SubscriptionLink.Status)

	rec = f.do(t, http.MethodGet, "/agent-network/providers/"+created.Id, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var fetched api.AgentNetworkProvider
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &fetched))
	require.NotNil(t, fetched.SubscriptionLink)
	assert.Equal(t, api.AgentNetworkSubscriptionLinkStatusNotLinked, fetched.SubscriptionLink.Status)

	// The fixture store has no encryption key, so linking is refused before
	// the admin is sent to the vendor.
	rec = f.do(t, http.MethodPost, "/agent-network/providers/"+created.Id+"/link", "")
	assert.Equal(t, http.StatusPreconditionFailed, rec.Code, rec.Body.String())

	rec = f.do(t, http.MethodDelete, "/agent-network/providers/"+created.Id+"/link", "")
	assert.Equal(t, http.StatusOK, rec.Code, "unlinking with nothing linked should succeed: %s", rec.Body.String())
}

func TestClaudeProviderLink_CompletionEndpoint(t *testing.T) {
	var exchanges atomic.Int32
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchanges.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access-secret","refresh_token":"refresh-secret","expires_in":3600}`))
	}))
	t.Cleanup(issuer.Close)
	f := newAgentNetworkHandlerFixture(t, agentnetwork.WithCatalogLookup(func(id string) (catalog.Provider, bool) {
		entry, ok := catalog.Lookup(id)
		if ok && id == "anthropic_claude_login" {
			profile := *entry.OAuth
			profile.TokenURL = issuer.URL
			entry.OAuth = &profile
		}
		return entry, ok
	}))
	key, err := crypt.GenerateKey()
	require.NoError(t, err)
	encryptor, err := crypt.NewFieldEncrypt(key)
	require.NoError(t, err)
	f.store.SetFieldEncrypt(encryptor)

	rec := f.do(t, http.MethodPost, "/agent-network/providers", `{"provider_id":"anthropic_claude_login","name":"Claude","upstream_url":"https://api.anthropic.com","enabled":true}`)
	require.Equal(t, http.StatusOK, rec.Code, "create provider: %s", rec.Body.String())
	var provider api.AgentNetworkProvider
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &provider))
	linkPath := "/agent-network/providers/" + provider.Id + "/link"
	rec = f.do(t, http.MethodPost, linkPath, "")
	require.Equal(t, http.StatusOK, rec.Code, "start link: %s", rec.Body.String())
	var flow api.AgentNetworkProviderLinkFlow
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &flow))
	require.NotNil(t, flow.Flow, "the wire response must discriminate login flows")
	assert.Equal(t, api.AgentNetworkProviderLinkFlowFlowAuthorizationCode, *flow.Flow, "Claude uses authorization code")
	require.NotNil(t, flow.AuthorizationUri, "Claude needs an authorization URL")
	authorize, err := url.Parse(*flow.AuthorizationUri)
	require.NoError(t, err)
	completePath := linkPath + "/" + flow.Id

	for name, body := range map[string]string{
		"empty": `{}`, "malformed": `{`, "unknown field": `{"code":"secret","extra":true}`,
		"extra object": `{"code":"secret"}{}`, "oversized code": `{"code":"` + strings.Repeat("x", 8193) + `"}`,
		"wrong state": `{"code":"secret#other-state"}`,
	} {
		t.Run(name, func(t *testing.T) {
			rec := f.do(t, http.MethodPost, completePath, body)
			assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, "invalid completion must be rejected: %s", rec.Body.String())
			assert.NotContains(t, rec.Body.String(), "secret", "errors must not echo authorization material")
		})
	}
	assert.Zero(t, exchanges.Load(), "invalid submissions must not reach the issuer")
	body, err := json.Marshal(api.AgentNetworkProviderLinkCompletion{Code: "approved#" + authorize.Query().Get("state")})
	require.NoError(t, err)
	rec = f.do(t, http.MethodPost, completePath, string(body))
	require.Equal(t, http.StatusOK, rec.Code, "complete login: %s", rec.Body.String())
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &flow))
	assert.Equal(t, api.AgentNetworkProviderLinkFlowStatusLinked, flow.Status, "a successful exchange must report linked")
	assert.NotContains(t, rec.Body.String(), "access-secret", "access tokens cannot reach the dashboard")
	assert.NotContains(t, rec.Body.String(), "refresh-secret", "refresh tokens cannot reach the dashboard")
	assert.Equal(t, int32(1), exchanges.Load(), "only the valid submission should exchange the code")
	rec = f.do(t, http.MethodPost, completePath, string(body))
	assert.Equal(t, http.StatusNotFound, rec.Code, "replayed completion must be refused")
	assert.Equal(t, int32(1), exchanges.Load(), "replayed completion must not contact the issuer")
	rec = f.do(t, http.MethodGet, completePath, "")
	require.Equal(t, http.StatusOK, rec.Code, "polling a completed login remains possible")
}
