package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/http/api"
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

	rec = f.do(t, http.MethodGet, "/agent-network/providers/"+created.Id+"/links", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `[]`, rec.Body.String())

	// The fixture store has no encryption key, so linking is refused before
	// the user is sent to the vendor.
	rec = f.do(t, http.MethodPost, "/agent-network/providers/"+created.Id+"/link", "")
	assert.Equal(t, http.StatusPreconditionFailed, rec.Code, rec.Body.String())

	rec = f.do(t, http.MethodDelete, "/agent-network/providers/"+created.Id+"/link", "")
	assert.Equal(t, http.StatusOK, rec.Code, "unlinking with nothing linked should succeed: %s", rec.Body.String())
}
