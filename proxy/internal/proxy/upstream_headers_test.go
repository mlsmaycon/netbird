package proxy

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
)

func TestApplyUpstreamHeaders_InjectsEveryTrustedHeader(t *testing.T) {
	r, _ := http.NewRequest(http.MethodPost, "https://upstream.example/v1/responses", nil)
	// A client trying to act for another vendor account must not get its own
	// values through: the strip runs first, then every injected header lands.
	r.Header.Set("Authorization", "Bearer client-token")
	r.Header.Set("Chatgpt-Account-Id", "spoofed")
	r.Header.Set("X-Keep", "kept")

	applyUpstreamHeaders(r, &middleware.UpstreamRewrite{
		StripHeaders: []string{"Authorization", "chatgpt-account-id"},
		AuthHeader:   &middleware.AuthHeader{Name: "Authorization", Value: "Bearer user-token"},
		ExtraAuthHeaders: []middleware.AuthHeader{
			{Name: "chatgpt-account-id", Value: "acct-1"},
			{Name: "", Value: "ignored"},
		},
	})

	assert.Equal(t, "Bearer user-token", r.Header.Get("Authorization"), "auth header should be the injected one")
	assert.Equal(t, []string{"acct-1"}, r.Header.Values("Chatgpt-Account-Id"), "account header should hold only the injected value")
	assert.Equal(t, "kept", r.Header.Get("X-Keep"), "unrelated headers should pass through")
}

func TestApplyUpstreamHeaders_SingleHeaderUnchanged(t *testing.T) {
	r, _ := http.NewRequest(http.MethodPost, "https://upstream.example/v1/messages", nil)
	r.Header.Set("x-api-key", "client")

	applyUpstreamHeaders(r, &middleware.UpstreamRewrite{
		StripHeaders: []string{"x-api-key"},
		AuthHeader:   &middleware.AuthHeader{Name: "x-api-key", Value: "operator"},
	})

	assert.Equal(t, "operator", r.Header.Get("x-api-key"), "single auth header path should behave as before")
}
