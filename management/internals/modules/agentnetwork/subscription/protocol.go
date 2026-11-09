package subscription

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/catalog"
)

// tokenProtocol isolates vendor wire formats and token semantics from flow storage.
type tokenProtocol interface {
	exchange(context.Context, *Client, *catalog.OAuthProfile, string, string, string) (*TokenSet, error)
	refresh(context.Context, *Client, *catalog.OAuthProfile, string) (*TokenSet, error)
	claims(*catalog.OAuthProfile, *TokenSet) (AccountClaims, error)
	expiry(*TokenSet, time.Time) time.Time
	uncertainRefreshIsTerminal() bool
}

func protocolFor(prof *catalog.OAuthProfile) (tokenProtocol, error) {
	if prof == nil {
		return nil, ErrUnsupportedFlow
	}
	switch prof.Protocol {
	case "", catalog.OAuthProtocolOpenAI:
		return openAIProtocol{}, nil
	case catalog.OAuthProtocolAnthropic:
		return anthropicProtocol{}, nil
	default:
		return nil, ErrUnsupportedFlow
	}
}

type openAIProtocol struct{}

func (openAIProtocol) exchange(ctx context.Context, c *Client, prof *catalog.OAuthProfile, code, verifier, _ string) (*TokenSet, error) {
	return c.exchangeCode(ctx, prof, code, verifier)
}

func (openAIProtocol) refresh(ctx context.Context, c *Client, prof *catalog.OAuthProfile, token string) (*TokenSet, error) {
	return c.refreshOpenAI(ctx, prof, token)
}

func (openAIProtocol) claims(prof *catalog.OAuthProfile, tokens *TokenSet) (AccountClaims, error) {
	return ParseAccountClaims(prof, tokens.IDToken)
}

func (openAIProtocol) expiry(tokens *TokenSet, now time.Time) time.Time {
	if tokens.ExpiresIn > 0 {
		return now.Add(tokens.ExpiresIn)
	}
	expiresAt, _ := AccessTokenExpiry(tokens.AccessToken)
	return expiresAt
}

func (openAIProtocol) uncertainRefreshIsTerminal() bool { return true }

type anthropicProtocol struct{}

func (anthropicProtocol) exchange(ctx context.Context, c *Client, prof *catalog.OAuthProfile, code, verifier, state string) (*TokenSet, error) {
	status, body, err := c.postJSON(ctx, prof.TokenURL, map[string]string{
		"grant_type": "authorization_code", "client_id": prof.ClientID,
		"code": code, "code_verifier": verifier, "state": state, "redirect_uri": prof.RedirectURI,
	})
	if err != nil {
		return nil, err
	}
	if !isSuccess(status) {
		return nil, fmt.Errorf("exchange authorization code: vendor answered %d", status)
	}
	tokens, err := decodeAnthropicTokens(body)
	if err != nil {
		return nil, err
	}
	if tokens.RefreshToken == "" {
		return nil, errors.New("exchange authorization code: missing refresh token")
	}
	return tokens, nil
}

func (anthropicProtocol) refresh(ctx context.Context, c *Client, prof *catalog.OAuthProfile, token string) (*TokenSet, error) {
	status, body, err := c.postJSON(ctx, prof.TokenURL, map[string]string{
		"grant_type": "refresh_token", "client_id": prof.ClientID, "refresh_token": token,
	})
	if err != nil {
		// A lost response can follow successful redemption of a single-use token.
		return nil, fmt.Errorf("%w: refresh outcome is unknown", ErrRelinkRequired)
	}
	if !isSuccess(status) {
		code := refreshErrorCode(body)
		if status == http.StatusUnauthorized || isPermanentRefreshError(code) || status >= http.StatusInternalServerError {
			return nil, fmt.Errorf("%w: vendor answered %d %s", ErrRelinkRequired, status, code)
		}
		return nil, fmt.Errorf("refresh token: vendor answered %d %s", status, code)
	}
	tokens, err := decodeAnthropicTokens(body)
	if err != nil {
		return nil, fmt.Errorf("%w: refresh returned an unusable token set", ErrRelinkRequired)
	}
	return tokens, nil
}

func (anthropicProtocol) claims(_ *catalog.OAuthProfile, tokens *TokenSet) (AccountClaims, error) {
	return tokens.Account, nil
}

func (anthropicProtocol) expiry(tokens *TokenSet, now time.Time) time.Time {
	return now.Add(tokens.ExpiresIn)
}

func (anthropicProtocol) uncertainRefreshIsTerminal() bool { return true }

func decodeAnthropicTokens(body []byte) (*TokenSet, error) {
	var resp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		Account      struct {
			UUID string `json:"uuid"`
		} `json:"account"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, errors.New("decode token response: malformed token set")
	}
	if resp.AccessToken == "" || resp.ExpiresIn <= 0 || resp.ExpiresIn > int64((365*24*time.Hour)/time.Second) {
		return nil, errors.New("decode token response: missing token or invalid expiry")
	}
	if resp.TokenType != "" && !strings.EqualFold(resp.TokenType, "bearer") {
		return nil, errors.New("decode token response: unsupported token type")
	}
	return &TokenSet{
		AccessToken: resp.AccessToken, RefreshToken: resp.RefreshToken,
		ExpiresIn: time.Duration(resp.ExpiresIn) * time.Second,
		Account:   AccountClaims{AccountID: resp.Account.UUID},
	}, nil
}

func authorizationURL(prof *catalog.OAuthProfile, state, challenge string) (string, error) {
	if _, err := protocolFor(prof); err != nil || prof.Flow != catalog.OAuthFlowAuthorizationCode {
		return "", ErrUnsupportedFlow
	}
	u, err := url.Parse(prof.AuthorizeURL)
	if err != nil || u.Host == "" || u.Scheme == "" {
		return "", errors.New("invalid authorization endpoint")
	}
	query := u.Query()
	query.Set("client_id", prof.ClientID)
	query.Set("response_type", "code")
	if prof.Protocol == catalog.OAuthProtocolAnthropic {
		query.Set("code", "true")
	} else {
		query.Set("prompt", "login")
		query.Set("id_token_add_organizations", "true")
		query.Set("codex_cli_simplified_flow", "true")
	}
	query.Set("redirect_uri", prof.RedirectURI)
	query.Set("scope", strings.Join(prof.Scopes, " "))
	query.Set("state", state)
	query.Set("code_challenge", challenge)
	query.Set("code_challenge_method", "S256")
	u.RawQuery = query.Encode()
	return u.String(), nil
}
