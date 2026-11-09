// Package subscription holds the provider-linked subscription logins Agent Network
// uses for user_oauth catalog entries: the vendor's login flow, the stored
// token set, and the refresh that keeps the proxy supplied with short-lived
// access tokens.
package subscription

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/catalog"
)

const (
	// maxResponseBytes bounds every vendor response we read.
	maxResponseBytes = 1 << 20
	// httpTimeout bounds one vendor call.
	httpTimeout = 15 * time.Second
	// defaultPollInterval applies when the vendor sends no usable interval.
	defaultPollInterval = 5 * time.Second
)

var (
	// ErrDeviceLoginDisabled means the vendor has device login turned off for
	// the client id.
	ErrDeviceLoginDisabled = errors.New("device login is not enabled for this client")
	// ErrAuthorizationPending means the user has not approved the code yet.
	ErrAuthorizationPending = errors.New("authorization pending")
	// ErrRelinkRequired means the vendor will never refresh this login again;
	// only a new login can replace it.
	ErrRelinkRequired = errors.New("subscription login must be linked again")
)

// permanentRefreshErrors are the vendor error codes after which a refresh
// token is dead. Retrying any of them cannot succeed.
var permanentRefreshErrors = map[string]struct{}{
	"refresh_token_reused":      {},
	"refresh_token_expired":     {},
	"refresh_token_invalidated": {},
	"invalid_grant":             {},
}

// DeviceCode is an issued user code and the handle used to poll for it.
type DeviceCode struct {
	DeviceAuthID string
	UserCode     string
	Interval     time.Duration
}

// DeviceGrant is the approved authorization code and verifier returned by device polling.
type DeviceGrant struct {
	AuthorizationCode string
	CodeVerifier      string
}

// TokenSet is what the vendor's token endpoint returns. Protocol validation
// decides which fields are required; omitted account metadata stays unchanged.
type TokenSet struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	ExpiresIn    time.Duration
	Account      AccountClaims
}

// AccountClaims are optional vendor account details from the token response or id_token.
type AccountClaims struct {
	AccountID string
	PlanType  string
	FedRAMP   bool
}

// Client speaks a vendor's subscription login protocol as described by an
// OAuthProfile. It never logs or returns token material in errors.
type Client struct {
	HTTP *http.Client
}

func (c *Client) httpClient() *http.Client {
	client := &http.Client{Timeout: httpTimeout}
	if c != nil && c.HTTP != nil {
		custom := *c.HTTP
		client = &custom
		if client.Timeout <= 0 {
			client.Timeout = httpTimeout
		}
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return client
}

// RequestDeviceCode asks the vendor for a user code.
func (c *Client) RequestDeviceCode(ctx context.Context, prof *catalog.OAuthProfile) (*DeviceCode, error) {
	status, body, err := c.postJSON(ctx, prof.DeviceCodeURL, map[string]string{"client_id": prof.ClientID})
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, ErrDeviceLoginDisabled
	}
	if !isSuccess(status) {
		return nil, fmt.Errorf("request device code: vendor answered %d", status)
	}
	var resp struct {
		DeviceAuthID string          `json:"device_auth_id"`
		UserCode     string          `json:"user_code"`
		UserCodeAlt  string          `json:"usercode"`
		Interval     json.RawMessage `json:"interval"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode device code response: %w", err)
	}
	code := resp.UserCode
	if code == "" {
		code = resp.UserCodeAlt
	}
	if resp.DeviceAuthID == "" || code == "" {
		return nil, errors.New("decode device code response: missing device_auth_id or user code")
	}
	return &DeviceCode{
		DeviceAuthID: resp.DeviceAuthID,
		UserCode:     code,
		Interval:     parseInterval(resp.Interval),
	}, nil
}

// PollDeviceCode checks whether the user approved the code, and when they
// have, exchanges the resulting authorization code for tokens. It returns
// ErrAuthorizationPending while the user has not approved yet.
func (c *Client) PollDeviceCode(ctx context.Context, prof *catalog.OAuthProfile, code *DeviceCode) (*TokenSet, error) {
	grant, err := c.PollDeviceGrant(ctx, prof, code)
	if err != nil {
		return nil, err
	}
	return c.exchangeCode(ctx, prof, grant.AuthorizationCode, grant.CodeVerifier)
}

// PollDeviceGrant reads the approved code without redeeming it, allowing an atomic claim first.
func (c *Client) PollDeviceGrant(ctx context.Context, prof *catalog.OAuthProfile, code *DeviceCode) (*DeviceGrant, error) {
	status, body, err := c.postJSON(ctx, prof.DeviceTokenURL, map[string]string{
		"device_auth_id": code.DeviceAuthID,
		"user_code":      code.UserCode,
	})
	if err != nil {
		return nil, err
	}
	if status == http.StatusForbidden || status == http.StatusNotFound {
		return nil, ErrAuthorizationPending
	}
	if !isSuccess(status) {
		return nil, fmt.Errorf("poll device code: vendor answered %d", status)
	}
	var grant struct {
		AuthorizationCode string `json:"authorization_code"`
		CodeVerifier      string `json:"code_verifier"`
	}
	if err := json.Unmarshal(body, &grant); err != nil {
		return nil, fmt.Errorf("decode device token response: %w", err)
	}
	if grant.AuthorizationCode == "" || grant.CodeVerifier == "" {
		return nil, errors.New("decode device token response: missing authorization code")
	}
	return &DeviceGrant{AuthorizationCode: grant.AuthorizationCode, CodeVerifier: grant.CodeVerifier}, nil
}

func (c *Client) exchangeCode(ctx context.Context, prof *catalog.OAuthProfile, code, verifier string) (*TokenSet, error) {
	redirectURI := prof.DeviceRedirectURI
	if prof.Flow == catalog.OAuthFlowAuthorizationCode {
		redirectURI = prof.RedirectURI
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {prof.ClientID},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {redirectURI},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, prof.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build code exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	status, body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	if !isSuccess(status) {
		return nil, fmt.Errorf("exchange authorization code: vendor answered %d", status)
	}
	tokens, err := decodeTokens(body)
	if err != nil {
		return nil, err
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" || tokens.IDToken == "" {
		return nil, errors.New("exchange authorization code: incomplete token set")
	}
	return tokens, nil
}

// Refresh redeems a refresh token. A refresh token is single use: callers
// must store the returned one before anything else can use the login.
// Permanent failures wrap ErrRelinkRequired.
func (c *Client) Refresh(ctx context.Context, prof *catalog.OAuthProfile, refreshToken string) (*TokenSet, error) {
	protocol, err := protocolFor(prof)
	if err != nil {
		return nil, err
	}
	return protocol.refresh(ctx, c, prof, refreshToken)
}

func (c *Client) refreshOpenAI(ctx context.Context, prof *catalog.OAuthProfile, refreshToken string) (*TokenSet, error) {
	status, body, err := c.postJSON(ctx, prof.TokenURL, map[string]string{
		"grant_type":    "refresh_token",
		"client_id":     prof.ClientID,
		"refresh_token": refreshToken,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: refresh outcome is unknown", ErrRelinkRequired)
	}
	if !isSuccess(status) {
		code := refreshErrorCode(body)
		// No non-success response proves that this single-use grant was not consumed.
		return nil, fmt.Errorf("%w: vendor answered %d %s", ErrRelinkRequired, status, code)
	}
	tokens, err := decodeTokens(body)
	if err != nil {
		return nil, fmt.Errorf("%w: refresh returned an unusable token set", ErrRelinkRequired)
	}
	return tokens, nil
}

func isPermanentRefreshError(code string) bool {
	_, ok := permanentRefreshErrors[code]
	return ok
}

// refreshErrorCode extracts the vendor error code from a failed refresh. The
// error field is either a string or an object carrying a code, depending on
// which layer of the vendor rejected the call. Only known-shape codes are
// returned so nothing else from the body reaches logs.
func refreshErrorCode(body []byte) string {
	var envelope struct {
		Error json.RawMessage `json:"error"`
		Code  string          `json:"code"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return ""
	}
	code := envelope.Code
	var s string
	if json.Unmarshal(envelope.Error, &s) == nil && s != "" {
		code = s
	}
	var obj struct {
		Code string `json:"code"`
		Type string `json:"type"`
	}
	if json.Unmarshal(envelope.Error, &obj) == nil {
		if obj.Code != "" {
			code = obj.Code
		} else if obj.Type != "" {
			code = obj.Type
		}
	}
	if !isErrorCodeShaped(code) {
		return ""
	}
	return code
}

func isErrorCodeShaped(code string) bool {
	if code == "" || len(code) > 64 {
		return false
	}
	for _, r := range code {
		if (r < 'a' || r > 'z') && r != '_' {
			return false
		}
	}
	return true
}

func decodeTokens(body []byte) (*TokenSet, error) {
	var resp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    *int64 `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, errors.New("decode token response: malformed token set")
	}
	if strings.TrimSpace(resp.AccessToken) == "" || strings.TrimSpace(resp.RefreshToken) == "" {
		return nil, errors.New("decode token response: missing access or refresh token")
	}
	if resp.TokenType != "" && !strings.EqualFold(resp.TokenType, "bearer") {
		return nil, errors.New("decode token response: unsupported token type")
	}
	tokens := &TokenSet{AccessToken: resp.AccessToken, RefreshToken: resp.RefreshToken, IDToken: resp.IDToken}
	if resp.ExpiresIn != nil {
		if *resp.ExpiresIn <= 0 || *resp.ExpiresIn > int64((365*24*time.Hour)/time.Second) {
			return nil, errors.New("decode token response: invalid expiry")
		}
		tokens.ExpiresIn = time.Duration(*resp.ExpiresIn) * time.Second
	} else if expiresAt, ok := AccessTokenExpiry(resp.AccessToken); !ok || !expiresAt.After(time.Now()) {
		return nil, errors.New("decode token response: missing usable expiry")
	}
	return tokens, nil
}

func (c *Client) postJSON(ctx context.Context, endpoint string, payload any) (int, []byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, fmt.Errorf("encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return 0, nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req)
}

func (c *Client) do(req *http.Request) (int, []byte, error) {
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		// The URL holds no secrets, but the transport error is enough.
		return 0, nil, fmt.Errorf("call %s: %w", req.URL.Host, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return 0, nil, fmt.Errorf("read %s response: %w", req.URL.Host, err)
	}
	return resp.StatusCode, body, nil
}

func isSuccess(status int) bool { return status >= 200 && status < 300 }

// parseInterval accepts the poll interval as a string or a number of seconds.
func parseInterval(raw json.RawMessage) time.Duration {
	var secs float64
	if json.Unmarshal(raw, &secs) != nil {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return defaultPollInterval
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err != nil {
			return defaultPollInterval
		}
		secs = v
	}
	if math.IsNaN(secs) || math.IsInf(secs, 0) || secs < 1 || secs > 60 {
		return defaultPollInterval
	}
	return time.Duration(secs * float64(time.Second))
}

// jwtPayload decodes a JWT's claims without verifying its signature. Tokens
// reach this only straight from the vendor's token endpoint over TLS, and the
// claims are used for routing headers, never for an authorization decision.
func jwtPayload(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("token is not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, fmt.Errorf("decode JWT claims: %w", err)
	}
	return claims, nil
}

// ParseAccountClaims reads the vendor account from an id_token.
func ParseAccountClaims(prof *catalog.OAuthProfile, idToken string) (AccountClaims, error) {
	claims, err := jwtPayload(idToken)
	if err != nil {
		return AccountClaims{}, err
	}
	ns, _ := claims[prof.ClaimsNamespace].(map[string]any)
	out := AccountClaims{}
	out.AccountID, _ = ns[prof.AccountIDClaim].(string)
	out.PlanType, _ = ns[prof.PlanTypeClaim].(string)
	out.FedRAMP, _ = ns[prof.FedRAMPClaim].(bool)
	if out.AccountID == "" {
		return AccountClaims{}, errors.New("id_token carries no account id")
	}
	return out, nil
}

// AccessTokenExpiry reads exp from an access token, reporting false when the
// token is not a JWT or has no readable exp.
func AccessTokenExpiry(accessToken string) (time.Time, bool) {
	claims, err := jwtPayload(accessToken)
	if err != nil {
		return time.Time{}, false
	}
	exp, ok := claims["exp"].(float64)
	if !ok || exp <= 0 || exp >= float64(math.MaxInt64) || math.Trunc(exp) != exp {
		return time.Time{}, false
	}
	return time.Unix(int64(exp), 0).UTC(), true
}
