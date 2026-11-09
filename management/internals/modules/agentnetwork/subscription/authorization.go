package subscription

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	cachestore "github.com/eko/gocache/lib/v4/store"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/catalog"
)

// ErrInvalidAuthorizationCode means the pasted result is malformed or belongs to another flow.
var ErrInvalidAuthorizationCode = errors.New("authorization result does not match this login")

const authorizationGrantSuffix = ":grant"

func (s *Service) startAuthorizationLink(ctx context.Context, key Key, startedBy string, entry catalog.Provider) (*Flow, error) {
	if s.cache == nil {
		return nil, errNoFlowCache
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	state, err := randomID()
	if err != nil {
		return nil, err
	}
	// RFC 7636 sections 4.1 and 4.2: 32 random bytes yield a 43-character verifier.
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return nil, fmt.Errorf("generate PKCE verifier: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	digest := sha256.Sum256([]byte(verifier))
	authorizeURI, err := authorizationURL(entry.OAuth, state, base64.RawURLEncoding.EncodeToString(digest[:]))
	if err != nil {
		return nil, err
	}
	ttl := entry.OAuth.FlowTTL
	if ttl <= 0 {
		ttl = defaultDeviceCodeTTL
	}
	flow := &flowState{
		Key: key, StartedBy: startedBy, ProviderType: entry.ID,
		Flow: catalog.OAuthFlowAuthorizationCode, AuthorizationURI: authorizeURI,
		AuthorizationState: state, ExpiresAt: s.now().Add(ttl),
		IntervalMS: (2 * time.Second).Milliseconds(),
	}
	if err := s.cache.Set(ctx, flowKeyPrefix+id+authorizationGrantSuffix, verifier, cachestore.WithExpiration(ttl)); err != nil {
		return nil, fmt.Errorf("store authorization grant: %w", err)
	}
	if err := s.saveFlow(ctx, id, flow); err != nil {
		// The unreachable verifier expires with its short TTL.
		return nil, err
	}
	return flow.view(id, FlowPending), nil
}

// CompleteLink consumes the PKCE grant once and exchanges a pasted authorization result.
func (s *Service) CompleteLink(ctx context.Context, key Key, startedBy, flowID, result string, entry catalog.Provider) (*Flow, error) {
	if s.cache == nil {
		return nil, errNoFlowCache
	}
	protocol, err := protocolFor(entry.OAuth)
	if err != nil || entry.OAuth.Flow != catalog.OAuthFlowAuthorizationCode {
		return nil, ErrUnsupportedFlow
	}
	flow, err := s.loadFlow(ctx, flowID)
	if err != nil {
		return nil, err
	}
	if flow.Key != key || flow.StartedBy != startedBy || flow.ProviderType != entry.ID || flow.Flow != entry.OAuth.Flow {
		return nil, ErrFlowNotFound
	}
	if !s.now().Before(flow.ExpiresAt) {
		return flow.view(flowID, FlowExpired), nil
	}
	code, state, err := parseAuthorizationResult(result, entry.OAuth.RedirectURI)
	if err != nil || subtle.ConstantTimeCompare([]byte(state), []byte(flow.AuthorizationState)) != 1 {
		return nil, ErrInvalidAuthorizationCode
	}
	verifier, found, err := s.cache.GetDel(ctx, flowKeyPrefix+flowID+authorizationGrantSuffix)
	if err != nil {
		return nil, fmt.Errorf("consume authorization grant: %w", err)
	}
	if !found || verifier == "" {
		return nil, ErrFlowNotFound
	}
	tokens, exchangeErr := protocol.exchange(ctx, s.client, entry.OAuth, code, verifier, state)
	// Once redeemed, cancellation must not prevent storing the returned login.
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), httpTimeout)
	defer cancel()
	status := FlowFailed
	if exchangeErr == nil {
		if err := s.storeLinked(writeCtx, key, startedBy, entry.OAuth, tokens); err != nil {
			log.WithContext(writeCtx).Errorf("store subscription login for provider %s: %v", key.ProviderID, err)
		} else {
			status = FlowLinked
		}
	}
	s.setFlowResult(writeCtx, flowID, status)
	view := flow.view(flowID, status)
	view.JustLinked = status == FlowLinked
	return view, nil
}

func parseAuthorizationResult(result, redirectURI string) (string, string, error) {
	result = strings.TrimSpace(result)
	if result == "" || len(result) > 8192 {
		return "", "", ErrInvalidAuthorizationCode
	}
	if strings.Contains(result, "://") {
		u, err := url.Parse(result)
		registered, registeredErr := url.Parse(redirectURI)
		if err != nil || registeredErr != nil || u.Scheme != registered.Scheme || u.Host != registered.Host || u.Path != registered.Path || u.User != nil || u.Fragment != "" {
			return "", "", ErrInvalidAuthorizationCode
		}
		values, err := url.ParseQuery(u.RawQuery)
		if err != nil || len(values["code"]) != 1 || len(values["state"]) != 1 || values.Get("error") != "" {
			return "", "", ErrInvalidAuthorizationCode
		}
		return validateAuthorizationParts(values.Get("code"), values.Get("state"))
	}
	code, state, ok := strings.Cut(result, "#")
	if !ok {
		return "", "", ErrInvalidAuthorizationCode
	}
	return validateAuthorizationParts(code, state)
}

func validateAuthorizationParts(code, state string) (string, string, error) {
	if code == "" || state == "" || strings.ContainsAny(code+state, "#\r\n\t ") {
		return "", "", ErrInvalidAuthorizationCode
	}
	return code, state, nil
}
