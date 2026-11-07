package types

import (
	"time"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// AgentConfig is the caller-scoped answer to "what may this caller
// use on the Agent Network?" — the account's proxy endpoint plus the
// providers and models the caller's groups authorize. It intentionally
// carries display metadata only: no keys, no upstream URLs, no policy or
// guardrail structure, and no hint of providers the caller cannot reach.
type AgentConfig struct {
	// Configured is false only when the account has no Agent Network set
	// up. A caller no policy covers yet still reads as configured, with an
	// empty Providers list: every member gets the same connection config,
	// and the empty list is what tells them to ask for access.
	Configured bool
	// Endpoint is the account's proxy base URL
	// ("https://<subdomain>.<cluster>"), reachable over the NetBird tunnel
	// only. Empty when Configured is false. Handing it to a member the
	// policies do not cover authorizes nothing on its own — the proxy
	// still refuses every request no policy permits.
	Endpoint string
	// Providers lists the providers at least one applicable policy
	// authorizes for the caller, in the account's created_at order.
	Providers []AgentConfigProvider
}

// AgentConfigProvider is one authorized provider in an AgentConfig.
type AgentConfigProvider struct {
	// ID is the provider record id, which the subscription link endpoints
	// take.
	ID string
	// Name is the operator-assigned label, e.g. "Bedrock prod".
	Name string
	// CatalogID names the catalog entry, e.g. "anthropic_api".
	CatalogID string
	// APIFlavor is the request-body shape the provider speaks — the
	// catalog entry's parser id ("anthropic", "openai"); empty when the
	// proxy dispatches the provider by URL path instead.
	APIFlavor string
	// AllModelsAllowed is true when no model allowlist restricts this
	// provider for the caller. Models then lists the declared/catalog
	// models as a courtesy (possibly none for gateway-style providers).
	AllModelsAllowed bool
	// Models is the effective model allowlist for the caller, or the
	// declared/catalog models when AllModelsAllowed is true.
	Models []string
	// CredentialKind is the catalog entry's credential kind.
	CredentialKind string
	// SubscriptionLink is the provider's linked-login state, set only for
	// user_oauth providers.
	SubscriptionLink *SubscriptionLinkState
}

// SubscriptionLinkStatus is the state of a provider's subscription login.
type SubscriptionLinkStatus string

const (
	SubscriptionLinked      SubscriptionLinkStatus = "linked"
	SubscriptionNotLinked   SubscriptionLinkStatus = "not_linked"
	SubscriptionNeedsRelink SubscriptionLinkStatus = "needs_relink"
)

// SubscriptionLinkState is the link state of one provider record. It never
// carries tokens.
type SubscriptionLinkState struct {
	Status   SubscriptionLinkStatus
	PlanType string
	// LinkedAt and LinkedBy are empty when nothing is linked.
	LinkedAt        *time.Time
	LinkedBy        string
	LastRefreshedAt *time.Time
}

// LinkStateFromCredential maps a stored login (nil when absent) to its
// displayable state.
func LinkStateFromCredential(cred *ProviderCredential) *SubscriptionLinkState {
	if cred == nil {
		return &SubscriptionLinkState{Status: SubscriptionNotLinked}
	}
	linkedAt := cred.CreatedAt
	state := &SubscriptionLinkState{
		Status:          SubscriptionLinked,
		PlanType:        cred.PlanType,
		LinkedAt:        &linkedAt,
		LinkedBy:        cred.LinkedBy,
		LastRefreshedAt: cred.LastRefreshedAt,
	}
	if cred.Status != CredentialActive {
		state.Status = SubscriptionNeedsRelink
	}
	return state
}

// ToAPIResponse renders the link state for the API.
func (l *SubscriptionLinkState) ToAPIResponse() *api.AgentNetworkSubscriptionLink {
	if l == nil {
		return nil
	}
	out := &api.AgentNetworkSubscriptionLink{
		Status:          api.AgentNetworkSubscriptionLinkStatus(l.Status),
		LinkedAt:        l.LinkedAt,
		LastRefreshedAt: l.LastRefreshedAt,
	}
	if l.PlanType != "" {
		plan := l.PlanType
		out.PlanType = &plan
	}
	if l.LinkedBy != "" {
		by := l.LinkedBy
		out.LinkedBy = &by
	}
	return out
}
