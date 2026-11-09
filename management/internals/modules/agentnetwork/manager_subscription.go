package agentnetwork

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/catalog"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/subscription"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/server/activity"
	nbcache "github.com/netbirdio/netbird/management/server/cache"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

// ErrProviderNotLinkable is returned for a provider record whose catalog entry
// does not use a linked subscription login, or that is disabled.
var ErrProviderNotLinkable = errors.New("provider does not use subscription logins")

// WithCacheStore sets the shared cache that holds in-progress subscription
// link flows. Production passes the server's shared cache so any replica can
// serve a poll; without it an in-process cache is used.
func WithCacheStore(cache nbcache.Store) ManagerOption {
	return func(m *managerImpl) { m.subscriptionCache = cache }
}

// WithSubscriptionClient replaces the HTTP client used to reach the vendor's
// login endpoints.
func WithSubscriptionClient(client *subscription.Client) ManagerOption {
	return func(m *managerImpl) { m.subscriptionClient = client }
}

// WithCatalogLookup replaces catalog resolution for subscription logins, so a
// test can point a profile at a fake issuer.
func WithCatalogLookup(lookup func(id string) (catalog.Provider, bool)) ManagerOption {
	return func(m *managerImpl) { m.lookupCatalog = lookup }
}

// pinUserOAuthProvider fixes the fields of a user_oauth record that decide
// where its linked login goes. The login is a person's subscription, so the
// record may only ever point at the vendor's own host, over verified TLS, and
// never carries an API key.
func pinUserOAuthProvider(p *types.Provider, entry catalog.Provider) error {
	want := "https://" + entry.DefaultHost
	u, err := url.Parse(strings.TrimSpace(p.UpstreamURL))
	if err != nil || !strings.EqualFold(u.Scheme, "https") || !strings.EqualFold(u.Host, entry.DefaultHost) ||
		strings.Trim(u.Path, "/") != "" || u.RawQuery != "" || u.User != nil {
		return status.Errorf(status.InvalidArgument, "upstream_url for %s must be %s", entry.ID, want)
	}
	if p.SkipTLSVerification {
		return status.Errorf(status.InvalidArgument, "skip_tls_verification cannot be set for %s", entry.ID)
	}
	p.UpstreamURL = want
	p.APIKey = ""
	return nil
}

// linkableProvider loads a provider record and its catalog entry, refusing
// records that are disabled or do not use a linked login.
func (m *managerImpl) linkableProvider(ctx context.Context, accountID, providerID string) (*types.Provider, catalog.Provider, error) {
	provider, err := m.store.GetAgentNetworkProviderByID(ctx, store.LockingStrengthNone, accountID, providerID)
	if err != nil {
		return nil, catalog.Provider{}, err
	}
	entry, ok := m.catalogEntry(provider.ProviderID)
	if !ok || !entry.UsesUserOAuth() || !provider.Enabled {
		return nil, catalog.Provider{}, ErrProviderNotLinkable
	}
	return provider, entry, nil
}

// GetProviderCredentialAccess serves the proxy the headers of the login linked
// to a provider. The proxy has already authorised the caller against the
// provider's policies; the login serves every request they allow, including
// those from machines that belong to no user.
func (m *managerImpl) GetProviderCredentialAccess(ctx context.Context, accountID, providerID string) (*subscription.Access, error) {
	_, entry, err := m.linkableProvider(ctx, accountID, providerID)
	if err != nil {
		return nil, err
	}
	return m.subscriptions.Access(ctx, subscription.Key{AccountID: accountID, ProviderID: providerID}, entry)
}

// StartProviderLink starts linking a subscription login to a provider. It
// needs permission to update providers: the login will serve everyone the
// provider's policies cover.
func (m *managerImpl) StartProviderLink(ctx context.Context, accountID, userID, providerID string, requested ...catalog.OAuthFlow) (*subscription.Flow, error) {
	if err := m.requirePermission(ctx, accountID, userID, modules.AgentNetworkProviders, operations.Update); err != nil {
		return nil, err
	}
	if !m.store.FieldEncryptionEnabled() {
		return nil, status.Errorf(status.PreconditionFailed, "subscription logins need a datastore encryption key on the management server")
	}
	_, entry, err := m.linkTarget(ctx, accountID, providerID)
	if err != nil {
		return nil, err
	}
	if len(requested) > 1 {
		return nil, status.Errorf(status.InvalidArgument, "only one login flow may be requested")
	}
	if len(requested) == 1 && requested[0] != "" {
		if !entry.OAuth.SupportsFlow(requested[0]) {
			return nil, linkError(subscription.ErrUnsupportedFlow)
		}
		profile := *entry.OAuth
		profile.Flow = requested[0]
		entry.OAuth = &profile
	}
	flow, err := m.subscriptions.StartLink(ctx, subscription.Key{AccountID: accountID, ProviderID: providerID}, userID, entry)
	if err != nil {
		return nil, linkError(err)
	}
	return flow, nil
}

// PollProviderLink advances a link the caller started.
func (m *managerImpl) PollProviderLink(ctx context.Context, accountID, userID, providerID, flowID string) (*subscription.Flow, error) {
	if err := m.requirePermission(ctx, accountID, userID, modules.AgentNetworkProviders, operations.Update); err != nil {
		return nil, err
	}
	provider, entry, err := m.linkTarget(ctx, accountID, providerID)
	if err != nil {
		return nil, err
	}
	flow, err := m.subscriptions.PollLink(ctx, subscription.Key{AccountID: accountID, ProviderID: providerID}, userID, flowID, entry)
	if err != nil {
		return nil, linkError(err)
	}
	if flow.JustLinked {
		m.accountManager.StoreEvent(ctx, userID, providerID, accountID, activity.AgentNetworkSubscriptionLinked, provider.EventMeta())
	}
	return flow, nil
}

// CompleteProviderLink exchanges the authorization result for a flow started by the caller.
func (m *managerImpl) CompleteProviderLink(ctx context.Context, accountID, userID, providerID, flowID, code string) (*subscription.Flow, error) {
	if err := m.requirePermission(ctx, accountID, userID, modules.AgentNetworkProviders, operations.Update); err != nil {
		return nil, err
	}
	if !m.store.FieldEncryptionEnabled() {
		return nil, status.Errorf(status.PreconditionFailed, "subscription logins need a datastore encryption key on the management server")
	}
	provider, entry, err := m.linkTarget(ctx, accountID, providerID)
	if err != nil {
		return nil, err
	}
	flow, err := m.subscriptions.CompleteLink(ctx, subscription.Key{AccountID: accountID, ProviderID: providerID}, userID, flowID, code, entry)
	if err != nil {
		return nil, linkError(err)
	}
	if flow.JustLinked {
		m.accountManager.StoreEvent(ctx, userID, providerID, accountID, activity.AgentNetworkSubscriptionLinked, provider.EventMeta())
	}
	return flow, nil
}

// UnlinkProvider forgets a provider's linked login.
func (m *managerImpl) UnlinkProvider(ctx context.Context, accountID, userID, providerID string) error {
	if err := m.requirePermission(ctx, accountID, userID, modules.AgentNetworkProviders, operations.Update); err != nil {
		return err
	}
	provider, err := m.store.GetAgentNetworkProviderByID(ctx, store.LockingStrengthNone, accountID, providerID)
	if err != nil {
		return err
	}
	if err := m.subscriptions.Unlink(ctx, subscription.Key{AccountID: accountID, ProviderID: providerID}); err != nil {
		return err
	}
	m.accountManager.StoreEvent(ctx, userID, providerID, accountID, activity.AgentNetworkSubscriptionUnlinked, provider.EventMeta())
	return nil
}

// linkTarget is linkableProvider with its refusal turned into an API error.
func (m *managerImpl) linkTarget(ctx context.Context, accountID, providerID string) (*types.Provider, catalog.Provider, error) {
	provider, entry, err := m.linkableProvider(ctx, accountID, providerID)
	if errors.Is(err, ErrProviderNotLinkable) {
		return nil, catalog.Provider{}, status.Errorf(status.InvalidArgument, "provider %s does not use a subscription login, or is disabled", providerID)
	}
	return provider, entry, err
}

// linkError maps subscription failures to API statuses.
func linkError(err error) error {
	switch {
	case errors.Is(err, subscription.ErrFlowNotFound):
		return status.Errorf(status.NotFound, "link flow not found")
	case errors.Is(err, subscription.ErrDeviceLoginDisabled):
		return status.Errorf(status.PreconditionFailed, "the vendor has device login turned off for this client")
	case errors.Is(err, subscription.ErrUnsupportedFlow):
		return status.Errorf(status.InvalidArgument, "provider login flow is not supported")
	case errors.Is(err, subscription.ErrInvalidAuthorizationCode):
		return status.Errorf(status.InvalidArgument, "authorization result is invalid or belongs to another login attempt")
	default:
		return fmt.Errorf("subscription link: %w", err)
	}
}

// attachLinkStates sets the link state of every user_oauth provider in
// providers from the account's stored logins. Tokens are never loaded.
func (m *managerImpl) attachLinkStates(ctx context.Context, accountID string, providers []*types.Provider) error {
	var states map[string]*types.ProviderCredential
	for _, p := range providers {
		entry, ok := m.catalogEntry(p.ProviderID)
		if !ok || !entry.UsesUserOAuth() {
			continue
		}
		if states == nil {
			loaded, err := m.linkStates(ctx, accountID)
			if err != nil {
				return err
			}
			states = loaded
		}
		p.SubscriptionLink = types.LinkStateFromCredential(states[p.ID])
	}
	return nil
}

// linkStates returns the account's stored logins by provider record id.
func (m *managerImpl) linkStates(ctx context.Context, accountID string) (map[string]*types.ProviderCredential, error) {
	creds, err := m.store.GetAccountAgentNetworkProviderCredentialStatuses(ctx, accountID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]*types.ProviderCredential, len(creds))
	for _, c := range creds {
		out[c.ProviderID] = c
	}
	return out, nil
}

// StartProviderLink on the mock manager is not supported.
func (*mockManager) StartProviderLink(_ context.Context, _, _, _ string, _ ...catalog.OAuthFlow) (*subscription.Flow, error) {
	return nil, ErrProviderNotLinkable
}

// PollProviderLink on the mock manager is not supported.
func (*mockManager) PollProviderLink(_ context.Context, _, _, _, _ string) (*subscription.Flow, error) {
	return nil, ErrProviderNotLinkable
}

// CompleteProviderLink on the mock manager is not supported.
func (*mockManager) CompleteProviderLink(_ context.Context, _, _, _, _, _ string) (*subscription.Flow, error) {
	return nil, ErrProviderNotLinkable
}

// UnlinkProvider on the mock manager is a no-op.
func (*mockManager) UnlinkProvider(_ context.Context, _, _, _ string) error { return nil }

// GetProviderCredentialAccess on the mock manager reports no login.
func (*mockManager) GetProviderCredentialAccess(_ context.Context, _, _ string) (*subscription.Access, error) {
	return nil, subscription.ErrNotLinked
}

// catalogEntry resolves a catalog entry through the configured lookup,
// falling back to the built-in catalog for managers built without one.
func (m *managerImpl) catalogEntry(id string) (catalog.Provider, bool) {
	if m.lookupCatalog == nil {
		return catalog.Lookup(id)
	}
	return m.lookupCatalog(id)
}
