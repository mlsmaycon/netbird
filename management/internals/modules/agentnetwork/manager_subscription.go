package agentnetwork

import (
	"context"
	"errors"
	"fmt"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/catalog"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/subscription"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	nbcache "github.com/netbirdio/netbird/management/server/cache"
	"github.com/netbirdio/netbird/management/server/store"
)

// ErrProviderNotLinkable is returned for a provider record whose catalog entry
// does not use per-user subscription logins, or that is disabled.
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

// linkableProvider loads a provider record and its catalog entry, refusing
// records that are disabled or do not use subscription logins.
func (m *managerImpl) linkableProvider(ctx context.Context, accountID, providerID string) (*types.Provider, catalog.Provider, error) {
	provider, err := m.store.GetAgentNetworkProviderByID(ctx, store.LockingStrengthNone, accountID, providerID)
	if err != nil {
		return nil, catalog.Provider{}, err
	}
	entry, ok := m.lookupCatalog(provider.ProviderID)
	if !ok || !entry.UsesUserOAuth() || !provider.Enabled {
		return nil, catalog.Provider{}, ErrProviderNotLinkable
	}
	return provider, entry, nil
}

// callerAuthorizedFor reports whether the user's own policies reach the
// provider record, the same selection the proxy's routing enforces.
func (m *managerImpl) callerAuthorizedFor(ctx context.Context, accountID, userID, providerID string) (bool, error) {
	user, err := m.store.GetUserByUserID(ctx, store.LockingStrengthNone, userID)
	if err != nil {
		return false, fmt.Errorf("get user: %w", err)
	}
	if user.AccountID != accountID {
		return false, nil
	}
	authorized, _, err := m.authorizedProvidersForGroups(ctx, accountID, user.AutoGroups)
	if err != nil {
		return false, err
	}
	for _, p := range authorized {
		if p.ID == providerID {
			return true, nil
		}
	}
	return false, nil
}

// GetUserCredentialAccess serves the proxy. Management re-checks that the
// user's policies still reach the provider, so a login outlives neither the
// user's access nor the provider's subscription kind.
func (m *managerImpl) GetUserCredentialAccess(ctx context.Context, accountID, userID, providerID string) (*subscription.Access, error) {
	if userID == "" {
		return nil, subscription.ErrNotLinked
	}
	_, entry, err := m.linkableProvider(ctx, accountID, providerID)
	if err != nil {
		return nil, err
	}
	ok, err := m.callerAuthorizedFor(ctx, accountID, userID, providerID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, subscription.ErrNotLinked
	}
	return m.subscriptions.Access(ctx, subscription.Key{AccountID: accountID, UserID: userID, ProviderID: providerID}, entry)
}

// GetUserCredentialAccess on the mock manager reports no login.
func (*mockManager) GetUserCredentialAccess(_ context.Context, _, _, _ string) (*subscription.Access, error) {
	return nil, subscription.ErrNotLinked
}
