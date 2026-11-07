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

// pinUserOAuthProvider fixes the fields of a user_oauth record that decide
// where users' tokens go. The tokens belong to users, not to the operator, so
// the record may only ever point at the vendor's own host, over verified TLS,
// and never carries an operator key.
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

// StartProviderLink starts a subscription login for the caller on a provider
// their own policies reach. A caller can only ever link their own login.
func (m *managerImpl) StartProviderLink(ctx context.Context, accountID, userID, providerID string) (*subscription.Flow, error) {
	if !m.store.FieldEncryptionEnabled() {
		return nil, status.Errorf(status.PreconditionFailed, "subscription logins need a datastore encryption key on the management server")
	}
	_, entry, err := m.callerLinkableProvider(ctx, accountID, userID, providerID)
	if err != nil {
		return nil, err
	}
	flow, err := m.subscriptions.StartLink(ctx, subscription.Key{AccountID: accountID, UserID: userID, ProviderID: providerID}, entry)
	if err != nil {
		return nil, linkError(err)
	}
	return flow, nil
}

// PollProviderLink advances a login the caller started.
func (m *managerImpl) PollProviderLink(ctx context.Context, accountID, userID, providerID, flowID string) (*subscription.Flow, error) {
	provider, entry, err := m.callerLinkableProvider(ctx, accountID, userID, providerID)
	if err != nil {
		return nil, err
	}
	flow, err := m.subscriptions.PollLink(ctx, subscription.Key{AccountID: accountID, UserID: userID, ProviderID: providerID}, flowID, entry)
	if err != nil {
		return nil, linkError(err)
	}
	if flow.JustLinked {
		m.accountManager.StoreEvent(ctx, userID, providerID, accountID, activity.AgentNetworkSubscriptionLinked, provider.EventMeta())
	}
	return flow, nil
}

// UnlinkProvider forgets the caller's own login. It needs no policy check:
// removing one's own login is always allowed, even after access was revoked.
func (m *managerImpl) UnlinkProvider(ctx context.Context, accountID, userID, providerID string) error {
	if err := m.subscriptions.Unlink(ctx, subscription.Key{AccountID: accountID, UserID: userID, ProviderID: providerID}); err != nil {
		return err
	}
	meta := map[string]any{"provider_record_id": providerID}
	if provider, err := m.store.GetAgentNetworkProviderByID(ctx, store.LockingStrengthNone, accountID, providerID); err == nil {
		meta = provider.EventMeta()
	}
	m.accountManager.StoreEvent(ctx, userID, providerID, accountID, activity.AgentNetworkSubscriptionUnlinked, meta)
	return nil
}

// ListProviderLinks shows administrators which users linked a login for a
// provider. Tokens are never loaded.
func (m *managerImpl) ListProviderLinks(ctx context.Context, accountID, userID, providerID string) ([]*types.UserCredential, error) {
	if err := m.requirePermission(ctx, accountID, userID, modules.AgentNetworkProviders, operations.Read); err != nil {
		return nil, err
	}
	if _, err := m.store.GetAgentNetworkProviderByID(ctx, store.LockingStrengthNone, accountID, providerID); err != nil {
		return nil, err
	}
	all, err := m.store.GetAccountAgentNetworkUserCredentialStatuses(ctx, accountID)
	if err != nil {
		return nil, err
	}
	out := make([]*types.UserCredential, 0, len(all))
	for _, c := range all {
		if c.ProviderID == providerID {
			out = append(out, c)
		}
	}
	return out, nil
}

// callerLinkableProvider is linkableProvider plus the caller's own policy
// check. An unreachable provider reads exactly like a missing one.
func (m *managerImpl) callerLinkableProvider(ctx context.Context, accountID, userID, providerID string) (*types.Provider, catalog.Provider, error) {
	provider, entry, err := m.linkableProvider(ctx, accountID, providerID)
	if errors.Is(err, ErrProviderNotLinkable) {
		return nil, catalog.Provider{}, status.Errorf(status.InvalidArgument, "provider %s does not use subscription logins", providerID)
	}
	if err != nil {
		return nil, catalog.Provider{}, err
	}
	ok, err := m.callerAuthorizedFor(ctx, accountID, userID, providerID)
	if err != nil {
		return nil, catalog.Provider{}, err
	}
	if !ok {
		return nil, catalog.Provider{}, status.NewAgentNetworkProviderNotFoundError(providerID)
	}
	return provider, entry, nil
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
	default:
		return fmt.Errorf("subscription link: %w", err)
	}
}

// linkStates returns the caller's link state per user_oauth provider record.
func (m *managerImpl) linkStates(ctx context.Context, accountID, userID string) (map[string]*types.UserCredential, error) {
	creds, err := m.store.GetUserAgentNetworkCredentialStatuses(ctx, accountID, userID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]*types.UserCredential, len(creds))
	for _, c := range creds {
		out[c.ProviderID] = c
	}
	return out, nil
}

// StartProviderLink on the mock manager is not supported.
func (*mockManager) StartProviderLink(_ context.Context, _, _, _ string) (*subscription.Flow, error) {
	return nil, ErrProviderNotLinkable
}

// PollProviderLink on the mock manager is not supported.
func (*mockManager) PollProviderLink(_ context.Context, _, _, _, _ string) (*subscription.Flow, error) {
	return nil, ErrProviderNotLinkable
}

// UnlinkProvider on the mock manager is a no-op.
func (*mockManager) UnlinkProvider(_ context.Context, _, _, _ string) error { return nil }

// ListProviderLinks on the mock manager reports none.
func (*mockManager) ListProviderLinks(_ context.Context, _, _, _ string) ([]*types.UserCredential, error) {
	return nil, nil
}

// GetUserCredentialAccess on the mock manager reports no login.
func (*mockManager) GetUserCredentialAccess(_ context.Context, _, _, _ string) (*subscription.Access, error) {
	return nil, subscription.ErrNotLinked
}
