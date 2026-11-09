package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	agentNetworkTypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/util/crypt"
)

const (
	credTestAccountID = "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	credTestUserID    = "edafee4e-63fb-11ec-90d6-0242ac120003"
)

func newCredentialTestStore(t *testing.T) Store {
	t.Helper()
	s, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)
	key, err := crypt.GenerateKey()
	require.NoError(t, err)
	enc, err := crypt.NewFieldEncrypt(key)
	require.NoError(t, err)
	s.SetFieldEncrypt(enc)
	return s
}

func linkTestCredential(t *testing.T, s Store, providerID string) *agentNetworkTypes.ProviderCredential {
	t.Helper()
	cred := &agentNetworkTypes.ProviderCredential{
		AccountID:       credTestAccountID,
		ProviderID:      providerID,
		LinkedBy:        credTestUserID,
		RefreshToken:    "refresh-secret",
		AccessToken:     "access-secret",
		AccessExpiresAt: time.Now().Add(time.Hour).UTC(),
		Status:          agentNetworkTypes.CredentialActive,
	}
	require.NoError(t, s.LinkAgentNetworkProviderCredential(context.Background(), cred))
	return cred
}

func credentialCount(t *testing.T, s Store) int {
	t.Helper()
	list, err := s.GetAccountAgentNetworkProviderCredentialStatuses(context.Background(), credTestAccountID)
	require.NoError(t, err)
	return len(list)
}

func TestAgentNetworkProviderCredential_EncryptedAtRest(t *testing.T) {
	s := newCredentialTestStore(t)
	linkTestCredential(t, s, "prov-1")

	var raw agentNetworkTypes.ProviderCredential
	require.NoError(t, s.(*SqlStore).db.Take(&raw, providerCredentialKeyCondition, credTestAccountID, "prov-1").Error)
	assert.NotContains(t, raw.RefreshToken, "refresh-secret", "the refresh token must not be stored in plaintext")
	assert.NotContains(t, raw.AccessToken, "access-secret", "the access token must not be stored in plaintext")

	got, err := s.GetAgentNetworkProviderCredential(context.Background(), credTestAccountID, "prov-1")
	require.NoError(t, err)
	assert.Equal(t, "refresh-secret", got.RefreshToken, "the token should decrypt on read")
	assert.Equal(t, credTestUserID, got.LinkedBy)

	statuses, err := s.GetAccountAgentNetworkProviderCredentialStatuses(context.Background(), credTestAccountID)
	require.NoError(t, err)
	require.Len(t, statuses, 1)
	assert.Empty(t, statuses[0].RefreshToken, "status listings must not carry tokens")
	assert.Equal(t, credTestUserID, statuses[0].LinkedBy, "status listings should say who linked")
}

func TestAgentNetworkProviderCredential_CompareAndSwap(t *testing.T) {
	ctx := context.Background()
	s := newCredentialTestStore(t)
	cred := linkTestCredential(t, s, "prov-1")
	require.Equal(t, int64(1), cred.Version)
	require.NotEmpty(t, cred.Generation, "each new login must receive an immutable generation")

	next := cred.Copy()
	next.RefreshToken = "rotated"
	ok, err := s.CompareAndSwapAgentNetworkProviderCredential(ctx, next, 1)
	require.NoError(t, err)
	assert.True(t, ok, "a swap at the current version should apply")
	assert.Equal(t, int64(2), next.Version)
	assert.Equal(t, cred.Generation, next.Generation, "refresh preserves the linked login's generation")

	stale := cred.Copy()
	stale.RefreshToken = "stale-writer"
	ok, err = s.CompareAndSwapAgentNetworkProviderCredential(ctx, stale, 1)
	require.NoError(t, err)
	assert.False(t, ok, "a swap at a stale version must be refused")

	got, err := s.GetAgentNetworkProviderCredential(ctx, credTestAccountID, "prov-1")
	require.NoError(t, err)
	assert.Equal(t, "rotated", got.RefreshToken, "the stale writer must not overwrite the rotated token")

	// Relinking continues the version so an in-flight refresh loses its swap.
	relinked := linkTestCredential(t, s, "prov-1")
	assert.Equal(t, int64(3), relinked.Version)
	assert.NotEqual(t, cred.Generation, relinked.Generation, "relink always creates a new generation")
}

func TestAgentNetworkProviderCredential_RelinkDuringRefreshClaim(t *testing.T) {
	ctx := context.Background()
	s := newCredentialTestStore(t)
	stale := linkTestCredential(t, s, "prov-1")
	db := s.(*SqlStore).db
	const callback = "test:claim_credential_refresh_after_version_read"
	// Reproduce the interleaving deterministically: the relink reads v1,
	// another replica claims v2, then the relink writes its replacement.
	// Run the competing write on this transaction so SQLite needs no second
	// writer; these are the same statements PostgreSQL can interleave.
	require.NoError(t, db.Callback().Query().After("gorm:query").Register(callback, func(tx *gorm.DB) {
		if tx.Statement.Table != stale.TableName() || len(tx.Statement.Selects) != 1 || tx.Statement.Selects[0] != "version" {
			return
		}
		snapshot, ok := tx.Statement.Dest.(*agentNetworkTypes.ProviderCredential)
		if !ok || snapshot.Version != stale.Version {
			return
		}
		claim := tx.Session(&gorm.Session{NewDB: true}).Model(&agentNetworkTypes.ProviderCredential{}).
			Where(providerCredentialKeyCondition+" AND version = ?", stale.AccountID, stale.ProviderID, stale.Version).
			Update("version", stale.Version+1)
		if claim.Error != nil {
			_ = tx.AddError(claim.Error)
			return
		}
		if claim.RowsAffected == 1 {
			stale.Version++
		}
	}))
	t.Cleanup(func() { assert.NoError(t, db.Callback().Query().Remove(callback)) })
	relinked := linkTestCredential(t, s, "prov-1")
	stale.RefreshToken = "old-login-rotated-token"
	ok, err := s.CompareAndSwapAgentNetworkProviderCredential(ctx, stale, stale.Version)
	require.NoError(t, err)
	assert.False(t, ok, "a refresh claim interleaved with relink must not overwrite the new login")
	stored, err := s.GetAgentNetworkProviderCredential(ctx, stale.AccountID, stale.ProviderID)
	require.NoError(t, err)
	assert.Equal(t, relinked.RefreshToken, stored.RefreshToken, "the replacement login must survive the old refresh")
}

func TestAgentNetworkProviderCredential_UnlinkRelinkVersionReuse(t *testing.T) {
	ctx := context.Background()
	s := newCredentialTestStore(t)
	stale := linkTestCredential(t, s, "prov-1")
	ok, err := s.CompareAndSwapAgentNetworkProviderCredential(ctx, stale, stale.Version)
	require.NoError(t, err)
	require.True(t, ok, "the old login's refresh must first claim its lease version")
	require.NoError(t, s.DeleteAgentNetworkProviderCredential(ctx, stale.AccountID, stale.ProviderID))
	relinked := linkTestCredential(t, s, "prov-1")
	ok, err = s.CompareAndSwapAgentNetworkProviderCredential(ctx, relinked, relinked.Version)
	require.NoError(t, err)
	require.True(t, ok, "the new login must be independently refreshable")
	require.Equal(t, stale.Version, relinked.Version, "the two distinct logins now have the same numeric version")
	require.NotEqual(t, stale.Generation, relinked.Generation, "reusing the numeric version must not reuse the login generation")
	stale.RefreshToken = "old-login-rotated-token"
	ok, err = s.CompareAndSwapAgentNetworkProviderCredential(ctx, stale, stale.Version)
	require.NoError(t, err)
	assert.False(t, ok, "version reuse must not let a deleted login overwrite its replacement")
	stored, err := s.GetAgentNetworkProviderCredential(ctx, stale.AccountID, stale.ProviderID)
	require.NoError(t, err)
	assert.Equal(t, relinked.RefreshToken, stored.RefreshToken, "the replacement login must survive the stale refresh")
}

func TestAgentNetworkProviderCredential_LegacyGenerationMigration(t *testing.T) {
	ctx := context.Background()
	s := newCredentialTestStore(t)
	linkTestCredential(t, s, "prov-1")
	db := s.(*SqlStore).db
	// Recreate the previous table shape with an encrypted credential already
	// present, then apply the same AutoMigrate used when management starts.
	require.NoError(t, db.Migrator().DropColumn(&agentNetworkTypes.ProviderCredential{}, "generation"))
	require.NoError(t, db.AutoMigrate(&agentNetworkTypes.ProviderCredential{}))
	legacy, err := s.GetAgentNetworkProviderCredential(ctx, credTestAccountID, "prov-1")
	require.NoError(t, err)
	assert.Empty(t, legacy.Generation, "migration must default existing rows to the legacy generation")
	assert.Equal(t, "refresh-secret", legacy.RefreshToken, "migration must preserve encrypted credentials")
	legacy.RefreshToken = "legacy-rotated-token"
	ok, err := s.CompareAndSwapAgentNetworkProviderCredential(ctx, legacy, legacy.Version)
	require.NoError(t, err)
	assert.True(t, ok, "a legacy login remains refreshable without forcing a relink")
	relinked := linkTestCredential(t, s, "prov-1")
	assert.NotEmpty(t, relinked.Generation, "the next relink must leave the legacy generation")
	ok, err = s.CompareAndSwapAgentNetworkProviderCredential(ctx, legacy, relinked.Version)
	require.NoError(t, err)
	assert.False(t, ok, "even a matching numeric version cannot let the legacy generation overwrite a new login")
}

func TestAgentNetworkProviderCredential_CleanupPaths(t *testing.T) {
	ctx := context.Background()

	t.Run("unlink", func(t *testing.T) {
		s := newCredentialTestStore(t)
		linkTestCredential(t, s, "prov-1")
		require.NoError(t, s.DeleteAgentNetworkProviderCredential(ctx, credTestAccountID, "prov-1"))
		require.NoError(t, s.DeleteAgentNetworkProviderCredential(ctx, credTestAccountID, "prov-1"), "unlinking twice is not an error")
		assert.Zero(t, credentialCount(t, s))
	})

	t.Run("user deletion keeps the provider's login", func(t *testing.T) {
		s := newCredentialTestStore(t)
		linkTestCredential(t, s, "prov-1")
		require.NoError(t, s.DeleteUser(ctx, credTestAccountID, credTestUserID))
		assert.Equal(t, 1, credentialCount(t, s), "the login belongs to the provider, not to the user who linked it")
	})

	t.Run("provider deletion", func(t *testing.T) {
		s := newCredentialTestStore(t)
		provider := agentNetworkTypes.NewProvider(credTestAccountID)
		provider.ProviderID = "chatgpt_codex"
		require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
		linkTestCredential(t, s, provider.ID)
		linkTestCredential(t, s, "other-provider")
		require.NoError(t, s.DeleteAgentNetworkProvider(ctx, credTestAccountID, provider.ID))
		list, err := s.GetAccountAgentNetworkProviderCredentialStatuses(ctx, credTestAccountID)
		require.NoError(t, err)
		require.Len(t, list, 1, "only the deleted provider's login should go")
		assert.Equal(t, "other-provider", list[0].ProviderID)
	})

	t.Run("account deletion", func(t *testing.T) {
		s := newCredentialTestStore(t)
		linkTestCredential(t, s, "prov-1")
		account, err := s.GetAccount(ctx, credTestAccountID)
		require.NoError(t, err)
		require.NoError(t, s.DeleteAccount(ctx, account))
		assert.Zero(t, credentialCount(t, s))
	})
}
