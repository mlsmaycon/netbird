package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

func linkTestCredential(t *testing.T, s Store, userID, providerID string) *agentNetworkTypes.UserCredential {
	t.Helper()
	cred := &agentNetworkTypes.UserCredential{
		AccountID:       credTestAccountID,
		UserID:          userID,
		ProviderID:      providerID,
		RefreshToken:    "refresh-secret",
		AccessToken:     "access-secret",
		AccessExpiresAt: time.Now().Add(time.Hour).UTC(),
		Status:          agentNetworkTypes.UserCredentialActive,
	}
	require.NoError(t, s.LinkAgentNetworkUserCredential(context.Background(), cred))
	return cred
}

func credentialCount(t *testing.T, s Store) int {
	t.Helper()
	list, err := s.GetAccountAgentNetworkUserCredentialStatuses(context.Background(), credTestAccountID)
	require.NoError(t, err)
	return len(list)
}

func TestAgentNetworkUserCredential_EncryptedAtRest(t *testing.T) {
	s := newCredentialTestStore(t)
	linkTestCredential(t, s, credTestUserID, "prov-1")

	var raw agentNetworkTypes.UserCredential
	require.NoError(t, s.(*SqlStore).db.Take(&raw, userCredentialKeyCondition, credTestAccountID, credTestUserID, "prov-1").Error)
	assert.NotContains(t, raw.RefreshToken, "refresh-secret", "the refresh token must not be stored in plaintext")
	assert.NotContains(t, raw.AccessToken, "access-secret", "the access token must not be stored in plaintext")

	got, err := s.GetAgentNetworkUserCredential(context.Background(), credTestAccountID, credTestUserID, "prov-1")
	require.NoError(t, err)
	assert.Equal(t, "refresh-secret", got.RefreshToken, "the token should decrypt on read")

	statuses, err := s.GetAccountAgentNetworkUserCredentialStatuses(context.Background(), credTestAccountID)
	require.NoError(t, err)
	require.Len(t, statuses, 1)
	assert.Empty(t, statuses[0].RefreshToken, "status listings must not carry tokens")
}

func TestAgentNetworkUserCredential_CompareAndSwap(t *testing.T) {
	ctx := context.Background()
	s := newCredentialTestStore(t)
	cred := linkTestCredential(t, s, credTestUserID, "prov-1")
	require.Equal(t, int64(1), cred.Version)

	next := cred.Copy()
	next.RefreshToken = "rotated"
	ok, err := s.CompareAndSwapAgentNetworkUserCredential(ctx, next, 1)
	require.NoError(t, err)
	assert.True(t, ok, "a swap at the current version should apply")
	assert.Equal(t, int64(2), next.Version)

	stale := cred.Copy()
	stale.RefreshToken = "stale-writer"
	ok, err = s.CompareAndSwapAgentNetworkUserCredential(ctx, stale, 1)
	require.NoError(t, err)
	assert.False(t, ok, "a swap at a stale version must be refused")

	got, err := s.GetAgentNetworkUserCredential(ctx, credTestAccountID, credTestUserID, "prov-1")
	require.NoError(t, err)
	assert.Equal(t, "rotated", got.RefreshToken, "the stale writer must not overwrite the rotated token")

	// Relinking continues the version so an in-flight refresh loses its swap.
	relinked := linkTestCredential(t, s, credTestUserID, "prov-1")
	assert.Equal(t, int64(3), relinked.Version)
}

func TestAgentNetworkUserCredential_CleanupPaths(t *testing.T) {
	ctx := context.Background()

	t.Run("unlink", func(t *testing.T) {
		s := newCredentialTestStore(t)
		linkTestCredential(t, s, credTestUserID, "prov-1")
		require.NoError(t, s.DeleteAgentNetworkUserCredential(ctx, credTestAccountID, credTestUserID, "prov-1"))
		require.NoError(t, s.DeleteAgentNetworkUserCredential(ctx, credTestAccountID, credTestUserID, "prov-1"), "unlinking twice is not an error")
		assert.Zero(t, credentialCount(t, s))
	})

	t.Run("user deletion", func(t *testing.T) {
		s := newCredentialTestStore(t)
		linkTestCredential(t, s, credTestUserID, "prov-1")
		linkTestCredential(t, s, "someone-else", "prov-1")
		require.NoError(t, s.DeleteUser(ctx, credTestAccountID, credTestUserID))
		list, err := s.GetAccountAgentNetworkUserCredentialStatuses(ctx, credTestAccountID)
		require.NoError(t, err)
		require.Len(t, list, 1, "only the deleted user's login should go")
		assert.Equal(t, "someone-else", list[0].UserID)
	})

	t.Run("provider deletion", func(t *testing.T) {
		s := newCredentialTestStore(t)
		provider := agentNetworkTypes.NewProvider(credTestAccountID)
		provider.ProviderID = "chatgpt_codex"
		require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
		linkTestCredential(t, s, credTestUserID, provider.ID)
		linkTestCredential(t, s, credTestUserID, "other-provider")
		require.NoError(t, s.DeleteAgentNetworkProvider(ctx, credTestAccountID, provider.ID))
		list, err := s.GetAccountAgentNetworkUserCredentialStatuses(ctx, credTestAccountID)
		require.NoError(t, err)
		require.Len(t, list, 1, "only the deleted provider's logins should go")
		assert.Equal(t, "other-provider", list[0].ProviderID)
	})

	t.Run("account deletion", func(t *testing.T) {
		s := newCredentialTestStore(t)
		linkTestCredential(t, s, credTestUserID, "prov-1")
		account, err := s.GetAccount(ctx, credTestAccountID)
		require.NoError(t, err)
		require.NoError(t, s.DeleteAccount(ctx, account))
		assert.Zero(t, credentialCount(t, s))
	})
}
