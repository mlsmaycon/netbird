package store

import (
	"context"
	"errors"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	agentNetworkTypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

const userCredentialKeyCondition = "account_id = ? AND user_id = ? AND provider_id = ?" //nolint:gosec // SQL condition, not a credential

// userCredentialStatusColumns are the columns safe to read without the
// encryptor: everything except the tokens.
var userCredentialStatusColumns = []string{
	"account_id", "user_id", "provider_id", "access_expires_at", "external_account_id",
	"plan_type", "fedramp", "status", "version", "created_at", "updated_at", "last_refreshed_at",
}

// GetAgentNetworkUserCredential returns one user's linked login for a provider
// record with its tokens decrypted, or a NotFound status error.
func (s *SqlStore) GetAgentNetworkUserCredential(ctx context.Context, accountID, userID, providerID string) (*agentNetworkTypes.UserCredential, error) {
	var cred agentNetworkTypes.UserCredential
	result := s.db.WithContext(ctx).Take(&cred, userCredentialKeyCondition, accountID, userID, providerID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "agent network user credential not found")
		}
		log.WithContext(ctx).Errorf("failed to get agent network user credential from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get agent network user credential from store")
	}
	if err := cred.DecryptSensitiveData(s.fieldEncrypt); err != nil {
		log.WithContext(ctx).Errorf("failed to decrypt agent network user credential: %v", err)
		return nil, status.Errorf(status.Internal, "failed to decrypt agent network user credential")
	}
	return &cred, nil
}

// GetAccountAgentNetworkUserCredentialStatuses lists the account's linked
// logins without their tokens, for status displays.
func (s *SqlStore) GetAccountAgentNetworkUserCredentialStatuses(ctx context.Context, accountID string) ([]*agentNetworkTypes.UserCredential, error) {
	var creds []*agentNetworkTypes.UserCredential
	result := s.db.WithContext(ctx).Select(userCredentialStatusColumns).Find(&creds, accountIDCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to list agent network user credentials from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to list agent network user credentials from store")
	}
	return creds, nil
}

// LinkAgentNetworkUserCredential stores a freshly linked login, replacing any
// previous one for the same user and provider record. The version continues
// from the replaced row so a refresh racing the relink loses its swap.
func (s *SqlStore) LinkAgentNetworkUserCredential(ctx context.Context, cred *agentNetworkTypes.UserCredential) error {
	sealed := cred.Copy()
	if err := sealed.EncryptSensitiveData(s.fieldEncrypt); err != nil {
		log.WithContext(ctx).Errorf("failed to encrypt agent network user credential: %v", err)
		return status.Errorf(status.Internal, "failed to encrypt agent network user credential")
	}
	err := s.transaction(ctx, func(tx *gorm.DB) error {
		var prev agentNetworkTypes.UserCredential
		err := tx.Select("version").Take(&prev, userCredentialKeyCondition, cred.AccountID, cred.UserID, cred.ProviderID).Error
		switch {
		case err == nil:
			sealed.Version = prev.Version + 1
		case errors.Is(err, gorm.ErrRecordNotFound):
			sealed.Version = 1
		default:
			return err
		}
		return tx.Save(sealed).Error
	})
	if err != nil {
		log.WithContext(ctx).Errorf("failed to save agent network user credential: %v", err)
		return status.Errorf(status.Internal, "failed to save agent network user credential")
	}
	cred.Version = sealed.Version
	return nil
}

// CompareAndSwapAgentNetworkUserCredential writes cred only when the stored
// row is still at expectedVersion, and reports whether it did. On success the
// row and cred carry expectedVersion+1.
func (s *SqlStore) CompareAndSwapAgentNetworkUserCredential(ctx context.Context, cred *agentNetworkTypes.UserCredential, expectedVersion int64) (bool, error) {
	sealed := cred.Copy()
	if err := sealed.EncryptSensitiveData(s.fieldEncrypt); err != nil {
		log.WithContext(ctx).Errorf("failed to encrypt agent network user credential: %v", err)
		return false, status.Errorf(status.Internal, "failed to encrypt agent network user credential")
	}
	result := s.db.WithContext(ctx).Model(&agentNetworkTypes.UserCredential{}).
		Where(userCredentialKeyCondition+" AND version = ?", cred.AccountID, cred.UserID, cred.ProviderID, expectedVersion).
		Updates(map[string]any{
			"refresh_token":       sealed.RefreshToken,
			"access_token":        sealed.AccessToken,
			"access_expires_at":   sealed.AccessExpiresAt,
			"external_account_id": sealed.ExternalAccountID,
			"plan_type":           sealed.PlanType,
			"fedramp":             sealed.FedRAMP,
			"status":              sealed.Status,
			"version":             expectedVersion + 1,
			"refresh_lease_until": sealed.RefreshLeaseUntil,
			"updated_at":          time.Now().UTC(),
			"last_refreshed_at":   sealed.LastRefreshedAt,
		})
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to update agent network user credential: %v", result.Error)
		return false, status.Errorf(status.Internal, "failed to update agent network user credential")
	}
	if result.RowsAffected == 0 {
		return false, nil
	}
	cred.Version = expectedVersion + 1
	return true, nil
}

// DeleteAgentNetworkUserCredential removes one user's login for a provider
// record. Removing a login that does not exist is not an error.
func (s *SqlStore) DeleteAgentNetworkUserCredential(ctx context.Context, accountID, userID, providerID string) error {
	result := s.db.WithContext(ctx).Delete(&agentNetworkTypes.UserCredential{}, userCredentialKeyCondition, accountID, userID, providerID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete agent network user credential: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete agent network user credential")
	}
	return nil
}

// DeleteAgentNetworkUserCredentialsForProvider removes every user's login for
// one provider record.
func (s *SqlStore) DeleteAgentNetworkUserCredentialsForProvider(ctx context.Context, accountID, providerID string) error {
	result := s.db.WithContext(ctx).Delete(&agentNetworkTypes.UserCredential{}, "account_id = ? AND provider_id = ?", accountID, providerID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete agent network user credentials for provider: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete agent network user credentials")
	}
	return nil
}
