package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	agentNetworkTypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

const providerCredentialKeyCondition = "account_id = ? AND provider_id = ?" //nolint:gosec // SQL condition, not a credential

// providerCredentialStatusColumns are the columns safe to read without the
// encryptor: everything except the tokens.
var providerCredentialStatusColumns = []string{
	"account_id", "provider_id", "linked_by", "access_expires_at", "external_account_id",
	"plan_type", "fedramp", "status", "version", "created_at", "updated_at", "last_refreshed_at",
}

// GetAgentNetworkProviderCredential returns the subscription login linked to a
// provider record with its tokens decrypted, or a NotFound status error.
func (s *SqlStore) GetAgentNetworkProviderCredential(ctx context.Context, accountID, providerID string) (*agentNetworkTypes.ProviderCredential, error) {
	var cred agentNetworkTypes.ProviderCredential
	result := s.db.WithContext(ctx).Take(&cred, providerCredentialKeyCondition, accountID, providerID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "agent network provider credential not found")
		}
		log.WithContext(ctx).Errorf("failed to get agent network provider credential from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get agent network provider credential from store")
	}
	if err := cred.DecryptSensitiveData(s.fieldEncrypt); err != nil {
		log.WithContext(ctx).Errorf("failed to decrypt agent network provider credential: %v", err)
		return nil, status.Errorf(status.Internal, "failed to decrypt agent network provider credential")
	}
	return &cred, nil
}

// GetAccountAgentNetworkProviderCredentialStatuses lists the account's linked
// logins without their tokens, for status displays.
func (s *SqlStore) GetAccountAgentNetworkProviderCredentialStatuses(ctx context.Context, accountID string) ([]*agentNetworkTypes.ProviderCredential, error) {
	var creds []*agentNetworkTypes.ProviderCredential
	result := s.db.WithContext(ctx).Select(providerCredentialStatusColumns).Find(&creds, accountIDCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to list agent network provider credentials from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to list agent network provider credentials from store")
	}
	return creds, nil
}

// LinkAgentNetworkProviderCredential stores a freshly linked login, replacing
// the provider's previous one. A fresh generation fences out old refreshes;
// the upsert increments the version atomically with replacing the login.
func (s *SqlStore) LinkAgentNetworkProviderCredential(ctx context.Context, cred *agentNetworkTypes.ProviderCredential) error {
	sealed := cred.Copy()
	if err := sealed.EncryptSensitiveData(s.fieldEncrypt); err != nil {
		log.WithContext(ctx).Errorf("failed to encrypt agent network provider credential: %v", err)
		return status.Errorf(status.Internal, "failed to encrypt agent network provider credential")
	}
	var generation [32]byte
	if _, err := rand.Read(generation[:]); err != nil {
		return fmt.Errorf("generate provider credential generation: %w", err)
	}
	sealed.Generation = base64.RawURLEncoding.EncodeToString(generation[:])
	sealed.Version = 1
	sealed.RefreshLeaseUntil = nil
	updates := clause.AssignmentColumns([]string{
		"linked_by", "generation", "refresh_token", "access_token", "access_expires_at",
		"external_account_id", "plan_type", "fedramp", "status", "refresh_lease_until",
		"created_at", "updated_at", "last_refreshed_at",
	})
	updates = append(updates, clause.Assignment{
		Column: clause.Column{Name: "version"},
		Value:  gorm.Expr("agent_network_provider_credentials.version + 1"),
	})
	err := s.transaction(ctx, func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "account_id"}, {Name: "provider_id"}},
			DoUpdates: updates,
		}).Create(sealed).Error; err != nil {
			return err
		}
		return tx.Select("version").Take(sealed, providerCredentialKeyCondition, cred.AccountID, cred.ProviderID).Error
	})
	if err != nil {
		log.WithContext(ctx).Errorf("failed to save agent network provider credential: %v", err)
		return status.Errorf(status.Internal, "failed to save agent network provider credential")
	}
	cred.Generation = sealed.Generation
	cred.Version = sealed.Version
	cred.RefreshLeaseUntil = nil
	return nil
}

// CompareAndSwapAgentNetworkProviderCredential writes cred only when the
// stored row is still the same generation at expectedVersion, and reports
// whether it did. On success the row and cred carry expectedVersion+1.
func (s *SqlStore) CompareAndSwapAgentNetworkProviderCredential(ctx context.Context, cred *agentNetworkTypes.ProviderCredential, expectedVersion int64) (bool, error) {
	sealed := cred.Copy()
	if err := sealed.EncryptSensitiveData(s.fieldEncrypt); err != nil {
		log.WithContext(ctx).Errorf("failed to encrypt agent network provider credential: %v", err)
		return false, status.Errorf(status.Internal, "failed to encrypt agent network provider credential")
	}
	result := s.db.WithContext(ctx).Model(&agentNetworkTypes.ProviderCredential{}).
		Where(providerCredentialKeyCondition+" AND generation = ? AND version = ?", cred.AccountID, cred.ProviderID, cred.Generation, expectedVersion).
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
		log.WithContext(ctx).Errorf("failed to update agent network provider credential: %v", result.Error)
		return false, status.Errorf(status.Internal, "failed to update agent network provider credential")
	}
	if result.RowsAffected == 0 {
		return false, nil
	}
	cred.Version = expectedVersion + 1
	return true, nil
}

// DeleteAgentNetworkProviderCredential removes a provider's linked login.
// Removing a login that does not exist is not an error.
func (s *SqlStore) DeleteAgentNetworkProviderCredential(ctx context.Context, accountID, providerID string) error {
	result := s.db.WithContext(ctx).Delete(&agentNetworkTypes.ProviderCredential{}, providerCredentialKeyCondition, accountID, providerID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete agent network provider credential: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete agent network provider credential")
	}
	return nil
}
