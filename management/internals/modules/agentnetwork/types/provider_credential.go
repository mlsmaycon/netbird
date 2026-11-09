package types

import (
	"errors"
	"fmt"
	"time"

	"github.com/netbirdio/netbird/util/crypt"
)

// CredentialStatus is the lifecycle state of a linked subscription login.
type CredentialStatus string

const (
	// CredentialActive is a login management can refresh and serve.
	CredentialActive CredentialStatus = "active"
	// CredentialNeedsRelink is a login the vendor refused to refresh
	// (reused, expired or revoked refresh token). Only a new login fixes it.
	CredentialNeedsRelink CredentialStatus = "needs_relink"
)

// ErrCredentialEncryptionUnavailable is returned when a subscription token
// would be written or read without a configured field encryptor. Unlike the
// provider api_key, these tokens are never stored in plaintext.
var ErrCredentialEncryptionUnavailable = errors.New("agent network provider credentials require a datastore encryption key")

// ProviderCredential is the subscription login linked to one provider record.
// It serves every request the provider's policies allow. Management is the
// only holder of the refresh token: the vendor invalidates a login whose
// refresh token is presented twice, so the proxy only ever receives
// short-lived access tokens derived from this row.
type ProviderCredential struct {
	AccountID  string `gorm:"primaryKey"`
	ProviderID string `gorm:"primaryKey"`
	// LinkedBy is the user who linked the current login.
	LinkedBy string `gorm:"column:linked_by"`

	RefreshToken    string    `gorm:"column:refresh_token"`
	AccessToken     string    `gorm:"column:access_token"`
	AccessExpiresAt time.Time `gorm:"column:access_expires_at"`

	// ExternalAccountID, PlanType and FedRAMP come from the id_token claims.
	// The id_token itself is not kept.
	ExternalAccountID string `gorm:"column:external_account_id"`
	PlanType          string `gorm:"column:plan_type"`
	FedRAMP           bool   `gorm:"column:fedramp"`

	Status CredentialStatus `gorm:"column:status"`
	// Generation identifies one linked login, so deleting and relinking a
	// provider cannot reuse a stale refresh writer's version.
	Generation string `gorm:"column:generation;not null;default:''"`
	// Version is bumped on every write. Writers compare-and-swap on it so two
	// management replicas cannot both act on the same refresh token.
	Version int64 `gorm:"column:version"`
	// RefreshLeaseUntil is set by the replica currently refreshing the login;
	// others wait for it instead of presenting the same refresh token.
	RefreshLeaseUntil *time.Time `gorm:"column:refresh_lease_until"`

	CreatedAt       time.Time
	UpdatedAt       time.Time
	LastRefreshedAt *time.Time `gorm:"column:last_refreshed_at"`
}

// TableName keeps the rows in their own table.
func (ProviderCredential) TableName() string { return "agent_network_provider_credentials" }

// Copy returns a deep copy.
func (c *ProviderCredential) Copy() *ProviderCredential {
	clone := *c
	if c.RefreshLeaseUntil != nil {
		t := *c.RefreshLeaseUntil
		clone.RefreshLeaseUntil = &t
	}
	if c.LastRefreshedAt != nil {
		t := *c.LastRefreshedAt
		clone.LastRefreshedAt = &t
	}
	return &clone
}

// AccessValidFor reports whether the access token is usable for at least d.
func (c *ProviderCredential) AccessValidFor(now time.Time, d time.Duration) bool {
	return c.Status == CredentialActive && c.AccessToken != "" && c.AccessExpiresAt.After(now.Add(d))
}

// EncryptSensitiveData encrypts the tokens in place. It refuses to proceed
// without an encryptor.
func (c *ProviderCredential) EncryptSensitiveData(enc *crypt.FieldEncrypt) error {
	if enc == nil {
		return ErrCredentialEncryptionUnavailable
	}
	for _, f := range []*string{&c.RefreshToken, &c.AccessToken} {
		if *f == "" {
			continue
		}
		encrypted, err := enc.Encrypt(*f)
		if err != nil {
			return fmt.Errorf("encrypt agent network provider credential: %w", err)
		}
		*f = encrypted
	}
	return nil
}

// DecryptSensitiveData decrypts the tokens in place. It refuses to proceed
// without an encryptor.
func (c *ProviderCredential) DecryptSensitiveData(enc *crypt.FieldEncrypt) error {
	if enc == nil {
		return ErrCredentialEncryptionUnavailable
	}
	for _, f := range []*string{&c.RefreshToken, &c.AccessToken} {
		if *f == "" {
			continue
		}
		decrypted, err := enc.Decrypt(*f)
		if err != nil {
			return fmt.Errorf("decrypt agent network provider credential: %w", err)
		}
		*f = decrypted
	}
	return nil
}
