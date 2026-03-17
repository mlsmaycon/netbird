# IdP Migration Tool — Developer Guide

## Overview

This tool migrates NetBird deployments from an external IdP (Auth0, Zitadel, Okta, etc.) to the embedded Dex IdP introduced in v0.60.0. It does two things:

1. **DB migration** — Re-encodes every user ID from `{original_id}` to Dex's protobuf-encoded format `base64(proto{original_id, connector_id})`.
2. **Config generation** — Transforms `management.json` by replacing `IdpManagerConfig` with `EmbeddedIdP` and updating `HttpConfig` fields.

## Code Layout

```
tools/idp-migrate/
├── main.go              # CLI entry point, connector resolution, config generation
├── main_test.go         # 22 tests covering all exported/internal functions
├── DEVELOPMENT.md       # this file
└── MIGRATION_GUIDE.md   # operator-facing step-by-step guide

management/server/idp/migration/
├── migration.go         # Server interface, MigrateUsersToStaticConnectors(), PopulateUserInfo(), migrateUser(), reconcileActivityStore()
├── migration_test.go    # 6 top-level tests (with subtests) using hand-written mocks
└── store.go             # Store, EventStore interfaces, SchemaCheck, RequiredSchema, SchemaError types

management/server/store/
└── sql_store_idp_migration.go   # CheckSchema(), ListUsers(), UpdateUserInfo(), UpdateUserID(), txDeferFKConstraints() on SqlStore

management/server/activity/store/
├── sql_store_idp_migration.go      # UpdateUserID() on activity Store
└── sql_store_idp_migration_test.go # 5 subtests for activity UpdateUserID

```

## Release / Distribution

The tool is included in `.goreleaser.yaml` as the `netbird-idp-migrate` build target. Each NetBird release produces pre-built archives for Linux (amd64, arm64, arm) that are uploaded to GitHub Releases. The archive naming convention is:

```
netbird-idp-migrate_<version>_linux_<arch>.tar.gz
```

The build requires `CGO_ENABLED=1` because it links the SQLite driver used by `SqlStore`. The cross-compilation setup (CC env for arm64/arm) mirrors the `netbird-mgmt` build.

## CLI Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--config` | string | *(required)* | Path to management.json |
| `--datadir` | string | `""` | Override data directory from config |
| `--idp-seed-info` | string | `""` | Base64-encoded connector JSON (overrides auto-detection) |
| `--dry-run` | bool | `false` | Preview changes without writing |
| `--force` | bool | `false` | Skip interactive confirmation prompt |
| `--skip-config` | bool | `false` | Skip config generation (DB-only migration) |
| `--skip-populate-user-info` | bool | `false` | Skip populating user info (user ID migration only) |
| `--log-level` | string | `"info"` | Log level (debug, info, warn, error) |

## Migration Flow

### Phase 0: Schema Validation

`validateSchema()` opens the store and calls `CheckSchema(RequiredSchema)` to verify that all tables and columns required by the migration exist in the database. If anything is missing, the tool exits with a descriptive error instructing the operator to start the management server (v0.60.0+) at least once so that automatic GORM migrations create the required schema.

### Phase 1: Populate User Info

Unless `--skip-populate-user-info` is set, `populateUserInfoFromIDP()` runs before connector resolution:

1. Creates an IDP manager from the existing `IdpManagerConfig` in management.json.
2. Calls `idpManager.GetAllAccounts()` to fetch email and name for all users from the external IDP.
3. Calls `migration.PopulateUserInfo()` which iterates over all store users, skipping service users and users that already have both email and name populated. For Dex-encoded user IDs, it decodes back to the original IDP ID for lookup.
4. Updates the store with any missing email/name values.

This ensures user contact info is preserved before the ID migration makes the original IDP IDs inaccessible.

### Phase 2: Connector Resolution

`resolveConnector()` uses a 3-tier priority:

1. `--idp-seed-info` flag — explicit base64-encoded connector JSON
2. `IDP_SEED_INFO` env var — same format, read via `migration.SeedConnectorFromEnv()`
3. Auto-detect from `management.json` — reads `IdpManagerConfig.ClientConfig` fields and maps `ManagerType` to a Dex connector type:

| ManagerType | Dex Connector Type | Notes |
|-------------|--------------------|----|
| `keycloak` | `keycloak` | |
| `okta` | `okta` | |
| `authentik` | `authentik` | |
| `pocketid` | `pocketid` | |
| `auth0` | `oidc` (generic) | |
| `azure` | `entra` | |
| `google` | `google` | |
| `zitadel` | **error** | Uses service account credentials — requires `--idp-seed-info` |
| `jumpcloud` | **error** | No Dex connector available |
| *(unknown)* | `oidc` (fallback) | Requires non-empty `ClientSecret` |

**Why Zitadel can't be auto-detected**: Zitadel's `IdpManagerConfig.ClientConfig` contains service account credentials (a login name like `netbird-service-account` and possibly a PAT), not OAuth client credentials. These can't be used as an OIDC connector's `clientID`/`clientSecret`. The user must create a confidential Web application in Zitadel and provide it via `--idp-seed-info`.

Additionally, `buildConnectorFromConfig` validates that `ClientSecret` is non-empty for all providers. If the secret is missing, the tool errors with instructions to use `--idp-seed-info`.

### Phase 3: DB Migration

`migrateDB()` orchestrates the database migration:

1. `openStores()` opens the main store (`SqlStore`) and activity store (non-fatal if missing).
2. Type-asserts both to `migration.Store` / `migration.EventStore`.
3. `previewUsers()` scans all users — counts pending vs already-migrated (using `DecodeDexUserID`).
4. `confirmPrompt()` asks for interactive confirmation (unless `--force` or `--dry-run`).
5. Calls `migration.MigrateUsersToStaticConnectors(srv, conn)`:
   - **Reconciliation pass**: fixes activity store references for users already migrated in the main DB but whose events still reference old IDs (from a previous partial failure).
   - **Main loop**: for each non-migrated user, calls `migrateUser()` which atomically updates the user ID in both the main store and activity store.
   - **Dry-run**: logs what would happen, skips all writes.

`SqlStore.UpdateUserID()` atomically updates the user's primary key and all foreign key references (peers, PATs, groups, policies, jobs, etc.) in a single transaction.

### Phase 4: Config Generation

Unless `--skip-config` is set, `generateConfig()` runs:

1. **Derive domain** — `deriveDomain()` priority:
   1. `HttpConfig.LetsEncryptDomain` (most explicit)
   2. Parse host from `HttpConfig.OIDCConfigEndpoint`
   3. Parse host from `HttpConfig.AuthIssuer`
   4. Parse host from `IdpManagerConfig.ClientConfig.Issuer` (last resort)

2. **Transform JSON** — reads existing config as raw JSON to preserve all fields, then:
   - Removes `IdpManagerConfig`
   - Adds `EmbeddedIdP` with the static connector, redirect URIs, etc.
   - Overrides the connector's `redirectURI` to use the derived management domain (not the IdP issuer)
   - Updates `HttpConfig`: `AuthIssuer`, `AuthAudience`, `AuthClientID`, `CLIAuthAudience`, `AuthKeysLocation`, `OIDCConfigEndpoint`, `IdpSignKeyRefreshEnabled`
   - Sets `AuthUserIDClaim` to `"sub"`
   - Generates `PKCEAuthorizationFlow` with Dex endpoints

3. **Write** — backs up original as `management.json.bak`, writes new config. In dry-run mode, prints to stdout instead.

## Interface Decoupling

Migration methods (`ListUsers`, `UpdateUserID`) are **not** on the core `store.Store` or `activity.Store` interfaces. Instead, they're defined in `migration/store.go`:

```go
type Store interface {
    ListUsers(ctx context.Context) ([]*types.User, error)
    UpdateUserID(ctx context.Context, accountID, oldUserID, newUserID string) error
    UpdateUserInfo(ctx context.Context, userID, email, name string) error
    CheckSchema(checks []SchemaCheck) []SchemaError
}

type EventStore interface {
    UpdateUserID(ctx context.Context, oldUserID, newUserID string) error
}
```

A `Server` interface wraps both stores for dependency injection:

```go
type Server interface {
    Store() Store
    EventStore() EventStore // may return nil
}
```

The concrete `SqlStore` types already have these methods (in their respective `sql_store_idp_migration.go` files), so they satisfy the interfaces via Go's structural typing — zero changes needed on the core store interfaces. At runtime, the standalone tool type-asserts:

```go
migStore, ok := mainStore.(migration.Store)
```

This keeps migration concerns completely separate from the core store contract.

## Dex User ID Encoding

`EncodeDexUserID(userID, connectorID)` produces a manually-encoded protobuf with two string fields, then base64-encodes the result (raw, no padding). `DecodeDexUserID` reverses this. The migration loop uses `DecodeDexUserID` to detect already-migrated users (decode succeeds → skip).

See `idp/dex/provider.go` for the implementation.

## Standalone Tool

The standalone tool (`tools/idp-migrate/main.go`) is the primary migration entry point. It opens stores directly, runs schema validation, populates user info from the external IDP, migrates user IDs, and generates the new config — then exits.

Previously, the combined server (`modules.go`) had a `seedIDPConnectors()` method that ran the same migration at startup via the `IDP_SEED_INFO` env var. This combined server path has been removed; migration is now handled exclusively by the standalone tool.

## Running Tests

```bash
# Migration library
go test -v ./management/server/idp/migration/...

# Standalone tool
go test -v ./tools/idp-migrate/...

# Activity store migration tests
go test -v -run TestUpdateUserID ./management/server/activity/store/...

# Build locally
go build ./tools/idp-migrate/
```

## Clean Removal

When migration tooling is no longer needed, delete:

1. `tools/idp-migrate/` — entire directory
2. `management/server/idp/migration/` — entire directory
3. `management/server/store/sql_store_idp_migration.go` — migration methods on main SqlStore
4. `management/server/activity/store/sql_store_idp_migration.go` — migration method on activity Store
5. `management/server/activity/store/sql_store_idp_migration_test.go` — tests for the above
6. In `.goreleaser.yaml`:
   - Remove the `netbird-idp-migrate` build entry
   - Remove the `netbird-idp-migrate` archive entry
7. Run `go mod tidy`

No core interfaces or mocks need editing — that's the point of the decoupling.
