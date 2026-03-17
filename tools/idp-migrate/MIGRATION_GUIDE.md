# Migrating from External IdP to Embedded IdP

This guide walks through migrating a self-hosted NetBird deployment from an external identity provider to the embedded Dex-based IdP introduced in v0.60.0.

## Overview

The migration tool does two things:

1. **Re-encodes user IDs** in the database to include the external connector ID, so Dex can route returning users to the correct external provider.
2. **Generates a new `management.json`** that replaces `IdpManagerConfig` with `EmbeddedIdP` and updates OAuth2 endpoints to the embedded Dex issuer.

After migration, existing users keep logging in through the same external provider — Dex acts as a broker in front of it. No passwords or credentials change.

---

## Before You Begin

### Prerequisites

| Requirement | Details |
|-------------|---------|
| NetBird version | `<INSERT_VERSION>` or later |
| Config access | You can read and write `management.json` |
| Server downtime | The management server **must be stopped** during migration |
| Backups | Back up your database and config before starting |

### Supported Providers

| Provider | Auto-detected | Connector type | Extra setup needed? |
|----------|:---:|----------------|---------------------|
| Auth0 | ✅ | Generic OIDC | No |
| Azure AD | ✅ | Entra | No |
| Keycloak | ✅ | Keycloak | No |
| Okta | ✅ | OIDC | No |
| Authentik | ✅ | OIDC | No |
| PocketID | ✅ | OIDC | No |
| Google | ✅ | Google | No |
| Zitadel | ❌ | Zitadel | Yes — see [Step 2](#step-2-prepare-your-provider-if-required) |
| JumpCloud | ❌ | — | No Dex connector; manual OIDC setup required |

> **Which path do I follow?**
>
> - **Auto-detected provider** → Skip Step 2 entirely. The tool reads your `management.json` and builds the connector automatically.
> - **Zitadel** → You must complete Step 2 to create an OAuth app and supply connector credentials.
> - **JumpCloud or other unsupported provider** → You must complete Step 2 to provide a custom OIDC connector.

---

## Step 1: Get the Migration Tool

**Option A — Download a pre-built binary:**

```bash
# Replace VERSION with the release tag, and adjust the architecture as needed
curl -L -o netbird-idp-migrate.tar.gz \
  https://github.com/netbirdio/netbird/releases/download/VERSION/netbird-idp-migrate_VERSION_linux_amd64.tar.gz
tar xzf netbird-idp-migrate.tar.gz
chmod +x netbird-idp-migrate
```

Available architectures: `linux_amd64`, `linux_arm64`, `linux_arm`.

**Option B — Build from source** (requires Go 1.25+ and a C compiler for CGO/SQLite):

```bash
go build -o netbird-idp-migrate ./tools/idp-migrate/
```

Copy the binary to the management server host if you built it elsewhere.

---

## Step 2: Prepare Your Provider (if required)

> **Auto-detected providers (Auth0, Azure AD, Keycloak, Okta, Authentik, PocketID, Google):** Skip this step — proceed to [Step 3](#step-3-stop-the-management-server).

### Zitadel

Zitadel requires manual connector setup because the management server's service account credentials cannot be reused as OAuth client credentials for the Dex OIDC connector.

1. Open the Zitadel console at `https://<your-zitadel-domain>/ui/console`.
2. Go to **Projects** → select the NetBird project → **Applications**.
3. Click **New** and create an application:
   - **Name:** `netbird-dex`
   - **Type:** Web
   - **Authentication Method:** Code
4. Set the redirect URI to `https://<your-management-domain>/oauth2/callback`.
5. Save and copy the **Client ID** and **Client Secret**.
6. Under **Token Settings**, enable both:
   - ✅ User roles inside ID token
   - ✅ User Info inside ID token
7. Create a `connector.json` file:

   ```json
   {
     "type": "zitadel",
     "name": "zitadel",
     "id": "zitadel",
     "config": {
       "issuer": "https://<your-zitadel-domain>",
       "clientID": "<client-id>",
       "clientSecret": "<client-secret>",
       "redirectURI": "https://<your-management-domain>/oauth2/callback"
     }
   }
   ```

You will pass this file in Step 5 with the `--idp-seed-info` flag.

See also: [Zitadel setup guide](https://docs.netbird.io/selfhosted/identity-providers/zitadel).

### Custom / Unsupported Provider (JumpCloud, etc.)

For providers without built-in detection, create a generic OIDC `connector.json`:

```json
{
  "type": "oidc",
  "name": "My Provider",
  "id": "my-provider",
  "config": {
    "issuer": "https://idp.example.com",
    "clientID": "my-client-id",
    "clientSecret": "my-client-secret",
    "redirectURI": "https://<your-management-domain>/oauth2/callback"
  }
}
```

You will pass this file in Step 5 with the `--idp-seed-info` flag.

---

## Step 3: Stop the Management Server

<details>
<summary><strong>Systemd / bare-metal</strong></summary>

```bash
sudo systemctl stop netbird-management
```
</details>

<details>
<summary><strong>Docker Compose</strong></summary>

```bash
docker compose stop management
```
</details>

---

## Step 4: Back Up Your Data

The tool creates `management.json.bak` automatically, but always make your own backups.

<details>
<summary><strong>Systemd / bare-metal (SQLite)</strong></summary>

```bash
cp /var/lib/netbird/store.db /var/lib/netbird/store.db.bak
cp /etc/netbird/management.json /etc/netbird/management.json.bak
```
</details>

<details>
<summary><strong>Docker Compose (SQLite in a named volume)</strong></summary>

Find the volume and its host path:

```bash
# Identify the volume name
VOLUME_NAME=$(docker volume ls --format '{{ .Name }}' | grep -i management)
echo "Volume: $VOLUME_NAME"

# Get the host path
VOLUME_PATH=$(docker volume inspect "$VOLUME_NAME" --format '{{ .Mountpoint }}')
echo "Path: $VOLUME_PATH"

# Verify store.db exists, then back up
sudo ls "$VOLUME_PATH/store.db"
sudo cp "$VOLUME_PATH/store.db" "$VOLUME_PATH/store.db.bak"
cp ~/netbird/management.json ~/netbird/management.json.bak
```
</details>

<details>
<summary><strong>PostgreSQL</strong></summary>

```bash
pg_dump -h <host> -U <user> -d <database> -f netbird-backup.sql
cp /etc/netbird/management.json /etc/netbird/management.json.bak
```
</details>

---

## Step 5: Run the Migration

### 5a. Dry run (always do this first)

This previews what will happen without writing any changes.

**Auto-detected providers:**

```bash
./netbird-idp-migrate \
  --config /etc/netbird/management.json \
  --dry-run
```

**Zitadel / custom providers** (pass the `connector.json` from Step 2):

```bash
./netbird-idp-migrate \
  --config /etc/netbird/management.json \
  --idp-seed-info "$(base64 < connector.json)" \
  --dry-run
```

> **Docker users:** If your database is in a volume that doesn't match the `Datadir` in `management.json`, add `--datadir`:
>
> ```bash
> ./netbird-idp-migrate \
>   --config ~/netbird/management.json \
>   --datadir /var/lib/docker/volumes/<volume-name>/_data \
>   --dry-run
> ```

You should see output like:

```
INFO resolved connector: type=oidc, id=auth0, name=auth0
INFO found 12 total users: 12 pending migration, 0 already migrated
INFO [DRY RUN] would migrate user abc123 -> CgZhYmMxMjMSB3ppdGFkZWw (account: acct-1)
...
INFO [DRY RUN] migration summary: 12 users would be migrated, 0 already migrated
INFO derived domain for embedded IdP: mgmt.example.com
INFO [DRY RUN] new management.json would be:
{ ... }
```

**Verify before proceeding:**

- ✅ Connector type and ID match your provider.
- ✅ User count matches what you expect.
- ✅ Generated config has the correct domain and endpoints.

### 5b. Execute the migration

Run the same command without `--dry-run`:

```bash
# Auto-detected providers
./netbird-idp-migrate --config /etc/netbird/management.json

# Zitadel / custom providers
./netbird-idp-migrate \
  --config /etc/netbird/management.json \
  --idp-seed-info "$(base64 < connector.json)"
```

The tool will show a summary and prompt for confirmation:

```
About to migrate 12 users. This cannot be easily undone. Continue? [y/N]
```

Type `y` and press Enter.

### 5c. Review the new config

Open `/etc/netbird/management.json` and verify:

- ✅ `IdpManagerConfig` is **removed**.
- ✅ `EmbeddedIdP` is present with `"Enabled": true` and your connector in `StaticConnectors`.
- ✅ `HttpConfig.AuthIssuer` is `https://<your-domain>/oauth2`.
- ✅ `HttpConfig.AuthClientID` is `"netbird-dashboard"`.

---

## Step 6: Post-Migration Configuration

### 6a. Update your reverse proxy

The embedded Dex IdP is served under `/oauth2/`. Your reverse proxy must route this path to the management server.

<details>
<summary><strong>Caddy</strong></summary>

Add to your `Caddyfile`, inside the site block for your management domain:

```
reverse_proxy /oauth2/* management:80
```

Place it alongside existing `/api/*` and `/management.ManagementService/*` routes, then reload:

```bash
docker compose restart caddy
# or
sudo systemctl reload caddy
```
</details>

<details>
<summary><strong>Nginx</strong></summary>

```nginx
location /oauth2/ {
    proxy_pass http://management:80;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Reload nginx after adding the route.
</details>

<details>
<summary><strong>Traefik</strong></summary>

Add a route matching the `/oauth2/` path prefix, forwarding to the management service.
</details>

**Verify the route works:**

```bash
curl -s https://<your-domain>/oauth2/.well-known/openid-configuration | head -5
```

Expected: a JSON response with `"issuer": "https://<your-domain>/oauth2"`.

### 6b. Update dashboard environment

If your dashboard uses a separate `dashboard.env` or environment variables, update the OAuth settings:

```bash
# Before (external IdP)
AUTH_AUTHORITY=https://external-idp.example.com
AUTH_CLIENT_ID=old-client-id
AUTH_AUDIENCE=old-audience

# After (embedded Dex)
AUTH_AUTHORITY=https://<your-domain>/oauth2
AUTH_CLIENT_ID=netbird-dashboard
AUTH_AUDIENCE=netbird-dashboard
```

Restart the dashboard after updating.

---

## Step 7: Start and Verify

### Start the management server

```bash
# Systemd
sudo systemctl start netbird-management

# Docker Compose
docker compose up -d management
```

### Verify everything works

1. **OIDC discovery:** Open `https://<your-domain>/oauth2/.well-known/openid-configuration` — it should return valid JSON.
2. **Dashboard login:** Log in to the dashboard — you should be redirected through your external IdP as before.
3. **Data integrity:** Check that peers are visible and policies are intact.

> **Tip:** Use an incognito/private browser window or clear cookies for your first login. Stale tokens from the old IdP will fail validation.

---

## Command Reference

```
Usage: netbird-idp-migrate [flags]

Flags:
  --config string        Path to management.json (required)
  --datadir string       Override data directory from config
  --idp-seed-info string Base64-encoded connector JSON (overrides auto-detection)
  --dry-run              Preview changes without writing
  --force                Skip confirmation prompt
  --skip-config          Skip config generation (DB migration only)
  --log-level string     Log level: debug, info, warn, error (default "info")
```

---

## Advanced Scenarios

### DB-only migration (manual config editing)

Migrate user IDs in the database but skip config generation:

```bash
./netbird-idp-migrate \
  --config /etc/netbird/management.json \
  --skip-config
```

### Non-interactive (CI / scripts)

```bash
./netbird-idp-migrate \
  --config /etc/netbird/management.json \
  --force
```

---

## Troubleshooting

### "store does not support migration operations"

The store implementation is missing the required `ListUsers`/`UpdateUserID` methods. Upgrade to v0.60.0+ binaries.

### "could not determine domain"

The tool couldn't infer your management server's domain. Either set `HttpConfig.LetsEncryptDomain` in `management.json` before running, or use `--skip-config` and configure the embedded IdP section manually.

### "could not open activity store"

This is a **warning**, not an error. If `events.db` doesn't exist (e.g., fresh install), activity event migration is skipped. User ID migration in the main database still proceeds normally.

### "no connector configuration found"

No IdP configuration was detected. Provide it explicitly with `--idp-seed-info`, set the `IDP_SEED_INFO` env var, or ensure `IdpManagerConfig` is present in `management.json`.

### "zitadel auto-detection is not supported"

Zitadel's management config uses service account credentials that aren't valid OAuth client credentials. Follow the [Zitadel setup](#zitadel) in Step 2 to create a dedicated OAuth application.

### "no client secret found"

The Dex OIDC connector requires a confidential OAuth client with a client secret. If `IdpManagerConfig.ClientConfig.ClientSecret` is empty in your config, provide the connector credentials via `--idp-seed-info`.

### "Errors.App.NotFound" from Zitadel after migration

The dashboard is still redirecting to Zitadel's `/oauth/v2/` endpoint instead of the management server's `/oauth2` endpoint. Set `AUTH_AUTHORITY=https://<your-domain>/oauth2` in your dashboard environment — see [Step 6b](#6b-update-dashboard-environment).

### OIDC discovery returns 404

The `/oauth2/` path is not being routed to the management server. Add a reverse proxy route — see [Step 6a](#6a-update-your-reverse-proxy).

### "jumpcloud does not have a supported Dex connector type"

JumpCloud has no native Dex connector. Configure a generic OIDC connector manually with `--idp-seed-info` — see [Custom providers](#custom--unsupported-provider-jumpcloud-etc) in Step 2.

### "failed to create embedded IDP service: cannot disable local authentication..."

The embedded IdP didn't support `StaticConnectors` in the config until post-`<INSERT_VERSION>`. Upgrade to a version that includes this fix.

### Partial failure / re-running

The migration is **idempotent**. Already-migrated users are detected and skipped. If the tool fails partway through, fix the underlying issue and re-run — it picks up where it left off.

---

## Rolling Back

If something goes wrong after migration:

1. **Stop** the management server.
2. **Restore the database:**
   - SQLite (bare-metal): `cp /var/lib/netbird/store.db.bak /var/lib/netbird/store.db`
   - SQLite (Docker volume): `sudo cp $VOLUME_PATH/store.db.bak $VOLUME_PATH/store.db`
   - PostgreSQL: restore from your `pg_dump` backup
3. **Restore the config:** `cp /etc/netbird/management.json.bak /etc/netbird/management.json`
4. **Revert** any reverse proxy or dashboard env changes.
5. **Start** the management server.
