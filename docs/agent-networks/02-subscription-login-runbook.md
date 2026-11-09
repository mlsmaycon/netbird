# Subscription login runbook

Agent Network supports provider-scoped ChatGPT and Claude subscription
logins. An administrator links once; all users and machines allowed by the
provider's policies use that plan. NetBird's signed agreement with Anthropic
permits the Claude integration and provider-wide sharing.

## Deployment

Deploy management, proxy, and dashboard versions that include
`anthropic_claude_login` together. Configure datastore field encryption before
linking. All management replicas must share the existing flow cache and
credential database. Keep the same encryption key available across replicas
and restarts. Management's normal database migration adds a credential
generation field so a refresh cannot overwrite a replaced login. Upgrade all
management replicas together; older replicas do not enforce this guard. No
protobuf migration is required.

For ChatGPT, management must reach `auth.openai.com` and the proxy must reach
`chatgpt.com`. Upgrade the dashboard and management together to offer the new
browser alternative. The catalog advertises supported flows; older callers
and dashboards keep using device authorization. Device login attempts started
before this upgrade may need to be restarted because redemption now requires
a one-time cache permit. Existing linked credentials remain usable.

Allow management HTTPS access to `platform.claude.com` for code exchanges and
refreshes. The administrator's browser uses `claude.ai` and the hosted code
page at `platform.claude.com`. The proxy forwards inference to
`api.anthropic.com` over verified TLS. The catalog pins these endpoints;
operators supply no client ID or secret. The public-client PKCE approach is
based on the selected [CLIProxyAPI reference](https://github.com/router-for-me/CLIProxyAPI/blob/681ce41b6e44c45b15b79378b003909d6ba29e68/internal/auth/claude/anthropic_auth.go)
and the hosted code callback used by
[Pi](https://github.com/earendil-works/pi/blob/2cac4f1a934cdc4a80b05a7d8ff2543cf5ee623c/packages/ai/src/auth/oauth/anthropic.ts).

## Link and verify

1. Add an enabled Anthropic provider, select **Claude**, and attach policies
   covering the intended users or machines. Review the shared-plan notice.
2. Open the authorization link, sign in to Claude, and approve access. Paste
   the complete `code#state` shown on the hosted code page into the dashboard.
   A full hosted callback URL containing code and state is also accepted.
   Management holds the PKCE verifier; it never reaches the dashboard.
3. Verify the Login column says **Linked**. A pending flow expires after
   15 minutes. Only the administrator who started it can complete it, and
   each valid submission can exchange a code once.
4. On an allowed NetBird peer, set
   `ANTHROPIC_BASE_URL=https://<endpoint>/claude-login` and use Claude Code.
   Check that requests and token usage appear for that caller. Subscription
   usage must have no API-price cost. The `/claude-login/v1/models` listing
   and `/claude-login/v1/messages/count_tokens` routes use the same login and
   caller restrictions as inference.
5. If an API-key Anthropic provider also exists, verify its clients use the
   bare endpoint URL. The subscription prefix is stripped at the proxy and
   cannot fall through to the API-key route when unlinked.

For ChatGPT, device authorization remains the default. If it is unavailable,
select **Use browser sign-in**, open the authorization link, and approve. Copy
the full `http://localhost:1455/auth/callback?...` URL from the browser's address
bar into the dashboard. A connection error on that page is expected when no
local callback listener is running; NetBird uses the pasted URL and does not
open a port. This works with self-hosted dashboards without client registration.
Only the initiating administrator can complete the attempt, and each accepted
code is exchanged once. The authorization parameters and callback-paste
approach follow [CLIProxyAPI's Codex login](https://github.com/router-for-me/CLIProxyAPI/blob/681ce41b6e44c45b15b79378b003909d6ba29e68/sdk/auth/codex.go).

Codex continues to use `/backend-api/codex`. Its native `/models` listing keeps
capability metadata while filtering known models against the caller's policies.
Verify HTTP inference and streaming with an allowed model, and rejection of a
disallowed model. Subscription routes reject WebSocket upgrades with
`llm_policy.unsupported_transport`; clients must use HTTP streaming until
per-message policy enforcement is supported. An unlinked Codex route cannot
fall through to an API-key provider. Neither subscription sends refresh tokens
to the proxy or clients.

## Recover a login

| Symptom | Action |
| --- | --- |
| Linking returns HTTP 412 | Configure datastore encryption on management, then start again. |
| Pasted code returns HTTP 422 | Paste this flow's complete Claude code and state, or ChatGPT's full localhost callback URL. Malformed or mismatched input does not consume the flow. |
| Completion returns HTTP 404 | Confirm the same administrator and provider are being used. A consumed or missing flow requires a new login. |
| Login failed or expired | Start a new flow. A submitted valid code is never retried automatically after an uncertain exchange. |
| Login needs linking again | Relink the provider. A revoked grant, unusable refresh response, uncertain transport/server failure, or abandoned refresh lease can require fresh consent. |
| Requests report `llm_policy.credential_not_linked` | Check the provider is enabled and linked, its policies cover this caller, and the client uses the expected prefix. |

Management remains the single refresh owner through the existing database
lease and compare-and-swap version. Refresh-token rotation is saved
atomically. Do not retry a token manually, move it between records, or log
authorization codes, access tokens, or refresh tokens while diagnosing a
failure. Successful link and unlink operations use existing audit events.
For OpenAI, an ambiguous response, including a failed connection or HTTP error,
requires relinking. An expired refresh lease is not reclaimed. Access-token
expiry uses `expires_in`, with a future JWT expiry accepted for older responses;
opaque tokens without a usable lifetime are rejected.

Unlinking deletes management's encrypted credential. A proxy may continue
using its cached access headers for up to five minutes, and existing
in-flight requests may finish. Disable the provider to stop routing while
that cache expires. To revoke vendor-side authorization as well, remove the application's access
in the Claude account. Before rolling back to a version without Claude
support, disable or remove Claude subscription providers and their policies.

## Validation coverage

The automated suite uses fake Anthropic and OpenAI endpoints, real encrypted SQLite
storage, and management-to-proxy gRPC to cover PKCE binding, replay rejection,
refresh rotation and uncertain outcomes, header replacement, route isolation,
device polling across replicas, and subscription accounting. Dashboard tests
cover device and browser login, switching flows, and their pending, success,
failure, expiry, and retry states. Deployment sign-off also requires human
Claude and ChatGPT logins and inference requests against the live services;
fake endpoints do not establish current vendor acceptance.
