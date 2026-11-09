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

ChatGPT keeps its existing device-code flow and `/backend-api/codex` route.
Neither subscription sends refresh tokens to the proxy or clients.

## Recover a login

| Symptom | Action |
| --- | --- |
| Linking returns HTTP 412 | Configure datastore encryption on management, then start again. |
| Pasted code returns HTTP 422 | Paste the complete code and state from this flow; malformed or mismatched input does not consume the flow. |
| Completion returns HTTP 404 | Confirm the same administrator and provider are being used. A consumed or missing flow requires a new login. |
| Login failed or expired | Start a new flow. A submitted valid code is never retried automatically after an uncertain exchange. |
| Login needs linking again | Relink the provider. A revoked grant, unusable refresh response, uncertain transport/server failure, or abandoned refresh lease can require fresh consent. |
| Requests report `llm_policy.credential_not_linked` | Check the provider is enabled and linked, its policies cover this caller, and the client uses the expected prefix. |

Management remains the single refresh owner through the existing database
lease and compare-and-swap version. Refresh-token rotation is saved
atomically. Do not retry a token manually, move it between records, or log
authorization codes, access tokens, or refresh tokens while diagnosing a
failure. Successful link and unlink operations use existing audit events.

Unlinking deletes management's encrypted credential. A proxy may continue
using its cached access headers for up to five minutes, and existing
in-flight requests may finish. Disable the provider to stop routing while
that cache expires. To revoke vendor-side authorization as well, remove the application's access
in the Claude account. Before rolling back to a version without Claude
support, disable or remove Claude subscription providers and their policies.

## Validation coverage

The automated suite uses fake Anthropic endpoints, real encrypted SQLite
storage, and management-to-proxy gRPC to cover PKCE binding, replay rejection,
refresh rotation and uncertain outcomes, header replacement, route isolation,
and subscription accounting. Dashboard tests cover the two login flows and
their pending, success, failure, expiry, and retry states. Deployment sign-off
also requires a human Claude login and an inference request against the live
service; fake endpoints do not establish current vendor acceptance.
