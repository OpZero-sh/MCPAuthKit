# MCPAuthKit Operational Runbook

Ops reference for the Cloudflare Worker OAuth 2.1 gateway. Complements
`CLAUDE.md` (architecture). Read-only unless noted.

## 1. Quick reference

| Thing | Value |
|---|---|
| Production URL | `https://authkit.open0p.com` |
| D1 name | `mcp-authkit-db` |
| D1 ID | `d8c71aec-fef5-4cb4-8193-7ca389316c08` |
| User source of truth | **Neon** (`authkit_users`) — not D1 |
| Worker entrypoint | `src/worker.js` (single file) |
| Schema | `schema.sql` |

Token prefixes / TTLs:
`mat_` access 1h · `mrt_` refresh 30d · `code_` auth code 10m ·
`sak_` server API key (no expiry).

## 2. Local dev and deploy

```bash
npm install
wrangler dev        # local Worker + local D1
wrangler deploy     # push to production
wrangler tail       # stream live prod logs
```

Secrets (managed via `wrangler secret put`, not `wrangler.toml`):

```bash
wrangler secret put ADMIN_KEY    # bearer for /api/servers
wrangler secret put SALT         # password hashing salt
```

`DB` is a D1 binding in `wrangler.toml`. The Neon connection string is a
separate secret read by `getNeonSql` in `src/worker.js`.

## 3. Database schema (tables)

Full shape in `schema.sql`. One-liners:

- `oauth_clients` — clients registered via `/oauth/register`.
- `auth_codes` — short-lived PKCE codes (10 min).
- `access_tokens` — `mat_` hashes + claims (1 h).
- `refresh_tokens` — `mrt_` hashes (30 d).
- `mcp_servers` — registered servers + `sak_` keys.
- `users` — **legacy**; canonical users live in Neon `authkit_users`.

Every token table stores `token_hash`, never the raw token.

## 4. Token-hash model

Rows are keyed by `base64url(sha256(token))`. Canonical implementation at
`src/worker.js:96-102`:

```js
async function sha256(input) {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
```

Byte-identical Node one-liner:

```bash
node -e "const h=require('crypto').createHash('sha256').update('mat_xxx').digest().toString('base64'); console.log(h.replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''))"
```

Downstream services (notably codez-hub, which cross-binds this D1)
recompute the same hash. Do not change `sha256()` without a coordinated
rollout.

## 5. Look up a token -> user

Compute the hash (section 4), then query D1. Always pass `--remote` for
production — without it, you hit the local SQLite shadow.

```bash
bunx wrangler d1 execute mcp-authkit-db --remote --command \
  "SELECT client_id, user_id, scope, expires_at, revoked FROM access_tokens WHERE token_hash = '<hash>'"
```

Resolve `user_id` -> email/name via the live endpoint (token must be
unrevoked and unexpired):

```bash
curl -H "Authorization: Bearer mat_xxx" https://authkit.open0p.com/oauth/userinfo
```

Refresh-token variant: same query, swap `access_tokens` for
`refresh_tokens`.

## 6. Revoke a token

RFC 7009 endpoint; works for both `mat_` and `mrt_`:

```bash
curl -sS -X POST https://authkit.open0p.com/oauth/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=mat_xxx&client_id=cid_xxx" -w "\nHTTP %{http_code}\n"
```

Verify in D1 (expect `revoked = 1`):

```bash
bunx wrangler d1 execute mcp-authkit-db --remote --command \
  "SELECT revoked, expires_at FROM access_tokens WHERE token_hash = '<hash>'"
```

Bulk-revoke everything for a user:

```bash
bunx wrangler d1 execute mcp-authkit-db --remote --command \
  "UPDATE access_tokens SET revoked = 1 WHERE user_id = '<user_id>'"
bunx wrangler d1 execute mcp-authkit-db --remote --command \
  "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = '<user_id>'"
```

## 7. Headless OAuth login (PKCE) — scripted

For service accounts, CI, smoke tests. `/oauth/authorize` POST accepts
form-encoded credentials and returns a 302 with `?code=` in `Location`;
follow the redirect manually to extract the code.

Sequence: (1) `POST /oauth/register` -> `client_id`, `redirect_uris`;
(2) generate PKCE verifier + `code_challenge` (S256);
(3) `POST /oauth/authorize` with `response_type=code`, `client_id`,
`redirect_uri`, `scope`, `state`, `code_challenge`,
`code_challenge_method=S256`, `action=approve`, `email`, `password` —
do NOT auto-follow the 302; parse `Location` for `?code=`;
(4) `POST /oauth/token` with `grant_type=authorization_code`, `code`,
`client_id`, `redirect_uri`, `code_verifier`.

```bash
# Step 3 — no -L; we need the raw Location header
curl -sS -D - -o /dev/null -X POST https://authkit.open0p.com/oauth/authorize \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "redirect_uri=$REDIRECT_URI" \
  --data-urlencode "scope=openid profile email" \
  --data-urlencode "state=xyz" \
  --data-urlencode "code_challenge=$CHALLENGE" \
  --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "action=approve" \
  --data-urlencode "email=$EMAIL" \
  --data-urlencode "password=$PASSWORD" | grep -i '^location:'

# Step 4 — exchange the code
curl -sS -X POST https://authkit.open0p.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "redirect_uri=$REDIRECT_URI" \
  --data-urlencode "code_verifier=$VERIFIER"
```

Reference implementation: `server/hub-auth.ts` in the CodeZero repo.

**Warning.** This flow requires the user's **plaintext password**. Fine
for scripted test accounts and dev; unacceptable for real end-users.

## 8. Inspecting accounts (Neon, not D1)

Canonical user rows live in the Neon table `authkit_users`. The D1
binding does NOT reach Neon — `wrangler d1 execute` cannot query user
records. Use psql, the Neon console, or the Neon MCP. The D1 `users`
table is legacy; do not rely on it.

## 9. Stray-account cleanup

Symptoms: an `@opzero.local` or otherwise unexpected account in
`/oauth/userinfo` or `access_tokens.user_id`. Example:
`opz-hub-agent@opzero.local` surfaced in production and should not have
existed.

Procedure: (1) identify `user_id` from `/oauth/userinfo` or an
`access_tokens` row; (2) bulk-revoke D1 tokens (section 6);
(3) delete the Neon row: `DELETE FROM authkit_users WHERE id = '<user_id>';`
(4) sanity-check no auth codes are still pending:

```bash
bunx wrangler d1 execute mcp-authkit-db --remote --command \
  "SELECT code_hash, expires_at FROM auth_codes WHERE user_id = '<user_id>'"
```

Revoking D1 tokens without deleting the Neon row leaves the account able
to log in again and mint fresh tokens — do both.

## 10. Common diagnostic queries

```bash
# Expired but not-yet-revoked access tokens (GC candidates)
bunx wrangler d1 execute mcp-authkit-db --remote --command \
  "SELECT COUNT(*) FROM access_tokens WHERE expires_at < strftime('%s','now') AND revoked = 0"

# Active access tokens per client
bunx wrangler d1 execute mcp-authkit-db --remote --command \
  "SELECT client_id, COUNT(*) AS n FROM access_tokens WHERE revoked = 0 AND expires_at > strftime('%s','now') GROUP BY client_id ORDER BY n DESC"

# Active refresh tokens per user
bunx wrangler d1 execute mcp-authkit-db --remote --command \
  "SELECT user_id, COUNT(*) AS n FROM refresh_tokens WHERE revoked = 0 AND expires_at > strftime('%s','now') GROUP BY user_id ORDER BY n DESC"

# Newest registered clients
bunx wrangler d1 execute mcp-authkit-db --remote --command \
  "SELECT client_id, client_name, created_at FROM oauth_clients ORDER BY created_at DESC LIMIT 20"
```

If `expires_at` is stored as ISO-8601 rather than a unix epoch in a given
table, swap `strftime('%s','now')` for `datetime('now')`. Check
`schema.sql` when unsure.
