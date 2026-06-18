# CLAUDE.md — MCP AuthKit (Cloudflare)

## What this repo is

OAuth 2.1 gateway for MCP servers, deployed on Cloudflare Workers with D1 (SQLite) as the database. This is the Cloudflare-hosted variant — the Vercel variant lives in `mcp-authkit-vercel`.

**Production URL**: https://auth.opzero.sh

## Production status

This is a **production auth system**. OpZero.sh and all MCP clients authenticate through this. Breaking changes break all auth flows. Always:
- Work on a feature branch, never push directly to `main`
- Test locally with `wrangler dev` before deploying
- Deploy with `wrangler deploy` only after verification

## Build & run

```bash
npm install                      # install deps
wrangler dev                     # local dev server (uses local D1)
wrangler deploy                  # deploy to Cloudflare Workers
wrangler tail                    # tail production logs
```

## Environment variables

Managed via Cloudflare dashboard and `wrangler secret`:

```bash
wrangler secret put ADMIN_KEY    # admin API key for server registration
wrangler secret put SALT         # password hashing salt
```

| Variable | Where | Description |
|----------|-------|-------------|
| `SALT` | `wrangler.toml` [vars] | Password hashing salt |
| `ADMIN_KEY` | Cloudflare secret | Bearer token for admin endpoints |
| `DB` | D1 binding | Cloudflare D1 database (`mcp-authkit-db`) |

**D1 Database ID**: `d8c71aec-fef5-4cb4-8193-7ca389316c08`

**Neon dependency**: Auth codes reference `user_id` from Neon `authkit_users` table (no D1 foreign key). The `users` table in D1 is legacy — canonical users live in Neon.

## Database

Cloudflare D1 (SQLite). Schema in `schema.sql`.

```bash
wrangler d1 execute mcp-authkit-db --file=schema.sql           # init remote
wrangler d1 execute mcp-authkit-db --local --file=schema.sql   # init local
```

**Tables**: `mcp_servers`, `users`, `oauth_clients`, `auth_codes`, `access_tokens`, `refresh_tokens`

## Source structure

```
src/worker.js          # Single-file Worker — all OAuth endpoints + consent UI
schema.sql             # D1 database schema
scripts/test-flow.sh   # Manual OAuth flow test script
migrations/            # D1 migrations
```

## OAuth flow

Same spec as the Vercel variant — RFC 8414, RFC 7591, PKCE S256.

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/.well-known/oauth-authorization-server` | GET | Discovery metadata |
| `/oauth/register` | POST | Dynamic client registration |
| `/oauth/authorize` | GET/POST | Consent screen |
| `/oauth/token` | POST | PKCE token exchange |
| `/oauth/revoke` | POST | Token revocation |
| `/oauth/userinfo` | GET | User info (Bearer auth) |
| `/api/servers` | GET/POST | Register/list MCP servers (Admin auth) |
| `/prm/:server_id` | GET | Protected Resource Metadata |

**Token prefixes**: `mat_` (access, 1hr), `mrt_` (refresh, 30d), `code_` (auth code, 10min), `sak_` (server API key)

## Testing

```bash
# Run the full OAuth flow test
bash scripts/test-flow.sh

# Manual checks:
# 1. Health / metadata
curl https://auth.opzero.sh/.well-known/oauth-authorization-server

# 2. Register test client
curl -X POST https://auth.opzero.sh/oauth/register \
  -H "Content-Type: application/json" \
  -d '{"redirect_uris":["http://localhost:3000/callback"],"client_name":"test"}'

# 3. List servers (admin)
curl https://auth.opzero.sh/api/servers \
  -H "Authorization: Bearer $ADMIN_KEY"

# 4. Tail production logs for debugging
wrangler tail
```

## Related repos

- **mcp-authkit-vercel** (`~/opzero-sh/mcp-authkit-vercel`) — Vercel Edge variant (Turso DB)
- **OpZero.sh** (`~/opzero-sh/OpZero.sh`) — Main consumer; uses `AUTHKIT_CLIENT_ID` pointing to this
- **Infra** (`~/opzero-sh/Infra`) — References this as a production system in repos.json
