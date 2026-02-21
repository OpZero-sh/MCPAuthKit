# Copilot Instructions for MCP AuthKit

## Project Overview

MCP AuthKit is a standalone OAuth 2.1 authorization server built as a **Cloudflare Worker + D1 (SQLite)** database, with user records stored in **Neon PostgreSQL**. It implements the full MCP OAuth specification so that MCP server builders don't have to, covering RFC 9728, RFC 8414, RFC 7591, PKCE (S256), token refresh/revocation, and multi-tenant support.

The entire gateway lives in a single file: `src/worker.js` (~600 lines of vanilla JavaScript — no TypeScript, no framework).

## Architecture

- **Runtime**: Cloudflare Workers (V8 isolates, Web Crypto API, `fetch` — no Node.js built-ins)
- **OAuth tables**: Cloudflare D1 (SQLite) — `mcp_servers`, `oauth_clients`, `auth_codes`, `access_tokens`, `refresh_tokens`
- **User table**: Neon PostgreSQL (`authkit_users`) — accessed via `@neondatabase/serverless`
- **Config**: `wrangler.toml` for Worker settings; secrets set via `wrangler secret put`
- **No build step**: `src/worker.js` is deployed directly with `wrangler deploy`

## Developer Workflow

```bash
npm install          # Install wrangler dev dependency
npm run dev          # Run locally with wrangler dev (port 8787)
npm run deploy       # Deploy to Cloudflare Workers
npm run db:init:local  # Initialize D1 schema locally
AUTHKIT_URL=http://localhost:8787 ADMIN_KEY=test-admin-key npm test  # End-to-end OAuth flow test
```

The test script (`scripts/test-flow.sh`) runs an end-to-end OAuth flow against a live (or local) instance using `curl` and `python3`. It requires a running Worker and valid `AUTHKIT_URL` / `ADMIN_KEY` environment variables.

## Environment / Secrets

| Name | How to set | Purpose |
|------|-----------|---------|
| `ADMIN_KEY` | `wrangler secret put ADMIN_KEY` | Protects `/api/servers` registration endpoint |
| `POSTGRES_URL` | `wrangler secret put POSTGRES_URL` | Neon connection string for user auth |
| `SALT` | `wrangler secret put SALT` | Pepper for password hashing — **must not be stored in `wrangler.toml`** in production (it is version-controlled) |

## Code Conventions

- **Plain JavaScript (ES modules)**. No TypeScript. No JSX. No transpilation.
- Use the **Web Crypto API** (`crypto.subtle`, `crypto.getRandomValues`) — never Node.js `crypto`.
- All responses must include `Cache-Control: no-store` and appropriate CORS headers (see `corsHeaders()` and `jsonResponse()` helpers).
- Token prefixes: `mat_` (access), `mrt_` (refresh), `code_` (auth code), `sak_` (server API key), `usr_` (user ID), `cid_` (client ID), `srv_` (server ID).
- All tokens are **SHA-256 hashed** before storage. Plaintext is never persisted.
- SQL runs via `env.DB.prepare(...).bind(...).first()` / `.all()` / `.run()` for D1, and via the tagged template from `neon(env.POSTGRES_URL)` for Postgres.
- Keep the single-file structure. Do not split `worker.js` into multiple modules without a strong reason.

## Key Endpoints

| Method | Path | Handler function |
|--------|------|-----------------|
| GET | `/.well-known/oauth-authorization-server` | `handleAuthServerMetadata` |
| GET | `/.well-known/openid-configuration` | `handleOpenIdCompatibilityMetadata` |
| POST | `/oauth/register` | `handleClientRegistration` |
| GET/POST | `/oauth/authorize` | `handleAuthorize` / `handleAuthorizeSubmit` |
| POST | `/oauth/token` | `handleToken` |
| POST | `/oauth/revoke` | `handleRevoke` |
| GET | `/oauth/userinfo` | `handleUserInfo` |
| GET | `/prm/:server_id` | `handlePRM` |
| POST | `/api/servers` | `handleServerRegistration` |
| GET/POST | `/auth/signup`, `/auth/login` | `handleSignup`, `handleLogin` |
| GET | `/health` | health check |

## What This Project Is (and Isn't)

This is a **reference implementation**, not a maintained library. Keep changes minimal and spec-compliant. When in doubt, check the relevant RFC. PRs that add new features or change the architecture are unlikely to be merged; bug fixes and spec-compliance issues are welcome.

## Security Considerations

- Never log or return raw tokens after initial issuance.
- Always validate `redirect_uri` against the registered list before redirecting.
- PKCE (`code_challenge` / `code_verifier` with S256) is mandatory — do not add `plain` method support.
- The `SALT` default in `wrangler.toml` must be moved to a Wrangler secret (`wrangler secret put SALT`) before production deployment — the `[vars]` block is version-controlled and should never hold secrets.
- **Password hashing uses SHA-256 (with salt) — this is a known security limitation.** SHA-256 is not a password-hashing function; production deployments should replace it with bcrypt, scrypt, or Argon2. Any PR that touches authentication code must note this limitation explicitly.
