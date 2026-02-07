# 🔐 MCP AuthKit

**OAuth for MCP servers, solved.**

[AuthKit.open0p.com](https://authkit.open0p.com)

A standalone Cloudflare Worker that implements the complete MCP OAuth specification so you don't have to. Built by [OpZero.sh](https://opzero.sh) to solve our own OAuth nightmare — now open for anyone to learn from.

> **Status:** Running in production at `authkit.open0p.com`, powering OAuth for [OpZero.sh](https://opzero.sh).

-----

## The Problem

Every MCP server builder hits the same wall: the OAuth spec is *brutal*. You need RFC 9728 discovery, RFC 8414 metadata, RFC 7591 dynamic client registration, PKCE with S256, consent screens, token lifecycle management — all before your first tool call works.

We spent weeks fighting this in a Next.js codebase before realizing: **OAuth is not your product. Rip it out.**

## The Solution

AuthKit is a single Cloudflare Worker (~600 lines) + D1 database that acts as a complete OAuth authorization server for any MCP server. Your MCP server points its `authorization_servers` to AuthKit, and the entire OAuth dance — registration, consent, tokens — happens here.

Your MCP server's only job: validate the Bearer token.

```json
// Your MCP server's /.well-known/oauth-protected-resource
{
  "resource": "https://your-mcp-server.com/mcp",
  "authorization_servers": ["https://your-authkit-instance.com"],
  "bearer_methods_supported": ["header"]
}
```

That's the entire integration.

## What It Implements

|Spec                                              |What                               |Status                     |
|--------------------------------------------------|-----------------------------------|---------------------------|
|[RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)|Protected Resource Metadata        |✅ Auto-generated per server|
|[RFC 8414](https://www.rfc-editor.org/rfc/rfc8414)|Authorization Server Metadata      |✅                          |
|[RFC 7591](https://www.rfc-editor.org/rfc/rfc7591)|Dynamic Client Registration        |✅                          |
|OAuth 2.1                                         |Authorization code + PKCE (S256)   |✅                          |
|—                                                 |Token refresh                      |✅                          |
|—                                                 |Token revocation                   |✅                          |
|—                                                 |Consent screen with login/signup   |✅                          |
|—                                                 |Multi-tenant (multiple MCP servers)|✅                          |

## Architecture

```
Claude/ChatGPT          AuthKit (CF Worker + D1)       Your MCP Server
     │                           │                           │
     │  POST /mcp (no token)     │                           │
     │──────────────────────────────────────────────────────►│
     │  401 + WWW-Authenticate   │                           │
     │◄──────────────────────────────────────────────────────│
     │                           │                           │
     │  GET /.well-known/oauth-protected-resource            │
     │──────────────────────────────────────────────────────►│
     │  { authorization_servers: ["https://authkit..."] }    │
     │◄──────────────────────────────────────────────────────│
     │                           │                           │
     │  GET /.well-known/oauth-authorization-server          │
     │─────────────────────────►│                           │
     │  { endpoints... }        │                           │
     │◄─────────────────────────│                           │
     │                           │                           │
     │  POST /oauth/register     │                           │
     │─────────────────────────►│                           │
     │  { client_id }           │                           │
     │◄─────────────────────────│                           │
     │                           │                           │
     │  GET /oauth/authorize     │                           │
     │─────────────────────────►│                           │
     │  [consent screen]        │                           │
     │◄─────────────────────────│                           │
     │  [user approves]         │                           │
     │─────────────────────────►│                           │
     │  302 → callback?code=xxx │                           │
     │◄─────────────────────────│                           │
     │                           │                           │
     │  POST /oauth/token        │                           │
     │─────────────────────────►│                           │
     │  { access_token, ... }   │                           │
     │◄─────────────────────────│                           │
     │                           │                           │
     │  POST /mcp (Bearer mat_xxx)                           │
     │──────────────────────────────────────────────────────►│
     │                           │  GET /oauth/userinfo      │
     │                           │◄──────────────────────────│
     │                           │  { sub, email, name }     │
     │                           │─────────────────────────►│
     │  [tools response]         │                           │
     │◄──────────────────────────────────────────────────────│
```

## Quick Start

### Prerequisites

- [Cloudflare account](https://dash.cloudflare.com/sign-up) (free tier works)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/)
- Node.js 18+

### Deploy

```bash
git clone https://github.com/opzero-sh/mcp-authkit.git
cd mcp-authkit

# Install dependencies
npm install

# Create the D1 database
wrangler d1 create mcp-authkit-db

# Update wrangler.toml with your database_id from the output above

# Initialize the schema
wrangler d1 execute mcp-authkit-db --file=schema.sql

# Set your admin secret (used to register MCP servers)
wrangler secret put ADMIN_KEY
# → enter a strong random string

# Deploy
wrangler deploy
```

Your AuthKit instance is live at `https://mcp-authkit.<your-subdomain>.workers.dev`.

### Register Your MCP Server

```bash
curl -X POST https://your-authkit.workers.dev/api/servers \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My MCP Server",
    "resource_url": "https://my-mcp.com/mcp",
    "scopes": ["mcp:tools"]
  }'
```

Response:

```json
{
  "server_id": "srv_abc123...",
  "api_key": "sak_xyz789...",
  "prm_url": "https://your-authkit.workers.dev/prm/srv_abc123...",
  "message": "Set authorization_servers in your PRM to point to this gateway."
}
```

### Wire Up Your MCP Server

See [Integration Guide →](docs/integration.md)

## API Reference

|Method|Endpoint                                 |Description                    |
|------|-----------------------------------------|-------------------------------|
|`GET` |`/.well-known/oauth-authorization-server`|Authorization server metadata  |
|`POST`|`/oauth/register`                        |Dynamic client registration    |
|`GET` |`/oauth/authorize`                       |Authorization + consent UI     |
|`POST`|`/oauth/token`                           |Code → token exchange (PKCE)   |
|`POST`|`/oauth/revoke`                          |Token revocation               |
|`GET` |`/oauth/userinfo`                        |User info from access token    |
|`GET` |`/prm/:server_id`                        |Auto-generated PRM for a server|
|`POST`|`/api/servers`                           |Register an MCP server (admin) |
|`GET` |`/health`                                |Health check                   |

See [API Reference →](docs/api.md)

## Token Format

|Type          |Prefix |Lifetime  |Example          |
|--------------|-------|----------|-----------------|
|Access token  |`mat_` |1 hour    |`mat_dhcbqsgb...`|
|Refresh token |`mrt_` |30 days   |`mrt_ydqd0ug1...`|
|Auth code     |`code_`|10 minutes|`code_zkm6ukm...`|
|Server API key|`sak_` |Permanent |`sak_6rvstdl7...`|

All tokens are hashed (SHA-256) before storage. The plaintext is only returned once at creation.

## Project Structure

```
mcp-authkit/
├── src/
│   └── worker.js          # The entire OAuth gateway (~600 lines)
├── docs/
│   ├── integration.md      # How to wire up your MCP server
│   ├── api.md              # Full API reference
│   ├── how-it-works.md     # Deep dive on the OAuth flow
│   ├── decisions.md        # Why we built it this way
│   └── war-story.md        # 10 attempts, every bug, the full timeline
├── scripts/
│   └── test-flow.sh        # End-to-end OAuth flow test
├── schema.sql              # D1 database schema
├── wrangler.toml           # Cloudflare Worker config
└── package.json
```

## Build Journal

This project exists because we spent **10 attempts across 5 days** trying to get MCP
OAuth working in a Next.js app with Better Auth. Trailing newlines in env vars,
boolean-vs-string consent redirects, hashed tokens compared as raw strings, missing
OPTIONS handlers, undocumented config flags — every bug manifested as "nothing happens."

The turning point was realizing OAuth is infrastructure, not product.

- [**The War Story**](docs/war-story.md) — All 10 attempts, every bug, the full timeline
- [Architecture Decisions](docs/decisions.md) — Why Cloudflare Workers, why standalone

## ⚠️ Caveats

This is a reference implementation that powers a real product. It is not:

- A maintained open source library with SLAs
- A drop-in replacement for Auth0/Stytch/Clerk
- Battle-tested at scale (it works for our traffic)

Use it to learn from, fork it, steal the patterns. If you need production auth with support, use a dedicated auth provider.

## License

[MIT](LICENSE)

## Credits

Built by [@jcameronjeff](https://x.com/devjefe) for [OpZero.sh](https://opzero.sh) — AI-native deployment infrastructure.

If this saves you the OAuth headache it saved us, consider giving [OpZero](https://opzero.sh) a look — it's the MCP deployment platform we built this for.
