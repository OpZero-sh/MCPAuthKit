<div align="center">

# MCP AuthKit

### OAuth 2.1 for MCP servers. One Worker. Five minutes.

**Every MCP server builder hits the same wall: the OAuth spec is brutal.<br>AuthKit is the other side of that wall.**

A single Cloudflare Worker + D1 database that handles the entire MCP OAuth specification --
discovery, registration, consent, tokens -- so your MCP server doesn't have to.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Cloudflare Workers](https://img.shields.io/badge/Runs_on-Cloudflare_Workers-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com)
[![OAuth 2.1](https://img.shields.io/badge/OAuth-2.1_+_PKCE-4A154B)](https://oauth.net/2.1/)
[![MCP](https://img.shields.io/badge/Protocol-MCP-8B5CF6)](https://modelcontextprotocol.io)
[![RFC 9728](https://img.shields.io/badge/RFC-9728-informational)](https://www.rfc-editor.org/rfc/rfc9728)

Running in production at [authkit.open0p.com](https://authkit.open0p.com), powering OAuth for [OpZero.sh](https://opzero.sh).

[Get Started](#quick-start) &#183; [How It Works](#how-it-works) &#183; [API Reference](#api-reference) &#183; [The War Story](#the-war-story)

</div>

---

## The Problem

You want to build an MCP server. Claude, ChatGPT, and other clients need to authenticate users with your server. The spec says: implement OAuth 2.1.

That means RFC 9728 (Protected Resource Metadata), RFC 8414 (Authorization Server Metadata), RFC 7591 (Dynamic Client Registration), PKCE with S256, consent screens, token refresh, token revocation, and multi-tenant support. All before your first tool call works.

We spent weeks fighting this. Then we ripped it out into its own service.

## The Solution

AuthKit is a standalone OAuth authorization server (~600 lines) purpose-built for MCP. Your MCP server points its `authorization_servers` to AuthKit, and the entire OAuth dance -- registration, consent, tokens -- happens here.

Your MCP server's only job: **validate the Bearer token.**

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

| Spec | What | Status |
|------|------|--------|
| [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) | Protected Resource Metadata | Auto-generated per server |
| [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) | Authorization Server Metadata | Complete |
| [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591) | Dynamic Client Registration | Complete |
| OAuth 2.1 | Authorization code + PKCE (S256) | Complete |
| -- | Token refresh (30-day TTL) | Complete |
| -- | Token revocation | Complete |
| -- | Consent screen with login/signup | Complete |
| -- | Multi-tenant (multiple MCP servers) | Complete |

## How It Works

```
Claude / ChatGPT         AuthKit (CF Worker + D1)       Your MCP Server
     |                           |                           |
     |  POST /mcp (no token)     |                           |
     |------------------------------------------------------------>|
     |  401 + WWW-Authenticate   |                           |
     |<------------------------------------------------------------|
     |                           |                           |
     |  GET /.well-known/oauth-protected-resource            |
     |------------------------------------------------------------>|
     |  { authorization_servers: ["https://authkit..."] }    |
     |<------------------------------------------------------------|
     |                           |                           |
     |  GET /.well-known/oauth-authorization-server          |
     |-------------------------->|                           |
     |  { endpoints... }        |                           |
     |<--------------------------|                           |
     |                           |                           |
     |  POST /oauth/register     |                           |
     |-------------------------->|                           |
     |  { client_id }           |                           |
     |<--------------------------|                           |
     |                           |                           |
     |  GET /oauth/authorize     |                           |
     |-------------------------->|                           |
     |  [consent screen]        |                           |
     |<--------------------------|                           |
     |  [user approves]         |                           |
     |-------------------------->|                           |
     |  302 -> callback?code=xxx|                           |
     |<--------------------------|                           |
     |                           |                           |
     |  POST /oauth/token        |                           |
     |-------------------------->|                           |
     |  { access_token, ... }   |                           |
     |<--------------------------|                           |
     |                           |                           |
     |  POST /mcp (Bearer mat_xxx)                           |
     |------------------------------------------------------------>|
     |                           |  GET /oauth/userinfo      |
     |                           |<--------------------------|
     |                           |  { sub, email, name }     |
     |                           |-------------------------->|
     |  [tools response]         |                           |
     |<------------------------------------------------------------|
```

## Quick Start

### Prerequisites

- [Cloudflare account](https://dash.cloudflare.com/sign-up) (free tier works)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/)

### Deploy

```bash
git clone https://github.com/OpZero-sh/MCPAuthKit.git
cd MCPAuthKit

npm install

# Create the D1 database
wrangler d1 create mcp-authkit-db
# Update wrangler.toml with your database_id from the output above

# Initialize the schema
wrangler d1 execute mcp-authkit-db --file=schema.sql

# Set your admin secret
wrangler secret put ADMIN_KEY
# -> enter a strong random string

# Deploy
wrangler deploy
```

Live at `https://mcp-authkit.<your-subdomain>.workers.dev`.

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

Point your server's Protected Resource Metadata at your AuthKit instance and validate tokens via the `/oauth/userinfo` endpoint. That's it.

See [Integration Guide](docs/integration.md) for the full walkthrough.

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/.well-known/oauth-authorization-server` | Authorization server metadata (RFC 8414) |
| `POST` | `/oauth/register` | Dynamic client registration (RFC 7591) |
| `GET` | `/oauth/authorize` | Authorization + consent UI |
| `POST` | `/oauth/token` | Code -> token exchange with PKCE |
| `POST` | `/oauth/revoke` | Token revocation |
| `GET` | `/oauth/userinfo` | User info from access token |
| `GET` | `/prm/:server_id` | Auto-generated Protected Resource Metadata (RFC 9728) |
| `POST` | `/api/servers` | Register an MCP server (admin) |
| `GET` | `/health` | Health check |

See [API Reference](docs/api.md) for request/response details.

## Token Format

| Type | Prefix | Lifetime | Example |
|------|--------|----------|---------|
| Access token | `mat_` | 1 hour | `mat_dhcbqsgb...` |
| Refresh token | `mrt_` | 30 days | `mrt_ydqd0ug1...` |
| Auth code | `code_` | 10 minutes | `code_zkm6ukm...` |
| Server API key | `sak_` | Permanent | `sak_6rvstdl7...` |

All tokens are hashed (SHA-256) before storage. The plaintext is only returned once at creation.

## Project Structure

```
mcp-authkit/
  src/
    worker.js              The entire OAuth gateway (~600 lines)
  docs/
    integration.md         How to wire up your MCP server
    api.md                 Full API reference
    how-it-works.md        Deep dive on the OAuth flow
    decisions.md           Why we built it this way
    war-story.md           10 attempts, every bug, the full timeline
  scripts/
    test-flow.sh           End-to-end OAuth flow test
  schema.sql               D1 database schema (7 tables)
  wrangler.toml            Cloudflare Worker config
  package.json
```

## The War Story

This project exists because we spent **10 attempts across 5 days** trying to get MCP OAuth working in a Next.js app with Better Auth. Trailing newlines in env vars, boolean-vs-string consent redirects, hashed tokens compared as raw strings, missing OPTIONS handlers, undocumented config flags -- every bug manifested as "nothing happens."

The turning point was realizing OAuth is infrastructure, not product. Rip it out.

- [**The War Story**](docs/war-story.md) -- All 10 attempts, every bug, the full timeline
- [Architecture Decisions](docs/decisions.md) -- Why Cloudflare Workers, why standalone

## Caveats

This is a reference implementation that powers a real product. It is not:

- A maintained library with SLAs
- A drop-in replacement for Auth0/Stytch/Clerk
- Battle-tested at massive scale (it works for our traffic)

Use it to learn from, fork it, steal the patterns. If you need production auth with support, use a dedicated auth provider.

## Built by OpZero

[OpZero](https://opzero.sh) is an AI-native deployment platform. Ship websites to Cloudflare, Netlify, and Vercel from any MCP client -- Claude, Cursor, or your own agents.

AuthKit is the OAuth layer that powers it. We open-sourced it because every MCP builder shouldn't have to fight the same spec.

- [opzero.sh](https://opzero.sh) -- Deploy from AI
- [UAT Engine](https://github.com/OpZero-sh/uat) -- AI-native testing over MCP (also open source)
- [@OpZero-sh](https://github.com/OpZero-sh) -- More from OpZero

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](LICENSE)

---

<div align="center">

Built by [@jcameronjeff](https://x.com/devjefe) for [OpZero.sh](https://opzero.sh)

If this saves you the OAuth headache it saved us, give [OpZero](https://opzero.sh) a look --<br>it's the deployment platform we built this for.

</div>
