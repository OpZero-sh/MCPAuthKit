# Integration Guide

How to wire your MCP server to use AuthKit for OAuth. Total integration is ~30 lines of code regardless of framework.

## Overview

Your MCP server needs three things:

1. **A PRM route** — tells clients where to authenticate
2. **A proper 401** — with the `WWW-Authenticate` discovery header
3. **Token validation** — one `fetch` call to AuthKit's `/oauth/userinfo`

No OAuth libraries. No JWT verification. No PKCE. No consent screens.

---

## Step 1: Register Your Server with AuthKit

```bash
curl -X POST https://your-authkit-instance.com/api/servers \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My MCP Server",
    "resource_url": "https://my-server.com/mcp",
    "scopes": ["mcp:tools", "mcp:read"]
  }'
```

Save the response:
```json
{
  "server_id": "srv_abc123...",
  "api_key": "sak_xyz789...",
  "prm_url": "https://your-authkit-instance.com/prm/srv_abc123..."
}
```

## Step 2: Serve Protected Resource Metadata

Add `/.well-known/oauth-protected-resource` to your server's root domain.

### Next.js (App Router)

```typescript
// app/.well-known/oauth-protected-resource/route.ts
import { NextResponse } from "next/server";

const AUTHKIT_URL = process.env.AUTHKIT_URL || "https://your-authkit-instance.com";

export async function GET() {
  return NextResponse.json(
    {
      resource: "https://my-server.com/mcp",
      authorization_servers: [AUTHKIT_URL],
      scopes_supported: ["mcp:tools", "mcp:read"],
      bearer_methods_supported: ["header"],
    },
    {
      headers: {
        "Cache-Control": "public, max-age=3600",
        "Access-Control-Allow-Origin": "*",
      },
    }
  );
}
```

### Express

```javascript
app.get("/.well-known/oauth-protected-resource", (req, res) => {
  res.set("Cache-Control", "public, max-age=3600");
  res.set("Access-Control-Allow-Origin", "*");
  res.json({
    resource: "https://my-server.com/mcp",
    authorization_servers: [process.env.AUTHKIT_URL],
    scopes_supported: ["mcp:tools", "mcp:read"],
    bearer_methods_supported: ["header"],
  });
});
```

### Cloudflare Worker

```javascript
if (url.pathname === "/.well-known/oauth-protected-resource") {
  return Response.json({
    resource: "https://my-server.com/mcp",
    authorization_servers: [env.AUTHKIT_URL],
    scopes_supported: ["mcp:tools", "mcp:read"],
    bearer_methods_supported: ["header"],
  }, {
    headers: {
      "Cache-Control": "public, max-age=3600",
      "Access-Control-Allow-Origin": "*",
    },
  });
}
```

## Step 3: Return 401 with Discovery Header

When your MCP endpoint receives a request without a valid token:

```javascript
return new Response(
  JSON.stringify({
    jsonrpc: "2.0",
    id: null,
    error: { code: -32001, message: "Unauthorized: Bearer token required" },
  }),
  {
    status: 401,
    headers: {
      "Content-Type": "application/json",
      "WWW-Authenticate": 'Bearer resource_metadata="https://my-server.com/.well-known/oauth-protected-resource"',
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Expose-Headers": "WWW-Authenticate",
    },
  }
);
```

**Critical:** The `resource_metadata` URL must point to your server's root domain PRM, not a subpath of your MCP endpoint.

## Step 4: Validate Tokens

AuthKit access tokens have the prefix `mat_`. Validate them with a single call:

```javascript
async function validateOAuthToken(token) {
  if (!token.startsWith("mat_")) return null;

  try {
    const res = await fetch(`${AUTHKIT_URL}/oauth/userinfo`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) return null;
    return await res.json(); // { sub: "usr_xxx", email: "...", name: "..." }
  } catch {
    return null;
  }
}
```

### Full Auth Check Pattern

If your server also supports API keys, stack the checks:

```javascript
async function authenticate(request) {
  const header = request.headers.get("Authorization");
  const token = header?.replace("Bearer ", "");

  if (!token) return null;

  // API key path (your existing logic)
  if (token.startsWith("wcd_")) {
    return await validateApiKey(token);
  }

  // OAuth path (AuthKit)
  if (token.startsWith("mat_")) {
    return await validateOAuthToken(token);
  }

  return null;
}
```

## Step 5: Map Users (If Needed)

AuthKit maintains its own user table. When an OAuth user hits your server for the first time, you may want to find-or-create them in your database:

```javascript
async function getOrCreateUser(authKitUser) {
  // authKitUser = { sub: "usr_xxx", email: "user@example.com", name: "Name" }
  let user = await db.getUserByEmail(authKitUser.email);

  if (!user) {
    user = await db.createUser({
      email: authKitUser.email,
      name: authKitUser.name,
      authProvider: "authkit",
      authProviderId: authKitUser.sub,
    });
  }

  return user;
}
```

---

## Performance Notes

**Token validation latency:** The `/oauth/userinfo` call adds one round trip per request. In practice this is ~5-15ms since AuthKit runs on Cloudflare's edge in 300+ cities. If you need to minimize this:

- Cache `/oauth/userinfo` responses for 5 minutes keyed by token hash
- Access tokens are valid for 1 hour, so aggressive caching is safe
- Don't verify JWT signatures — you don't have JWTs, just opaque tokens

## Common Pitfalls

| Problem | Cause | Fix |
|---|---|---|
| Claude says "couldn't connect" | PRM returns 404 | Make sure `/.well-known/oauth-protected-resource` exists at root |
| Redirect loop | `authorization_servers` URL has trailing newline | Check env vars for `\n` characters |
| CORS errors in browser | Missing headers on PRM | Add `Access-Control-Allow-Origin: *` |
| "Invalid redirect_uri" | DCR registered wrong callback | AuthKit accepts any redirect_uri by default |
| Token works then stops | Access token expired (1hr) | Client should use refresh token flow |

## If You Previously Had OAuth In Your Server

If you're migrating from a custom OAuth implementation:

1. Add the PRM route (Step 2)
2. Redirect `/.well-known/oauth-authorization-server` to AuthKit's metadata with a `308`
3. Update token validation (Step 4)
4. Verify the 401 header points to the new PRM
5. **Test end-to-end before deleting old code**
6. Delete old OAuth routes, consent pages, PKCE utils, JWT signing code
