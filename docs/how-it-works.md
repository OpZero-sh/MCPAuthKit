# How It Works

What happens when Claude connects to an MCP server using AuthKit, step by step.

## The Discovery Chain

MCP OAuth is a chain of HTTP requests. If any link breaks, it fails silently.

### 1. Initial Request → 401

Claude sends a `POST` to your MCP endpoint with no token. Your server responds:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://your-server.com/.well-known/oauth-protected-resource"
```

### 2. Protected Resource Metadata (RFC 9728)

Claude follows the header URL. Your server returns:

```json
{
  "resource": "https://your-server.com/mcp",
  "authorization_servers": ["https://authkit.example.com"],
  "bearer_methods_supported": ["header"]
}
```

This is the handoff to AuthKit.

### 3. Authorization Server Metadata (RFC 8414)

Claude fetches AuthKit's metadata to discover all endpoints.

### 4. Dynamic Client Registration (RFC 7591)

Claude registers itself and gets a `client_id`. This is cached for future use.

### 5. Authorization + PKCE

Claude generates a PKCE challenge and redirects the user to AuthKit's consent screen. The user logs in and approves.

### 6. Code → Tokens

AuthKit redirects back with an authorization code. Claude exchanges it for an access token (1hr) and refresh token (30d), proving the PKCE challenge.

### 7. Authenticated Request

Claude retries the MCP request with `Authorization: Bearer mat_xxx`. Your server validates it via AuthKit's `/oauth/userinfo` endpoint.

### 8. Refresh

When the access token expires, Claude uses the refresh token to get a new one without user interaction.

## Security Model

- **Tokens are hashed.** SHA-256 hashes stored, never plaintext.
- **PKCE is mandatory.** S256 only. Prevents code interception.
- **Codes are single-use.** Marked after first exchange.
- **Short-lived access tokens.** 1 hour. Refresh tokens last 30 days.
- **Password hashing.** SHA-256 + salt. (Consider upgrading to bcrypt for production.)
