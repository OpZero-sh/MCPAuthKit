# API Reference

All endpoints served from the AuthKit Worker root URL.

---

## Discovery

### `GET /.well-known/oauth-authorization-server`

Authorization Server Metadata per [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414).

```json
{
  "issuer": "https://authkit.example.com",
  "authorization_endpoint": "https://authkit.example.com/oauth/authorize",
  "token_endpoint": "https://authkit.example.com/oauth/token",
  "registration_endpoint": "https://authkit.example.com/oauth/register",
  "revocation_endpoint": "https://authkit.example.com/oauth/revoke",
  "userinfo_endpoint": "https://authkit.example.com/oauth/userinfo",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
  "scopes_supported": ["openid", "profile", "email", "mcp:tools", "mcp:deploy", "mcp:read", "mcp:write"],
  "subject_types_supported": ["public"]
}
```

All endpoint URLs auto-derive from the Worker hostname.

### `GET /prm/:server_id`

Auto-generated Protected Resource Metadata ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)) for a registered MCP server.

```json
{
  "resource": "https://your-mcp-server.com/mcp",
  "authorization_servers": ["https://authkit.example.com"],
  "scopes_supported": ["mcp:tools"],
  "bearer_methods_supported": ["header"]
}
```

---

## Dynamic Client Registration

### `POST /oauth/register`

Registers an OAuth client per [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591). MCP clients call this automatically.

**Request:**
```json
{
  "client_name": "Claude MCP Client",
  "redirect_uris": ["https://claude.ai/api/mcp/oauth/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

**Response:**
```json
{
  "client_id": "cid_abc123...",
  "client_name": "Claude MCP Client",
  "redirect_uris": ["https://claude.ai/api/mcp/oauth/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

No authentication required — public client registration per spec.

---

## Authorization

### `GET /oauth/authorize`

Renders consent screen. MCP clients redirect users here.

| Param | Required | Description |
|---|---|---|
| `response_type` | ✅ | Must be `code` |
| `client_id` | ✅ | From DCR |
| `redirect_uri` | ✅ | Must match registered URI |
| `scope` | ✅ | Space-separated |
| `state` | ✅ | CSRF protection |
| `code_challenge` | ✅ | Base64url S256 challenge |
| `code_challenge_method` | ✅ | Must be `S256` |

### `POST /oauth/authorize`

Processes consent form (login/signup + approve). On success, redirects to `redirect_uri?code=code_xxx&state=xxx`.

---

## Token Exchange

### `POST /oauth/token`

#### Authorization Code → Tokens

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=code_xxx
&redirect_uri=https://callback.example.com
&client_id=cid_abc123
&code_verifier=YOUR_PKCE_VERIFIER
```

**Response:**
```json
{
  "access_token": "mat_abc123...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "mrt_xyz789...",
  "scope": "mcp:tools"
}
```

#### Refresh → New Access Token

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=mrt_xyz789
&client_id=cid_abc123
```

PKCE with S256 is **required**. Plain challenges rejected.

---

## Token Operations

### `POST /oauth/revoke`

```
POST /oauth/revoke
Content-Type: application/x-www-form-urlencoded

token=mat_abc123&client_id=cid_abc123
```

Always returns `200 OK` per RFC 7009.

### `GET /oauth/userinfo`

**This is the endpoint your MCP server calls to validate tokens.**

```bash
curl https://authkit.example.com/oauth/userinfo \
  -H "Authorization: Bearer mat_abc123..."
```

```json
{
  "sub": "usr_abc123...",
  "email": "user@example.com",
  "name": "User Name"
}
```

Returns `401` for missing, invalid, expired, or revoked tokens.

---

## Admin API

### `POST /api/servers`

Register an MCP server. Requires `ADMIN_KEY` in Authorization header.

```json
{
  "name": "My MCP Server",
  "resource_url": "https://my-server.com/mcp",
  "scopes": ["mcp:tools", "mcp:read"],
  "owner_email": "admin@my-server.com"
}
```

**Response:**
```json
{
  "server_id": "srv_abc123...",
  "api_key": "sak_xyz789...",
  "prm_url": "https://authkit.example.com/prm/srv_abc123..."
}
```

The `api_key` is shown **once**. Store it.

### `GET /health`

```json
{ "status": "ok", "service": "mcp-authkit", "version": "0.1.0" }
```

---

## Error Format

```json
{
  "error": "error_code",
  "error_description": "Human-readable message"
}
```

| Status | Error | When |
|---|---|---|
| 400 | `invalid_request` | Missing/malformed parameters |
| 400 | `invalid_grant` | Bad code, expired, wrong PKCE |
| 400 | `unsupported_grant_type` | Not authorization_code or refresh_token |
| 401 | `invalid_token` | Expired/revoked/unknown token |
| 401 | `unauthorized` | Bad admin key |
| 404 | — | Unknown endpoint or server ID |
