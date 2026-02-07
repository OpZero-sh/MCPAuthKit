-- MCP AuthKit Database Schema
-- Cloudflare D1 (SQLite)
-- Run: wrangler d1 execute mcp-authkit-db --file=schema.sql

-----------------------------------------------------------
-- MCP servers that delegate OAuth to this gateway
-----------------------------------------------------------
CREATE TABLE IF NOT EXISTS mcp_servers (
  id              TEXT PRIMARY KEY,          -- srv_xxx
  name            TEXT NOT NULL,
  owner_email     TEXT,
  resource_url    TEXT NOT NULL,             -- The MCP server's resource URL
  callback_urls   TEXT DEFAULT '[]',         -- JSON array of allowed callbacks
  scopes          TEXT DEFAULT '["mcp:tools"]', -- JSON array of supported scopes
  api_key_hash    TEXT,                      -- SHA-256 of the sak_ key
  created_at      TEXT DEFAULT (datetime('now')),
  updated_at      TEXT DEFAULT (datetime('now'))
);

-----------------------------------------------------------
-- Users who authenticate through the consent screen
-----------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  id              TEXT PRIMARY KEY,          -- usr_xxx
  email           TEXT UNIQUE NOT NULL,
  name            TEXT,
  password_hash   TEXT,                      -- SHA-256(password + salt)
  created_at      TEXT DEFAULT (datetime('now'))
);

-----------------------------------------------------------
-- Dynamically registered OAuth clients (Claude, ChatGPT, etc.)
-----------------------------------------------------------
CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id                   TEXT PRIMARY KEY,  -- cid_xxx
  client_name                 TEXT,
  redirect_uris               TEXT NOT NULL,     -- JSON array
  grant_types                 TEXT DEFAULT '["authorization_code","refresh_token"]',
  response_types              TEXT DEFAULT '["code"]',
  token_endpoint_auth_method  TEXT DEFAULT 'none',
  server_id                   TEXT,
  created_at                  TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (server_id) REFERENCES mcp_servers(id)
);

-----------------------------------------------------------
-- Authorization codes (short-lived, single-use)
-----------------------------------------------------------
CREATE TABLE IF NOT EXISTS auth_codes (
  code_hash               TEXT PRIMARY KEY,  -- SHA-256 of code_xxx
  client_id               TEXT NOT NULL,
  user_id                 TEXT NOT NULL,
  server_id               TEXT NOT NULL,
  redirect_uri            TEXT NOT NULL,
  scope                   TEXT,
  code_challenge          TEXT,
  code_challenge_method   TEXT DEFAULT 'S256',
  expires_at              TEXT NOT NULL,      -- 10 minutes from creation
  used                    INTEGER DEFAULT 0,
  created_at              TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-----------------------------------------------------------
-- Access tokens (1 hour TTL)
-----------------------------------------------------------
CREATE TABLE IF NOT EXISTS access_tokens (
  token_hash    TEXT PRIMARY KEY,            -- SHA-256 of mat_xxx
  client_id     TEXT NOT NULL,
  user_id       TEXT NOT NULL,
  server_id     TEXT NOT NULL,
  scope         TEXT,
  expires_at    TEXT NOT NULL,
  revoked       INTEGER DEFAULT 0,
  created_at    TEXT DEFAULT (datetime('now'))
);

-----------------------------------------------------------
-- Refresh tokens (30 day TTL)
-----------------------------------------------------------
CREATE TABLE IF NOT EXISTS refresh_tokens (
  token_hash    TEXT PRIMARY KEY,            -- SHA-256 of mrt_xxx
  client_id     TEXT NOT NULL,
  user_id       TEXT NOT NULL,
  server_id     TEXT NOT NULL,
  scope         TEXT,
  expires_at    TEXT NOT NULL,
  revoked       INTEGER DEFAULT 0,
  created_at    TEXT DEFAULT (datetime('now'))
);

-----------------------------------------------------------
-- Indexes
-----------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_access_tokens_user ON access_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_access_tokens_expires ON access_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_codes_client ON auth_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON auth_codes(expires_at);
