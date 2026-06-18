-- Migration 002 — password reset tokens
-- Apply: wrangler d1 execute mcp-authkit-db --file=migrations/002_password_reset_tokens.sql
-- Local: wrangler d1 execute mcp-authkit-db --local --file=migrations/002_password_reset_tokens.sql
--
-- Short-lived, single-use tokens backing the /auth/forgot + /auth/reset flow.
-- user_id references the canonical Neon authkit_users row (no D1 FK), the same
-- pattern as auth_codes.

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  token_hash    TEXT PRIMARY KEY,            -- SHA-256 of rst_xxx
  user_id       TEXT NOT NULL,              -- Neon authkit_users.id
  email         TEXT NOT NULL,
  expires_at    TEXT NOT NULL,              -- 1 hour from creation
  used          INTEGER DEFAULT 0,
  created_at    TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_password_reset_user ON password_reset_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_password_reset_expires ON password_reset_tokens(expires_at);
