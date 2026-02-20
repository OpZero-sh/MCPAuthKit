-- Neon (PostgreSQL) migration: blog posts table
-- Run against the Neon database referenced by POSTGRES_URL
--
-- psql "$POSTGRES_URL" -f migrations/001_create_posts.sql

CREATE TABLE IF NOT EXISTS posts (
  id            TEXT PRIMARY KEY,
  slug          TEXT UNIQUE NOT NULL,
  title         TEXT NOT NULL,
  content       TEXT NOT NULL,              -- raw JSX (artifact), HTML, or markdown
  format        TEXT NOT NULL DEFAULT 'markdown'
                CHECK (format IN ('markdown', 'html', 'artifact')),
  dependencies  JSONB DEFAULT '{}',         -- e.g. {"recharts": "2.12.7"} for ESM.sh imports
  published     BOOLEAN NOT NULL DEFAULT false,
  created_at    TIMESTAMPTZ DEFAULT now(),
  updated_at    TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_posts_slug ON posts(slug);
CREATE INDEX IF NOT EXISTS idx_posts_published ON posts(published);
