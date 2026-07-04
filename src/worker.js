/**
 * MCP AuthKit — OAuth Gateway for MCP Servers
 *
 * A standalone Cloudflare Worker that implements the complete MCP OAuth spec:
 * - RFC 9728 Protected Resource Metadata
 * - RFC 8414 Authorization Server Metadata
 * - RFC 7591 Dynamic Client Registration
 * - OAuth 2.1 with PKCE (S256)
 * - Token refresh & revocation
 *
 * Any MCP server can point its `authorization_servers` here
 * instead of implementing OAuth from scratch.
 *
 * Users are stored in the shared Neon PostgreSQL database (authkit_users table).
 * OAuth tables (clients, tokens, codes, servers) remain in Cloudflare D1.
 */

import { neon } from '@neondatabase/serverless';

// ─── Neon (PostgreSQL) Helper ───────────────────────────────────────────────

function getNeonSql(env) {
  if (!env.POSTGRES_URL) {
    throw new Error('POSTGRES_URL secret is not configured');
  }
  return neon(env.POSTGRES_URL);
}

/**
 * Dual-write an access token to Neon so OpZero can validate it
 * via shared DB lookup without a remote call.
 * Table is auto-created if missing.
 */
async function syncAccessTokenToNeon(env, { tokenHash, clientId, userId, serverId, scope, expiresAt }) {
  try {
    const sql = getNeonSql(env);
    await sql`
      INSERT INTO authkit_access_tokens (token_hash, client_id, user_id, server_id, scope, expires_at, revoked, created_at)
      VALUES (${tokenHash}, ${clientId}, ${userId}, ${serverId}, ${scope}, ${expiresAt}, 0, ${new Date().toISOString()})
      ON CONFLICT (token_hash) DO NOTHING
    `;
  } catch (e) {
    // If table doesn't exist, create it and retry once
    if (e.message?.includes('does not exist') || e.message?.includes('relation')) {
      const sql = getNeonSql(env);
      await sql`
        CREATE TABLE IF NOT EXISTS authkit_access_tokens (
          token_hash  TEXT PRIMARY KEY,
          client_id   TEXT NOT NULL,
          user_id     TEXT NOT NULL,
          server_id   TEXT NOT NULL DEFAULT 'default',
          scope       TEXT,
          expires_at  TEXT NOT NULL,
          revoked     INTEGER DEFAULT 0,
          created_at  TEXT DEFAULT (now())
        )
      `;
      await sql`
        CREATE TABLE IF NOT EXISTS authkit_oauth_clients (
          client_id    TEXT PRIMARY KEY,
          client_name  TEXT,
          redirect_uris TEXT,
          server_id    TEXT,
          created_at   TEXT DEFAULT (now())
        )
      `;
      await sql`
        INSERT INTO authkit_access_tokens (token_hash, client_id, user_id, server_id, scope, expires_at, revoked, created_at)
        VALUES (${tokenHash}, ${clientId}, ${userId}, ${serverId}, ${scope}, ${expiresAt}, 0, ${new Date().toISOString()})
        ON CONFLICT (token_hash) DO NOTHING
      `;
    } else {
      console.error('Neon token sync failed:', e.message);
    }
  }
}

/**
 * Sync an OAuth client to Neon for OpZero's shared DB lookup.
 */
async function syncOAuthClientToNeon(env, { clientId, clientName, redirectUris, serverId }) {
  try {
    const sql = getNeonSql(env);
    await sql`
      INSERT INTO authkit_oauth_clients (client_id, client_name, redirect_uris, server_id, created_at)
      VALUES (${clientId}, ${clientName}, ${redirectUris}, ${serverId}, ${new Date().toISOString()})
      ON CONFLICT (client_id) DO UPDATE SET client_name = EXCLUDED.client_name, redirect_uris = EXCLUDED.redirect_uris
    `;
  } catch (e) {
    console.error('Neon client sync failed:', e.message);
  }
}

// ─── Crypto Helpers ──────────────────────────────────────────────────────────

async function sha256(input) {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function generateId(prefix = '', length = 32) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let result = prefix;
  const values = crypto.getRandomValues(new Uint8Array(length));
  for (const v of values) result += chars[v % chars.length];
  return result;
}

function jsonResponse(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
      ...headers,
    },
  });
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
}

// ─── Route Handler ───────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    try {
      // ── Well-Known Endpoints ──
      if (path === '/.well-known/oauth-authorization-server') {
        return handleAuthServerMetadata(url, env);
      }
      if (path === '/.well-known/openid-configuration') {
        return handleOpenIdCompatibilityMetadata(url, env);
      }
      // ── OAuth Endpoints ──
      if (path === '/oauth/register' && method === 'POST') {
        return await handleClientRegistration(request, env);
      }
      if (path === '/oauth/authorize' && method === 'GET') {
        return await handleAuthorize(request, url, env);
      }
      if (path === '/oauth/authorize' && method === 'POST') {
        return await handleAuthorizeSubmit(request, url, env);
      }
      if (path === '/oauth/token' && method === 'POST') {
        return await handleToken(request, env);
      }
      if (path === '/oauth/revoke' && method === 'POST') {
        return await handleRevoke(request, env);
      }
      if (path === '/oauth/userinfo' && method === 'GET') {
        return await handleUserInfo(request, env);
      }

      // ── Server Registration API ──
      if (path === '/api/servers' && method === 'POST') {
        return await handleRegisterServer(request, env);
      }
      if (path === '/api/servers' && method === 'GET') {
        return await handleListServers(request, env);
      }

      // ── PRM Generator (for MCP servers to use) ──
      if (path.startsWith('/prm/') && method === 'GET') {
        return await handlePRM(path, url, env);
      }

      // ── Login / Signup (minimal for MVP) ──
      if (path === '/auth/signup' && method === 'POST') {
        return await handleSignup(request, env);
      }
      if (path === '/auth/login' && method === 'POST') {
        return await handleLogin(request, env);
      }

      // ── Password Reset ──
      if (path === '/auth/forgot' && method === 'GET') {
        return new Response(getForgotFormHTML(), { headers: { 'Content-Type': 'text/html' } });
      }
      if (path === '/auth/forgot' && method === 'POST') {
        return await handleForgotPassword(request, env);
      }
      if (path === '/auth/reset' && method === 'GET') {
        return await handleResetPage(request, env);
      }
      if (path === '/auth/reset' && method === 'POST') {
        return await handleResetPassword(request, env);
      }

      // ── Health ──
      if (path === '/health') {
        return jsonResponse({ status: 'ok', service: 'mcp-authkit', version: '0.1.0' });
      }

      // ── Blog ──
      if (path.startsWith('/blog/') && method === 'GET') {
        const slug = path.replace('/blog/', '');
        if (slug) {
          return await handleBlogPost(slug, env);
        }
      }

      // ── Landing page ──
      if (path === '/') {
        return new Response(getLandingHTML(), {
          headers: { 'Content-Type': 'text/html' },
        });
      }

      return jsonResponse({ error: 'not_found', message: `No route for ${method} ${path}` }, 404);

    } catch (err) {
      console.error('Worker error:', err?.message, err?.stack);
      return jsonResponse({ error: 'server_error', message: err?.message || String(err), stack: err?.stack }, 500);
    }
  },
};

// ─── Authorization Server Metadata (RFC 8414) ───────────────────────────────

function handleAuthServerMetadata(url, env) {
  const issuer = `${url.protocol}//${url.host}`;
  return jsonResponse({
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    registration_endpoint: `${issuer}/oauth/register`,
    revocation_endpoint: `${issuer}/oauth/revoke`,
    userinfo_endpoint: `${issuer}/oauth/userinfo`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
    scopes_supported: ['openid', 'profile', 'email', 'mcp:tools', 'mcp:deploy', 'mcp:read', 'mcp:write'],
    subject_types_supported: ['public'],
  });
}

// Compatibility endpoint for clients that probe OpenID discovery first.
// Intentionally mirrors RFC 8414 metadata and does not advertise OIDC/JWKS fields.
function handleOpenIdCompatibilityMetadata(url, env) {
  return handleAuthServerMetadata(url, env);
}

// ─── Protected Resource Metadata Generator ───────────────────────────────────
// MCP servers can use /prm/{server_id} as their PRM endpoint

async function handlePRM(path, url, env) {
  const serverId = path.replace('/prm/', '');
  const server = await env.DB.prepare('SELECT * FROM mcp_servers WHERE id = ?').bind(serverId).first();
  
  if (!server) {
    return jsonResponse({ error: 'server_not_found' }, 404);
  }

  const issuer = `${url.protocol}//${url.host}`;
  return jsonResponse({
    resource: server.resource_url,
    authorization_servers: [issuer],
    scopes_supported: JSON.parse(server.scopes || '["mcp:tools"]'),
    bearer_methods_supported: ['header'],
  });
}

// ─── Dynamic Client Registration (RFC 7591) ──────────────────────────────────

async function handleClientRegistration(request, env) {
  const body = await request.json();
  
  const clientId = generateId('cid_', 24);
  const redirectUris = body.redirect_uris || [];
  
  if (!redirectUris.length) {
    return jsonResponse({ error: 'invalid_client_metadata', error_description: 'redirect_uris required' }, 400);
  }

  const clientName = body.client_name || 'Unknown Client';
  const serverId = body.server_id || null;

  await env.DB.prepare(`
    INSERT INTO oauth_clients (client_id, client_name, redirect_uris, grant_types, response_types, token_endpoint_auth_method, server_id)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).bind(
    clientId,
    clientName,
    JSON.stringify(redirectUris),
    JSON.stringify(body.grant_types || ['authorization_code', 'refresh_token']),
    JSON.stringify(body.response_types || ['code']),
    body.token_endpoint_auth_method || 'none',
    serverId
  ).run();

  // Sync to Neon for OpZero shared DB lookup
  await syncOAuthClientToNeon(env, {
    clientId, clientName, redirectUris: JSON.stringify(redirectUris), serverId,
  });

  return jsonResponse({
    client_id: clientId,
    client_name: body.client_name || 'Unknown Client',
    redirect_uris: redirectUris,
    grant_types: body.grant_types || ['authorization_code', 'refresh_token'],
    response_types: body.response_types || ['code'],
    token_endpoint_auth_method: body.token_endpoint_auth_method || 'none',
  }, 201);
}

// ─── Authorization Endpoint ──────────────────────────────────────────────────

async function handleAuthorize(request, url, env) {
  const params = url.searchParams;
  const clientId = params.get('client_id');
  const redirectUri = params.get('redirect_uri');
  const responseType = params.get('response_type');
  const scope = params.get('scope') || 'mcp:tools';
  const state = params.get('state');
  const codeChallenge = params.get('code_challenge');
  const codeChallengeMethod = params.get('code_challenge_method') || 'S256';

  // Validate client — auto-register if unknown (supports web clients that
  // skip Dynamic Client Registration, while MCP clients already register
  // via /oauth/register and will be found here as before).
  let client = await env.DB.prepare('SELECT * FROM oauth_clients WHERE client_id = ?').bind(clientId).first();
  if (!client) {
    if (!clientId || !redirectUri) {
      return jsonResponse({ error: 'invalid_client', error_description: 'client_id and redirect_uri are required' }, 400);
    }
    await env.DB.prepare(`
      INSERT OR IGNORE INTO oauth_clients (client_id, client_name, redirect_uris, grant_types, response_types, token_endpoint_auth_method, server_id)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      clientId,
      `Web Client (${clientId})`,
      JSON.stringify([redirectUri]),
      JSON.stringify(['authorization_code', 'refresh_token']),
      JSON.stringify(['code']),
      'none',
      null
    ).run();
    client = await env.DB.prepare('SELECT * FROM oauth_clients WHERE client_id = ?').bind(clientId).first();
    if (!client) {
      return jsonResponse({ error: 'server_error', error_description: 'Failed to register client' }, 500);
    }
  }

  // Validate redirect_uri
  const allowedUris = JSON.parse(client.redirect_uris);
  if (!allowedUris.includes(redirectUri)) {
    return jsonResponse({ error: 'invalid_request', error_description: 'redirect_uri not registered' }, 400);
  }

  if (responseType !== 'code') {
    return redirectWithError(redirectUri, state, 'unsupported_response_type', 'Only code is supported');
  }

  if (codeChallengeMethod !== 'S256') {
    return redirectWithError(redirectUri, state, 'invalid_request', 'Only S256 code_challenge_method is supported');
  }

  // Render consent/login page
  return new Response(getConsentHTML({
    clientName: client.client_name,
    clientId,
    redirectUri,
    scope,
    state,
    codeChallenge,
    codeChallengeMethod,
  }), {
    headers: { 'Content-Type': 'text/html' },
  });
}

async function handleAuthorizeSubmit(request, url, env) {
  const formData = await request.formData();
  const action = formData.get('action');
  const clientId = formData.get('client_id');
  const redirectUri = formData.get('redirect_uri');
  const scope = formData.get('scope');
  const state = formData.get('state');
  const codeChallenge = formData.get('code_challenge');
  const codeChallengeMethod = formData.get('code_challenge_method');
  const email = formData.get('email');
  const password = formData.get('password');
  const authMode = formData.get('auth_mode') || 'login';

  if (action === 'deny') {
    return redirectWithError(redirectUri, state, 'access_denied', 'User denied the request');
  }

  // Authenticate user against Neon (authkit_users table)
  const sql = getNeonSql(env);
  let user;
  if (authMode === 'signup') {
    const name = formData.get('name') || email.split('@')[0];
    const passwordHash = await sha256(password + (env.SALT || 'mcp-authkit-salt'));
    const userId = generateId('usr_', 20);

    try {
      await sql`INSERT INTO authkit_users (id, email, name, password_hash, created_at)
                VALUES (${userId}, ${email}, ${name}, ${passwordHash}, ${new Date().toISOString()})`;
      user = { id: userId, email, name };
    } catch (e) {
      if (e.message?.includes('unique') || e.message?.includes('duplicate')) {
        const clientRow = await env.DB.prepare('SELECT client_name FROM oauth_clients WHERE client_id = ?').bind(clientId).first();
        return new Response(getConsentHTML({
          clientName: clientRow?.client_name || 'App',
          clientId, redirectUri, scope, state, codeChallenge, codeChallengeMethod,
          error: 'Email already registered. Please log in instead.',
        }), { headers: { 'Content-Type': 'text/html' } });
      }
      throw e;
    }
  } else {
    const passwordHash = await sha256(password + (env.SALT || 'mcp-authkit-salt'));
    const rows = await sql`SELECT id, email, name FROM authkit_users
                           WHERE email = ${email} AND password_hash = ${passwordHash}`;
    user = rows[0] || null;

    if (!user) {
      const clientRow = await env.DB.prepare('SELECT client_name FROM oauth_clients WHERE client_id = ?').bind(clientId).first();
      return new Response(getConsentHTML({
        clientName: clientRow?.client_name || 'App',
        clientId, redirectUri, scope, state, codeChallenge, codeChallengeMethod,
        error: 'Invalid email or password.',
      }), { headers: { 'Content-Type': 'text/html' } });
    }
  }

  // Generate authorization code
  const code = generateId('code_', 32);
  const codeHash = await sha256(code);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString(); // 10 min

  // Get server_id from client
  const client = await env.DB.prepare('SELECT server_id FROM oauth_clients WHERE client_id = ?').bind(clientId).first();

  await env.DB.prepare(`
    INSERT INTO auth_codes (code_hash, client_id, user_id, server_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(codeHash, clientId, user.id, client?.server_id || 'default', redirectUri, scope, codeChallenge, codeChallengeMethod, expiresAt).run();

  // Redirect with code
  const redirect = new URL(redirectUri);
  redirect.searchParams.set('code', code);
  if (state) redirect.searchParams.set('state', state);

  return Response.redirect(redirect.toString(), 302);
}

// ─── Token Endpoint ──────────────────────────────────────────────────────────

async function handleToken(request, env) {
  const body = await request.formData ? await request.formData() : null;
  let params;
  
  // Handle both form-encoded and JSON bodies
  if (body && typeof body.get === 'function') {
    params = Object.fromEntries(body);
  } else {
    params = await request.json().catch(() => ({}));
  }

  const grantType = params.grant_type;

  if (grantType === 'authorization_code') {
    return handleAuthCodeExchange(params, env);
  } else if (grantType === 'refresh_token') {
    return handleRefreshToken(params, env);
  }

  return jsonResponse({ error: 'unsupported_grant_type' }, 400);
}

async function handleAuthCodeExchange(params, env) {
  const { code, client_id, redirect_uri, code_verifier } = params;

  if (!code || !client_id || !code_verifier) {
    return jsonResponse({ error: 'invalid_request', error_description: 'code, client_id, and code_verifier required' }, 400);
  }

  const codeHash = await sha256(code);
  const authCode = await env.DB.prepare('SELECT * FROM auth_codes WHERE code_hash = ? AND used = 0').bind(codeHash).first();

  if (!authCode) {
    return jsonResponse({ error: 'invalid_grant', error_description: 'Invalid or expired code' }, 400);
  }

  // Verify not expired
  if (new Date(authCode.expires_at) < new Date()) {
    return jsonResponse({ error: 'invalid_grant', error_description: 'Authorization code expired' }, 400);
  }

  // Verify client_id matches
  if (authCode.client_id !== client_id) {
    return jsonResponse({ error: 'invalid_grant', error_description: 'client_id mismatch' }, 400);
  }

  // Verify redirect_uri matches (if provided)
  if (redirect_uri && authCode.redirect_uri !== redirect_uri) {
    return jsonResponse({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' }, 400);
  }

  // Verify PKCE
  const expectedChallenge = await sha256(code_verifier);
  if (expectedChallenge !== authCode.code_challenge) {
    return jsonResponse({ error: 'invalid_grant', error_description: 'PKCE verification failed' }, 400);
  }

  // Mark code as used
  await env.DB.prepare('UPDATE auth_codes SET used = 1 WHERE code_hash = ?').bind(codeHash).run();

  // Issue tokens
  const accessToken = generateId('mat_', 40);
  const refreshToken = generateId('mrt_', 40);
  const accessTokenHash = await sha256(accessToken);
  const refreshTokenHash = await sha256(refreshToken);
  
  const accessExpiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour
  const refreshExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 days

  await env.DB.prepare(`
    INSERT INTO access_tokens (token_hash, client_id, user_id, server_id, scope, expires_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(accessTokenHash, client_id, authCode.user_id, authCode.server_id, authCode.scope, accessExpiresAt).run();

  await env.DB.prepare(`
    INSERT INTO refresh_tokens (token_hash, client_id, user_id, server_id, scope, expires_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(refreshTokenHash, client_id, authCode.user_id, authCode.server_id, authCode.scope, refreshExpiresAt).run();

  // Dual-write access token to Neon for OpZero's shared DB validation
  await syncAccessTokenToNeon(env, {
    tokenHash: accessTokenHash, clientId: client_id, userId: authCode.user_id,
    serverId: authCode.server_id, scope: authCode.scope, expiresAt: accessExpiresAt,
  });

  return jsonResponse({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    refresh_token: refreshToken,
    scope: authCode.scope,
  });
}

async function handleRefreshToken(params, env) {
  const { refresh_token, client_id } = params;

  if (!refresh_token || !client_id) {
    return jsonResponse({ error: 'invalid_request' }, 400);
  }

  const tokenHash = await sha256(refresh_token);
  const stored = await env.DB.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ? AND revoked = 0').bind(tokenHash).first();

  if (!stored || new Date(stored.expires_at) < new Date()) {
    return jsonResponse({ error: 'invalid_grant', error_description: 'Invalid or expired refresh token' }, 400);
  }

  if (stored.client_id !== client_id) {
    return jsonResponse({ error: 'invalid_grant', error_description: 'client_id mismatch' }, 400);
  }

  // Issue new access token
  const accessToken = generateId('mat_', 40);
  const accessTokenHash = await sha256(accessToken);
  const accessExpiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();

  await env.DB.prepare(`
    INSERT INTO access_tokens (token_hash, client_id, user_id, server_id, scope, expires_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(accessTokenHash, client_id, stored.user_id, stored.server_id, stored.scope, accessExpiresAt).run();

  // Dual-write refreshed access token to Neon
  await syncAccessTokenToNeon(env, {
    tokenHash: accessTokenHash, clientId: client_id, userId: stored.user_id,
    serverId: stored.server_id, scope: stored.scope, expiresAt: accessExpiresAt,
  });

  return jsonResponse({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    scope: stored.scope,
  });
}

// ─── Revoke Endpoint ─────────────────────────────────────────────────────────

async function handleRevoke(request, env) {
  const body = await request.formData().catch(() => null) || await request.json().catch(() => ({}));
  const token = typeof body.get === 'function' ? body.get('token') : body.token;

  if (!token) {
    return jsonResponse({ error: 'invalid_request' }, 400);
  }

  const tokenHash = await sha256(token);
  
  // Try revoking from both tables
  await env.DB.prepare('UPDATE access_tokens SET revoked = 1 WHERE token_hash = ?').bind(tokenHash).run();
  await env.DB.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?').bind(tokenHash).run();

  // Also revoke in Neon
  try {
    const sql = getNeonSql(env);
    await sql`UPDATE authkit_access_tokens SET revoked = 1 WHERE token_hash = ${tokenHash}`;
  } catch (e) {
    console.error('Neon revocation sync failed:', e.message);
  }

  return new Response(null, { status: 200, headers: corsHeaders() });
}

// ─── UserInfo Endpoint ───────────────────────────────────────────────────────

async function handleUserInfo(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  const token = authHeader.replace('Bearer ', '');

  if (!token) {
    return jsonResponse({ error: 'invalid_token' }, 401);
  }

  const tokenHash = await sha256(token);
  const stored = await env.DB.prepare('SELECT * FROM access_tokens WHERE token_hash = ? AND revoked = 0').bind(tokenHash).first();

  if (!stored || new Date(stored.expires_at) < new Date()) {
    return jsonResponse({ error: 'invalid_token' }, 401);
  }

  // Fetch user from Neon
  const sql = getNeonSql(env);
  const rows = await sql`SELECT id, email, name FROM authkit_users WHERE id = ${stored.user_id}`;
  const user = rows[0];

  if (!user) {
    return jsonResponse({ error: 'invalid_token', error_description: 'User not found' }, 401);
  }

  return jsonResponse({
    sub: user.id,
    email: user.email,
    name: user.name,
  });
}

// ─── Token Validation (for MCP servers to call) ─────────────────────────────

async function validateToken(token, env) {
  const tokenHash = await sha256(token);
  // Token lives in D1
  const stored = await env.DB.prepare('SELECT * FROM access_tokens WHERE token_hash = ? AND revoked = 0').bind(tokenHash).first();

  if (!stored || new Date(stored.expires_at) < new Date()) {
    return null;
  }

  // User lives in Neon
  const sql = getNeonSql(env);
  const rows = await sql`SELECT id, email, name FROM authkit_users WHERE id = ${stored.user_id}`;
  const user = rows[0];

  return {
    user_id: stored.user_id,
    email: user?.email,
    name: user?.name,
    scope: stored.scope,
    server_id: stored.server_id,
    expires_at: stored.expires_at,
  };
}

// ─── Server Registration API ─────────────────────────────────────────────────

async function handleRegisterServer(request, env) {
  const body = await request.json();
  const { name, resource_url, scopes, callback_urls } = body;

  // Simple API key auth for server registration
  const authHeader = request.headers.get('Authorization') || '';
  const adminKey = authHeader.replace('Bearer ', '');
  if (adminKey !== env.ADMIN_KEY) {
    return jsonResponse({ error: 'unauthorized' }, 401);
  }

  if (!name || !resource_url) {
    return jsonResponse({ error: 'invalid_request', error_description: 'name and resource_url required' }, 400);
  }

  const serverId = generateId('srv_', 16);
  const apiKey = generateId('sak_', 32);
  const apiKeyHash = await sha256(apiKey);

  await env.DB.prepare(`
    INSERT INTO mcp_servers (id, name, resource_url, scopes, callback_urls, api_key_hash)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(
    serverId,
    name,
    resource_url,
    JSON.stringify(scopes || ['mcp:tools']),
    JSON.stringify(callback_urls || []),
    apiKeyHash
  ).run();

  return jsonResponse({
    server_id: serverId,
    name,
    resource_url,
    api_key: apiKey,
    prm_url: `${new URL(request.url).origin}/prm/${serverId}`,
    message: 'Set authorization_servers in your PRM to point to this gateway.',
  }, 201);
}

async function handleListServers(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  const adminKey = authHeader.replace('Bearer ', '');
  if (adminKey !== env.ADMIN_KEY) {
    return jsonResponse({ error: 'unauthorized' }, 401);
  }

  const { results } = await env.DB.prepare('SELECT id, name, resource_url, scopes, created_at FROM mcp_servers').all();
  return jsonResponse({ servers: results });
}

// ─── Auth (Minimal MVP) ─────────────────────────────────────────────────────

async function handleSignup(request, env) {
  const { email, password, name } = await request.json();
  const passwordHash = await sha256(password + (env.SALT || 'mcp-authkit-salt'));
  const userId = generateId('usr_', 20);
  const sql = getNeonSql(env);

  try {
    await sql`INSERT INTO authkit_users (id, email, name, password_hash, created_at)
              VALUES (${userId}, ${email}, ${name || email.split('@')[0]}, ${passwordHash}, ${new Date().toISOString()})`;
    return jsonResponse({ user_id: userId, email }, 201);
  } catch (e) {
    if (e.message?.includes('unique') || e.message?.includes('duplicate')) {
      return jsonResponse({ error: 'email_exists', message: 'Email already registered' }, 409);
    }
    throw e;
  }
}

async function handleLogin(request, env) {
  const { email, password } = await request.json();
  const passwordHash = await sha256(password + (env.SALT || 'mcp-authkit-salt'));
  const sql = getNeonSql(env);
  const rows = await sql`SELECT id, email, name FROM authkit_users
                         WHERE email = ${email} AND password_hash = ${passwordHash}`;
  const user = rows[0] || null;

  if (!user) {
    return jsonResponse({ error: 'invalid_credentials' }, 401);
  }

  // Issue a session token
  const sessionToken = generateId('ses_', 32);
  return jsonResponse({ user_id: user.id, email: user.email, name: user.name, session_token: sessionToken });
}

// ─── Password Reset ─────────────────────────────────────────────────────────
//
// Reset tokens live in D1 (mirroring auth_codes: short-lived, single-use,
// user_id references Neon authkit_users with no FK). Only the password update
// itself touches the canonical Neon row. The reset link host is derived from
// the incoming request, so it follows whatever domain serves the worker.

const RESET_TOKEN_TTL_MS = 60 * 60 * 1000;   // reset link valid for 1 hour
const RESET_THROTTLE_MS = 5 * 60 * 1000;     // don't re-send while a fresh token is live

async function handleForgotPassword(request, env) {
  const formData = await request.formData();
  const email = (formData.get('email') || '').toString().trim().toLowerCase();

  // Respond identically whether or not the account exists — no user enumeration.
  const genericPage = () => new Response(
    getAuthMessageHTML({
      heading: 'Check your email',
      message: 'If an account exists for that address, a password reset link is on its way. It expires in 1 hour.',
    }),
    { headers: { 'Content-Type': 'text/html' } }
  );

  if (!email || !email.includes('@')) {
    return genericPage();
  }

  try {
    const sql = getNeonSql(env);
    const rows = await sql`SELECT id, email FROM authkit_users WHERE email = ${email}`;
    const user = rows[0];
    if (user) {
      const nowIso = new Date().toISOString();
      // Throttle reset-email bombing: if a fresh unused token already exists,
      // don't mint and send another one.
      const recent = await env.DB
        .prepare('SELECT created_at FROM password_reset_tokens WHERE user_id = ? AND used = 0 AND expires_at > ? ORDER BY created_at DESC LIMIT 1')
        .bind(user.id, nowIso).first();
      const recentlySent = recent && (Date.now() - new Date(recent.created_at).getTime()) < RESET_THROTTLE_MS;

      if (!recentlySent) {
        const token = generateId('rst_', 40);
        const tokenHash = await sha256(token);
        const expiresAt = new Date(Date.now() + RESET_TOKEN_TTL_MS).toISOString();
        await env.DB
          .prepare('INSERT INTO password_reset_tokens (token_hash, user_id, email, expires_at, used, created_at) VALUES (?, ?, ?, ?, 0, ?)')
          .bind(tokenHash, user.id, user.email, expiresAt, nowIso).run();

        const resetUrl = `${new URL(request.url).origin}/auth/reset?token=${token}`;
        await sendResetEmail(env, { to: user.email, resetUrl });
      }
    }
  } catch (e) {
    // Never surface internal state to the requester; log for ops.
    console.error('forgot-password failed:', e?.message);
  }

  return genericPage();
}

async function handleResetPage(request, env) {
  const token = new URL(request.url).searchParams.get('token') || '';
  const record = await lookupResetToken(env, token);
  if (!record) {
    return new Response(getExpiredLinkHTML(), { headers: { 'Content-Type': 'text/html' }, status: 400 });
  }
  return new Response(getResetFormHTML(token), { headers: { 'Content-Type': 'text/html' } });
}

async function handleResetPassword(request, env) {
  const formData = await request.formData();
  const token = (formData.get('token') || '').toString();
  const password = (formData.get('password') || '').toString();

  if (password.length < 8) {
    return new Response(getResetFormHTML(token, 'Password must be at least 8 characters.'), {
      headers: { 'Content-Type': 'text/html' }, status: 400,
    });
  }

  const record = await lookupResetToken(env, token);
  if (!record) {
    return new Response(getExpiredLinkHTML(), { headers: { 'Content-Type': 'text/html' }, status: 400 });
  }

  const tokenHash = await sha256(token);
  const passwordHash = await sha256(password + (env.SALT || 'mcp-authkit-salt'));

  // Update the canonical password in Neon, burn the token, then revoke the
  // user's live sessions so a stolen pre-reset token can't outlive the change.
  const sql = getNeonSql(env);
  await sql`UPDATE authkit_users SET password_hash = ${passwordHash} WHERE id = ${record.user_id}`;

  await env.DB.prepare('UPDATE password_reset_tokens SET used = 1 WHERE token_hash = ?').bind(tokenHash).run();
  await env.DB.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?').bind(record.user_id).run();
  await env.DB.prepare('UPDATE access_tokens SET revoked = 1 WHERE user_id = ?').bind(record.user_id).run();

  // Mirror the revocation into Neon so OpZero's shared-DB validation also
  // rejects pre-reset access tokens immediately (matches /oauth/revoke).
  try {
    await sql`UPDATE authkit_access_tokens SET revoked = 1 WHERE user_id = ${record.user_id}`;
  } catch (e) {
    console.error('Neon token revoke on reset failed:', e?.message);
  }

  return new Response(
    getAuthMessageHTML({
      heading: 'Password updated',
      message: 'Your password has been reset. Head back to the app and log in with your new password.',
    }),
    { headers: { 'Content-Type': 'text/html' } }
  );
}

async function lookupResetToken(env, token) {
  if (!token) return null;
  const tokenHash = await sha256(token);
  const row = await env.DB
    .prepare('SELECT token_hash, user_id, email, expires_at, used FROM password_reset_tokens WHERE token_hash = ?')
    .bind(tokenHash).first();
  if (!row || row.used) return null;
  if (new Date(row.expires_at) < new Date()) return null;
  return row;
}

async function sendResetEmail(env, { to, resetUrl }) {
  if (!env.RESEND_API_KEY) {
    console.error('RESEND_API_KEY not configured — reset email not sent for', to);
    return;
  }
  const from = env.RESEND_FROM || 'OpZero <no-reply@auth.opzero.sh>';
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from,
        to,
        subject: 'Reset your OpZero password',
        html: getResetEmailHTML(resetUrl),
        text: `Reset your OpZero password:\n\n${resetUrl}\n\nThis link expires in 1 hour. If you didn't request it, you can ignore this email.`,
      }),
    });
    if (!res.ok) {
      console.error('Resend send failed:', res.status, await res.text().catch(() => ''));
    }
  } catch (e) {
    console.error('Resend send threw:', e?.message);
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function redirectWithError(redirectUri, state, error, description) {
  const redirect = new URL(redirectUri);
  redirect.searchParams.set('error', error);
  if (description) redirect.searchParams.set('error_description', description);
  if (state) redirect.searchParams.set('state', state);
  return Response.redirect(redirect.toString(), 302);
}

// ─── Blog Post Handler ───────────────────────────────────────────────────────

async function handleBlogPost(slug, env) {
  const sql = getNeonSql(env);
  const rows = await sql`SELECT title, content, format, dependencies FROM posts WHERE slug = ${slug} AND published = true LIMIT 1`;
  const post = rows[0];

  if (!post) {
    return new Response('Not found', { status: 404, headers: { 'Content-Type': 'text/html' } });
  }

  let renderedContent;
  if (post.format === 'artifact') {
    const srcdoc = buildArtifactSrcdoc(post.content, post.dependencies);
    renderedContent = `<iframe sandbox="allow-scripts allow-same-origin" srcdoc="${escapeAttr(srcdoc)}" style="width:100%;min-height:80vh;border:none;" loading="lazy"></iframe>`;
  } else if (post.format === 'html') {
    renderedContent = post.content;
  } else {
    // markdown — rendered as-is (assumes pre-rendered HTML or client-side rendering)
    renderedContent = post.content;
  }

  return new Response(getBlogPostHTML(post.title, renderedContent), {
    headers: { 'Content-Type': 'text/html' },
  });
}

function buildArtifactSrcdoc(componentCode, dependencies) {
  const deps = (typeof dependencies === 'string' ? JSON.parse(dependencies) : dependencies) || {};

  const importMapEntries = {
    'react': 'https://esm.sh/react@18',
    'react-dom': 'https://esm.sh/react-dom@18',
    'react-dom/client': 'https://esm.sh/react-dom@18/client',
    'react/jsx-runtime': 'https://esm.sh/react@18/jsx-runtime',
  };

  for (const [pkg, version] of Object.entries(deps)) {
    importMapEntries[pkg] = `https://esm.sh/${pkg}@${version}`;
  }

  const importMap = JSON.stringify({ imports: importMapEntries }, null, 2);

  // The component code uses `export default`, so we capture the default export
  // by replacing it with a variable assignment that we can reference when mounting.
  const mountCode = componentCode
    .replace(/export\s+default\s+function\s+/, 'function ')
    .replace(/export\s+default\s+/, 'const __Component__ = ');

  // Extract the function name if it was a named export default function
  const funcNameMatch = componentCode.match(/export\s+default\s+function\s+(\w+)/);
  const componentRef = funcNameMatch ? funcNameMatch[1] : '__Component__';

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <script type="importmap">
${importMap}
  </script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
  </style>
</head>
<body>
  <div id="root"></div>
  <script type="module">
    import React from 'react';
    import { createRoot } from 'react-dom/client';

    ${mountCode}

    createRoot(document.getElementById('root')).render(React.createElement(${componentRef}));
  </script>
</body>
</html>`;
}

function escapeAttr(str) {
  return str.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function getBlogPostHTML(title, content) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} — OpZero Blog</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a0a; color: #e5e5e5; min-height: 100vh; }
    header { border-bottom: 1px solid #1f1f1f; padding: 16px 24px; }
    header a { color: #22c55e; text-decoration: none; font-size: 14px; letter-spacing: 1px; }
    .content { max-width: 900px; margin: 0 auto; padding: 40px 24px; }
    h1 { font-size: 32px; font-weight: 700; margin-bottom: 32px; color: #fafafa; }
    iframe { width: 100%; min-height: 80vh; border: none; border-radius: 8px; background: #fff; }
    footer { border-top: 1px solid #1f1f1f; padding: 24px; text-align: center; color: #525252; font-size: 13px; margin-top: 48px; }
  </style>
</head>
<body>
  <header><a href="/">OpZero</a></header>
  <div class="content">
    <h1>${title}</h1>
    ${content}
  </div>
  <footer>OpZero.sh</footer>
</body>
</html>`;
}

// ─── Consent Screen HTML ─────────────────────────────────────────────────────

function getConsentHTML({ clientName, clientId, redirectUri, scope, state, codeChallenge, codeChallengeMethod, error }) {
  const scopes = scope.split(/[\s+]/).filter(Boolean);
  const scopeLabels = {
    'openid': 'Verify your identity',
    'profile': 'Access your profile info',
    'email': 'See your email address',
    'mcp:tools': 'Use MCP tools on your behalf',
    'mcp:deploy': 'Deploy websites and apps',
    'mcp:read': 'Read your projects and data',
    'mcp:write': 'Modify your projects and data',
    'deploy': 'Deploy websites and apps',
    'preview': 'Create live previews',
    'read': 'Read your projects',
  };

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorize ${clientName} — OpZero</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: #050507; color: #e5e5e5; min-height: 100vh;
      display: flex; align-items: center; justify-content: center;
      padding: 20px; position: relative; overflow: hidden;
    }
    body::before {
      content: ""; position: absolute; inset: 0; pointer-events: none; opacity: 0.6;
      background:
        radial-gradient(ellipse at top, rgba(0,245,255,0.12), transparent 55%),
        radial-gradient(ellipse at bottom, rgba(139,92,246,0.10), transparent 60%);
    }
    .card {
      position: relative; z-index: 1;
      background: rgba(13,13,18,0.72); backdrop-filter: blur(16px);
      border: 1px solid rgba(0,245,255,0.18); border-radius: 16px;
      padding: 40px; max-width: 420px; width: 100%;
      box-shadow: 0 20px 80px -20px rgba(0,245,255,0.25);
    }
    .logo { font-size: 20px; font-weight: 700; letter-spacing: 0.5px; margin-bottom: 4px;
      background: linear-gradient(90deg, #00F5FF, #8B5CF6); -webkit-background-clip: text;
      background-clip: text; -webkit-text-fill-color: transparent; }
    .tagline { font-size: 10px; color: #737373; letter-spacing: 3px; text-transform: uppercase; margin-bottom: 28px; }
    h1 { font-size: 20px; font-weight: 600; margin-bottom: 8px; color: #fafafa; }
    .subtitle { color: #a3a3a3; font-size: 14px; margin-bottom: 24px; line-height: 1.5; }
    .client-name { color: #00F5FF; font-weight: 600; }
    .scopes { margin-bottom: 24px; }
    .scope { display: flex; align-items: center; gap: 10px; padding: 10px 0; border-bottom: 1px solid rgba(255,255,255,0.06); font-size: 14px; }
    .scope:last-child { border-bottom: none; }
    .scope-icon { color: #00F5FF; font-size: 16px; }
    .divider { height: 1px; background: rgba(255,255,255,0.08); margin: 24px 0; }
    .tabs { display: flex; gap: 0; margin-bottom: 20px; }
    .tab { flex: 1; padding: 10px; text-align: center; font-size: 13px; cursor: pointer;
           border: 1px solid rgba(255,255,255,0.10); color: #737373; transition: all 0.2s; background: transparent; }
    .tab:first-child { border-radius: 8px 0 0 8px; }
    .tab:last-child { border-radius: 0 8px 8px 0; }
    .tab.active { background: rgba(0,245,255,0.08); color: #fafafa; border-color: rgba(0,245,255,0.35); }
    .field { margin-bottom: 16px; }
    .field label { display: block; font-size: 13px; color: #a3a3a3; margin-bottom: 6px; }
    .field input { width: 100%; padding: 10px 14px; background: rgba(5,5,7,0.6); border: 1px solid rgba(255,255,255,0.12);
                   border-radius: 8px; color: #fafafa; font-size: 14px; outline: none; transition: all 0.2s; }
    .field input:focus { border-color: #00F5FF; box-shadow: 0 0 0 3px rgba(0,245,255,0.12); }
    .name-field { display: none; }
    .actions { display: flex; gap: 12px; margin-top: 24px; }
    .btn { flex: 1; padding: 12px; border-radius: 10px; font-size: 14px; font-weight: 600;
           cursor: pointer; border: none; transition: all 0.2s; }
    .btn-allow { background: linear-gradient(90deg, #00F5FF, #8B5CF6); color: #050507; }
    .btn-allow:hover { filter: brightness(1.08); box-shadow: 0 0 20px rgba(0,245,255,0.35); }
    .btn-deny { background: transparent; border: 1px solid rgba(255,255,255,0.15); color: #a3a3a3; }
    .btn-deny:hover { border-color: #737373; color: #e5e5e5; }
    .error { background: #371520; border: 1px solid #5c1d2e; color: #f87171; padding: 10px 14px;
             border-radius: 8px; font-size: 13px; margin-bottom: 16px; }
    .forgot { text-align: right; margin: -6px 0 4px; }
    .forgot a { color: #00F5FF; font-size: 12px; text-decoration: none; }
    .forgot a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">OpZero</div>
    <div class="tagline">Account Access</div>
    <h1>Authorize Connection</h1>
    <p class="subtitle"><span class="client-name">${clientName}</span> wants to connect to your account and access the following:</p>
    
    <div class="scopes">
      ${scopes.map(s => `<div class="scope"><span class="scope-icon">✓</span> ${scopeLabels[s] || s}</div>`).join('')}
    </div>

    <div class="divider"></div>

    ${error ? `<div class="error">${error}</div>` : ''}

    <div class="tabs">
      <button class="tab active" onclick="switchTab('login')" id="tab-login">Log In</button>
      <button class="tab" onclick="switchTab('signup')" id="tab-signup">Sign Up</button>
    </div>

    <form method="POST" action="/oauth/authorize" id="auth-form">
      <input type="hidden" name="client_id" value="${clientId}" />
      <input type="hidden" name="redirect_uri" value="${redirectUri}" />
      <input type="hidden" name="scope" value="${scope}" />
      <input type="hidden" name="state" value="${state || ''}" />
      <input type="hidden" name="code_challenge" value="${codeChallenge || ''}" />
      <input type="hidden" name="code_challenge_method" value="${codeChallengeMethod}" />
      <input type="hidden" name="auth_mode" value="login" id="auth-mode" />
      <input type="hidden" name="action" value="allow" id="action-field" />

      <div class="field name-field" id="name-field">
        <label for="name">Name</label>
        <input type="text" id="name" name="name" placeholder="Your name" />
      </div>

      <div class="field">
        <label for="email">Email</label>
        <input type="email" id="email" name="email" placeholder="you@example.com" required />
      </div>

      <div class="field">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" placeholder="••••••••" required minlength="8" />
      </div>

      <div class="forgot"><a href="/auth/forgot">Forgot password?</a></div>

      <div class="actions">
        <!-- Deny must not be a submit button: implicit submission (Enter key /
             mobile "Go") uses the form's first submit button, which sent
             action=deny for users who approved. -->
        <button type="button" class="btn btn-deny" onclick="denyAccess()">Deny</button>
        <button type="submit" class="btn btn-allow">Allow</button>
      </div>
    </form>
  </div>

  <script>
    function denyAccess() {
      document.getElementById('action-field').value = 'deny';
      document.getElementById('auth-form').submit();
    }
    function switchTab(mode) {
      document.getElementById('auth-mode').value = mode;
      document.getElementById('tab-login').classList.toggle('active', mode === 'login');
      document.getElementById('tab-signup').classList.toggle('active', mode === 'signup');
      document.getElementById('name-field').style.display = mode === 'signup' ? 'block' : 'none';
    }
  </script>
</body>
</html>`;
}

// ─── Password Reset UI ───────────────────────────────────────────────────────

const AUTH_PAGE_STYLE = `
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: #050507; color: #e5e5e5; min-height: 100vh;
      display: flex; align-items: center; justify-content: center; padding: 20px;
      position: relative; overflow: hidden; }
    body::before { content: ""; position: absolute; inset: 0; pointer-events: none; opacity: 0.6;
      background:
        radial-gradient(ellipse at top, rgba(0,245,255,0.12), transparent 55%),
        radial-gradient(ellipse at bottom, rgba(139,92,246,0.10), transparent 60%); }
    .card { position: relative; z-index: 1;
      background: rgba(13,13,18,0.72); backdrop-filter: blur(16px);
      border: 1px solid rgba(0,245,255,0.18); border-radius: 16px;
      padding: 40px; max-width: 420px; width: 100%;
      box-shadow: 0 20px 80px -20px rgba(0,245,255,0.25); }
    .logo { font-size: 20px; font-weight: 700; letter-spacing: 0.5px; margin-bottom: 4px;
      background: linear-gradient(90deg, #00F5FF, #8B5CF6); -webkit-background-clip: text;
      background-clip: text; -webkit-text-fill-color: transparent; }
    .tagline { font-size: 10px; color: #737373; letter-spacing: 3px; text-transform: uppercase; margin-bottom: 28px; }
    h1 { font-size: 20px; font-weight: 600; margin-bottom: 8px; color: #fafafa; }
    .subtitle { color: #a3a3a3; font-size: 14px; margin-bottom: 24px; line-height: 1.5; }
    .field { margin-bottom: 16px; }
    .field label { display: block; font-size: 13px; color: #a3a3a3; margin-bottom: 6px; }
    .field input { width: 100%; padding: 10px 14px; background: rgba(5,5,7,0.6); border: 1px solid rgba(255,255,255,0.12);
      border-radius: 8px; color: #fafafa; font-size: 14px; outline: none; transition: all 0.2s; }
    .field input:focus { border-color: #00F5FF; box-shadow: 0 0 0 3px rgba(0,245,255,0.12); }
    .btn { width: 100%; padding: 12px; border-radius: 10px; font-size: 14px; font-weight: 600;
      cursor: pointer; border: none; background: linear-gradient(90deg, #00F5FF, #8B5CF6); color: #050507; transition: all 0.2s; }
    .btn:hover { filter: brightness(1.08); box-shadow: 0 0 20px rgba(0,245,255,0.35); }
    .error { background: #371520; border: 1px solid #5c1d2e; color: #f87171; padding: 10px 14px;
      border-radius: 8px; font-size: 13px; margin-bottom: 16px; }
    .muted { color: #a3a3a3; font-size: 14px; line-height: 1.6; }
    .backlink { display: inline-block; margin-top: 20px; color: #00F5FF; text-decoration: none; font-size: 13px; }
    .backlink:hover { text-decoration: underline; }
`;

function authPage(title, inner) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} — OpZero</title>
  <style>${AUTH_PAGE_STYLE}</style>
</head>
<body>
  <div class="card">
    <div class="logo">OpZero</div>
    <div class="tagline">Account Access</div>
    ${inner}
  </div>
</body>
</html>`;
}

function getForgotFormHTML(error) {
  return authPage('Reset password', `
    <h1>Reset your password</h1>
    <p class="subtitle">Enter your account email and we'll send you a link to set a new password.</p>
    ${error ? `<div class="error">${error}</div>` : ''}
    <form method="POST" action="/auth/forgot">
      <div class="field">
        <label for="email">Email</label>
        <input type="email" id="email" name="email" placeholder="you@example.com" required autofocus />
      </div>
      <button type="submit" class="btn">Send reset link</button>
    </form>`);
}

function getResetFormHTML(token, error) {
  return authPage('Set new password', `
    <h1>Set a new password</h1>
    <p class="subtitle">Choose a new password for your account.</p>
    ${error ? `<div class="error">${error}</div>` : ''}
    <form method="POST" action="/auth/reset">
      <input type="hidden" name="token" value="${escapeAttr(token)}" />
      <div class="field">
        <label for="password">New password</label>
        <input type="password" id="password" name="password" placeholder="••••••••" required minlength="8" autofocus />
      </div>
      <button type="submit" class="btn">Update password</button>
    </form>`);
}

function getAuthMessageHTML({ heading, message, linkHref, linkText }) {
  return authPage(heading, `
    <h1>${heading}</h1>
    <p class="muted">${message}</p>
    ${linkHref ? `<a class="backlink" href="${linkHref}">${linkText || 'Back'}</a>` : ''}`);
}

function getExpiredLinkHTML() {
  return getAuthMessageHTML({
    heading: 'Link expired',
    message: 'This password reset link is invalid or has expired. Request a new one from the login screen.',
    linkHref: '/auth/forgot',
    linkText: 'Request a new link',
  });
}

function getResetEmailHTML(resetUrl) {
  return `<!DOCTYPE html>
<html><body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background:#0a0a0a; color:#e5e5e5; padding:40px;">
  <div style="max-width:480px;margin:0 auto;background:#0d0d12;border:1px solid #1c2330;border-radius:16px;padding:40px;">
    <div style="font-size:18px;font-weight:700;letter-spacing:0.5px;color:#00F5FF;margin-bottom:24px;">OpZero</div>
    <h1 style="font-size:20px;color:#fafafa;margin:0 0 12px;">Reset your password</h1>
    <p style="color:#a3a3a3;font-size:14px;line-height:1.6;margin:0 0 24px;">We received a request to reset your OpZero password. Click below to choose a new one. This link expires in 1 hour.</p>
    <a href="${resetUrl}" style="display:inline-block;background:#00F5FF;color:#050507;font-weight:600;font-size:14px;text-decoration:none;padding:12px 24px;border-radius:10px;">Reset password</a>
    <p style="color:#525252;font-size:12px;line-height:1.6;margin:24px 0 0;">If you didn't request this, you can safely ignore this email. The link only works once:<br><span style="color:#737373;word-break:break-all;">${resetUrl}</span></p>
  </div>
</body></html>`;
}

// ─── Landing Page HTML ───────────────────────────────────────────────────────

function getLandingHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MCP AuthKit — OAuth for MCP Servers</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a0a; color: #e5e5e5; }
    .container { max-width: 800px; margin: 0 auto; padding: 60px 24px; }
    .badge { display: inline-block; padding: 4px 12px; border: 1px solid #22c55e33; color: #22c55e; 
             border-radius: 100px; font-size: 12px; letter-spacing: 1px; margin-bottom: 24px; }
    h1 { font-size: 48px; font-weight: 700; line-height: 1.1; margin-bottom: 16px; }
    h1 span { color: #22c55e; }
    .lead { font-size: 18px; color: #a3a3a3; line-height: 1.6; margin-bottom: 48px; max-width: 600px; }
    .code-block { background: #141414; border: 1px solid #262626; border-radius: 12px; padding: 24px; 
                  font-family: 'SF Mono', 'Fira Code', monospace; font-size: 13px; line-height: 1.7;
                  overflow-x: auto; margin-bottom: 48px; }
    .comment { color: #525252; }
    .key { color: #22c55e; }
    .string { color: #f59e0b; }
    .section { margin-bottom: 48px; }
    .section h2 { font-size: 24px; margin-bottom: 16px; }
    .section p { color: #a3a3a3; line-height: 1.6; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; margin-top: 24px; }
    .card { background: #141414; border: 1px solid #262626; border-radius: 12px; padding: 24px; }
    .card h3 { font-size: 16px; margin-bottom: 8px; }
    .card p { font-size: 14px; color: #737373; }
    .footer { margin-top: 80px; padding-top: 24px; border-top: 1px solid #1f1f1f; color: #525252; font-size: 13px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="badge">ALPHA</div>
    <h1>OAuth for <span>MCP</span>, solved.</h1>
    <p class="lead">
      Stop implementing RFC 9728, PKCE, DCR, and token management from scratch. 
      Point your MCP server's authorization_servers here and ship your product.
    </p>

    <div class="code-block">
      <span class="comment">// Your MCP server's Protected Resource Metadata</span><br>
      <span class="comment">// GET /.well-known/oauth-protected-resource</span><br>
      {<br>
      &nbsp;&nbsp;<span class="key">"resource"</span>: <span class="string">"https://your-mcp.com/mcp"</span>,<br>
      &nbsp;&nbsp;<span class="key">"authorization_servers"</span>: [<span class="string">"https://auth.opzero.sh"</span>],<br>
      &nbsp;&nbsp;<span class="key">"bearer_methods_supported"</span>: [<span class="string">"header"</span>]<br>
      }<br><br>
      <span class="comment">// That's it. AuthKit handles everything else:</span><br>
      <span class="comment">// ✓ Dynamic Client Registration (RFC 7591)</span><br>
      <span class="comment">// ✓ PKCE S256 challenge/verification</span><br>
      <span class="comment">// ✓ Consent screen with login/signup</span><br>
      <span class="comment">// ✓ Token issuance & refresh</span><br>
      <span class="comment">// ✓ Token revocation</span>
    </div>

    <div class="section">
      <h2>How it works</h2>
      <p>Register your MCP server, get a server ID, and point your PRM to AuthKit. 
         When Claude, ChatGPT, or any MCP client connects, AuthKit handles the full 
         OAuth dance — registration, consent, tokens — and your server just validates 
         the Bearer token.</p>

      <div class="grid">
        <div class="card">
          <h3>🔌 Plug & Play</h3>
          <p>One JSON change to your PRM. No OAuth code in your server.</p>
        </div>
        <div class="card">
          <h3>📋 Spec Compliant</h3>
          <p>RFC 9728, 8414, 7591, OAuth 2.1 with PKCE. Passes Claude's validation.</p>
        </div>
        <div class="card">
          <h3>⚡ Edge Deployed</h3>
          <p>Runs on Cloudflare Workers. Sub-50ms auth worldwide.</p>
        </div>
        <div class="card">
          <h3>🔑 Token Validation</h3>
          <p>Simple API to validate tokens in your MCP server middleware.</p>
        </div>
      </div>
    </div>

    <div class="section">
      <h2>Endpoints</h2>
      <div class="code-block">
        GET &nbsp;/.well-known/oauth-authorization-server<br>
        POST /oauth/register &nbsp;&nbsp;&nbsp;<span class="comment">← Dynamic Client Registration</span><br>
        GET &nbsp;/oauth/authorize &nbsp;&nbsp;<span class="comment">← Authorization + Consent UI</span><br>
        POST /oauth/token &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="comment">← Code → Tokens (PKCE)</span><br>
        POST /oauth/revoke &nbsp;&nbsp;&nbsp;&nbsp;<span class="comment">← Token revocation</span><br>
        GET &nbsp;/oauth/userinfo &nbsp;&nbsp;&nbsp;<span class="comment">← User info from token</span><br>
        GET &nbsp;/prm/{server_id} &nbsp;&nbsp;<span class="comment">← Auto-generated PRM</span><br>
        POST /api/servers &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="comment">← Register your MCP server</span>
      </div>
    </div>

    <div class="footer">
      MCP AuthKit — by <a href="https://opzero.sh" style="color: #22c55e; text-decoration: none;">OpZero.sh</a>
    </div>
  </div>
</body>
</html>`;
}
