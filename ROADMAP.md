# MCPAuthKit Roadmap

MCPAuthKit is the **hosted OAuth 2.1 layer for the whole OpZero platform** — a single Cloudflare Worker (`src/worker.js`) with a D1-backed token store. It implements MCP's full OAuth surface (RFC 9728 / 8414 / 7591 discovery + dynamic registration, PKCE S256, consent, `mat_` access tokens, and rotating refresh tokens with replay-family revocation). It authenticates **CodeZ / CodeZero**, **codez-hub** (machine `agent:ws` connections), and the **deploy MCP** through one authorization server. Today it runs at `auth.opzero.sh`; the platform is consolidating it under `auth.opzero.sh`.

See the [OpZero platform roadmap](https://github.com/OpZero-sh/.github/blob/main/ROADMAP.md) for the north star and phase map.

> Status legend: ✅ shipped · 🟡 in progress · ⚪ planned
> Last verified against the code on branch `rebrand-authzero`: **2026-06-17**

---

## Near-term (Phase 1–2)

- 🟡 **AuthZero rebrand** *(branch `rebrand-authzero`)*. Consent and device-activation screens already render as "AuthZero" with the OpZero aesthetic (`worker.js` ~L1302/L1521/L1583, commit `ce54b6f`). Remaining: finalize copy/assets and merge to `main`.
- 🟡 **Device-code grant (RFC 8628)** — `migrations/002_device_codes.sql` is applied and the flow is largely built: `device_authorization_endpoint` advertised in discovery, `/oauth/device/authorization` + `/device` (GET/POST activation) routes, `urn:ietf:params:oauth:grant-type:device_code` in `/oauth/token`, polling with `slow_down`/`interval`, and per-IP `rate_limits`. Lets headless machines/containers log in without a local browser — the path that retires direct-mint. Remaining: end-to-end test from a real machine agent + activation-screen polish.
- ✅ **Rotating refresh tokens + replay-family revocation.** `/oauth/token` refresh grant rotates the token and, on replay of a revoked token, revokes the entire `family_id` (`worker.js` ~L586–593, commits `c7fcc57`/`a30ba36`). This is the reliability backbone for always-on agents.
- ✅ **Scope validation + `agent:ws` scope** for codez-hub machine connections (`worker.js` authorize/token paths, commits `c4dc1ba`/`7fa99e0`).
- ⚪ **Single MCPAuthKit consent for both surfaces (Phase 1/2)** — one consent issues **one token family per `user_id`** covering the CodeZ UI session *and* the `code.opzero.sh/mcp` connector. The hub keys each machine DO by the token's `user_id`, so UI + machine agent must resolve to the same user.
- ⚪ **Repoint `auth.opzero.sh` to this worker (Phase 1).** Add the custom hostname via CNAME → Cloudflare for SaaS (the `[env.production]` route in `wrangler.toml` is still commented out; `auth.opzero.sh` currently resolves to Vercel). Watch the CAA gotcha noted in the hub RUNBOOK. Keep `authkit.open0p.com` as a redirect during cutover.

---

## Later (Phase 5 — harden it like a product)

- ⚪ **Per-connector scopes** — distinct scope sets for the UI, the hosted `/mcp` connector, and the deploy MCP, so each gets least-privilege tokens rather than a shared grant.
- ⚪ **Rotation tooling** — operational visibility into token families: inspect/revoke a user's family, detect stuck/expired refresh families, and surface replay events (the 2026-06 outage was an expired token + revoked family with no recovery).
- ⚪ **Retire directly-minted `mat_` tokens.** Hand-inserting long-lived `mat_` rows into D1 (e.g. the `opz-2.local` stopgap, expiry 2030) is opaque, unrevocable per-user, and bypasses consent. Once device-code + auto re-login are reliable, replace minted machine tokens with OAuth-issued sessions and remove direct-mint for user-owned machines.
- ⚪ **Teams / multi-tenant scoping** — more than one user per org with shared machines and scoped tokens (Phase 5).
