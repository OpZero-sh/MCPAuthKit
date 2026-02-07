# Why We Built This

A build-in-public account of how MCP OAuth broke us, and what we did about it.

## The Pain

[OpZero](https://opzero.sh) is an MCP server that deploys websites. You tell Claude "deploy this to Netlify" and it happens. The MCP tools work great — when you can authenticate.

We started with API key auth. Simple, stateless, works everywhere. But MCP clients like Claude.ai and ChatGPT are moving toward OAuth. The spec requires it for remote MCP servers.

So we built it. In Next.js. Inside our app.

## What Went Wrong

Everything.

**The spec is deep.** MCP OAuth isn't just "add a `/login` endpoint." It's a chain of five RFCs that must work together. If any single step returns the wrong shape, wrong URL, wrong header — the client silently gives up.

**Trailing newlines.** Our metadata URLs had a `\n` at the end from an environment variable. Claude's client would fetch the URL with the newline and get a 404. No error message. Days of debugging.

**500 instead of 401.** Our middleware crashed before it could return a proper 401 response. Claude saw a 500 and assumed the server was broken.

**Consent screen in Next.js.** Building an OAuth consent UI inside the same app that serves the MCP endpoint created routing conflicts and state management headaches.

**Token validation complexity.** JWT signing, PKCE verification, code exchange, refresh rotation — all mixed in with the MCP handler code. The auth logic was bigger than the business logic.

## The Realization

OAuth is not our product. Deploying websites is our product.

We were spending 80% of our time on auth infrastructure and 20% on the thing people actually pay for.

## The Decision

Extract OAuth into a standalone service at the edge.

**Why Cloudflare Workers:**
- Sub-50ms worldwide — auth shouldn't add latency
- D1 for storage — no external database to manage
- Free tier covers thousands of token exchanges
- Single file deployment — no build step, no framework

**Why not Auth0/Stytch/Clerk:**
- They don't implement MCP-specific discovery (RFC 9728 PRM)
- MCP clients need a very specific metadata chain that generic OAuth providers don't serve
- We wanted to understand the spec, not abstract it away

**Why standalone, not a library:**
- A library still means OAuth code in your server
- A standalone gateway means your server has zero OAuth code
- Your server validates tokens with a single HTTP call

## What We'd Do Differently

**Start here.** If we could rewind, we'd never put OAuth in the Next.js app. We'd build this first.

**More logging.** The hardest bugs were silent ones — Claude's client giving up without telling us why.

**Test with multiple clients.** Claude, ChatGPT, and other MCP clients all have slightly different OAuth implementations.

## Cost

AuthKit runs on Cloudflare's free tier: Workers (100K req/day), D1 (5M reads/day). For a bootstrapped MCP server, the OAuth layer costs $0/month.
