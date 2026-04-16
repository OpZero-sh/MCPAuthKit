#!/bin/bash
# End-to-end OAuth flow test for MCP AuthKit
# Usage: AUTHKIT_URL=https://your-instance.workers.dev ADMIN_KEY=your_key bash scripts/test-flow.sh

set -e

BASE_URL="${AUTHKIT_URL:-http://localhost:8787}"
ADMIN_KEY="${ADMIN_KEY:-test-admin-key}"
REDIRECT_URI="https://example.com/callback"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass() { echo -e "${GREEN}✓ $1${NC}"; }
fail() { echo -e "${RED}✗ $1${NC}"; exit 1; }
info() { echo -e "${YELLOW}→ $1${NC}"; }

echo "============================================"
echo "  MCP AuthKit End-to-End Test"
echo "  Target: $BASE_URL"
echo "============================================"
echo ""

info "Health check"
curl -sf "$BASE_URL/health" | python3 -c "import json,sys; assert json.load(sys.stdin)['status']=='ok'" && pass "Health" || fail "Health"

info "Authorization server metadata"
curl -sf "$BASE_URL/.well-known/oauth-authorization-server" | python3 -c "
import json,sys; d=json.load(sys.stdin)
assert 'authorization_endpoint' in d and 'S256' in d['code_challenge_methods_supported']
" && pass "Metadata" || fail "Metadata"

info "Register MCP server"
SERVER_RESP=$(curl -sf -X POST "$BASE_URL/api/servers" -H "Authorization: Bearer $ADMIN_KEY" -H "Content-Type: application/json" \
  -d "{\"name\":\"Test $(date +%s)\",\"resource_url\":\"https://test.example.com/mcp\",\"scopes\":[\"mcp:tools\"]}")
SERVER_ID=$(echo "$SERVER_RESP" | python3 -c "import json,sys; print(json.load(sys.stdin)['server_id'])")
pass "Server: $SERVER_ID"

info "Check PRM"
curl -sf "$BASE_URL/prm/$SERVER_ID" | python3 -c "import json,sys; assert 'authorization_servers' in json.load(sys.stdin)" && pass "PRM" || fail "PRM"

info "Dynamic client registration"
CLIENT_ID=$(curl -sf -X POST "$BASE_URL/oauth/register" -H "Content-Type: application/json" \
  -d "{\"client_name\":\"Test\",\"redirect_uris\":[\"$REDIRECT_URI\"],\"grant_types\":[\"authorization_code\",\"refresh_token\"],\"response_types\":[\"code\"],\"token_endpoint_auth_method\":\"none\"}" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['client_id'])")
pass "Client: $CLIENT_ID"

info "Create user"
TEST_EMAIL="test-$(date +%s)@example.com"
USER_ID=$(curl -sf -X POST "$BASE_URL/auth/signup" -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"testpass123!\",\"name\":\"Test\"}" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['user']['id'])")
pass "User: $USER_ID"

info "PKCE + authorize"
CV=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
CC=$(echo -n "$CV" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')
AUTH_RESP=$(curl -s -D- -o /dev/null -X POST "$BASE_URL/oauth/authorize" \
  -d "response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=mcp:tools&state=test&code_challenge=$CC&code_challenge_method=S256&email=$TEST_EMAIL&password=testpass123!&action=approve")
CODE=$(echo "$AUTH_RESP" | grep -i "^location:" | grep -o 'code=[^&]*' | cut -d= -f2)
[ -n "$CODE" ] && pass "Auth code: ${CODE:0:20}..." || fail "No auth code"

info "Token exchange"
TOKEN_RESP=$(curl -sf -X POST "$BASE_URL/oauth/token" -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=$CODE&redirect_uri=$REDIRECT_URI&client_id=$CLIENT_ID&code_verifier=$CV")
AT=$(echo "$TOKEN_RESP" | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")
RT=$(echo "$TOKEN_RESP" | python3 -c "import json,sys; print(json.load(sys.stdin)['refresh_token'])")
pass "Tokens issued"

info "UserInfo"
UI_EMAIL=$(curl -sf "$BASE_URL/oauth/userinfo" -H "Authorization: Bearer $AT" | python3 -c "import json,sys; print(json.load(sys.stdin)['email'])")
[ "$UI_EMAIL" = "$TEST_EMAIL" ] && pass "UserInfo: $UI_EMAIL" || fail "Email mismatch"

info "Refresh"
REFRESH_RESP=$(curl -sf -X POST "$BASE_URL/oauth/token" -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=$RT&client_id=$CLIENT_ID")
NEW_AT=$(echo "$REFRESH_RESP" | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")
NEW_RT=$(echo "$REFRESH_RESP" | python3 -c "import json,sys; print(json.load(sys.stdin).get('refresh_token',''))")
pass "Refreshed: ${NEW_AT:0:20}..."

info "Rotation: new refresh token issued"
[ -n "$NEW_RT" ] && pass "New RT present: ${NEW_RT:0:20}..." || fail "No refresh_token in refresh response"
[ "$NEW_RT" != "$RT" ] && pass "NEW_RT differs from original RT" || fail "Refresh token was not rotated"

info "Rotation chain: refresh with NEW_RT"
REFRESH2_RESP=$(curl -sf -X POST "$BASE_URL/oauth/token" -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=$NEW_RT&client_id=$CLIENT_ID")
NEW_AT2=$(echo "$REFRESH2_RESP" | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")
NEW_RT2=$(echo "$REFRESH2_RESP" | python3 -c "import json,sys; print(json.load(sys.stdin).get('refresh_token',''))")
[ -n "$NEW_RT2" ] && [ "$NEW_RT2" != "$NEW_RT" ] && [ "$NEW_RT2" != "$RT" ] \
  && pass "Second-gen RT differs from NEW_RT and RT: ${NEW_RT2:0:20}..." \
  || fail "Rotation chain failed (NEW_RT2 missing or not rotated)"

info "Replay detection: reuse ORIGINAL RT after rotation"
REPLAY_BODY=$(mktemp)
REPLAY_STATUS=$(curl -s -o "$REPLAY_BODY" -w "%{http_code}" -X POST "$BASE_URL/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=$RT&client_id=$CLIENT_ID")
REPLAY_RESP=$(cat "$REPLAY_BODY")
rm -f "$REPLAY_BODY"
[ "$REPLAY_STATUS" = "400" ] && pass "Replay returns HTTP 400" || fail "Replay status was $REPLAY_STATUS, expected 400"
echo "$REPLAY_RESP" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert d.get('error')=='invalid_grant', f\"error was {d.get('error')}\"
desc=(d.get('error_description') or '').lower()
assert ('replay' in desc) or ('family' in desc), f\"description did not mention replay/family: {desc}\"
" && pass "Replay error=invalid_grant with replay/family description" || fail "Replay response did not match expected shape: $REPLAY_RESP"

info "Cascade revocation: NEW_RT2 should be invalidated"
CASCADE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=$NEW_RT2&client_id=$CLIENT_ID")
[ "$CASCADE_STATUS" = "400" ] && pass "NEW_RT2 rejected (family revoked)" || fail "NEW_RT2 status $CASCADE_STATUS, expected 400 after cascade"

info "Scope validation: unsupported scope stripped"
CV2=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
CC2=$(echo -n "$CV2" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')
AUTH2_RESP=$(curl -s -D- -o /dev/null -X POST "$BASE_URL/oauth/authorize" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "redirect_uri=$REDIRECT_URI" \
  --data-urlencode "scope=invalid_scope:foo mcp:tools" \
  --data-urlencode "state=scopetest" \
  --data-urlencode "code_challenge=$CC2" \
  --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "email=$TEST_EMAIL" \
  --data-urlencode "password=testpass123!" \
  --data-urlencode "action=approve")
CODE2=$(echo "$AUTH2_RESP" | grep -i "^location:" | grep -o 'code=[^&]*' | cut -d= -f2)
[ -n "$CODE2" ] && pass "Auth code issued with mixed scopes" || fail "No auth code for scope test"

TOKEN2_RESP=$(curl -sf -X POST "$BASE_URL/oauth/token" -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=$CODE2&redirect_uri=$REDIRECT_URI&client_id=$CLIENT_ID&code_verifier=$CV2")
GRANTED_SCOPE=$(echo "$TOKEN2_RESP" | python3 -c "import json,sys; print(json.load(sys.stdin).get('scope',''))")
info "Granted scope: '$GRANTED_SCOPE'"
echo "$GRANTED_SCOPE" | grep -qv "invalid_scope" && echo "$GRANTED_SCOPE" | grep -q "mcp:tools" \
  && pass "Invalid scope stripped; mcp:tools retained" \
  || fail "Scope validation failed — got: '$GRANTED_SCOPE'"

info "Revoke + verify"
curl -sf -X POST "$BASE_URL/oauth/revoke" -d "token=$NEW_AT&client_id=$CLIENT_ID" > /dev/null
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/oauth/userinfo" -H "Authorization: Bearer $NEW_AT")
[ "$STATUS" = "401" ] && pass "Revoked token rejected" || fail "Revoked token still valid"

echo ""
echo -e "${GREEN}All tests passed!${NC}"
