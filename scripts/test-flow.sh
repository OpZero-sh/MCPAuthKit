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
NEW_AT=$(curl -sf -X POST "$BASE_URL/oauth/token" -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=$RT&client_id=$CLIENT_ID" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")
pass "Refreshed: ${NEW_AT:0:20}..."

info "Revoke + verify"
curl -sf -X POST "$BASE_URL/oauth/revoke" -d "token=$NEW_AT&client_id=$CLIENT_ID" > /dev/null
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/oauth/userinfo" -H "Authorization: Bearer $NEW_AT")
[ "$STATUS" = "401" ] && pass "Revoked token rejected" || fail "Revoked token still valid"

echo ""
echo -e "${GREEN}All tests passed!${NC}"
