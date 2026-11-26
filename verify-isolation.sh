#!/usr/bin/env bash
#
# Proves the cage actually holds, from inside the ARTEX container.
# Run after `docker compose up -d` and after the egress daemon is active.
#
#   ./verify-isolation.sh

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

PASS=0
FAIL=0
SKIP=0

green() { printf '\033[32m%s\033[0m' "$*"; }
red()   { printf '\033[31m%s\033[0m' "$*"; }
dim()   { printf '\033[2m%s\033[0m' "$*"; }

pass() { PASS=$((PASS + 1)); printf '  %s %s\n' "$(green PASS)" "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  %s %s\n' "$(red FAIL)" "$1"; }
skip() { SKIP=$((SKIP + 1)); printf '  %s %s\n' "$(dim SKIP)" "$1"; }

in_ctr() { docker compose exec -T artex sh -c "$1" 2>/dev/null; }

expect_ok() {
  local label="$1" cmd="$2"
  if in_ctr "$cmd" >/dev/null 2>&1; then pass "$label"; else fail "$label (expected to succeed)"; fi
}

expect_blocked() {
  local label="$1" cmd="$2"
  if in_ctr "$cmd" >/dev/null 2>&1; then fail "$label (expected to be blocked)"; else pass "$label"; fi
}

echo
echo "ARTEX cage — isolation checks"
echo "──────────────────────────────────────────────────────────────"

if ! docker compose ps --status running --format '{{.Service}}' 2>/dev/null | grep -q '^artex$'; then
  echo "  artex container is not running — start it first:"
  echo "    docker compose up -d"
  exit 2
fi

# 1. Check the configured OpenAI-compatible endpoint, if there is one.
model_url="$(docker compose exec -T artex printenv ARTEX_LLM_BASE_URL 2>/dev/null || true)"
provider="$(docker compose exec -T artex printenv ARTEX_LLM_PROVIDER 2>/dev/null || true)"
if [ -z "$model_url" ] || { [ "$provider" != "openai" ] && [ "$provider" != "openai-responses" ]; }; then
  skip "no OpenAI-compatible model endpoint configured via environment"
else
  code="$(docker compose exec -T artex sh -c \
    'curl -s -o /dev/null -m 6 -w "%{http_code}" -- "$1"' \
    sh "${model_url%/}/models" 2>/dev/null || true)"
  case "$code" in
    200) pass "configured model endpoint reachable" ;;
    401|403) skip "model endpoint responded with HTTP $code (authentication required)" ;;
    *) fail "model endpoint returned HTTP ${code:-none} — approve it in the console?" ;;
  esac
fi

# 1b. the default route must leave through the cage, not the lab network
gw="$(in_ctr "ip route show default" | awk '{print $3; exit}')"
if [ "$gw" = "172.30.10.1" ]; then
  pass "default route is the egress gateway ($gw)"
else
  fail "default route is '${gw:-none}', expected 172.30.10.1"
fi

# 2. the open internet must not be
expect_blocked "public internet blocked (1.1.1.1:443)" \
  "curl -s -o /dev/null -m 6 https://1.1.1.1"

# 3. the VM's own LAN gateway / host LAN must not be
expect_blocked "LAN gateway blocked (192.168.183.2)" \
  "curl -s -o /dev/null -m 5 http://192.168.183.2"

# 4. the console must not be reachable from the container
expect_blocked "egress console unreachable from container" \
  "curl -s -o /dev/null -m 5 http://172.30.10.1:9099"

# 5. the ARTEX web UI must not be reachable from the container
expect_blocked "ARTEX UI unreachable from container" \
  "curl -s -o /dev/null -m 5 http://172.30.10.1:8787"

# 6. no docker socket inside the container
if in_ctr 'test -S /var/run/docker.sock'; then
  fail "docker socket is mounted inside the container"
else
  pass "no docker socket in the container"
fi

# 7. the lab network must be reachable
if docker compose ps --status running --format '{{.Service}}' 2>/dev/null | grep -qv '^\(artex\|postgres\)$'; then
  expect_ok "lab targets reachable (172.30.20.0/24)" \
    "sh -c 'command -v nc >/dev/null && nc -z -w2 172.30.20.2 80 || curl -s -o /dev/null -m 4 http://172.30.20.2'"
else
  skip "no lab targets running (add them under the 'lab' network)"
fi

# 8. a raw socket to an unapproved destination must not complete
expect_blocked "raw TCP to unapproved host blocked" \
  "sh -c 'exec 3<>/dev/tcp/93.184.216.34/80'"

echo "──────────────────────────────────────────────────────────────"
printf '  %d passed, %d failed, %d skipped\n\n' "$PASS" "$FAIL" "$SKIP"

if [ "$FAIL" -gt 0 ]; then
  echo "  Something is open that should not be. Check:"
  echo "    systemctl status artex-egressd"
  echo "    nft list table inet artex_egress"
  echo
  exit 1
fi

echo "  These checks do not verify the kill switch or Docker DNS isolation."
echo "  See README → Residual risks."
echo
