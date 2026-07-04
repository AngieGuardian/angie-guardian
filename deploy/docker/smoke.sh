#!/usr/bin/env bash
# End-to-end smoke test for the Angie Guardian Docker harness.
#
#   docker compose up --build -d
#   ./smoke.sh
#
# Drives the protected site (Angie :8080 on host loopback) and asserts the
# auth_request decisions behave: allowlisted paths pass, browser-shaped
# requests get a PoW challenge, WAF signatures deny, and stopping guardiand
# fails OPEN (backend still served) with the harness's fail-open toggle.
set -u
BASE="${BASE:-http://127.0.0.1:8080}"
pass=0; fail=0

check() { # description  expected_substr  curl-args...
    local desc="$1" expect="$2"; shift 2
    local out; out=$(curl -s -o /dev/null -w '%{http_code}' "$@" 2>/dev/null)
    if [[ "$out" == *"$expect"* ]]; then
        printf '  ok   %-52s [%s]\n' "$desc" "$out"; pass=$((pass+1))
    else
        printf '  FAIL %-52s [got %s, want %s]\n' "$desc" "$out" "$expect"; fail=$((fail+1))
    fi
}

body_has() { # description  expected_substr  curl-args...
    local desc="$1" expect="$2"; shift 2
    local out; out=$(curl -s "$@" 2>/dev/null)
    if grep -qi -- "$expect" <<<"$out"; then
        printf '  ok   %-52s\n' "$desc"; pass=$((pass+1))
    else
        printf '  FAIL %-52s [missing %q]\n' "$desc" "$expect"; fail=$((fail+1))
    fi
}

echo "== Guardian harness smoke test =="
# NOTE: every request from the host shares one source IP (the Docker gateway),
# so a WAF deny places a behavioural block that would poison later assertions.
# The signature-deny probe therefore runs LAST, and we clear any block via the
# admin API between phases. ADMIN carries the harness admin token.
ADMIN="${ADMIN:-http://127.0.0.1:8072}"
ADMIN_TOKEN="${ADMIN_TOKEN:-harness-admin-token}"
gw_unblock() {
    # Clear any behavioural block on the shared gateway source IPs so the
    # assertion order is deterministic regardless of prior runs.
    for ip in 172.18.0.1 172.19.0.1 172.20.0.1; do
        curl -s -o /dev/null -X DELETE \
          -H "Authorization: Bearer $ADMIN_TOKEN" \
          "$ADMIN/admin/blocks/$ip" 2>/dev/null || true
    done
}
gw_unblock

# Allowlisted path -> reaches backend (whoami echoes "Hostname:").
body_has "allowlisted /robots.txt reaches backend" "Hostname:" "$BASE/robots.txt"

# Browser-shaped GET on a PoW domain -> 401 challenge diverted to interstitial.
check "browser GET is challenged (interstitial)" "200" \
    -H 'User-Agent: Mozilla/5.0' "$BASE/somepage"
body_has "challenge page is the PoW interstitial" "challenge" \
    -H 'User-Agent: Mozilla/5.0' "$BASE/somepage"

# Non-browser UA (curl) on PoW-always domain -> passes WAF, reaches backend.
body_has "curl UA passes to backend (no PoW tax)" "Hostname:" \
    -H 'User-Agent: curl/8' "$BASE/api-ish"

# WAF signature hit -> 403 denied. Runs last: it blocks the shared source IP.
check "WAF signature (/.env) is denied" "403" \
    -H 'User-Agent: curl/8' "$BASE/.env"

echo
echo "== fail-open check (stops guardiand) =="
docker compose stop guardiand >/dev/null 2>&1
sleep 1
body_has "backend still served with guardiand down" "Hostname:" "$BASE/robots.txt"
docker compose start guardiand >/dev/null 2>&1
sleep 2

echo
echo "== result: $pass passed, $fail failed =="
[[ $fail -eq 0 ]]
