#!/usr/bin/env bash
# Repeatable, staging-only DDoS/attack-mode drill for Angie Guardian.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/ddos-drill.sh [options]

Required:
  --ack-staging                 Confirm the target is disposable staging
  --site-url URL                Angie's public base URL
  --admin-url URL               Guardian admin base URL
  --auth-url URL                Guardian auth base URL (private/loopback only)
  --host HOST                   Protected Host value
  --origin-count-url URL        Private endpoint returning the origin request count
  GUARDIAN_DRILL_ADMIN_TOKEN    Admin bearer token (environment only)

Options:
  --report PATH                 Markdown report path (default: timestamped file)
  --loadtest PATH               guardian-loadtest binary (built from this tree by default)
  --duration DURATION           Raw-flood duration (default: 10s)
  --concurrency N               Flood concurrency (default: 32)
  --requests N                  Challenge requests per measured phase (default: 1000)
  --redemptions N               Complete valid challenge journeys (default: 5)
  --fault-mode MODE             skip, open, or closed (default: skip)
  --block-ip IP                 Exercise mirror/nftables with this drill client IP
  --probe-url URL               Extra legitimate URL expected to remain HTTP 200; repeatable
  --plan                        Print the phases without contacting a target
  -h, --help                    Show this help

The script never discovers or guesses a target. It refuses an already-pinned or
non-normal attack posture, pins attack mode with a 10-minute TTL, and restores
automatic posture on exit. Fault injection itself remains an explicit operator
action because service-control commands differ by staging platform.
EOF
}

die() {
  echo "ddos-drill: $*" >&2
  exit 1
}

site_url=
admin_url=
auth_url=
drill_host=
origin_count_url=
report=
loadtest=
duration=10s
concurrency=32
requests=1000
redemptions=5
fault_mode=skip
block_ip=
ack_staging=0
plan_only=0
declare -a probe_urls=()

while (($#)); do
  case "$1" in
    --ack-staging) ack_staging=1; shift ;;
    --site-url) site_url=${2:?missing URL}; shift 2 ;;
    --admin-url) admin_url=${2:?missing URL}; shift 2 ;;
    --auth-url) auth_url=${2:?missing URL}; shift 2 ;;
    --host) drill_host=${2:?missing host}; shift 2 ;;
    --origin-count-url) origin_count_url=${2:?missing URL}; shift 2 ;;
    --report) report=${2:?missing path}; shift 2 ;;
    --loadtest) loadtest=${2:?missing path}; shift 2 ;;
    --duration) duration=${2:?missing duration}; shift 2 ;;
    --concurrency) concurrency=${2:?missing concurrency}; shift 2 ;;
    --requests) requests=${2:?missing request count}; shift 2 ;;
    --redemptions) redemptions=${2:?missing redemption count}; shift 2 ;;
    --fault-mode) fault_mode=${2:?missing fault mode}; shift 2 ;;
    --block-ip) block_ip=${2:?missing IP}; shift 2 ;;
    --probe-url) probe_urls+=("${2:?missing URL}"); shift 2 ;;
    --plan) plan_only=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

case "$fault_mode" in
  skip|open|closed) ;;
  *) die "--fault-mode must be skip, open, or closed" ;;
esac
[[ "$concurrency" =~ ^[1-9][0-9]*$ ]] || die "--concurrency must be a positive integer"
[[ "$requests" =~ ^[1-9][0-9]*$ ]] || die "--requests must be a positive integer"
[[ "$redemptions" =~ ^[0-9]+$ ]] || die "--redemptions must be a non-negative integer"

if ((plan_only)); then
  cat <<'EOF'
1. Refuse an HTTP flood through Angie and measure origin isolation.
2. Run a single-request-per-source phase and record automatic detector signals.
3. Pin attack posture with a 10-minute TTL and run a challenge flood.
4. Complete valid challenge/solve/redemption journeys and probe legitimate URLs.
5. Optionally verify fail-open/fail-closed during an operator-injected sidecar fault.
6. Optionally place one short-lived manual block and verify mirror/nftables status.
7. Restore attack posture to auto, remove the drill block, and capture final state.
EOF
  exit 0
fi

((ack_staging)) || die "refusing to generate attack traffic without --ack-staging"
[[ -n "$site_url" ]] || die "--site-url is required"
[[ -n "$admin_url" ]] || die "--admin-url is required"
[[ -n "$auth_url" ]] || die "--auth-url is required"
[[ -n "$drill_host" ]] || die "--host is required"
[[ -n "$origin_count_url" ]] || die "--origin-count-url is required"
[[ -n "${GUARDIAN_DRILL_ADMIN_TOKEN:-}" ]] || die "GUARDIAN_DRILL_ADMIN_TOKEN is required"
[[ "$drill_host" =~ ^[A-Za-z0-9._:-]+$ ]] || die "--host contains unsupported characters"
if [[ -n "$block_ip" ]]; then
  [[ "$block_ip" =~ ^[0-9A-Fa-f:.]+$ ]] || die "--block-ip must be an IPv4 or IPv6 literal"
fi

admin_token=$GUARDIAN_DRILL_ADMIN_TOKEN
unset GUARDIAN_DRILL_ADMIN_TOKEN

site_url=${site_url%/}
admin_url=${admin_url%/}
auth_url=${auth_url%/}
origin_count_url=${origin_count_url%/}

for command in curl jq git; do
  command -v "$command" >/dev/null || die "$command is required"
done

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp_dir=$(mktemp -d)
attack_changed=0
block_created=0

admin_curl() {
  curl --fail --silent --show-error \
    -H "Authorization: Bearer $admin_token" "$@"
}

cleanup() {
  status=$?
  trap - EXIT INT TERM
  set +e
  if ((block_created)); then
    admin_curl -X DELETE "$admin_url/admin/blocks/$block_ip" >/dev/null
  fi
  if ((attack_changed)); then
    admin_curl -H 'Content-Type: application/json' -X POST \
      -d '{"level":"auto"}' "$admin_url/admin/attack" >/dev/null
  fi
  rm -rf -- "$tmp_dir"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ -z "$loadtest" ]]; then
  command -v go >/dev/null || die "go is required when --loadtest is omitted"
  loadtest="$tmp_dir/guardian-loadtest"
  (cd "$repo_root" && go build -o "$loadtest" ./cmd/guardian-loadtest)
fi
[[ -x "$loadtest" ]] || die "load-test binary is not executable: $loadtest"

if [[ -z "$report" ]]; then
  report="$PWD/ddos-drill-$(date -u +%Y%m%dT%H%M%SZ).md"
fi
[[ ! -e "$report" ]] || die "refusing to overwrite existing report: $report"
mkdir -p "$(dirname "$report")"
: >"$report"

section() {
  printf '\n## %s\n\n' "$1" | tee -a "$report"
}

record() {
  printf '%s\n' "$*" | tee -a "$report"
}

code_start() { record '```text'; }
code_end() { record '```'; }

origin_count() {
  value=$(curl --fail --silent --show-error "$origin_count_url" | tr -d '[:space:]')
  [[ "$value" =~ ^[0-9]+$ ]] || die "origin count endpoint did not return an integer"
  printf '%s' "$value"
}

snapshot() {
  label=$1
  section "$label snapshot"
  record '### GET /healthz'
  code_start
  admin_curl "$admin_url/healthz" 2>&1 | tee -a "$report"
  code_end
  for endpoint in readyz admin/attack admin/offload admin/stats; do
    record "### GET /$endpoint"
    code_start
    admin_curl "$admin_url/$endpoint" | jq . 2>&1 | tee -a "$report"
    code_end
  done
  record '### Selected metrics'
  code_start
  admin_curl "$admin_url/metrics" \
    | grep -E '^guardian_(attack_mode($|_)|challenges_total|challenge_failures_total|decisions_total|evaluate_seconds_(count|sum)|shed_total|store_up|store_ops_total|store_op_seconds_(count|sum)|offload_(healthy|entries|ops_total))' \
    | tee -a "$report" || true
  code_end
  record "Origin request count: $(origin_count)"
}

run_load() {
  title=$1
  contract=$2
  shift 2
  section "$title"
  code_start
  : >"$tmp_dir/last-load.txt"
  "$loadtest" "$@" 2>&1 | tee "$tmp_dir/last-load.txt" | tee -a "$report"
  code_end
  if [[ "$contract" == strict ]]; then
    grep -Eq 'errors=0, unexpected-status=0, unexpected-contract=0' "$tmp_dir/last-load.txt" \
      || die "$title produced transport or response-contract failures; see $report"
  fi
}

probe_200() {
  label=$1
  url=$2
  status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
    -H "Host: $drill_host" "$url")
  record "$label: HTTP $status"
  [[ "$status" == 200 ]] || die "$label returned HTTP $status, want 200"
}

started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
commit=$(git -C "$repo_root" rev-parse HEAD)
cat >>"$report" <<EOF
# Angie Guardian DDoS drill report

- Started (UTC): $started_at
- Repository commit: $commit
- Site: $site_url
- Admin: $admin_url
- Auth hot path: $auth_url
- Protected host: $drill_host
- Raw-flood concurrency/duration: $concurrency / $duration
- Requests per challenge phase: $requests
- Valid redemptions: $redemptions
- Expected fail mode: $fault_mode
EOF

section 'Preflight'
probe_200 'Guardian liveness' "$admin_url/healthz"
ready_status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' "$admin_url/readyz")
record "Guardian readiness: HTTP $ready_status"
[[ "$ready_status" == 200 ]] || die "Guardian is not ready before the drill"

initial_attack=$(admin_curl "$admin_url/admin/attack")
record 'Initial attack state:'
code_start
jq . <<<"$initial_attack" | tee -a "$report"
code_end
[[ $(jq -r '.enabled // true' <<<"$initial_attack") == true ]] || die "attack mode is disabled"
[[ $(jq -r '.pinned // false' <<<"$initial_attack") == false ]] || die "attack posture is already pinned; preserving it"
[[ $(jq -r '.level // "normal"' <<<"$initial_attack") == normal ]] || die "attack posture is not normal before the drill"

snapshot 'Baseline'

before=$(origin_count)
run_load 'Raw HTTP refusal flood through Angie' observe \
  -url "$site_url" -scenario refuse-angie -host "$drill_host" \
  -c "$concurrency" -d "$duration"
after=$(origin_count)
record "Origin delta during refused flood: $((after - before)) (want 0)"
((after == before)) || die "refused flood reached the origin"

run_load 'Many-source low-rate phase (one request per synthetic source)' strict \
  -url "$auth_url" -scenario challenge -host "$drill_host" \
  -c 1 -n "$requests"

section 'Automatic detector after many-source traffic'
code_start
admin_curl "$admin_url/admin/attack" | jq . | tee -a "$report"
code_end

section 'Pin attack posture'
code_start
attack_response=$(admin_curl -H 'Content-Type: application/json' -X POST \
  -d '{"level":"attack","ttl":"10m"}' "$admin_url/admin/attack")
attack_changed=1
jq . <<<"$attack_response" | tee -a "$report"
code_end
[[ $(admin_curl "$admin_url/admin/attack" | jq -r .level) == attack ]] \
  || die "attack posture did not become attack"

run_load 'Challenge issuance flood under attack posture' strict \
  -url "$auth_url" -scenario challenge -host "$drill_host" \
  -c "$concurrency" -n "$requests"

if ((redemptions > 0)); then
  section 'Valid redemption activity'
  for ((i = 1; i <= redemptions; i++)); do
    record "### Journey $i/$redemptions"
    code_start
    : >"$tmp_dir/last-load.txt"
    "$loadtest" -url "$auth_url" -scenario token -host "$drill_host" \
      -ip "198.18.0.$(((i - 1) % 254 + 1))" -c 1 -n 1 2>&1 \
      | tee "$tmp_dir/last-load.txt" | tee -a "$report"
    code_end
    grep -Eq 'errors=0, unexpected-status=0, unexpected-contract=0' "$tmp_dir/last-load.txt" \
      || die "valid redemption journey $i failed; see $report"
  done
fi

section 'False-positive probes'
probe_200 'Guardian liveness under attack' "$admin_url/healthz"
probe_200 'Guardian readiness under attack' "$admin_url/readyz"
for url in "${probe_urls[@]}"; do
  probe_200 "Legitimate probe $url" "$url"
done

if [[ "$fault_mode" != skip ]]; then
  [[ -t 0 ]] || die "--fault-mode $fault_mode needs an interactive terminal"
  section "Operator-injected sidecar fault ($fault_mode)"
  record 'Inject a sidecar timeout, connection failure, or 5xx now.'
  read -r -p 'Press Enter when the fault is active... '
  fault_before=$(origin_count)
  fault_status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
    -H "Host: $drill_host" -H 'User-Agent: Mozilla/5.0 (Guardian drill)' \
    "$site_url/__guardian-drill-fault")
  fault_after=$(origin_count)
  record "Fault request: HTTP $fault_status; origin delta $((fault_after - fault_before))"
  if [[ "$fault_mode" == open ]]; then
    [[ "$fault_status" == 200 && $fault_after -eq $((fault_before + 1)) ]] \
      || die "fail-open did not resume the origin handler"
  else
    [[ "$fault_status" == 500 && $fault_after -eq $fault_before ]] \
      || die "fail-closed did not reject before the origin"
  fi
  read -r -p 'Restore the sidecar, then press Enter... '
  probe_200 'Guardian liveness after fault rollback' "$admin_url/healthz"
fi

if [[ -n "$block_ip" ]]; then
  section 'Block mirror and nftables offload'
  existing_block=$(admin_curl "$admin_url/admin/blocks/$block_ip")
  [[ $(jq -r '.blocked // false' <<<"$existing_block") == false ]] \
    || die "refusing to replace an existing block for $block_ip"
  code_start
  block_response=$(admin_curl -H 'Content-Type: application/json' -X PUT \
    -d '{"reason":"DDoS staging drill","ttl":"5m"}' \
    "$admin_url/admin/blocks/$block_ip")
  block_created=1
  jq . <<<"$block_response" | tee -a "$report"
  code_end
  record 'Offload status after block:'
  code_start
  admin_curl "$admin_url/admin/offload" | jq . | tee -a "$report"
  code_end
  probe_200 'Management access while drill IP is blocked' "$admin_url/healthz"
  blocked_status=$(curl --max-time 5 --silent --show-error --output /dev/null \
    --write-out '%{http_code}' -H "Host: $drill_host" "$site_url/__guardian-drill-block" || true)
  record "Blocked-client site probe: HTTP ${blocked_status:-connection failure} (403 for mirror, connection failure for nftables)"
  code_start
  admin_curl -X DELETE "$admin_url/admin/blocks/$block_ip" | jq . | tee -a "$report"
  code_end
  block_created=0
  probe_200 'Site after drill block rollback' "$site_url/__guardian-drill-block"
fi

section 'Restore automatic posture'
code_start
admin_curl -H 'Content-Type: application/json' -X POST \
  -d '{"level":"auto"}' "$admin_url/admin/attack" | jq . | tee -a "$report"
code_end
attack_changed=0

snapshot 'Final'
record "Completed (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
record "Report: $report"
