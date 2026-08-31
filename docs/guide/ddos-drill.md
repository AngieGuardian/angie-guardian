# DDoS and Attack-Mode Drill

Run this exercise on disposable staging after changing capacity, proxy
topology, attack-mode thresholds, Angie admission, the store, or block offload.
The goal is to measure where traffic is rejected and what reaches the origin,
not to produce a flattering request-rate number.

::: danger Never point the drill at production
The drill deliberately generates floods, pins attack mode, solves challenges,
can stop or fault the sidecar, and can block the runner's source address. Use a
staging hostname with isolated capacity, a private admin/auth path, an origin
request counter, and an operator who can recover access out of band.
:::

## What the drill proves

| Phase | Required result |
|---|---|
| Raw HTTP refusal flood through Angie | Expected `403`s, measured throughput/latency, zero origin delta |
| Attack pin | Every replica reports `level:"attack"`, `pinned:true`, stateless issuance active |
| Challenge flood | Issuance ceiling and rejection point recorded; store and evaluate latency remain visible |
| Many-source low-rate traffic | One request per synthetic address; aggregate detector signals/posture recorded without crossing a per-IP threshold |
| Valid redemption activity | Real challenge/solve/pass journeys succeed; failures and solve time are recorded |
| Sidecar timeout/5xx | Fail-open serves exactly the original handler; fail-closed rejects before the origin |
| Block offload | Mirror denies cheaply; nftables, when enabled, drops only public ports; management remains reachable |
| False-positive probes | Existing token, health, readiness, ACME, operator, and selected application probes remain usable |

The repository already tests the safety contracts in `TestAttackModeTrips`,
`TestFailOpenWhenGuardianDown`, `TestStoreOutageFailOpen`,
`TestBlockOffloadMirror`, and the separately gated nftables suite. The staging
drill complements those deterministic tests with the target host's actual
ceilings and operator procedures.

## Prepare staging

Before starting:

- Use the same Guardian/Angie versions, limits, store type, proxy trust, and
  machine class as production where practical.
- Keep the public site, private admin listener, and private auth listener on
  separate explicit URLs. Never publish the auth listener to the internet.
- Provide a private `origin-count-url` that returns one integer and is not
  routed through the public site. The E2E backend's management listener exposes
  `/count` for this purpose.
- Enable attack mode and begin at automatic `normal` posture. The runner refuses
  an existing pin or a non-normal starting posture rather than overwriting an
  operator decision.
- Choose a PoW-enabled host for challenge/redemption phases. The same host must
  produce the refusal contract used by `guardian-loadtest` for the raw flood.
- Put `/healthz`, `/readyz`, an ACME test path, and one representative legitimate
  application URL on the probe list.
- Record quiet-host CPU, RSS, open files, bandwidth, Guardian metrics, backend
  request count, and application latency for at least five minutes.

Build the existing load generator and inspect the exact plan:

```sh
make build
bash scripts/ddos-drill.sh --plan
```

## Run the traffic phases

The runner has no target defaults. The admin token is accepted only through the
environment so it is not exposed in the process list or copied into the report.

```sh
export GUARDIAN_DRILL_ADMIN_TOKEN="$(sudo cat /var/lib/guardian/admin.token)"

make ddos-drill DDOS_DRILL_ARGS='\
  --ack-staging \
  --site-url https://drill.example.test \
  --admin-url http://127.0.0.1:8072 \
  --auth-url http://127.0.0.1:8071 \
  --host drill.example.test \
  --origin-count-url http://127.0.0.1:18081/count \
  --concurrency 32 --duration 10s --requests 1000 --redemptions 5 \
  --probe-url https://drill.example.test/.well-known/acme-challenge/drill \
  --probe-url https://drill.example.test/account'
```

Run at least three concurrency steps, for example 8, 32, and 128, on a quiet
host. Stop increasing load when any abort condition appears. Use the same flags
when comparing releases or hosts. The report records:

- the exact commit, target, flags, and start/end time;
- `guardian-loadtest` throughput, latency, errors, unexpected statuses, and
  per-second completions;
- Guardian health, readiness, attack/offload/stats output and selected metrics;
- origin request counts before and after traffic;
- false-positive probes and cleanup results.

Read the per-second counts before accepting an aggregate. A falling line means
the system was not at steady state. Record the first concurrency where p99
latency, errors, shedding, store latency, backend saturation, or false-positive
impact crosses its allowed bound as the rejection point. Set production alerts
and admission below the last clean step, with operational headroom.

### Why the phases use existing scenarios

- `refuse-angie` sends original HTTP requests through Angie's real
  `/auth -> @guardian_challenge` refusal path and proves they do not touch the
  origin. Its contract expects the ordinary refusal `403`; once Angie's
  per-client control-plane admission starts returning `429`, the load tool
  records those as unexpected statuses. In this phase they identify the
  intended rejection point rather than a drill failure, provided the origin
  delta stays zero.
- `challenge` rotates a synthetic private address on every direct auth request.
  At normal concurrency it is the challenge flood; with `-c 1`, every source
  contributes exactly one request and remains below per-client thresholds.
- Repeated one-request `token` runs perform real issue, solve, redemption, and
  vouched-auth journeys. They deliberately pay the proof of work instead of
  manufacturing a work-free valid-redemption flood that cannot exist in
  production.

## Exercise sidecar failure

Pass `--fault-mode open` or `--fault-mode closed` to add an interactive fault
phase. The runner pauses without executing platform-specific service commands.
At the prompt, inject one reviewed staging fault:

```sh
# systemd staging: connection failure / Angie-generated upstream 502
sudo systemctl stop guardiand

# Docker staging
docker compose stop guardiand
```

Use a fault proxy in the staging Guardian upstream when the exercise must
distinguish a delayed response from an explicit sidecar `500`. Delay it beyond
Angie's configured two-second auth timeout, then return a plain `500` in a
separate pass. Do not change the application upstream.

The runner sends a marked request and checks both its status and the private
origin counter:

- fail-open: `200` and origin delta exactly one;
- fail-closed: `500` and origin delta zero.

Restore the sidecar at the second prompt. The runner requires `/healthz` to
recover. Also inspect Angie logs: the failing upstream must be Guardian, while
an application 5xx after a successful authorization remains an application
alert.

For the deeper store-outage case, run the existing deterministic chaos test. It
pauses Valkey to consume the full timeout budget, then stops/restarts it and
verifies readiness, stateless fallback, block retention, limiter behavior, and
clean recovery:

```sh
go test -tags e2e -run '^TestStoreOutageFailOpen$' -count=1 \
  -timeout 15m ./test/e2e/...
```

## Exercise block offload

Only use `--block-ip` when it is the exact source address Guardian sees for the
drill runner, management uses a different safe path, and the address is not a
CDN, load-balancer, NAT gateway, or shared operator address.

```sh
# Add to the normal command:
--block-ip 198.51.100.44
```

The runner creates a five-minute manual block, captures `/admin/offload`, checks
that management stays reachable, probes the public site, deletes that exact
block, and verifies recovery. A mirror-only deployment should return `403`; a
healthy nftables sink should cause a connection failure on its configured
public port.

Run the kernel-specific automated proof separately. It skips when the runtime
cannot grant `NET_ADMIN` or the kernel lacks nftables; a skip is not a pass and
must be recorded in the drill report:

```sh
make e2e-nft
```

## Abort conditions

Stop load immediately and begin cleanup when any of these occurs:

- management or out-of-band access becomes unreliable;
- origin bandwidth or backend saturation crosses the staging safety limit;
- `/healthz` fails outside the deliberate fault phase;
- `/readyz` degrades outside a deliberate store fault;
- an ACME, operator, existing-token, or legitimate application probe fails;
- the origin count moves during a phase that should reject before the origin;
- the attack pin, manual block, or temporary route cannot be rolled back;
- traffic reaches any address outside the documented staging target.

The runner installs cleanup traps and gives the attack pin a ten-minute TTL,
but neither replaces an operator. After an abort, explicitly verify attack mode
is back on `auto`, the drill block is absent, the sidecar is running, temporary
fault routing is removed, and Angie has the known-good configuration.

## Record the result

Attach the generated Markdown report to the change or incident record and add
the host-level measurements the runner cannot observe: CPU, RSS, file
descriptors, connection counts, bandwidth, application queue depth, and
provider rejection counters. Summarize each phase with:

The report contains internal URLs and authenticated operational state. Store it
with incident evidence, restrict access, and apply the site's normal retention
and privacy policy; do not publish it as a benchmark artifact.

| Phase | Offered load | Accepted/rejected | p99 | First rejection | Origin delta | False positives | Result |
|---|---:|---:|---:|---|---:|---:|---|
| Raw HTTP | | | | | | | |
| Challenge | | | | | | | |
| Many-source | | | | | | | |
| Redemption | | | | | | | |
| Sidecar fault | | | | | | | |
| Block offload | | | | | | | |

Record measured ceilings as properties of this exact host, topology,
configuration, and commit, not as universal Guardian limits. Follow the
[incident runbook](/guide/ddos-incident-runbook) to turn those measurements
into alert and emergency-action thresholds.
