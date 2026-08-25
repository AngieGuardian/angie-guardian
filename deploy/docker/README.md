# Docker test harness

A semi-production stack for exercising Angie Guardian end to end without a real
site:

```
Angie (reverse proxy, auth_request)  ──►  guardiand (sidecar)  ──►  whoami backend
        :8080 on host loopback              internal only              internal only
```

It wires the full Path A topology (the `auth_request` decision flow, the PoW
challenge interstitial, WAF rules denies, behavioural blocking, the admin
API, and the fail-open toggle) so you can verify behaviour and reproduce
findings on a real Angie binary.

## The end-to-end suite

The automated e2e tests live in `test/e2e/` (Go, `//go:build e2e`) and boot
`compose.e2e.yaml` with [testcontainers-go](https://golang.testcontainers.org/),
drive traffic **through Angie**, and assert on the guardian's decisions and its
report surface (Prometheus `/metrics` + the admin API). Run them from the repo
root (Go and make are required; Docker is the only external service):

```sh
make e2e                              # or: go test -tags e2e ./test/e2e/...
```

The suite picks five free host ports (including a generated-certificate TLS
listener), brings the stack up, runs every scenario,
and tears the stack (and its volumes) back down. It covers: allowlist passthrough,
PoW challenge issuance, **full SHA-256 and Argon2id solves through Angie**
(challenge → solve → cookie → vouched request, plus SHA-256 spent-challenge
replay), the no-JS meta-refresh
fallback, WAF `allow`/`deny`/`block`/`challenge` actions, scanner-UA blocking, per-domain
policy (`localhost` vs `api.localhost`), fail-open when guardiand is stopped,
Guardian control-plane and operator-defined application admission shedding
(each verified against an origin request counter), and the `/metrics` +
`/admin/*` report surface. It also covers TLS 1.2/1.3, HTTP/2 ALPN and SETTINGS,
stalled TLS/header/body clients, body-size and keepalive limits, decoded HTTP/2
header limits, repeated stream resets, origin isolation, and recovery.

For a longer manual reset soak with no timing gate:

```sh
make e2e-angie-soak ANGIE_HARDENING_SOAK_DURATION=5m
```

Because every request from the host shares one source IP (the Docker gateway), a
WAF `block` blocks that IP; the harness clears such blocks via the admin API
(`DELETE /admin/blocks/{ip}`) around block-placing tests so they can't poison the
rest of the run.

## Prebuilt image

Every release publishes the same sidecar image to the GitLab and GitHub
container registries (built by the `docker-release` CI job from this
directory's Dockerfile):

```sh
docker pull registry.melroy.org/melroy/angie-guardian:1.0.0
docker pull ghcr.io/angieguardian/angie-guardian:1.0.0
```

Images from 1.0.0 onward are signed by Cosign. Download `SHA256SUMS`,
`SHA256SUMS.asc`, `RELEASE-KEY.asc`, and `cosign.pub` from the matching GitLab
or GitHub release. First verify the GPG fingerprint and signature exactly as in
the [release verification guide](https://angieguardian.org/guide/release-verification),
then authenticate the Cosign key through the signed checksum list and verify
the image:

```sh
sha256sum -c --ignore-missing SHA256SUMS  # must report cosign.pub: OK
cosign verify --key cosign.pub \
  registry.melroy.org/melroy/angie-guardian:1.0.0
cosign verify --key cosign.pub \
  ghcr.io/angieguardian/angie-guardian:1.0.0
```

Each registry carries its own signature for the image digest it serves. The
digest can differ across registries because a registry may canonicalize the
manifest differently. Cosign resolves the tag and verifies that the attached
signature claims that registry's digest. For a deployment manifest, pin a
verified digest rather than the mutable `latest` tag.

The image runs `guardiand -config /etc/guardian/guardian.yaml` as a nonroot
user; mount your config read-only at that path and persist
`/var/lib/guardian` (pebble store directory) and `/etc/guardian/keys` (signing
key), as `compose.yaml` here does. Its distroless-safe healthcheck runs the built-in
`-healthcheck` probe and requires every configured `/healthz` listener before
Compose marks Guardian healthy or starts Angie.

That probe is **liveness**: it deliberately does not follow the store, because
Guardian serves fail-open and a store outage must not restart-loop a container
that is still protecting traffic. For readiness ("is the store actually
working?") poll `GET /readyz` on the admin listener; it returns `503` while the
store probe is pending, failing or stale. See
[Alerting](https://angieguardian.org/guide/production#alerting)
for the shipped Prometheus rules.

## Manual use

```sh
cd deploy/docker
docker compose up --build -d
docker compose down -v     # tear down + drop volumes
```

- Protected site: `http://127.0.0.1:8080` (override with `GUARDIAN_SITE_PORT`)
- Admin API + `/metrics`: `http://127.0.0.1:8072` (token `harness-admin-token`,
  override the host port with `GUARDIAN_ADMIN_PORT`)
- Dashboard login: `http://127.0.0.1:8072/admin/dashboard#token=harness-admin-token`
- guardiand's hot path (8071) is **not** published (internal network only),
  mirroring production where the sidecar must not be directly reachable.

## Two guardian configs

- `guardian.docker.yaml`: the manual demo harness (mounted by default):
  realistic PoW difficulty (5.5, so the interstitial is perceptible on a fast
  desktop).
- `guardian.e2e.yaml`: the automated suite's config, selected via
  `GUARDIAN_CONFIG=./guardian.e2e.yaml`: identical except for a lower PoW
  difficulty (4), because the suite brute-forces every challenge in Go and
  asserts exact escalation values (16 bits + 4 = 20).

Keep their shared hosts, thresholds, and admin token in sync; the E2E config
also carries test-only hosts whose assertions depend on their exact values.

`rules-common.yaml` is kept byte-for-byte in sync with the shipped
`deploy/rules-common.yaml` starter. `rules-api.yaml` is an E2E-only domain
addition used by `rules.localhost` to exercise cumulative rule files and an
Accept-header allow without weakening the shared starter policy.

## Reproducing review findings

- **Metrics label cardinality regression check:**
  ```sh
  for h in a.evil b.evil c.evil; do curl -s -o /dev/null -H "Host: $h" http://127.0.0.1:8080/; done
  curl -s http://127.0.0.1:8072/metrics | grep '^guardian_decisions_total' | grep -o 'domain="[^"]*"' | sort -u
  ```
  All unconfigured Host values must collapse to one `domain="default"` series.

- **Direct-reach header spoofing:** add `ports: ["127.0.0.1:8071:8071"]` to the
  guardiand service, then `curl -H 'X-Guardian-IP: 9.9.9.9' http://127.0.0.1:8071/auth`
  the sidecar trusts the header when reached directly.

- **Fail-closed:** comment out the `error_page 500 502 503 504 =
  @guardian_fail_open;` line in the mounted top-level
  `deploy/angie-guardian.conf`, `docker compose restart angie`, stop guardiand,
  and the site returns 500 instead of resuming the backend handler.

## Notes on the configs here vs `deploy/`

Both harness configs include the exact top-level `deploy/angie-guardian.conf`,
`deploy/angie-guardian-location.conf`, and optional `deploy/angie-hardening-*.conf`
files shipped to operators. The
server glue uses a rewrite plus a pathless `proxy_pass` in named locations,
because Angie rejects a URI part on `proxy_pass` there.
