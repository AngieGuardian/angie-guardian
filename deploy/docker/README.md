# Docker test harness

A semi-production stack for exercising Angie Guardian end to end without a real
site:

```
Angie (reverse proxy, auth_request)  ──►  guardiand (sidecar)  ──►  whoami backend
        :8080 on host loopback              internal only              internal only
```

It wires the full Path A topology (the `auth_request` decision flow, the PoW
challenge interstitial, WAF signature denies, behavioural blocking, the admin
API, and the fail-open toggle) so you can verify behaviour and reproduce
findings on a real Angie binary.

## The end-to-end suite

The automated e2e tests live in `test/e2e/` (Go, `//go:build e2e`) and boot
**this** compose stack with [testcontainers-go](https://golang.testcontainers.org/),
drive traffic **through Angie**, and assert on the guardian's decisions and its
report surface (Prometheus `/metrics` + the admin API). Run them from the repo
root (Go and make are required; Docker is the only external service):

```sh
make e2e                              # or: go test -tags e2e ./test/e2e/...
```

The suite picks two free host ports, brings the stack up, runs every scenario,
and tears the stack (and its volumes) back down. It covers: allowlist passthrough,
PoW challenge issuance, a **full PoW solve through Angie** (challenge → solve →
cookie → vouched request → spent-challenge replay), the no-JS meta-refresh
fallback, WAF `deny`/`block`/`challenge` actions, scanner-UA blocking, per-domain
policy (`localhost` vs `api.localhost`), fail-open when guardiand is stopped, and
the `/metrics` + `/admin/*` report surface.

Because every request from the host shares one source IP (the Docker gateway), a
WAF `block` blocks that IP; the harness clears such blocks via the admin API
(`DELETE /admin/blocks/{ip}`) around block-placing tests so they can't poison the
rest of the run.

## Prebuilt image

Every release publishes the sidecar image to the project's container registry
(built by the `docker-release` CI job from this directory's Dockerfile):

```sh
docker pull registry.melroy.org/melroy/angie-guardian:latest   # or a tag, e.g. :0.7.0
```

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
[Alerting](https://angie-guardian-31c118.pages.melroy.org/guide/production#alerting)
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

Keep the two structurally in sync (hosts, thresholds, admin token); the e2e
assertions depend on those exact values.

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

Both harness configs include the exact top-level `deploy/angie-guardian.conf`
and `deploy/angie-guardian-location.conf` files shipped to operators. The
server glue uses a rewrite plus a pathless `proxy_pass` in named locations,
because Angie rejects a URI part on `proxy_pass` there.
