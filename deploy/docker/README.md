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
root (Docker is the only prerequisite):

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
docker pull registry.melroy.org/melroy/angie-guardian:latest   # or a tag, e.g. :0.6.0
```

The image runs `guardiand -config /etc/guardian/guardian.yaml` as a nonroot
user; mount your config read-only at that path and persist
`/var/lib/guardian` (bbolt store) and `/etc/guardian/keys` (signing key), as
`compose.yaml` here does.

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

- `guardian.docker.yaml` — the manual demo harness (mounted by default):
  realistic PoW difficulty (5.5, so the interstitial is perceptible on a fast
  desktop).
- `guardian.e2e.yaml` — the automated suite's config, selected via
  `GUARDIAN_CONFIG=./guardian.e2e.yaml`: identical except for a lower PoW
  difficulty (4), because the suite brute-forces every challenge in Go and
  asserts exact escalation values (16 bits + 4 = 20).

Keep the two structurally in sync (hosts, thresholds, admin token); the e2e
assertions depend on those exact values.

## Reproducing review findings

- **Metrics label cardinality (unbounded `domain` label):**
  ```sh
  for h in a.evil b.evil c.evil; do curl -s -o /dev/null -H "Host: $h" http://127.0.0.1:8080/; done
  curl -s http://127.0.0.1:8072/metrics | grep '^guardian_decisions_total' | grep -o 'domain="[^"]*"' | sort -u
  ```
  Each spoofed Host becomes its own series → unbounded growth under a Host flood.

- **Direct-reach header spoofing:** add `ports: ["127.0.0.1:8071:8071"]` to the
  guardiand service, then `curl -H 'X-Guardian-IP: 9.9.9.9' http://127.0.0.1:8071/auth`
  the sidecar trusts the header when reached directly.

- **Fail-closed:** comment out `error_page 500 = @guardian_bypass;` in
  `angie.docker.conf`, `docker compose restart angie`, stop guardiand, and the
  site returns 500 instead of serving the backend.

## Notes on the configs here vs `deploy/`

`angie.docker.conf` uses `rewrite ^ /challenge break; proxy_pass http://guardian;`
in the named `@guardian_challenge` / `@guardian_denied` locations. A named
location cannot carry a URI part on `proxy_pass` (Angie rejects it at config
test), so the top-level `deploy/angie-guardian.conf` needs the same treatment.
