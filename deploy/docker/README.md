# Docker test harness

A semi-production stack for exercising Angie Guardian end to end without a real
site:

```
Angie (reverse proxy, auth_request)  ──►  guardiand (sidecar)  ──►  whoami backend
        :8080 on host loopback              internal only              internal only
```

It wires the full Path A topology — the `auth_request` decision flow, the PoW
challenge interstitial, WAF signature denies, behavioural blocking, the admin
API, and the fail-open toggle — so you can verify behaviour and reproduce
findings on a real Angie binary.

## Usage

```sh
cd deploy/docker
docker compose up --build -d
./smoke.sh                 # end-to-end assertions (expects 6/6)
docker compose down -v     # tear down + drop volumes
```

- Protected site: `http://127.0.0.1:8080`
- Admin API + `/metrics`: `http://127.0.0.1:8072` (token `harness-admin-token`)
- guardiand's hot path (8071) is **not** published — internal network only,
  mirroring production where the sidecar must not be directly reachable.

## What the smoke test checks

| Check | Expected |
|-------|----------|
| Allowlisted `/robots.txt` | reaches backend (200, whoami body) |
| Browser-shaped GET (`Mozilla` UA) | PoW challenge interstitial (200 HTML) |
| curl UA on PoW-always domain | passes WAF to backend |
| `/.env` signature | 403 deny (and places a behavioural block) |
| guardiand stopped | backend still served (fail-open) |

Because every request from the host shares one source IP (the Docker gateway),
a WAF deny blocks that IP; the smoke test clears the block via the admin API
between phases and runs the blocking probe last.

## Reproducing review findings

- **Metrics label cardinality (unbounded `domain` label):**
  ```sh
  for h in a.evil b.evil c.evil; do curl -s -o /dev/null -H "Host: $h" http://127.0.0.1:8080/; done
  curl -s http://127.0.0.1:8072/metrics | grep '^guardian_decisions_total' | grep -o 'domain="[^"]*"' | sort -u
  ```
  Each spoofed Host becomes its own series → unbounded growth under a Host flood.

- **Direct-reach header spoofing:** add `ports: ["127.0.0.1:8071:8071"]` to the
  guardiand service, then `curl -H 'X-Guardian-IP: 9.9.9.9' http://127.0.0.1:8071/auth`
  — the sidecar trusts the header when reached directly.

- **Fail-closed:** comment out `error_page 500 = @guardian_bypass;` in
  `angie.docker.conf`, `docker compose restart angie`, stop guardiand, and the
  site returns 500 instead of serving the backend.

## Notes on the configs here vs `deploy/`

`angie.docker.conf` uses `rewrite ^ /challenge break; proxy_pass http://guardian;`
in the named `@guardian_challenge` / `@guardian_denied` locations. A named
location cannot carry a URI part on `proxy_pass` (Angie rejects it at config
test), so the top-level `deploy/angie-guardian.conf` needs the same treatment.
