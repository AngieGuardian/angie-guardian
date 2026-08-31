# DDoS Incident Runbook

Use this checklist when an HTTP attack is affecting a Guardian-protected site.
Keep a copy with the on-call material: the public documentation may be
unreachable during the incident.

::: danger Guardian is not a volumetric DDoS terminator
Guardian sees a request only after Angie has accepted the connection and parsed
HTTP. A CDN, DDoS provider, load balancer, firewall, or ISP must absorb bandwidth
exhaustion, SYN floods, connection floods, TLS-handshake floods, and QUIC abuse.
Angie owns request parsing, HTTP/2 streams, slow clients, request sizes, and
local connection admission. Guardian owns Layer-7 decisions after that point.
:::

## First five minutes

1. Open an incident record and note the start time, affected hosts, current
   release, Guardian configuration hash, and Angie configuration hash.
2. Check upstream bandwidth and connection saturation first. If either is near
   capacity, enable the provider's attack control before changing Guardian.
3. Confirm management access uses a path that cannot be blocked by the public
   traffic policy. Keep the current shell open.
4. Capture the current state before changing it:

   ```sh
   export A=http://127.0.0.1:8072
   export TOKEN="$(sudo cat /var/lib/guardian/admin.token)"
   date -u
   curl -fsS "$A/healthz"
   curl -sS "$A/readyz" | jq .
   curl -fsS -H "Authorization: Bearer $TOKEN" "$A/admin/attack" | jq .
   curl -fsS -H "Authorization: Bearer $TOKEN" "$A/admin/stats" | jq .
   curl -fsS -H "Authorization: Bearer $TOKEN" "$A/admin/offload" | jq .
   curl -fsS -H "Authorization: Bearer $TOKEN" "$A/metrics" > guardian-metrics.before.txt
   ```

5. Decide which layer is saturated, then make one bounded change at a time.
   Record the command, timestamp, result, and rollback owner.

## Control ownership

| Symptom or control | Owning layer | Do not expect from Guardian |
|---|---|---|
| Link saturation, packet loss before the host | ISP, CDN, DDoS/L4 provider | Recover bandwidth already exhausted upstream |
| SYN, connection, TLS, or QUIC handshake flood | Provider, firewall/kernel, Angie | Inspect a request that Angie has not decoded |
| Slow headers/body, oversized input, HTTP/2 stream abuse | Angie hardening profile | Apply request-parser or socket timeouts |
| Site request-rate and backend concurrency | Angie/site policy | Guess the application's safe capacity |
| Challenge flood, distributed low-solve HTTP traffic | Guardian attack mode | Replace upstream admission |
| Known blocked-address flood | Guardian mirror; optional nftables | Drop packets before Angie unless nftables is enabled |
| Database, PHP, application 5xx, expensive routes | Application/origin | Convert an application failure into auth fail-open |

## Required preparation

Do these before an incident. If one is missing during an attack, treat the
remediation as a risky emergency change rather than an established control.

- Put a CDN or L4 mitigation service in front of the public address and make the
  origin private or firewall it to the provider's current egress ranges.
- Restore the real client address in Angie using only authenticated proxy
  sources. Verify `$remote_addr` in the access log; never trust a public
  `X-Forwarded-For` header.
- Include the Guardian control-plane limits and the optional Angie hardening
  profile. Add a site-specific request limit sized from a measured backend
  ceiling; never rate-limit `/__guardian/auth` directly.
- Keep SSH, the Guardian admin listener, metrics, and the origin management
  interface private. Test access from the on-call network.
- Preserve `/healthz`, `/readyz`, and ACME HTTP-01 handling. Put CDN/LB ranges in
  `enforcement.nftables.never_block`, and scope managed nftables drops to public
  ports only.
- Load the shipped Prometheus alerts and import the Grafana dashboard. Run the
  [staging drill](/guide/ddos-drill) after capacity or topology changes.
- Keep the current Guardian and Angie configs, the previous known-good copies,
  and their validation/reload commands in the incident system.

Verify the local boundaries before relying on them:

```sh
sudo angie -t
sudo -u guardian guardiand -config /etc/guardian/guardian.yaml -t
sudo ss -lntup
curl -fsS http://127.0.0.1:8072/healthz
curl -fsS http://127.0.0.1:8072/readyz
```

## Detect and classify

Thresholds are starting points, not universal capacity promises. Establish the
real rejection point with the drill, then alert before it. Attack-mode
thresholds are per Guardian instance; edge, origin, and bandwidth values are
fleet totals unless their dashboards say otherwise.

| Signal | Starting incident trigger | Where to read it |
|---|---|---|
| Public request rate | Sustained above twice the same-period baseline or 80% of the measured safe ceiling | CDN/LB and Angie request counters |
| Challenge issuance | Above configured `challenge_rate`; attack candidate above `attack_challenge_rate` | `guardian_attack_mode_signal{signal="challenge_rate"}` and `guardian_challenges_total{outcome="issued"}` |
| Solve ratio | Below configured `min_solve_ratio` while issuance is high | `guardian_attack_mode_signal{signal="solve_ratio"}` |
| Guardian shedding | Any sustained `shed` rate; urgent when legitimate probes fail | `rate(guardian_shed_total{outcome="shed"}[5m])` |
| Store errors | More than 5% over 10 minutes with at least 20 operations | `GuardianStoreErrors`, `/admin/stats` |
| Store latency | More than 25% of operations above 25 ms, or p99 above the drilled limit | attack signal and `guardian_store_op_seconds` |
| Backend saturation | 80% of the measured CPU, worker, connection, or queue ceiling | Application and host monitoring |
| Origin bandwidth | 70% warning, 85% urgent, or provider-specific headroom | Host/provider interface metrics |
| Protection availability | `GuardianScrapeAbsent` or `guardian_store_up == 0` | Prometheus alerts and `/readyz` |

A low solve ratio alone is not proof of an attack: an excessive difficulty or a
broken challenge page looks the same. Compare solve time, browser errors, and a
known-good client before escalating.

### Protection alerts versus application errors

- `GuardianScrapeAbsent` means the admin/metrics target vanished. In the
  default fail-open topology, assume protection may be absent even if the site
  still returns `200`.
- `GuardianStoreDown` means stateful protection is failing open while Guardian
  remains live. `/healthz` deliberately stays green; `/readyz` turns `503`.
- `GuardianStoreErrors`, `GuardianRedeemInternalErrors`, and
  `GuardianStatelessSpendFallback` identify partial Guardian degradation.
- `GuardianLoadShedding` is an intentional Guardian rejection, not an
  application 5xx.
- An origin or FastCGI 5xx occurs after authorization and is not intercepted by
  `@guardian_fail_open`. Keep application 5xx alerts separate. In Angie logs,
  check whether the failing upstream is `guardian` or the application before
  declaring a protection outage.

## Emergency actions

Every action below includes a check and a rollback. Prefer a pre-tested control;
do not introduce nftables, a new proxy trust range, or fail-closed behavior for
the first time while under pressure.

| Action | Apply | Verify | Roll back |
|---|---|---|---|
| Enable provider attack controls | Use the provider's saved API/UI procedure and attach its change ID to the incident | `curl -sv --resolve HOST:443:EDGE_IP https://HOST/health` from outside, plus provider traffic and origin-bandwidth graphs | Disable the incident rule by its exact change ID after traffic normalizes; repeat the external probe |
| Pin Guardian attack mode | `curl -fsS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"level":"attack","ttl":"30m"}' "$A/admin/attack"` on every replica | `curl -fsS -H "Authorization: Bearer $TOKEN" "$A/admin/attack" | jq '{level,pinned,effects}'` and `guardian_attack_mode == 2` | POST `{"level":"auto"}` to every replica and verify `pinned:false`; a TTL is only the safety net |
| Tighten a pre-tested Angie site limit | Restore the prepared incident include, then `sudo angie -t && sudo systemctl reload angie` | `sudo angie -T`, expected `429` at the tested boundary, and no rise in origin requests for rejected traffic | Restore the saved normal include, run `angie -t`, reload, and verify the normal limit |
| Disable an expensive route | Enable its prepared Angie maintenance/`return 503` include before `proxy_pass`; validate and reload | `curl -i https://HOST/ROUTE` returns the planned status and the origin counter does not move | Remove only that incident include, validate/reload, and make one known-good request |
| Serve a bare deny response | Uncomment the documented `return 403;` in `@guardian_denied`; validate/reload | A known denied request returns a small `403`; Guardian/origin request counts do not rise for repeats | Restore the styled denied-page proxy, validate/reload, and verify one denial |
| Enable prepared nftables offload | Enable only the reviewed config with public `ports` and complete `never_block`; restart Guardian if required | `GET /admin/offload`, `nft list table inet guardian`, a test block drops only public traffic, and admin/SSH remain reachable | Set `enabled:false`, restart, verify the table is gone or empty and mirror enforcement still denies the test IP |
| Change fail mode | Use only the pre-approved variant of the 5xx `error_page` in `/__guardian/auth`; `angie -t` and reload | Stop or fault the sidecar: fail-open must serve the origin; fail-closed must return `500` without an origin delta | Restore the normal snippet, validate/reload, restart Guardian, and repeat the fault probe |

Never allowlist an attacking address merely to reduce load. Do not add a broad
trusted-proxy range, remove the origin firewall, expose the auth/admin listener,
or kernel-block a CDN/LB address. Preserve these exceptions explicitly:

- operator and monitoring source ranges;
- `/healthz` and `/readyz` on the private admin listener;
- ACME HTTP-01 if it is used during the incident;
- load balancer and CDN ranges in nftables `never_block`;
- the application's already-tested machine/API PoW exemptions.

## Recovery and rollback

1. Confirm public rate, connection count, origin bandwidth, Guardian latency,
   store health, and backend saturation remain below the entry threshold for at
   least one full attack-mode window and `min_dwell`.
2. Return every replica to automatic posture. Existing proof tokens remain
   valid throughout an attack-mode change; do not rotate signing keys as a
   traffic-control measure.
3. Restore expensive routes and normal Angie limits one change at a time. Run
   `angie -t`, reload, and probe after each change.
4. Remove only incident-created manual blocks. The delete operation also clears
   the counters that could immediately re-block the address:

   ```sh
   curl -fsS -H "Authorization: Bearer $TOKEN" -X DELETE \
     "$A/admin/blocks/203.0.113.9" | jq .
   ```

   Investigate an `incomplete:true` response before declaring cleanup complete.
5. Verify `/readyz` is `200`, `guardian_store_up` is `1`, store error counters
   have stopped increasing, stateless fallback has stopped increasing, and new
   stateful challenge/solve/replay behavior works.
6. Confirm nftables entries expire or are removed, offload is healthy, the block
   mirror is complete, and management access still works.
7. Retain the before/after metric snapshots, alert timeline, Angie/Guardian and
   application logs, provider graphs, configuration diffs, commands, block
   list, drill/incident report, and relevant packet samples according to the
   site's privacy and retention policy.

Close the incident only after the origin is private again, all temporary pins
and route changes are gone, alerts are green, and the rollback has a second
operator's review.
