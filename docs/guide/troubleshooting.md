# Troubleshooting

Symptoms you're most likely to hit, and what causes them. Most are
configuration or environment issues, not bugs.

## The challenge page reloads forever

A browser solves the proof-of-work, gets redirected, and lands right back on
the interstitial, in a loop.

**Cause:** the token cookie is being set `Secure` but the client connection is
plain HTTP, so the browser refuses to store it and arrives at the next request
still unvouched. Guardian sets the cookie `Secure` by default and only drops it
when Angie tells it the connection is plain HTTP.

**Fix:** make sure Angie passes the scheme through. The solution endpoint must
carry `X-Guardian-Proto: $scheme` (it's in the shipped
[`deploy/angie-guardian.conf`](https://gitlab.melroy.org/melroy/angie-guardian/-/blob/main/deploy/angie-guardian.conf)). If you serve the site over plain HTTP on purpose,
that header lets Guardian drop `Secure` so the cookie sticks; if you serve
HTTPS, the header should be `https` and the loop shouldn't happen. Terminating
TLS upstream? Ensure `$scheme` reflects the *client's* scheme, not the
Angie→backend hop.

## Legitimate visitors get challenged or blocked

**A shared source IP (office NAT, corporate proxy) gets blocked.** Behavioural
blocks are per-IP, so one bad actor behind a NAT can score a block that hits
everyone sharing that egress. Put known-good shared ranges on
`allowlist.ips`: allowlisted IPs are never scored.

**A real crawler is being challenged instead of allowed.** Verified-bot
allowlisting needs the crawler's IP to reverse-DNS *and* forward-confirm. Check
with the admin API: `GET /admin/intel/<ip>` and the bot's rDNS. A cold PTR
lookup can take over a second; the first request from a new crawler IP may be
challenged before verification completes, then cached. If a genuine crawler
never verifies, its rDNS may not match the configured domains; see
[Bots, GeoIP & Reputation](/guide/bots-ip-intel).

**Everyone is challenged too aggressively.** If `pow.mode: always`, every
unvouched request is challenged once per `token_ttl`. Lower `base_difficulty`
or switch to `pow.mode: suspicion` (disables the catch-all; explicit anomaly,
WAF, GeoIP, and reputation challenge policies still apply); see
[Configuration](/guide/configuration).

## "Guardian is down but the site still works"

This is **fail-open** working as designed. When guardiand is unreachable, Angie's
internal auth location converts its own upstream error to `204`, so
`auth_request` allows the request and Angie resumes the vhost's original
static, FastCGI, or proxy handler. The site stays up; it is just unprotected
until Guardian returns.

**Don't mistake this for health.** Alert on it: watch the systemd unit
(`Type=notify` marks the service failed if it wedges), the `/metrics` endpoint,
and store connectivity via `guardian_store_up`. `deploy/alerts.yaml` ships the
rules; see [Alerting](/guide/production#alerting).

To verify fail-open is wired correctly, stop guardiand and confirm the site
still serves. If it returns 500 instead, check the 5xx `error_page` and
`@guardian_fail_open` target in `deploy/angie-guardian.conf`. To deliberately
fail closed, comment out that `error_page`; you may then also comment out the
unused named location, but removing only the still-referenced target makes the
Angie configuration invalid.

## `/readyz` says degraded

`/readyz` returns `503` only when **store** readiness is not established. The
process is still serving: Guardian [fails open](/guide/threat-model), so traffic
keeps flowing while single-spend, behavioural scoreboards and blocks are not
working. `/healthz` staying `200` in this state is correct, not a bug.

The body carries one of four coarse reasons:

| `reason` | What to do |
|---|---|
| `store probe pending` | The daemon just started and no probe has completed. Give it a few seconds. |
| `store probe unavailable` | No probe is attached. This is a wiring fault, not a store fault, and should not happen with a configured `admin.listen`. |
| `store probe failed` | The write/read-back round trip failed. This is the real one. |
| `store probe stale` | No probe completed for three intervals. The probe loop is wedged; treat the store as down and check for a hung backend. |

The reason is deliberately coarse: `/readyz` is unauthenticated and raw backend
errors can carry addresses, DSN credentials and filesystem paths. For the
detail, read the log (guardiand logs one `store probe failed` warning per
transition, not per tick) or the `health.store.error` field of the token-guarded
[`GET /admin/stats`](/reference/admin-api#get-admin-stats):

```sh
curl -s -H "Authorization: Bearer $TOKEN" localhost:8072/admin/stats \
  | jq .health.store
```

Common causes, in the order worth checking:

- **Redis/Valkey unreachable**: wrong `store.addr`, a firewall, or the server
  simply down. The raw error usually says so verbatim.
- **Disk full or read-only filesystem** on a `pebble`/`buntdb` backend. The
  probe writes *and reads back*, so a backend that accepts writes and silently
  loses them fails here even though a ping would pass.
- **Permissions** on `store.path` after a unit or user change.

A degraded nftables sink or a raised attack posture appear in the `/readyz` body
but never change the status code: both are still protecting traffic. If the
`enforcement` block shows an unhealthy sink, see
[Block Enforcement Offload](/guide/block-offload).

## Admin API returns 401

The bearer token doesn't match. Precedence, highest first:

1. `admin.token` in `guardian.yaml` (or the `ADMIN_TOKEN` env var),
2. the persistent `admin.token_file` (auto-generated `0600` on first start),
3. for a **loopback** admin bind only, an ephemeral token minted per start and
   printed in the startup log.

If you set none of these and bound `admin.listen` to a **non-loopback** address,
guardiand refuses to start (it will not expose an unauthenticated admin API).
Using `token_file`? The live token is whatever's in the file, not what the YAML
says. Check the startup log line `admin token loaded`/`generated`.

## Config edit didn't take effect

Most of `guardian.yaml` hot-reloads on `SIGHUP` / `POST /admin/reload`
(domains, lists, thresholds, difficulty, rules/model/geoip/feed sources,
`log_level`). A handful of fields are fixed at startup (`listen`,
`admin.listen`, `trusted_proxy`, the `store` block, signing key paths, and the
admin token/token-file/dashboard setup), and a
reload that changes one is rejected. If you changed one of those, restart the
daemon. The running config stays active after any rejected reload and the error
is logged (or returned `422` from the admin endpoint). Validate the config and
its startup-required local artifacts before reloading with `guardiand -config … -t`.

## Challenge issuance is slow / the store can't keep up

Under a very high rate of *new* clients (each triggering a challenge write),
the embedded writer becomes the ceiling: ~39k issuances/s on `pebble` async,
~36k/s on `buntdb` async, and ~25k/s on `pebble` with `sync: true`
(fsync-per-write) on the reference machine. Symptoms: rising challenge
latency, `guardian_store_op` latency climbing. Set `store.sync: false` (the
default) if you had turned fsync on, move to the `redis`/`valkey` backend to
share the write across replicas, set `pow.mode: suspicion` so most requests do
no write, or enable [attack mode](/guide/attack-mode), whose stateless issuance
removes the write at issue time entirely when a flood trips the posture. See
[Choosing a store backend](/guide/production#choosing-a-store-backend).

## Tokens rejected across replicas / after a restart

Multi-instance replicas must share the signing key (`signing_key_file`) and
`previous_key_dir`, or one instance won't verify another's tokens. Across a
restart, the key is never regenerated, so restarts don't log clients out,
unless the key file moved or its directory isn't persisted (check a container's
volume mounts). Clock skew between replicas larger than a token's validity
window can also reject otherwise-valid tokens; keep them NTP-synced. Live
replicas refresh shared key files automatically after rotation. If rejection
continues, verify both paths really refer to the same shared filesystem and
that every replica can read the archive and acquire the key's rotation lock.
Retired archives stop participating in verification after the seven-day token
horizon even if the files are retained on disk.
