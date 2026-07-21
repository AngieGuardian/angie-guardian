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

**Fix:** make sure Angie passes the scheme through. The auth subrequest must
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
`error_page 500 = @guardian_bypass` serves the request unfiltered rather than
erroring. The site stays up; it is just unprotected until Guardian returns.

**Don't mistake this for health.** Alert on it: watch the systemd unit
(`Type=notify` marks the service failed if it wedges), the `/metrics` endpoint,
and store connectivity. See [Run it in Production](/guide/production).

To verify the bypass is wired correctly, stop guardiand and confirm the site
still serves; if it returns 500 instead, the `@guardian_bypass` fallback is
missing from your Angie config.

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
