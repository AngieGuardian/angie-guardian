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

## The challenge page says "Solver error"

The interstitial renders, but instead of counting hashes the status line
reports "Solver error" and asks for a reload (depending on the browser's
worker-blocking behaviour it may instead sit at "Starting…" forever). The
browser console shows a Content-Security-Policy violation like:

```
Content-Security-Policy: The page's settings blocked a worker script
(worker-src) at blob:https://example.com/... from being executed because it
violates the following directive: "script-src 'unsafe-inline' 'self'"
```

**Cause:** the site's CSP is being applied to the challenge page, whose PoW
solver runs in a `blob:` Web Worker that a normal site policy (rightly)
forbids. In Angie, a server-level `add_header Content-Security-Policy ...` in
the vhost is inherited by every location that defines no `add_header` of its
own, so it lands on the interstitial when the challenge location does not set
headers itself. This happens with a `deploy/angie-guardian.conf` copied before
the snippet set a location CSP, or with hand-written glue.

**Fix:** update `/etc/angie/angie-guardian.conf` to the current shipped
snippet (it is versioned with the release archive) and reload Angie. It gives
`@guardian_challenge` and `@guardian_denied` their own page-fitted
`Content-Security-Policy`, which also stops the vhost's server-level headers
from being inherited there; the site-wide CSP itself needs no change. With
hand-written glue, add the same `add_header` line from the shipped snippet to
your challenge location. Do **not** fix it by adding `worker-src blob:` to the
site-wide policy: that weakens the whole site for one internal page.

If the vhost sets other server-wide headers (`Strict-Transport-Security` is
the one that matters), re-add them in those two locations; see
[Site security headers and the challenge page](/guide/angie#site-security-headers-and-the-challenge-page).
The same symptom can also come from a CDN or proxy in front of Angie that
injects a CSP onto every response passing through it; exempt the interstitial
there.

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

**`/robots.txt` serves the interstitial instead of the file.** With
`pow.mode: always` every unvouched request is challenged, and a crawler cannot
solve one, so it never reads your `Disallow` rules (including the ones steering
it away from honeypot traps). Exempt the file fleet-wide with a
[per-path overlay](/reference/configuration#per-path-overrides-domains-host-paths)
under `defaults`, which leaves blocks, GeoIP and the WAF in place:

```yaml
defaults:
  paths:
    "/robots.txt": { pow: { enabled: false } }
```

**A stylesheet, image or `fetch()` gets a bare `403` instead of the page.** A
request that cannot execute the interstitial is refused a challenge rather than
issued one, because scoring it for abandoning a page it cannot run is how an
ordinary browser talks itself into a `challenge_farm` block. Counted as
`guardian_challenges_total{outcome="subresource_refused"}`; usually a favicon or
a stale SPA `fetch()`, and benign. A subresource carrying a valid token is never
affected, since the token stage allows it long before the challenge handler is
reached. If a top-level *navigation* is being refused, an intermediate proxy is
rewriting `Sec-Fetch-Dest`; stop it doing that. There is no config key to turn
the refusal off, because withholding the header does the same job with no daemon
change: add `proxy_set_header Sec-Fetch-Dest "";` to
`location @guardian_challenge` and Guardian is back to challenging everything.

**`curl`, an API client or a feed reader gets a bare `403` instead of the
interstitial.** Counted as
`guardian_challenges_total{outcome="accept_heuristic_refused"}`. When a request
carries no Fetch metadata at all, its `Accept` header is the only thing left
that distinguishes a page navigation from something that could never render one,
so a request whose `Accept` is present and names neither `text/html` nor
`text/*` is refused a challenge instead of being issued one it will drop. The
request this was built for is the browser's own favicon service, which refreshes
a known icon URL on a system principal with no cookie, no `Sec-Fetch-*` even
over HTTPS, and `Accept: */*`, and used to escalate the visitor on every page
render.

`Accept` is a heuristic, not proof: `*/*` formally accepts HTML, and the Fetch
standard only says browsers *should* send the document `Accept` value for a
navigation. So it is consulted last, and never against a stronger signal:
`Sec-Fetch-Dest` naming any document-like destination, or
`Sec-Fetch-Mode: navigate`, exempts the request whatever it asks for. So does an
absent `Accept`, and so does one that is not a well-formed media range, since
refusing on input that cannot be read is deciding from noise.

The 403 body names what would change the outcome, so it is worth reading rather
than just counting: `proof-of-work challenge requires a document navigation:
Accept must list text/html or text/*`.

**The tradeoff, stated plainly.** On modern HTTPS browsers a recognized document
destination protects customized `Accept` values. Where Fetch metadata is
unavailable, meaning plain HTTP, older clients, or a proxy that strips the
headers, this can refuse an unusual real navigation whose `Accept` lacks
`text/html`. That is deliberate, and it is the case to watch if you serve a
plain-HTTP vhost to unusual clients. The off switch is the same shape as the one
above and needs no daemon change: add `proxy_set_header Accept "";` to
`location @guardian_challenge`.

**`guardian_challenges_total{outcome="frame_unscored"}` is climbing.** Your
protected URLs are being loaded in a frame whose Fetch metadata cannot establish
that the interstitial will render, so those issuances raise difficulty but are
never reported as `challenge_farm`. Before that exemption, a third party could
drive arbitrary visitors into a block on your site simply by framing it in a
loop.

**This metric does not by itself mean a hostile third party.** The metadata is
ambiguous, which is the whole reason these are issued rather than refused.
`Sec-Fetch-Site` accumulates across the redirect chain, so your own embedded
login callback (`A -> IdP -> A` inside a same-origin iframe) reports
`cross-site` and lands here too, as does any `fencedframe` navigation. Before
concluding you are being framed, check whether the URIs involved are your own
SSO or embed callbacks. A steady rate against ordinary page URLs you never frame
yourself is the signal worth chasing.

**The `Sec-Fetch-*` protections above do not apply on a plain-HTTP site.**
Browsers send those headers only to potentially-trustworthy origins (HTTPS and
localhost), so over plain HTTP every destination reads as unknown and the
pre-existing challenge-everything behaviour applies to subresources and frames
alike.

The `Accept` refusal is the exception, and the only one: it needs no Fetch
metadata, so it is the sole protection that works over plain HTTP. It is also
the only one whose false-positive risk is higher there, for exactly the same
reason, since nothing stronger is available to exempt an unusual navigation.

**Everyone is challenged too aggressively.** If `pow.mode: always`, every
unvouched request is challenged once per `token_ttl`. Lower `base_difficulty`
or switch to `pow.mode: suspicion` (disables the catch-all; explicit anomaly,
WAF, GeoIP, and reputation challenge policies still apply); see
[Configuration](/guide/configuration).

**A visitor is challenged in a loop even though they hold a cookie.** The
reason names which check the token failed, so you can tell this from the
server side without a browser capture. Read it from
`GET /admin/decisions?reason=pow`, the dashboard's Recent decisions table, the
`X-Guardian-Reason` response header, or the JSON decision log.

| `reason` | What it means | Where to look |
|---|---|---|
| `pow:no_token` | No `guardian_token` cookie arrived at all. | The client is fetching anonymously, or the cookie never reached Guardian: check that Angie relays it with `proxy_set_header X-Guardian-Cookie $http_cookie`. Favicon and other subresource requests can appear here too, but this reason alone does not prove the browser omitted the cookie; compare the browser's request headers with what Angie relayed before concluding that. |
| `pow:token_expired` | Real work, but past its `exp` or older than this path's `token_ttl`. | Normal once per `token_ttl`. A tight loop means `token_ttl` is shorter than you meant, a [per-path overlay](/reference/configuration#per-domain-options-defaults-and-domains-host) sets a shorter one than the path that issued the token, or the verifier's clock is ahead. |
| `pow:token_binding` | Correctly signed and in date, but bound to another host or client. | Tokens bind to host + IP + User-Agent. Expect this from a visitor whose egress IP changes (mobile, CGNAT, a VPN toggling) or across two hostnames of the same site. Persistent and site-wide means the client IP Guardian sees is not stable: check `proxy_set_header X-Guardian-IP` and any proxy in front of Angie. |
| `pow:token_underdifficulty` | Real token, solved at fewer bits than this path demands. | A per-path `base_difficulty` higher than where the visitor earned their token. Expected on entering a stricter path; they solve once more and continue. |
| `pow:token_invalid` | Did not parse or verify under any live signing key. | An empty, truncated, or mangled cookie; a token from another deployment; a signing key that rotated out; or an issuer clock ahead of the verifier, leaving `nbf` in the future. If it appears fleet-wide after a restart or rotation, see [Tokens rejected across replicas / after a restart](#tokens-rejected-across-replicas-after-a-restart). |

All five collapse to the single `pow` category in `guardian_decisions_total`,
so they cost no extra Prometheus series and existing `pow` alerts keep
matching.

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
its startup-required local artifacts before reloading with `guardiand -t`,
and ask the running daemon whether the edit is reloadable at all with
[`GET /admin/reload/preflight`](/reference/admin-api#get-admin-reload-preflight):
it lists exactly which changed fields would require a restart.

## Challenge issuance is slow / the store can't keep up

Under a very high rate of *new* clients (each triggering a challenge write),
the embedded writer becomes the ceiling: ~61k issuances/s on `pebble` async,
~56k/s on `buntdb` async, and ~34k/s on `pebble` with `sync: true`
(fsync-per-write) on the reference machine. Symptoms: rising challenge
latency, `guardian_store_op` latency climbing. Set `store.sync: false` (the
default) if you had turned fsync on, move to the `redis`/`valkey` backend to
share the write across replicas, set `pow.mode: suspicion` so most requests do
no write, or enable [attack mode](/guide/attack-mode), whose stateless issuance
removes the write at issue time entirely when a flood trips the posture. See
[Choosing a store backend](/guide/production#choosing-a-store-backend).

## Tokens rejected across replicas / after a restart

The signal to look for is `pow:token_invalid` in
`GET /admin/decisions?reason=pow`: a key problem rejects tokens at the
signature, so it reads as invalid rather than expired or wrongly bound. Clock
skew can produce either time verdict: a verifier behind the issuer sees a
not-yet-valid `nbf` and reports `pow:token_invalid`, while a verifier far enough
ahead sees an elapsed `exp` and reports `pow:token_expired`.

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
