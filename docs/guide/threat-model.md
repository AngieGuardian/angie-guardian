# Security Model & Limitations

Angie Guardian is a WAF and proof-of-work bot firewall. Knowing precisely what
it defends against, and what it deliberately does not, is the difference between
sound protection and a false sense of one. This page is the honest map.

## What Guardian defends against

- **Automated scraping and bulk abuse.** On domains using `pow.mode: always`,
  the proof-of-work interstitial makes every unvouched client pay a small
  computation before its first request is served, then rides a signed,
  short-lived token. In `suspicion` mode only clients flagged by policy pay.
  A client that keeps fetching challenges without ever solving one is
  rate-limited, escalated to the difficulty ceiling, and past the
  `challenge_farm` threshold temporarily blocked.
- **Scanner and probe traffic.** WAF rules (literal keywords + RE2 regexes,
  on the path, query, User-Agent and named headers) deny known-bad requests:
  dotfile probes, admin-panel scans, injection payloads. Repeat offenders earn
  a behavioural IP block with backoff.
- **Credential stuffing and login abuse**, to the extent it comes from
  unvouched automation: `always` mode taxes the initial login request, while
  `suspicion` mode taxes only requests flagged by its configured policies;
  behavioural scoring still applies.
- **Forged / spoofed bot identity.** A client claiming to be Googlebot in its
  User-Agent is only allowlisted if its IP reverse-DNS *and* forward-confirms
  to the crawler's published domains. A proven impostor is denied and scored.
- **Origin-based abuse**, when configured: GeoIP/ASN scoping and external IP
  reputation feeds can deny or challenge selected countries, networks or
  known-bad address ranges.
- **Tampering and replay** of Guardian's own tokens and IDs: tokens are EdDSA
  JWTs bound to `{host, client fingerprint}` with a short expiry; challenges
  are single-spend (an atomic compare-and-swap marks them redeemed) and bound
  to the host and client they were issued to. A redemption presenting an
  unknown, already-spent, or wrong-client challenge ID fails verification and
  emits a tamper event against the source IP, feeding the behavioural
  scoreboard when `waf.ip_behaviour.enabled` is on (off by default).

## What Guardian does NOT defend against

These are out of scope by design. Guardian is one layer; pair it with the
tools that own these problems.

- **Volumetric / L3–L4 floods.** Proof-of-work only taxes clients that *solve*
  the puzzle. A raw flood that never follows the challenge redirect is not
  Guardian's problem to absorb: put Angie's own
  [rate limiting](/guide/angie#rate-limiting-volumetric-ddos) in front, and a
  network/transport DDoS mitigation in front of that. Guardian *fails open* (see
  below), so it will not itself become the bottleneck under a flood.
- **Request-body attacks.** Angie's `auth_request` subrequest carries only the
  request line and headers, by design. Body-borne payloads (SQL in a POST form,
  file-upload exploits) are the backend's input validation to handle, or a full
  inline WAF's. Guardian never sees the body.
- **Attacks from inside a trusted range.** Anything on the static allowlist or
  a verified crawler is admitted with reduced scrutiny.
  Allowlist deliberately; an allowlisted attacker is an allowlisted attacker.
- **A native solver outpacing browsers.** Proof-of-work is a *cost* mechanism,
  not a bypass-proof gate. A determined attacker with native SHA-256 hardware
  solves challenges faster than a browser's JavaScript does; difficulty tuning
  raises their cost, it does not stop them. PoW buys economics, not certainty.
  See [difficulty tuning](/guide/configuration#base-difficulty-and-max-difficulty).
- **Vulnerabilities in the protected application.** Guardian filters who gets
  through; it does not fix the app behind it. A logic flaw reachable by a
  vouched, well-behaved client is still reachable.
- **Perfect bot detection.** Anomaly scoring and WAF rules are heuristics.
  They raise the cost and catch the unsubtle; a patient, browser-faithful
  adversary can blend in. The goal is economic deterrence, not an oracle.

## Trust boundaries you own

Two configuration facts are load-bearing for Guardian's security. Get them
wrong and the protections above weaken or invert:

- **The `X-Guardian-*` headers are trusted.** Guardian reads the client IP,
  host and cookie from headers Angie sets on the subrequest; a client that can
  reach the sidecar's listener directly can forge them to spoof another IP,
  frame it into a block, or ride an allowlisted identity. Guardian **refuses
  to start** on a non-loopback `listen` unless `trusted_proxy: true` asserts
  you have isolated the listener to Angie. Keep that promise (loopback,
  private network, firewall, or mTLS). As a tripwire, `require_proxied: true`
  makes the guard endpoints reject requests arriving without the headers
  (counted in `guardian_unproxied_rejects_total`) instead of processing them
  under their own socket identity, so bypass traffic surfaces. It is not a
  spoofing defense: a direct client that forges the headers still passes it,
  so the isolation promise stays load-bearing.
- **The admin API is bearer-token protected and should stay off the public
  internet.** Bind `admin.listen` to loopback or a management interface.
  Guardian refuses a non-loopback admin bind without a token. The listener is
  plain HTTP; use a TLS/mTLS proxy or service mesh for any cross-network hop so
  the bearer credential cannot be observed and replayed.

### Response security headers

Every page Guardian serves carries its own `Content-Security-Policy`, fitted to
exactly what that page uses, plus `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer` and a matching `X-Frame-Options`:

| Page | Policy |
| --- | --- |
| PoW interstitial | inline script and style, a `blob:` worker for the solver, same-origin `fetch`; framing limited to same-origin |
| Denied page | inline style only, no script, no subresources; framing limited to same-origin |
| Admin dashboard | inline script and style, same-origin vendored chart libraries, `data:` favicon, same-origin `fetch`; framing refused outright |

The Angie glue (`deploy/angie-guardian.conf`) also adds the interstitial and
denied policies with `add_header`, not as duplication: an Angie location that
sets any `add_header` stops inheriting the server-level ones, which is what
keeps a vhost's own site CSP (typically lacking `worker-src blob:`) from
breaking the solver. Keep both; a browser enforces every policy it receives,
and the two intersect to exactly the policy in the table. Guardian sending
them itself keeps the pages self-protecting when Angie is not in the path at
all: a direct probe, a development setup, a hand-written vhost whose
`add_header` lines were never copied, and the admin listener, which Angie
never fronts.

## Fail-open by design

If Guardian is unreachable, its internal Angie auth location converts the
upstream failure to `204`, which `auth_request` treats as allow, and the
vhost's original static, FastCGI, or proxy handler resumes. If one internal
stage errors, it abstains and later stages still run; only when none returns a
terminal decision does the request default to allow. This keeps the WAF from
becoming a single point of failure: a full Guardian outage is a *protection*
outage, the site keeps serving unfiltered. Monitor for it (the systemd unit is
`Type=notify` with a watchdog, `/metrics` exposes store health): "up but
degraded to fail-open" is exactly the condition to alert on. See
[Run it in Production](/guide/production).

Fail-open covers Guardian being *down or erroring*, not overload. When the
daemon itself is saturated, [attack mode](/guide/attack-mode)'s optional
load-shedding bound (`attack_mode.effects.max_inflight`) is the middle ground:
token holders pass only after the store-free deny, WAF, honeypot and spoof
checks clear and a complete authoritative mirror can prove there is no
behavioural block; everyone else gets a fast `503` with `Retry-After` (or the
terminal deny). Overload never turns a token into a policy or shared-block
bypass.

## Reporting a vulnerability

Found a hole in the above? See
[SECURITY.md](https://gitlab.melroy.org/melroy/angie-guardian/-/blob/main/SECURITY.md)
for the private disclosure process.
