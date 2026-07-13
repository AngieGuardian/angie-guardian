# Security Model & Limitations

Angie Guardian is a WAF and proof-of-work bot firewall. Knowing precisely what
it defends against, and what it deliberately does not, is the difference between
sound protection and a false sense of one. This page is the honest map.

## What Guardian defends against

- **Automated scraping and bulk abuse.** On domains using `pow.mode: always`,
  the proof-of-work interstitial makes every unvouched client pay a small
  computation before its first request is served, then rides a signed,
  short-lived token. In `suspicion` mode only clients flagged by policy pay.
- **Scanner and probe traffic.** WAF signature rules (keywords + RE2 regexes,
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
  JWTs bound to `{host, client fingerprint}` with a short expiry; challenges are
  single-spend (an atomic compare-and-swap marks them redeemed) and the stored
  record binds each challenge to the host and client it was issued to. A
  redemption that presents an unknown, already-spent, or wrong-client challenge
  ID fails verification and is scored as a tamper event against the source IP,
  feeding the behavioural scoreboard. This scoring is on by default; it is not
  gated behind a feature toggle.

## What Guardian does NOT defend against

These are out of scope by design. Guardian is one layer; pair it with the
tools that own these problems.

- **Volumetric / L3–L4 floods.** Proof-of-work only taxes clients that *solve*
  the puzzle. A raw flood that never follows the challenge redirect is not
  Guardian's problem to absorb — put Angie's own
  [rate limiting](/guide/angie#rate-limiting-volumetric-ddos) in front, and a
  network/transport DDoS mitigation in front of that. Guardian *fails open* (see
  below), so it will not itself become the bottleneck under a flood.
- **Request-body attacks.** Angie's `auth_request` subrequest carries only the
  request line and headers, by design. Body-borne payloads (SQL in a POST form,
  file-upload exploits) are the backend's input validation to handle, or a full
  inline WAF's. Guardian never sees the body.
- **Attacks from inside a trusted range.** Anything on the static allowlist, a
  verified crawler, or a trusted-proxy source is admitted with reduced scrutiny.
  Allowlist deliberately; an allowlisted attacker is an allowlisted attacker.
- **A native solver outpacing browsers.** Proof-of-work is a *cost* mechanism,
  not a bypass-proof gate. A determined attacker with native SHA-256 hardware
  solves challenges faster than a browser's JavaScript does; difficulty tuning
  raises their cost, it does not stop them. PoW buys economics, not certainty.
  See [difficulty tuning](/guide/configuration#base_difficulty-and-max_difficulty).
- **Vulnerabilities in the protected application.** Guardian filters who gets
  through; it does not fix the app behind it. A logic flaw reachable by a
  vouched, well-behaved client is still reachable.
- **Perfect bot detection.** Anomaly scoring and signatures are heuristics.
  They raise the cost and catch the unsubtle; a patient, browser-faithful
  adversary can blend in. The goal is economic deterrence, not an oracle.

## Trust boundaries you own

Two configuration facts are load-bearing for Guardian's security. Get them
wrong and the protections above weaken or invert:

- **The `X-Guardian-*` headers are trusted.** Guardian reads the client IP,
  host and cookie from headers Angie sets on the subrequest. If a client can
  reach the sidecar's listener directly, it can forge those headers — spoof
  another IP, frame it into a block, or ride an allowlisted identity. Guardian
  **refuses to start** on a non-loopback `listen` unless you set
  `trusted_proxy: true` to assert you have isolated the listener to Angie. Keep
  that promise (loopback, private network, firewall, or mTLS).
- **The admin API is bearer-token protected and should stay off the public
  internet.** Bind `admin.listen` to loopback or a management interface.
  Guardian refuses a non-loopback admin bind without a token.

## Fail-open by design

If Guardian is unreachable or a stage errors, it degrades to **allow** rather
than taking the site down. This is a deliberate availability choice: a WAF that
fails closed is a single point of failure for the whole site. The trade-off is
that a Guardian outage is a *protection* outage — the site keeps serving, but
unfiltered. Monitor for it: the systemd unit is `Type=notify` with a watchdog,
`/metrics` exposes store health, and "up but degraded to fail-open" is exactly
the condition to alert on. See [Run it in Production](/guide/production).

## Reporting a vulnerability

Found a hole in the above? See
[SECURITY.md](https://gitlab.melroy.org/melroy/angie-guardian/-/blob/main/SECURITY.md)
for the private disclosure process.
