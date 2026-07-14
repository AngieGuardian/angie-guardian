---
layout: home

hero:
  name: Angie Guardian
  text: WAF & proof-of-work bot firewall for Angie
  tagline: A sidecar daemon that answers allow, challenge, or deny for every request. Stock auth_request wiring, no custom Angie build, no C module.
  image:
    src: /logo.svg
    alt: Angie Guardian
  actions:
    - theme: brand
      text: Get Started
      link: /guide/getting-started
    - theme: alt
      text: What is Guardian?
      link: /guide/what-is-guardian
    - theme: alt
      text: View on GitLab
      link: https://gitlab.melroy.org/melroy/angie-guardian

features:
  - icon: 🛡️
    title: WAF layer on every request
    details: Hot-reloadable keyword/regex threat signatures (RE2, no ReDoS by construction) over path, query, UA, and headers, honeypot trap paths, and tamper detection on single-spend proof-of-work challenge IDs. Per-domain configurable.
  - icon: 🧩
    title: Proof-of-work challenges
    details: SHA-256 leading-zero-bits challenge with a parallel pure-JS solver, difficulty tunable in 2x quarter steps and escalating per host and IP against challenge farming, Ed25519-signed JWT cookie on success, replay protection, and a no-JS fallback.
  - icon: 🌍
    title: Origin intelligence
    details: Verified crawler allowlisting by rDNS identity (never by forgeable User-Agent), GeoIP country/ASN scoping, and external IP reputation feeds with background refresh and fail-open semantics.
  - icon: 📈
    title: Statistical anomaly scoring
    details: guardian-train learns per-domain baselines from Angie JSON access logs offline; the online scorer rates unvouched requests that reach it in about 260 ns and drives challenge, deny, and difficulty escalation.
  - icon: 🚫
    title: Behavioural IP blocking
    details: When enabled, signature hits, PoW failures, and tamper events feed per-IP scoreboards with exponential backoff. A honeypot hit denies immediately and places a persistent block when behavioural scoring is enabled.
  - icon: ⚡
    title: Built for the hot path
    details: Read paths clear 75k+ req/s on a single node. Verified tokens are cached in-process (about 144 ns), so returning clients never leave the fast path.
  - icon: 🔭
    title: Observable by default
    details: Prometheus /metrics, a bearer-token admin API, a built-in reporting dashboard, and a ready-made Grafana dashboard.
  - icon: 🗄️
    title: Pluggable state stores
    details: memory for dev, embedded bbolt for a single box, Redis/Valkey for replicas sharing blocks, counters, spent challenges, and bot verdicts; signing-key files are shared separately.
  - icon: 🕸️
    title: Optional WASM module
    details: The store-free WAF checks compiled to WebAssembly and run in-process inside Angie, for operators who prefer that integration path.
---

## Quick start

Build the daemon and use the local-path configuration from the
[Getting Started guide](/guide/getting-started):

```sh
go build ./cmd/guardiand
mkdir -p .guardian
./guardiand -config guardian.yaml
```

```nginx
# http {} context: keepalive upstream to the sidecar.
upstream guardian {
    server 127.0.0.1:8071;
    keepalive 64;
}

# each protected server {} block, after replacing both your_backend placeholders
# and merging Guardian directives into any existing location /:
include /etc/angie/angie-guardian.conf;
```

Continue with the [Getting Started guide](/guide/getting-started).
