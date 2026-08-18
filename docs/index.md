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
      text: View on GitHub
      link: https://github.com/AngieGuardian/angie-guardian

features:
  - icon: 🛡️
    title: WAF layer on every request
    details: Hot-reloadable WAF rules with literal/regex matchers over path, query, UA, and headers, honeypot trap paths, and tamper detection on single-spend proof-of-work challenge IDs. Per-domain configurable.
  - icon: 🧩
    title: Proof-of-work challenges
    details: SHA-256 leading-zero-bits challenge by default, with optional fleet-default or per-domain Argon2id memory-hard work, per-host/IP escalation, bounded verification, Ed25519-signed JWT cookies, replay protection, and an opt-in no-JS fallback.
  - icon: ⚡
    title: Built for speed
    details: Write paths clear 150.000+ requests per second on a single node. Verified tokens are cached in-process (about 35 nanosecond, allocation-free) up 188k req/sec.
  - icon: 🌍
    title: Origin intelligence
    details: Verified crawler allowlisting by rDNS identity (never by forgeable User-Agent), GeoIP country/ASN scoping, and external IP reputation feeds with background refresh and fail-open semantics.
  - icon: 📈
    title: Statistical anomaly scoring
    details: guardian-train learns domain and route/method baselines from Angie JSON access logs offline; the sub-microsecond online scorer rates unvouched requests and drives challenge, deny, and difficulty escalation.
  - icon: 🚫
    title: Behavioural IP blocking
    details: When enabled, WAF rule hits, PoW failures, tamper events, bot spoofing, and challenge farming feed per-IP scoreboards with exponential backoff. A honeypot hit denies immediately and places a persistent block when behavioural scoring is enabled.
  - icon: 🔭
    title: Observable by design
    details: Prometheus /metrics, a bearer-token admin API, a **built-in reporting dashboard** with activity graphs and a world map of attack origins, and a ready-made Grafana dashboard.
  - icon: 🗄️
    title: Pluggable state stores
    details: memory for dev, embedded pebble or buntdb for a durable single box, Redis/Valkey for replicas sharing blocks, counters, spent challenges, and bot verdicts; signing-key files are shared separately.
  - icon: 🕸️
    title: Optional WASM module
    details: The store-free WAF checks compiled to WebAssembly and run in-process inside Angie, for operators who prefer that integration path.
---

## Quick start

For a normal Linux host, install a pinned `amd64` or `arm64` archive from the
[releases page](https://github.com/AngieGuardian/angie-guardian/releases).
It includes the binaries, canonical annotated config, starter WAF rules, Angie
snippets, and systemd unit; no repository checkout or Go toolchain is required.

```sh
# After selecting, downloading, and extracting a versioned release:
sudo install -Dm755 guardiand /usr/local/bin/guardiand
```

The [Getting Started guide](/guide/getting-started) gives the complete
copy/paste flow: choose the correct archive, install the config and rules,
wire the existing Angie vhost, start systemd, and verify a real request. Source
builds and the Docker demo are kept as explicitly separate paths.
