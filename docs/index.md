---
layout: home

hero:
  name: Angie Guardian
  text: WAF & proof-of-work bot firewall for Angie
  tagline: Stop HTTP floods and AI scrapers at 180,000+ requests per second without slowing down real users. Ultra-fast, adaptive Proof-of-Work bot defense with no reverse-proxy bottleneck and zero required external databases.
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
    details: Hot-reloadable WAF rules with literal/regex matchers over path, query, UA, and headers, honeypot trap paths, and <b>tamper detection</b> on single-spend challenge IDs. Per-domain configurable.
  - icon: 🧩
    title: Proof-of-work challenges
    details: Default SHA-256 or optional fleet/domain <b>Argon2id memory-hard PoW</b>, featuring per-IP escalation, bounded verification, replay-protected Ed25519 JWT cookies, and an opt-in no-JS fallback.
  - icon: ⚡
    title: Built for speed
    details: Write paths clear <b>150k+ req/sec</b> on a single node. Verified tokens are cached in-process (about 0.15ms, allocation-free) up to and including <b>188,000 requests per second</b>.
  - icon: 🌍
    title: Origin intelligence
    details: Verified crawler allowlisting by <b>rDNS identity</b> (never forgeable User-Agents), GeoIP country/ASN scoping, and external IP reputation feeds with background refresh and fail-open semantics.
  - icon: 📈
    title: Statistical anomaly scoring
    details: <code>guardian-train</code> learns domain and route/method baselines offline; the <b>sub-microsecond online scorer</b> rates unvouched requests and drives dynamic challenge escalation.
  - icon: 🚫
    title: Behavioural IP blocking
    details: Rule hits, PoW failures, tamper events, and honeypots feed per-IP scoreboards with <b>exponential backoff</b>. Honeypot traps immediately apply a persistent block.
  - icon: 🔭
    title: Observable by design
    details: Prometheus <code>/metrics</code>, a bearer-token admin API, a <b>built-in reporting dashboard</b> with real-time graphs and attack maps, plus ready-made Grafana templates.
  - icon: 🗄️
    title: Pluggable state stores
    details: In-memory for dev, <b>embedded Pebble or BuntDB</b> for durable single-node setups, and Redis/Valkey for high-availability cluster state sharing.
  - icon: 🕸️
    title: Optional WASM module
    details: Store-free WAF checks compiled directly to <b>WebAssembly</b> running in-process inside Angie for zero-latency, store-less integration.
---

## Quick start

For a normal Linux host (running Ubuntu/Debian based systems), just run:

```sh
curl -fsSL https://raw.githubusercontent.com/AngieGuardian/angie-guardian/main/scripts/install.sh | sudo bash
```

You need to manually adjust your Angie configuration after installation. Same command can be used for updates as well.

The [Getting Started guide](/guide/getting-started) gives you more details as well as a complete manual
copy/paste flow: choose the correct archive, install the config and rules,
wire the existing Angie vhost, start systemd, and verify a real request.
