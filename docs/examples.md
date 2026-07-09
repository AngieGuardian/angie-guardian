# Examples

Complete, copy-paste-ready configurations for common setups. Every example
inherits anything it doesn't mention from `defaults`; see the
[Configuration Options reference](/reference/configuration) for each field.

## Minimum viable config

One protected domain, PoW plus behavioural blocking, persistent single-box
store:

```yaml
listen: 127.0.0.1:8071            # Angie's auth_request target
signing_key_file: /etc/guardian/ed25519.key
store:
  backend: bbolt
  path: /var/lib/guardian/guardian.db

defaults:
  pow: { enabled: true, base_difficulty: 5 }
  waf:
    ip_behaviour: { enabled: true }

domains:
  example.com: {}                 # inherits all defaults
```

## Mixed estate: HTML site, API, static assets

```yaml
domains:
  # HTML site behind PHP/Node: full protection. Difficulty takes quarter
  # steps: 5.25 is exactly 2x the work of 5.
  example.com:
    pow: { enabled: true, base_difficulty: 5.25, token_ttl: 2h }
    waf: { honeypot: { enabled: true, paths: [ "/wp-admin-old/" ] } }

  # API host: WAF only, no interstitial a machine client can't solve.
  api.example.com:
    pow: { enabled: false }

  # Static assets: keep it light.
  static.example.com:
    pow: { enabled: false }
    waf: { ip_behaviour: { enabled: false } }
```

## Suspicion-only challenges (anomaly model)

Ordinary visitors never see an interstitial; only clients the anomaly scorer
flags are challenged, with difficulty scaled by the score. Requires a
[trained model](/guide/anomaly).

```yaml
domains:
  shop.example.com:
    pow: { enabled: true, mode: suspicion, base_difficulty: 5, max_difficulty: 6 }
    waf:
      anomaly: { enabled: true, model: /etc/guardian/model.json,
                 challenge_at: 0.5, deny_at: 0.85 }
```

## The full annotated example

The complete `guardian.example.yaml` shipped with the repository:

```yaml
# Angie Guardian example configuration.
#
# Per-domain settings are merged over `defaults` field-by-field: a domain only
# needs to mention what it changes. Unknown hosts fall back to `defaults`.

listen: 127.0.0.1:8071        # the auth hot path (Angie's auth_request target)
log_level: info

# The sidecar trusts the X-Guardian-* headers Angie sets on the subrequest
# (client IP, host, cookie). Keep `listen` on loopback so no client can reach
# it directly and forge them. To bind a non-loopback address (Angie on another
# host), isolate the listener to Angie (private network / firewall / mTLS) and
# set the line below, otherwise guardiand refuses to start.
# trusted_proxy: true

# Admin API + Prometheus /metrics, on a SEPARATE listener from the hot path.
# /metrics and /healthz are open (a scraper needs no secret); every /admin
# route requires the bearer token. Binding to a non-loopback address without
# a configured token is refused at startup. Leave admin.listen empty to
# disable it.
admin:
  listen: 127.0.0.1:8072
  # Bearer token resolution: `token` (or the ADMIN_TOKEN env var) wins;
  # otherwise one is auto-generated into `token_file` on first start (0600,
  # never regenerated, like the signing key) so you never invent one by hand.
  # With neither set, a loopback listener gets a fresh token each start,
  # printed in the startup log.
  token: ""                   # or set the ADMIN_TOKEN env var
  token_file: /etc/guardian/admin.token
  # Built-in reporting page at GET /admin/dashboard (active blocks with
  # one-click block/unblock, recent deny/challenge decisions with filters,
  # challenge stats, per-domain config). On startup guardiand logs a
  # ready-to-open login URL ("admin dashboard ready") carrying the token in
  # the URL fragment; the page moves it into sessionStorage. Off by default.
  dashboard: true

# Persistent Ed25519 signing key for PoW JWTs. Generated on first run if
# missing; NEVER regenerated on restart, so restarts don't log clients out
# and replicas can share it. Retired keys (from `POST /admin/rotate-key`) are
# archived here and still accepted for verification until their tokens expire.
signing_key_file: /etc/guardian/ed25519.key
previous_key_dir: /etc/guardian/keys.d

store:
  backend: bbolt              # memory | bbolt | redis
  path: /var/lib/guardian/guardian.db
  # redis backend (multi-instance): all replicas share one server.
  # addr: 127.0.0.1:6379
  # password: ""              # or the REDIS_PASSWORD env var
  # db: 0

defaults:
  waf:
    ip_behaviour:
      enabled: true
      block_ttl: 15m          # first offense; doubles per repeat offense
      max_block_ttl: 4h       # backoff cap
      thresholds:             # bad events per window before the IP is blocked
        signature: 10/min     # WAF signature hits
        pow_fail: 10/min      # failed challenge solutions
        tamper: 10/min        # forged/replayed challenge or signed IDs
        bot_spoof: 5/min      # clients caught impersonating a verified bot
    keywords:
      enabled: true           # requires the rules file to exist (fail-fast);
      rules_file: /etc/guardian/rules.d/common.yaml   # start from deploy/rules-common.yaml
    anomaly:
      enabled: false          # requires a model trained from your own logs:
      model: /etc/guardian/model.json   #   guardian-train -out model.json /var/log/angie/*.access.json
      challenge_at: 0.6       # score >= this -> PoW challenge, difficulty scaled by score
      deny_at: 0.9            # score >= this -> deny outright
    honeypot:
      enabled: false          # trap paths: one hit = instant block. Add paths no
      paths: []               # legit client visits, e.g. [ "/admin-old/" ], and
                              # Disallow them in robots.txt.
    uuid_tamper: { enabled: true }
  pow:
    enabled: true
    mode: always              # always: challenge every unvouched browser
                              # suspicion: only challenge anomalous clients (needs waf.anomaly)
    # Difficulty N = 4*N leading zero bits; +1 is 16x the work, and quarter
    # steps are allowed: each +0.25 doubles it (5.25 = 2x harder than 5).
    # See "Measured solve times" in the configuration guide before changing.
    base_difficulty: 5        # ~1s on a mid-range phone, near instant on desktop
    max_difficulty: 6         # ceiling for anomaly-scaled challenges
    token_ttl: 4h
    challenge_ttl: 30m
    noscript_fallback: true
  allowlist:
    ips: [ "127.0.0.1", "::1" ]
    # No crawler names in uas: a UA string is forgeable. Use verified_bots
    # below instead (see the configuration reference).
    uas: []
    paths:
      - /robots.txt
      - /favicon.ico
      - /.well-known/         # trailing slash = prefix match (ACME http-01 etc.)
  denylist:
    ips: []
  # Crawlers allowlisted by proven rDNS identity, not by their forgeable
  # User-Agent string.
  verified_bots:
    bots:
      - name: googlebot
      - name: bingbot

domains:
  # HTML site with a PHP/Node.js backend: full protection, PoW + WAF.
  # Fractional difficulty: 5.25 is exactly 2x the work of the default 5.
  example.com:
    pow: { enabled: true, base_difficulty: 5.25, max_difficulty: 6, token_ttl: 2h }
    waf: { honeypot: { enabled: true } }

  # API host: WAF only, no PoW interstitial a machine client can't solve.
  api.example.com:
    pow: { enabled: false }

  # Static assets host: keep it light.
  static.example.com:
    pow: { enabled: false }
    waf: { ip_behaviour: { enabled: false } }
```

## Angie: full wiring

```nginx
# http {} context: keepalive upstream (REQUIRED for throughput) + rate limits.
upstream guardian {
    server 127.0.0.1:8071;
    keepalive 64;
}
limit_req_zone  $binary_remote_addr zone=guard:10m rate=30r/s;
limit_conn_zone $binary_remote_addr zone=gconn:10m;

server {
    listen 443 ssl;
    server_name example.com;

    # Volumetric protection runs BEFORE auth_request: a rejected flood
    # never reaches the sidecar.
    limit_req  zone=guard burst=60 nodelay;
    limit_conn gconn 20;
    limit_req_status  429;
    limit_conn_status 429;

    # Guardian: auth_request wiring + challenge/pass/denied routes.
    include /etc/angie/angie-guardian.conf;

    # JSON access log feeding guardian-train (format from deploy/angie-json-log.conf).
    access_log /var/log/angie/example.com.access.json guardian_json;

    location / {
        proxy_pass http://127.0.0.1:3000;
    }
}
```

## Multi-instance replicas (Redis/Valkey)

```yaml
store:
  backend: redis            # same value for both Redis and Valkey
  addr: 127.0.0.1:6379
  # password: ""            # or the REDIS_PASSWORD env var
signing_key_file: /etc/guardian/ed25519.key   # same file on every replica
previous_key_dir: /etc/guardian/keys.d        # shared, e.g. NFS or synced
```

## WASM guest config

For the in-process stateless WAF (see the [WASM module guide](/guide/wasm)):

```nginx
wasm_modules {
    load /etc/guardian/guardian.wasm id=guardian type=reactor
      config='
        domains:
          example.com:
            allowlist: { paths: [ "/robots.txt" ] }
            honeypot:  { enabled: true, paths: [ "/wp-login.php" ] }
            rules:
              - { id: dotfile, action: deny, keywords: [ "/.env", "/.git/" ] }
      ';
}
```
