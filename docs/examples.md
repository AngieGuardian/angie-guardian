# Examples

Configuration examples for common setups. Blocks explicitly described as
fragments must be merged into a complete file; the minimum and full annotated
examples are standalone. Every domain inherits anything it doesn't mention
from `defaults`; see the
[Configuration Options reference](/reference/configuration) for each field.

## Minimum viable config

One protected domain, PoW plus behavioural blocking, persistent single-box
store:

```yaml
listen: 127.0.0.1:8071            # Angie's auth_request target
signing_key_file: /var/lib/guardian/ed25519.key   # signs PoW challenges and
                                                  # the JWT cookie a solve
                                                  # earns; created on first run,
                                                  # keep it secret
store:
  backend: pebble
  path: /var/lib/guardian/pebble

defaults:
  pow: { enabled: true }          # base_difficulty defaults to 5; raise it to
                                  # 5.25-5.5 when actively scraped
  waf:
    ip_behaviour: { enabled: true }

domains:
  example.com: {}                 # inherits all defaults
```

## Mixed estate: HTML site, API, static assets

Guardian evaluates the request line and headers (Angie's `auth_request`
forwards no body), so on every profile below, payload validation stays with
the backend or a full inline WAF.

```yaml
domains:
  # HTML site behind PHP/Node: all Guardian layers, PoW + the URI/header WAF.
  # Difficulty takes quarter steps: each +0.25 doubles the work (so 5.75 is
  # 2x the work of 5.5).
  example.com:
    pow: { enabled: true, base_difficulty: 5.5 }   # token_ttl inherits 4h
    # Honeypot: no generic trap path is safe to copy (one hit persistently
    # blocks the source IP when ip_behaviour is on). Invent a path specific
    # to YOUR site that nothing links to, then enable:
    # waf: { honeypot: { enabled: true, paths: [ "/your-own-trap/" ] } }

  # API host: WAF only, no interstitial a machine client can't solve. With
  # PoW off, challenge-action rules degrade to deny (nothing to challenge
  # with); give APIs their own rules file if that is too blunt.
  api.example.com:
    pow: { enabled: false }

  # Static assets: no PoW, no behavioural scoring. Signature rules still
  # apply from defaults; override waf.keywords too for a minimal policy.
  static.example.com:
    pow: { enabled: false }
    waf: { ip_behaviour: { enabled: false } }
```

## One host, different paths: PoW everywhere except the API

Not every estate splits its API onto its own subdomain. A `paths` overlay
scopes any setting to a URI prefix within one host: the most specific key
wins, and each entry only overrides the fields it mentions (see the
[reference](/reference/configuration#per-path-overrides-domains-host-paths)).
Here machine clients under `/api/v1/` skip the interstitial while the WAF
keeps covering them (note that challenge-action rules degrade to deny where
PoW is off), and the login page demands harder work:

```yaml
domains:
  example.com:
    pow: { enabled: true }
    paths:
      "/api/v1/":
        pow: { enabled: false }
      "/account/login":
        pow: { base_difficulty: 6 }
```

## Signature rules: one starter file, scoped per domain

Signature rules are not auto-discovered: a rules file must be installed on
disk and named by `waf.keywords.rules_file`, with `enabled: true`, or no
signature matching happens at all. The install recipe in the
[production guide](/guide/production#systemd) copies the shipped starter file
`deploy/rules-common.yaml` to `/etc/guardian/rules.d/common.yaml`; a
configured file that is missing fails validation (and so startup) rather than
silently matching nothing.

`defaults.waf.keywords` is inherited by every domain and path overlay unless
overridden there. Scoping works three ways: point a domain (or path overlay)
at a *different* rules file, disable matching for that scope, or disable
selected rules from the effective file by their exact `id` with
`disabled_rule_ids` (no need to copy the file for one exception). The `id`
inside a rules file is both the log/reason label (a hit reports `waf:<id>`)
and the case-sensitive selector for exclusions; rules are evaluated in file
order, first match wins, and a disabled rule simply falls through to the next
matching rule. Separate files remain fully supported for genuinely different
rule sets:

```yaml
defaults:
  waf:
    keywords:
      enabled: true
      rules_file: /etc/guardian/rules.d/common.yaml

domains:
  # A real WordPress site: keep the shared starter set but drop its
  # wp-probe rule, which would flag legitimate wp-login traffic.
  wordpress.example.com:
    waf:
      keywords:
        disabled_rule_ids: [ wp-probe ]

  # APIs get their own, stricter-or-looser file instead of the shared one
  # (e.g. drop challenge-action heuristics, which degrade to deny where PoW
  # is off). Exclusions always select from the scope's own effective file,
  # here api.yaml.
  api.example.com:
    waf:
      keywords:
        enabled: true
        rules_file: /etc/guardian/rules.d/api.yaml
        disabled_rule_ids: [ scanner-ua ]

  # No signature matching at all on the assets host.
  static.example.com:
    waf:
      keywords:
        enabled: false
```

`disabled_rule_ids` overlays like every list: omitted inherits the parent's
resolved list, `[]` clears inherited exclusions, and a non-empty list replaces
them wholesale. Unknown, empty or duplicate ids are rejected at `-t`, startup
and reload, and a rules-file update that removes a still-excluded id keeps the
last-good rules active, so a typo or rename can never silently re-enable a
rule. `GET /admin/config` shows each scope's effective `rules_file` and
exclusions together.

See [the signature-rules walkthrough](/guide/configuration#signature-rules-waf-keywords)
for the file format, inheritance, and hot-reload behavior, and the
[field reference](/reference/configuration#waf-keywords) for every rule field.

## Suspicion-only challenges (anomaly model)

This fragment disables the catch-all and defines only an anomaly challenge
policy, so ordinary visitors never see an interstitial. Explicit WAF, GeoIP,
or reputation challenge policies would still apply. Requires a [trained
model](/guide/anomaly) and a top-level signing key.

```yaml
domains:
  shop.example.com:
    pow: { enabled: true, mode: suspicion, base_difficulty: 5.5, max_difficulty: 6 }
    waf:
      anomaly: { enabled: true, model: /etc/guardian/model.json,
                 challenge_at: 0.5, deny_at: 0.85 }
```

## GeoIP scoping and reputation feeds

Deny or challenge by origin country/ASN, and enforce external blocklists.
Needs MaxMind-format databases on disk (GeoLite2 or DB-IP); grab them from
[the P3TERX mirror or MaxMind](/guide/bots-ip-intel#getting-the-databases),
then see [Bots, GeoIP & Reputation](/guide/bots-ip-intel).

```yaml
signing_key_file: /var/lib/guardian/ed25519.key

defaults:
  pow: { enabled: true }
  reputation: { enabled: true }   # every domain enforces the feeds
  geo:
    enabled: true
    deny: { countries: [ KP ] }
    challenge: { countries: [ CN, RU ] }

geoip:
  location_db: /var/lib/GeoIP/GeoLite2-Country.mmdb
  asn_db: /var/lib/GeoIP/GeoLite2-ASN.mmdb

reputation:
  cache_dir: /var/lib/guardian/feeds
  feeds:
    - name: firehol-level1
      url: https://iplists.firehol.org/files/firehol_level1.netset
      refresh: 12h
      action: deny

domains:
  # Home-market shop: NL/BE/DE browse normally, everyone else proves work.
  shop.example.nl:
    geo:
      enabled: true
      allow: { countries: [ NL, BE, DE ] }
      deny: { countries: [] }
      challenge: { countries: [] }
      default_action: challenge
```

## The full annotated example

The complete `guardian.example.yaml` shipped with every release, every option
annotated. It is the **host/systemd profile**: loopback listeners, root-owned
read-only config under `/etc/guardian`, generated keys and state under
`/var/lib/guardian` (see
[Filesystem layout and ownership](/guide/production#filesystem-layout-and-ownership)).
The [Getting Started guide](/guide/getting-started#_2-configure-guardian)
installs this file and its required starter rules at those exact paths.
For containers, follow the
[Docker section of the production guide](/guide/production#docker), which
adapts the listeners (`0.0.0.0` + `trusted_proxy` behind loopback-only port
bindings) and puts keys and state on named volumes. The repo's
`deploy/docker/guardian.docker.yaml` is the runnable **demo harness only**; it
contains a fixed admin token and demo-only exceptions, so don't copy it into
production.

<!-- Included verbatim from the repo root; edit guardian.example.yaml, not this page. -->
<<< ../guardian.example.yaml

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

    # Guardian: auth_request wiring + challenge/pass/denied routes. Adapt the
    # file's two http://your_backend placeholders before including it; it
    # already declares location /, so do not add another root location here.
    include /etc/angie/angie-guardian.conf;

    # JSON access log feeding guardian-train (format from deploy/angie-json-log.conf).
    access_log /var/log/angie/example.com.access.json guardian_json;

}
```

## Multi-instance replicas (Redis/Valkey)

```yaml
store:
  backend: redis            # same value for both Redis and Valkey
  addr: 127.0.0.1:6379
  # password: ""            # or the REDIS_PASSWORD env var
signing_key_file: /var/lib/guardian/ed25519.key   # same file on every replica
previous_key_dir: /var/lib/guardian/keys.d        # same lock-capable shared filesystem
# Retired archives verify pre-rotation tokens for at most 7 days; older files
# may be retained on disk but are ignored by the active verifier.
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
            # invent your own trap path; in the WASM guest a hit denies only
            # that request (no persistent block), but a copied generic path
            # can still deny a route your site really serves
            honeypot:  { enabled: true, paths: [ "/your-own-trap/" ] }
            rules:
              - { id: dotfile, action: deny, keywords: [ "/.env", "/.git/" ] }
      ';
}
```
