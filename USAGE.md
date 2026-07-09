# Angie Guardian: Usage

A step-by-step guide to configuring, deploying and operating Angie Guardian.
For an overview of what Guardian is and how it works, see the
[README](README.md).

## Contents

1. [Configure Guardian](#1-configure-guardian) (including
   [difficulty tuning](#base_difficulty-and-max_difficulty))
2. [Wire it into Angie](#2-wire-it-into-angie)
3. [Run it (systemd)](#3-run-it-systemd)
4. [Operate it via the admin API](#4-operate-it-via-the-admin-api) (including
   [the reporting dashboard](#the-reporting-dashboard))
5. [Train the anomaly model](#5-train-the-anomaly-model)
6. [Load-test your deployment](#6-load-test-your-deployment)
7. [Choosing a store backend](#choosing-a-store-backend)
8. [Multi-instance (Redis/Valkey)](#multi-instance-redisvalkey)
9. [WASM module (optional)](#wasm-module-optional)

## 1. Configure Guardian

Copy `guardian.example.yaml` and adjust it. The minimum viable config is tiny;
everything else inherits from `defaults`:

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

Per-domain entries are merged field-by-field over `defaults`, so a domain only
names what it changes. Unknown hosts fall back to `defaults`.

```yaml
domains:
  # HTML site behind PHP/Node: full protection. Difficulty takes quarter
  # steps: 5.25 is exactly 2x the work of 5 (see the difficulty table below).
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

  # Only challenge clients the anomaly scorer flags; ordinary visitors
  # never see an interstitial. Requires a trained model (see below).
  shop.example.com:
    pow: { enabled: true, mode: suspicion, base_difficulty: 5, max_difficulty: 6 }
    waf:
      anomaly: { enabled: true, model: /etc/guardian/model.json,
                 challenge_at: 0.5, deny_at: 0.85 }
```

Validate a config without starting the daemon with `-t` (like `angie -t`). It
loads and validates the file (YAML syntax, unknown fields, and semantic checks),
then exits: `0` and `ok` when valid, `1` and the reason when not.

```sh
./guardiand -config guardian.yaml -t
# config guardian.yaml: ok
# ...or, on a bad config:
# config guardian.yaml: FAILED
# config guardian.yaml: store.backend must be memory, bbolt or redis, got "etcd"
```

### Signature rules

`waf.keywords.rules_file` points at a YAML rules file (start from
`deploy/rules-common.yaml`, which documents every field). Rules are keyword
and RE2-regex signatures with an `action` of `deny`, `challenge` or `block`,
hot-reloaded on change. A rule matches against the targets it names:

- `path`, `query` (the default pair) and `ua`, all URL-decoded and lowercased;
- `header:<name>` for any request header, e.g. `header:referer` to catch
  Log4Shell-style payloads hiding in URL-shaped headers (values are
  percent-decoded too, so encoding is no escape hatch);
- `methods: [ TRACE, TRACK ]` restricts a rule to those HTTP methods, and a
  rule with only `methods` fires on the method alone.

**Request bodies are never inspected.** Angie's `auth_request` subrequest
carries only the request line and headers, never the body, so no rule can see
POST payloads. That is a deliberate design boundary, not a missing feature:
inspecting bodies would mean buffering every upload through the sidecar.
Body-borne attacks are for your backend's input validation or a full inline
WAF; Guardian's job is keeping bots and scanners from reaching it at all.

### base_difficulty and max_difficulty

`base_difficulty` is the **floor** every clean client pays; `max_difficulty` is
the **ceiling**. They are not a choice between two modes: a request's suspicion
score decides where in `[base, max]` it lands.

A difficulty of `N` requires `4 * N` leading zero **bits** in the SHA-256, so a
full step (+1) is 16x the work, and the scale takes **quarter steps**: each
+0.25 is exactly one bit, doubling the expected work. `5.25` is twice as hard
as `5`, `5.5` four times, giving fine-grained control between the huge full
steps. Values off the quarter grid (like `4.3`) are rejected at load.

Which value fires:

- **`mode: always` (the default):** every unvouched browser-shaped request pays
  exactly `base_difficulty`, once, then rides a `token_ttl` cookie.
- **A WAF signature hit:** one full step over base (`base + 1`, i.e. +4 bits =
  16x, capped at `max`).
- **The anomaly scorer:** scales the difficulty across the `[base, max]` range
  with the score, so a more bot-like client pays more. Requires `waf.anomaly`
  enabled with a trained model.
- **Challenge farming:** an IP that keeps requesting challenges without ever
  solving one gets escalated on top of whichever value above applied. The
  first 4 unsolved challenges are free (multiple tabs, reloads), then every 2
  further abandoned challenges add one bit (2x work), capped at `max`. Any
  successful solve resets the IP to a clean slate. The counter lives for
  `challenge_ttl`, and escalated issuances show up in Prometheus as
  `guardian_challenges_total{outcome="escalated"}`.

#### Measured solve times and recommended values

The interstitial solves in parallel web workers (up to 8) with a pure-JS
SHA-256. Measured throughput in Chrome on a fast desktop is ~1.1 million
hashes/s per worker, ~9 MH/s with 8 workers; scale down for weaker devices.
For comparison, a native (Go) solver does ~7.6 MH/s **per core**, so a bot
pays the same order of work a real browser does.

Expected (mean) solve times by device class:

| difficulty | bits | expected hashes | desktop (9 MH/s) | laptop (3 MH/s) | phone (1 MH/s) |
|-----------:|-----:|----------------:|-----------------:|----------------:|---------------:|
| 4.0        | 16   | 66 k            | 0.01 s           | 0.02 s          | 0.07 s         |
| 4.5        | 18   | 262 k           | 0.03 s           | 0.09 s          | 0.26 s         |
| 5.0        | 20   | 1.0 M           | 0.12 s           | 0.35 s          | 1.0 s          |
| 5.25       | 21   | 2.1 M           | 0.23 s           | 0.7 s           | 2.1 s          |
| 5.5        | 22   | 4.2 M           | 0.47 s           | 1.4 s           | 4.2 s          |
| 5.75       | 23   | 8.4 M           | 0.9 s            | 2.8 s           | 8.4 s          |
| 6.0        | 24   | 16.8 M          | 1.9 s            | 5.6 s           | 17 s           |
| 6.5        | 26   | 67 M            | 7.5 s            | 22 s            | 67 s           |

Solve time is exponentially distributed around the mean: the median visitor
waits ~0.7x the mean, but ~5% wait 3x and ~1% wait 4.6x. Budget for the tail,
not the mean.

Recommendations:

- **`base_difficulty: 5`** (the default): imperceptible on desktop, about a
  second on a mid-range phone. A sensible tax for `mode: always`, paid once
  per `token_ttl`.
- **`5.25`–`5.5`** when you are actively being scraped and can accept a few
  seconds on phones.
- **`4`–`4.5`** only when the interstitial itself (not the work) is the
  deterrent you want; the computation is near instant everywhere.
- **`max_difficulty: 6`** (the default) for anomaly escalation. `6.5` and up
  is effectively a soft deny: a minute of hashing on a phone. Values above 7
  mostly punish real visitors on slow devices.
- Watch `guardian_challenge_solve_seconds` in Prometheus (or the average on
  the dashboard) after changing values: it is the real-world solve time of
  *your* visitors' devices.

Note that PoW only taxes clients that solve the puzzle. A client that farms
challenges without solving them is throttled (60 issuances per IP per minute)
and escalated (see challenge farming above), but a raw flood that never even
follows the challenge redirect is **not** PoW's problem: see
[Rate limiting](#rate-limiting-volumetric-ddos) below.

## 2. Wire it into Angie

Add the keepalive upstream once in the `http {}` context, then include the
per-server snippet in each protected `server {}` block:

```nginx
# http {} context, REQUIRED for throughput (connection reuse to the sidecar):
upstream guardian {
    server 127.0.0.1:8071;
    keepalive 64;
}

# each protected server {} block:
include /etc/angie/angie-guardian.conf;   # from deploy/angie-guardian.conf
```

`deploy/angie-guardian.conf` documents the fail-open toggle (what happens when
the sidecar is down) and the challenge/pass/denied routes. Two header relays in
that snippet matter beyond routing: `X-Guardian-Difficulty` carries an
escalated difficulty (WAF signature hit, anomaly score) from the auth decision
into the issued challenge, and `X-Guardian-Proto` (`$scheme`) tells Guardian
whether the token cookie may carry the `Secure` flag; without it a plain-http
site would loop on the challenge. If you wrote your own glue before these
lines existed, copy them over.

To feed the anomaly trainer, switch protected vhosts to the JSON access log
from `deploy/angie-json-log.conf`:

```nginx
access_log /var/log/angie/example.com.access.json guardian_json;
```

### Rate limiting (volumetric DDoS)

PoW taxes bots that speak HTTP and solve the puzzle; it does **not** absorb a raw
flood. Every request still costs an `auth_request` subrequest and a store lookup
whether or not the client ever solves anything, and a client that follows the
challenge redirect also makes the sidecar issue and persist a challenge. Under
enough load the sidecar saturates and fail-open (the default) sends the flood
straight to your backend. Volumetric DDoS is Angie's job, in front of the
`auth_request`, so a flood is dropped before it reaches the sidecar at all. The
two layers are complementary: rate limits absorb volume, PoW taxes the bots that
get through. Tune the rates to your real traffic before enabling.

```nginx
# http {} context: one shared zone per limiter.
limit_req_zone  $binary_remote_addr zone=guard:10m rate=30r/s;
limit_conn_zone $binary_remote_addr zone=gconn:10m;

# in each protected server {} (or the location / block). limit_req runs in an
# earlier phase than auth_request, so a rejected flood never reaches the sidecar.
limit_req  zone=guard burst=60 nodelay;   # smooth spikes, reject sustained floods
limit_conn gconn 20;                       # cap concurrent connections per client
limit_req_status  429;
limit_conn_status 429;
```

## 3. Run it (systemd)

```sh
sudo cp guardiand /usr/local/bin/
sudo install -Dm600 guardian.yaml /etc/guardian/guardian.yaml
sudo cp deploy/guardiand.service /etc/systemd/system/
sudo systemctl enable --now guardiand
curl -s localhost:8072/healthz         # -> ok
```

## 4. Operate it via the admin API

The admin API + `/metrics` live on `admin.listen` (e.g. `127.0.0.1:8072`),
separate from the auth hot path. `/metrics` and `/healthz` are open; every
`/admin/*` route needs a bearer token.

You never have to invent that token yourself. It resolves in this order:

1. `admin.token` (or the `ADMIN_TOKEN` env var), if set;
2. `admin.token_file`: auto-generated on first start (0600) and reused
   forever after, like the PoW signing key;
3. neither set: a loopback listener gets a fresh ephemeral token each start,
   printed in the startup log. A non-loopback bind refuses to start without
   an explicitly configured token (1 or 2).

```sh
TOKEN=$(cat /etc/guardian/admin.token)   # or your admin.token value
A=http://127.0.0.1:8072

# Is an IP currently blocked, and why?
curl -s -H "Authorization: Bearer $TOKEN" $A/admin/blocks/203.0.113.9
# {"ip":"203.0.113.9","blocked":true,"reason":"threshold:signature"}

# List every currently active block, with reasons and expiry.
curl -s -H "Authorization: Bearer $TOKEN" $A/admin/blocks
# {"count":2,"blocks":[{"ip":"203.0.113.9","reason":"waf:dotfile-probe",
#                       "expires_at":"2026-07-05T18:30:00Z"}, ...]}

# What did the guardian just challenge or deny? Newest first, from an
# in-process ring buffer (per instance, cleared on restart). Filters:
# ?limit= (default 50), ?action=deny|challenge, ?reason=<prefix e.g. waf>.
curl -s -H "Authorization: Bearer $TOKEN" "$A/admin/decisions?action=deny&limit=20"

# A small "right now" rollup: active blocks, recent counts by action and
# reason category, and the PoW lifecycle (challenges issued/solved/failed +
# average solve seconds). (Long-horizon numbers live in /metrics.)
curl -s -H "Authorization: Bearer $TOKEN" $A/admin/stats

# Block an IP for two hours (reason + ttl optional; default 15m).
curl -s -H "Authorization: Bearer $TOKEN" -X PUT \
     -d '{"reason":"manual abuse report","ttl":"2h"}' \
     $A/admin/blocks/203.0.113.9

# Lift a block.
curl -s -H "Authorization: Bearer $TOKEN" -X DELETE $A/admin/blocks/203.0.113.9

# "Why would this request be challenged?" Score it against the domain's
# anomaly model, for tuning challenge_at / deny_at.
curl -s -H "Authorization: Bearer $TOKEN" \
     "$A/admin/score?host=shop.example.com&uri=/cgi-bin/x?a=1&ua=curl/8"
# {"host":"shop.example.com","scored":true,"score":0.72}

# Rotate the Ed25519 signing key. Old tokens keep verifying until they
# expire, so nobody is logged out.
curl -s -H "Authorization: Bearer $TOKEN" -X POST $A/admin/rotate-key
# {"rotated":true}

# See which features are active per domain.
curl -s -H "Authorization: Bearer $TOKEN" $A/admin/config

# Prometheus scrape (no token needed).
curl -s $A/metrics | grep guardian_
```

### The reporting dashboard

Set `admin.dashboard: true`, start guardiand, and open the login link it
prints:

```
INFO admin dashboard ready url=http://127.0.0.1:8072/admin/dashboard#token=9f2c…
```

The token rides the URL **fragment**, which browsers never send over the
network; the page moves it into the tab's sessionStorage and scrubs it from
the address bar. (Opening the bare URL instead shows a paste-the-token gate.)

The dashboard shows active blocks (with one-click unblock and a block-an-IP
form), the recent deny/challenge feed (filterable by action and free text),
challenge lifecycle counters with the average solve time, per-domain feature
status, and headline counters, auto-refreshing every 5 seconds. The page is a
static shell: it stores no secrets and every data call goes to the
token-guarded `/admin/*` endpoints. It is **internal-only by construction**:
it lives on the admin listener, which refuses a non-loopback bind without a
configured token, and stays off unless enabled.

## 5. Train the anomaly model

Once JSON logs have accumulated, build a per-domain baseline offline and drop
it where the config's `anomaly.model` points. `guardiand` hot-swaps the
artifact when the file changes, no restart needed:

```sh
guardian-train -out /etc/guardian/model.json \
               -min-requests 5000 \
               /var/log/angie/*.access.json

# From a stream (e.g. journald, or gzip'd logs):
zcat /var/log/angie/example.com.access.json.*.gz | guardian-train -out model.json -
```

Re-run it from cron; `guardiand` picks up each new model within seconds.
Domains below `-min-requests` are dropped (a thin baseline misclassifies
everything).

## 6. Load-test your deployment

`guardian-loadtest` drives the `/auth` hot path the way Angie does, over
keepalive connections, and reports throughput + latency percentiles:

```sh
# Plain allow path (full pipeline).
guardian-loadtest -url http://127.0.0.1:8071 -scenario allow -host example.com -c 64 -d 10s

# Production common path: solve one real challenge, then hammer with the cookie.
guardian-loadtest -scenario token -host example.com -c 128 -d 10s

# Worst case: a denylisted client (exercises the deny + logging path).
guardian-loadtest -scenario deny -host example.com -ip 203.0.113.9 -c 64 -d 10s

# Write path: issue a fresh PoW challenge per request (a store CAS write each).
# This is what separates the store backends; see the Performance table in the
# README. The scenario rotates the client IP itself to avoid the issuance limit.
guardian-loadtest -scenario challenge -host example.com -c 64 -d 10s
```

The `allow`, `token` and `deny` scenarios are read-dominated (one block lookup
each) and behave the same on any backend; `challenge` is write-heavy and is
where bbolt's single embedded writer trails redis/valkey. See
[Choosing a store backend](#choosing-a-store-backend).

## Choosing a store backend

- **memory**: single instance, state lost on restart. Fine for dev or a small
  site that can re-learn blocks after a restart.
- **bbolt**: single instance, persistent. The default. Writes are coalesced
  (`db.Batch`) so concurrent challenge/event writes share fsyncs, but it is
  still one embedded writer: under a very high sustained rate of *new* clients
  (each of which triggers a challenge write in `pow.mode: always`), the single
  writer becomes the ceiling. Load-test with `guardian-loadtest` at your
  expected new-client rate before relying on it near 50k req/s; if the writer
  saturates, switch to the `redis` backend or set `pow.mode: suspicion` (only
  anomalous clients are challenged, so most requests do no write).
- **redis**: multi-instance and the highest write throughput. Works with both
  Redis and [Valkey](https://valkey.io/) (the open-source Redis fork), which is
  a drop-in replacement (same wire protocol, same `backend: redis` value). See
  below.

## Multi-instance (Redis/Valkey)

To run replicas behind a load balancer, point every instance at one shared
Redis or Valkey instance and share the signing key + `previous_key_dir` across
them, so any instance verifies any other's tokens and sees any other's blocks.
Valkey is a fully compatible drop-in replacement for Redis; the configuration
is identical for both.

```yaml
store:
  backend: redis            # same value for both Redis and Valkey
  addr: 127.0.0.1:6379
  # password: ""          # or the REDIS_PASSWORD env var
signing_key_file: /etc/guardian/ed25519.key   # same file on every replica
previous_key_dir: /etc/guardian/keys.d        # shared, e.g. NFS or synced
```

## WASM module (optional)

Instead of the sidecar, you can run Guardian's **stateless WAF checks**
in-process inside Angie via its WebAssembly support. This path does the
store-free checks only (allowlist, denylist, honeypot, keyword/regex
signatures); proof-of-work, behavioural IP blocking, and anomaly scoring need
the shared store and remain sidecar-only. Use it when you want the WASM
integration and the stateless WAF subset is enough, or alongside a backend that
handles the rest.

Build the module (architecture-independent):

```sh
make wasm        # -> dist/guardian.wasm
# or: GOOS=wasip1 GOARCH=wasm go build -o guardian.wasm ./transport/wasm
```

Requires an Angie build with WASM support (wasmtime or WAMR). Load it and wire
the handler using the snippet in `deploy/angie-wasm.conf`:

```nginx
# http {} context: load the module once, with the guest config inline.
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

# location {}: run the guest as the content handler.
location / {
    wasm_content handler "ngx:wasi/http-handler-entry#handle-request" module=guardian;
    # ... your normal proxy_pass / root handling continues when allowed ...
}
```

The guest reads its per-domain config from the module `config=` blob (YAML or
JSON) via the http-wasm `get_config` call. It returns *allow* to continue to
your backend, or a `403` to block. Editing the rules means updating the Angie
config and reloading Angie (the `.wasm` itself does not need rebuilding for a
config change).

**A config error fails closed.** If the `config=` blob does not parse (a
typo'd field, an invalid CIDR, or two domain keys that collapse to the same
host after normalization: `a.test` vs `A.test:443`) the guest denies **every
request on every host** with `500 Guardian WASM misconfigured`, and the only
signal is one line in Angie's error log. Unlike the sidecar, which refuses to
start on a bad `guardian.yaml`, a bad guest config only surfaces at request
time, so validate before reloading production Angie: exercise a request
against a staging instance first, or run the same blob through the sidecar's
loader.
