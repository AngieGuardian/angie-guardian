# Angie Guardian: Usage

A step-by-step guide to configuring, deploying and operating Angie Guardian.
For an overview of what Guardian is and how it works, see the
[README](README.md).

## Contents

1. [Configure Guardian](#1-configure-guardian)
2. [Wire it into Angie](#2-wire-it-into-angie)
3. [Run it (systemd)](#3-run-it-systemd)
4. [Operate it via the admin API](#4-operate-it-via-the-admin-api)
5. [Train the anomaly model](#5-train-the-anomaly-model)
6. [Load-test your deployment](#6-load-test-your-deployment)
7. [Multi-instance (redis)](#multi-instance-redis)

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
  pow: { enabled: true, base_difficulty: 4 }
  waf:
    ip_behaviour: { enabled: true }

domains:
  example.com: {}                 # inherits all defaults
```

Per-domain entries are merged field-by-field over `defaults`, so a domain only
names what it changes. Unknown hosts fall back to `defaults`.

```yaml
domains:
  # HTML site behind PHP/Node: full protection.
  example.com:
    pow: { enabled: true, base_difficulty: 5, token_ttl: 2h }
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
    pow: { enabled: true, mode: suspicion, base_difficulty: 4, max_difficulty: 6 }
    waf:
      anomaly: { enabled: true, model: /etc/guardian/model.json,
                 challenge_at: 0.5, deny_at: 0.85 }
```

Validate a config without starting the daemon by pointing a throwaway run at
it. A bad config exits non-zero with the reason:

```sh
./guardiand -config guardian.yaml -version   # loads+validates, then prints version
```

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
the sidecar is down) and the challenge/pass/denied routes. To feed the anomaly
trainer, switch protected vhosts to the JSON access log from
`deploy/angie-json-log.conf`:

```nginx
access_log /var/log/angie/example.com.access.json guardian_json;
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

The admin API + `/metrics` live on `admin.listen` (default `127.0.0.1:8072`),
separate from the auth hot path. `/metrics` and `/healthz` are open; every
`/admin/*` route needs the bearer token (`admin.token`, or the `ADMIN_TOKEN`
env var). Bind to a non-loopback address and Guardian refuses to start without
a token.

```sh
TOKEN=your-admin-token
A=http://127.0.0.1:8072

# Is an IP currently blocked, and why?
curl -s -H "Authorization: Bearer $TOKEN" $A/admin/blocks/203.0.113.9
# {"ip":"203.0.113.9","blocked":true,"reason":"threshold:signature"}

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
```

## Multi-instance (redis)

To run replicas behind a load balancer, point every instance at one
redis/valkey and share the signing key + `previous_key_dir` across them, so any
instance verifies any other's tokens and sees any other's blocks:

```yaml
store:
  backend: redis
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
