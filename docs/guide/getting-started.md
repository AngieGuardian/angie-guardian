# Getting Started

This walks you from a fresh checkout to a protected site in four steps:
build, configure, wire into Angie, verify.

## Prerequisites

- [Angie](https://angie.software/) serving your site(s).
- Go (to build from source), or a release tarball with prebuilt binaries.

## 1. Build

```sh
go build ./cmd/guardiand
```

Or grab a release archive from the
[releases page](https://gitlab.melroy.org/melroy/angie-guardian/-/releases);
it contains `guardiand`, `guardian-train`, `guardian-loadtest`, the optional
`guardian.wasm`, and the deploy snippets.

## 2. Configure

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

Validate it without starting the daemon (like `angie -t`):

```sh
./guardiand -config guardian.yaml -t
# config guardian.yaml: ok
```

See the [Configuration guide](/guide/configuration) for the per-domain model
and difficulty tuning, and the
[Configuration Options reference](/reference/configuration) for every field.

## 3. Wire it into Angie

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

See [Wire it into Angie](/guide/angie) for the fail-open toggle, JSON access
logs, and rate limiting.

## 4. Run and verify

```sh
./guardiand -config guardian.yaml
curl -s localhost:8072/healthz     # -> ok
```

Visit your site in a browser: the first request gets a brief interstitial
while the proof-of-work is solved, then a signed cookie keeps subsequent
requests on the fast path. A `curl` without the cookie sees the challenge
response instead.

For a permanent setup (systemd unit, store choice, multi-instance), continue
with [Run it in Production](/guide/production).
