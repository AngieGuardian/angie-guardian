# WASM Module

Instead of the sidecar, you can run Guardian's **stateless WAF checks**
in-process inside Angie via its WebAssembly support. This path does the
store-free checks only (allowlist, denylist, honeypot, keyword/regex
signatures); proof-of-work and behavioural IP blocking need sidecar state,
while anomaly scoring also remains sidecar-only.

Use it when you want the WASM integration and the stateless WAF subset is
enough, or alongside a backend that handles the rest. Both paths share the
same parsing and matching logic. The guest has no store or PoW manager, so a
matching `deny`, `challenge`, or `block` rule returns the same `403`, and a
honeypot hit denies only that request; only the sidecar can issue a challenge
or persist an IP block. Per-path `paths` overlays are also sidecar-only: the
guest config schema does not accept a `paths` key.

## Build

The module is architecture-independent:

```sh
make wasm        # -> dist/guardian.wasm
# or: GOOS=wasip1 GOARCH=wasm go build -o guardian.wasm ./transport/wasm
```

## Load it into Angie

Requires an Angie build with WASM support (wasmtime or WAMR). Load it and wire
the handler using the snippet in [`deploy/angie-wasm.conf`](https://gitlab.melroy.org/melroy/angie-guardian/-/blob/main/deploy/angie-wasm.conf):

```nginx
# http {} context: load the module once, with the guest config inline.
wasm_modules {
    load /etc/guardian/guardian.wasm id=guardian type=reactor
      config='
        domains:
          example.com:
            allowlist: { paths: [ "/robots.txt" ] }
            # invent your own trap path; a guest honeypot hit denies only
            # that request (no persistent block), but a copied generic path
            # can still deny a route your site really serves
            honeypot:  { enabled: true, paths: [ "/your-own-trap/" ] }
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

## A config error fails closed

::: danger Validate before reloading production Angie
If the `config=` blob does not parse (a typo'd field, a trailing YAML document,
an invalid CIDR, or two domain keys that collapse to the same host after
normalization: `a.test` vs `A.test:443`) the guest denies **every request on
every host** with `500 Guardian WASM misconfigured`, and the only signal is one
line in Angie's error log.
:::

Unlike the sidecar, which refuses to start on a bad `guardian.yaml`, a bad
guest config only surfaces at request time. The guest schema uses inline
`rules` and is not accepted by `guardiand -t`, so exercise a request against a
staging WASM instance before reloading production Angie.
