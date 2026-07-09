# WASM Module

Instead of the sidecar, you can run Guardian's **stateless WAF checks**
in-process inside Angie via its WebAssembly support. This path does the
store-free checks only (allowlist, denylist, honeypot, keyword/regex
signatures); proof-of-work, behavioural IP blocking, and anomaly scoring need
the shared store and remain sidecar-only.

Use it when you want the WASM integration and the stateless WAF subset is
enough, or alongside a backend that handles the rest. Both paths call the same
store-free evaluator, so the WAF decisions are identical to the sidecar's.

## Build

The module is architecture-independent:

```sh
make wasm        # -> dist/guardian.wasm
# or: GOOS=wasip1 GOARCH=wasm go build -o guardian.wasm ./transport/wasm
```

## Load it into Angie

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

## A config error fails closed

::: danger Validate before reloading production Angie
If the `config=` blob does not parse (a typo'd field, an invalid CIDR, or two
domain keys that collapse to the same host after normalization: `a.test` vs
`A.test:443`) the guest denies **every request on every host** with
`500 Guardian WASM misconfigured`, and the only signal is one line in Angie's
error log.
:::

Unlike the sidecar, which refuses to start on a bad `guardian.yaml`, a bad
guest config only surfaces at request time. Exercise a request against a
staging instance first, or run the same blob through the sidecar's loader.
