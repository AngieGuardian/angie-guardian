# Proof-of-work algorithms

`sha256` is the recommended default. `argon2id` is an optional fleet-default or
per-domain policy. Both issue a short-lived, host/IP-bound challenge and mint
the same signed browser token after a valid solution. Changing the configured
algorithm does not revoke existing tokens.

## Which algorithm should I use?

We recommend `sha256` for most sites, especially those handling high request
rates. Visitors' browsers do the work of finding a valid proof, while Angie
Guardian can check that proof quickly with very little server work. Choose
`argon2id` only when you have measured evidence that it is a better fit for
your site.

Consider `argon2id` when attackers can use GPUs or ASICs to solve SHA-256
puzzles much faster than visitors' browsers. Argon2id requires memory bandwidth
as well as CPU time, which reduces but does not eliminate that hardware
advantage. Angie Guardian asks for exactly one result with a bounded memory and
iteration cost.

That trade-off has real costs:

- each proof uses 8–32 MiB (32 MiB by default), and the single worker starts
  with 40 MiB of WASM linear memory with a hard 48 MiB ceiling; this is more
  demanding on old or memory-constrained phones;
- Angie Guardian must perform the same Argon2id computation to verify a result,
  unlike SHA-256 Hashcash verification, so verifier concurrency and rate limits
  are mandatory;
- browsers need WebAssembly and Web Workers; the content-addressed worker,
  runtime, and WASM add about 34 KiB on first use, then are cached immutably;
- Argon2id reduces a hardware cost imbalance. It does not identify humans,
  stop distributed clients, or absorb a connection flood.

Neither option is “quantum proof.” A sufficiently capable quantum computer can
in theory use Grover-style search to reduce generic hash-search complexity.
Argon2id is a memory-hard password-hashing construction, not a post-quantum
proof system. Angie Guardian's PoW buys an economic cost today, not a
cryptographic guarantee about future hardware.

## Configure Argon2id

The algorithm and its work parameters are allowed in `defaults` and per domain,
but not in `paths:`. A host uses one browser runtime consistently; path overlays
may still enable or disable PoW, change token lifetime, or tune other policy.

```yaml
argon2_verifier:
  max_concurrent: 1
  verification_rate_limit: 10/min

defaults:
  pow:
    enabled: true
    algorithm: sha256

domains:
  memory-hard.example.com:
    pow:
      algorithm: argon2id
      argon2id:
        memory_kib: 32768
        base_iterations: 1
        max_iterations: 2
        attack_iterations_cap: 3
```

This is one fixed-result Argon2id computation. Angie Guardian does **not**
combine the memory cost with a leading-zero search. Normal visitors get
`base_iterations`; suspicion or per-client escalation selects
`max_iterations`; attack posture is hard-capped by
`attack_iterations_cap`. Parallelism is fixed at one and the output is 32
bytes. Memory is limited to 8192–32768 KiB and iterations to 1–3, so the
browser launches exactly one worker; its WASM linear memory has a hard 48 MiB
ceiling.

Each stateful challenge record or signed stateless challenge ID carries the
algorithm, memory, iterations, and salt selected at issuance. Redemption uses
those authenticated values, not the current domain setting. A challenge issued
just before a hot reload from `sha256` to `argon2id`, or the reverse, is
therefore solvable until its normal `challenge_ttl` expires.

## Server capacity and saturation

`argon2_verifier.max_concurrent` is global because every domain shares the
process CPU, heap, and memory bus. Start at one. Admission occurs only after
cheap challenge authentication, freshness, and binding checks. A full pool
returns `503 Retry-After` without consuming the challenge; the browser retries
the same result with capped exponential backoff plus 0–1500 ms random jitter.
The verification rate is independently enforced per host+IP and, when
`geoip.asn_db` is configured, per host+ASN. Exhausting that rate returns `429`
with `Retry-After` set to the remaining time in the fixed rate-limit window,
also without consuming the challenge; the browser retries that same result
through the same bounded retry path.

For a high-throughput proxy host, reserve the cores used by ordinary Angie
Guardian traffic and provide two additional cores for Argon2id and runtime
overhead: if the hot path needs `N` cores, provision at least `N+2`. Do not
place a systemd `CPUQuota` or container CPU limit below that budget. The
verifier has its own bounded admission path, but runs in the same Go process;
prove the result on your hardware with simultaneous token-path traffic and
Argon2id redemptions. The token-path throughput/latency must fit your budget.
For Angie Guardian's 150k req/s target, use a maximum 5% throughput regression
as the acceptance gate.

Each concurrent default verification needs roughly 32 MiB in addition to the
normal service heap. Include `max_concurrent * memory_kib` plus headroom when
setting `GOMEMLIMIT`, systemd `MemoryMax`, or a container memory limit.

## JavaScript-free fallback

`noscript_fallback` is `false` by default and may be enabled in `defaults`, a
domain, or a path overlay. With it enabled, a browser with JavaScript disabled,
or without usable Web Workers/WebAssembly, may redeem the challenge only after
the mandatory minimum five-second wait.

```yaml
pow:
  noscript_fallback: true
  noscript_redemption_rate_limit: 6/min
```

This deliberately disables computational proof for that client. Waiting is
cheap to parallelize, so it weakens both algorithms. Angie Guardian therefore
applies an independent pre-redemption limit per host+IP and, when known, per
host+ASN after authenticating the challenge and its original URI, but before
minting a token. The original URI selects the effective domain/path-overlay
limit; rotating paths does not create separate counters. The fallback never
bypasses Angie's `limit_req`/`limit_conn`, a CDN limit, or any other global
front-door limit. Leave it off unless no-script accessibility is worth that
trade-off.

## Implementations and browser supply chain

The server verifier uses `golang.org/x/crypto/argon2`, the Go project's
supplementary cryptography package. It does not depend on a similarly named
third-party GitHub wrapper.

The solver uses the official `P-H-C/phc-winner-argon2` C reference source pinned
to commit `f57e61e19229e23c4445b85494dbf7c07de721cb`, compiled with the pinned
Emscripten 4.0.10 image. The generated WASM is 23,672 bytes. CI rebuilds it
byte-for-byte and rejects a WASM artifact above 300 KiB. Content-addressed JS
and WASM responses carry:

```text
Cache-Control: public, max-age=31536000, immutable
```

Run `./scripts/build-argon2-wasm.sh` to reproduce and verify the committed
artifacts locally. The source license and pin are under
[web/argon2-reference/](https://github.com/AngieGuardian/angie-guardian/tree/main/web/argon2-reference/README.md).
