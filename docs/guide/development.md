# Development

This page is about working on Guardian itself rather than running it.
Everything here needs a repository checkout and the Go toolchain selected by
`go.mod`, and none of it is part of a release: the tools live under `test/` and
are run with `go run`, so they are never installed on a server and never
compiled into `guardiand`.

## Test and benchmark targets

| Target | What it covers |
|---|---|
| `make test` | The whole tree under `-race`. Fast, and the one to run constantly. |
| `make e2e` | Real Angie plus guardiand plus a backend, driven through Angie. Needs Docker. |
| `make e2e-nft` | The nftables block-offload path. Needs `nf_tables` and `NET_ADMIN`, and skips cleanly without them. |
| `make fuzz` | Every fuzz target for `FUZZTIME` each: the URI decoder, WAF rules, config, the anomaly model, PoW redeem. |
| `make vet` | `go vet ./...`. |
| `make bench-regress` | Hot-path `allocs/op` against `allocs-baseline.txt`. Deterministic, so it also runs in CI. |
| `make bench-report` | A hot-path snapshot of the current tree (`sec/op`, `B/op`, `allocs/op`) with the spread across runs. Manual, gates nothing, wants a quiet machine. |

The end-to-end suite only runs in CI on `main` and on release tags, never on a
merge request, so run `make e2e` locally before merging anything that touches
the request path or the Admin API. For throughput numbers use
[`guardian-loadtest`](/guide/load-testing), never a benchmark.

## Seed the dashboard with traffic

An empty dashboard is hard to work on. `make seed` fills a throwaway instance
with a realistic mix (solved and failed proof of work, challenges, denies,
behavioural blocks, allowed traffic), from two shells:

```sh
go run ./cmd/guardiand -config test/seed/guardian.seed.yaml
make seed                  # two minutes
make seed SEEDTIME=5m
```

Then open `http://127.0.0.1:18072/admin/dashboard#token=seed-demo-token`. The
seed configuration is memory-only and meant for local development. This is not
a load test: it generates variety, not throughput.

## Try a dashboard change against a running daemon

The dashboard is embedded in the binary with `go:embed`, so seeing an edit
against real data would otherwise mean a rebuild and a deploy.
`make dashboard-dev` serves `web/dashboard.html` from the working tree and
forwards every other `/admin/` path to a guardiand that is already running,
wherever it is:

```sh
make dashboard-dev                                      # the seed instance above
make dashboard-dev UPSTREAM=http://192.168.1.42:8072    # a real deployment
make dashboard-dev UPSTREAM=... DASHDEV_LISTEN=127.0.0.1:9000
```

Open `http://127.0.0.1:8073/admin/dashboard` and enter that daemon's admin
token. The edit loop is then save the file and reload the tab: the HTML is read
on every request.

Nothing about the page changes to make this work. Its URLs are origin-relative
(it fetches `/admin/stats`, and loads `chart.umd.min.js` relative to
`/admin/dashboard`), so any listener answering both the page and `/admin/*`
serves it unmodified. That means no CORS, no configuration key, and no special
build: the bearer token is forwarded untouched and the upstream authenticates
it exactly as it would for its own copy of the page.

::: warning It is a real daemon on the other side
The dashboard's write actions (unblock, clearing counters, blocking an IP) are
forwarded like everything else, so against a production upstream they act on
production.

The locally served page also carries no `Content-Security-Policy`. guardiand
sets a fitted one on its own dashboard route, and reproducing it here would
only let a local experiment fail for an unrelated reason, so this proves page
logic and not the policy.
:::

Passing `-page ""` serves the copy embedded in the build instead of the working
tree, which turns the same command into a plain viewer for a remote daemon:

```sh
go run ./test/dashdev -upstream http://192.168.1.42:8072 -page ""
```

This is deliberately a development command rather than a mode of `guardiand`.
Every in-daemon alternative charges the production binary for a development
convenience: letting the page live on another origin needs CORS on a
token-guarded admin API, serving the page off disk adds a filesystem read path
plus ambiguity about which HTML is live, and a forwarding mode inside guardiand
would put an operator-authenticated reverse proxy inside a security daemon.

## Testing the dashboard's own logic

The dashboard is one self-contained page, and a fair amount of what an operator
reads is decided by its inline script: the User-Agent classification behind
"Solve time by client", the bucket walk behind every p90, the rollups over the
decisions feed. That logic is covered by `web/dashboard_script_test.go`, which
lifts named top-level declarations out of `dashboard.html` and runs them in
[goja](https://github.com/dop251/goja), a pure-Go JavaScript interpreter, with
small stubs for the page's DOM builders. It needs no browser, no headless
Chrome and no `node` in CI, and it is a test-only dependency that is absent from
the shipped binary.

```go
vm := jsRuntime(t, "millis", "UA_CLASSES", "uaClass")
var got string
call(t, vm, `uaClass("Mozilla/5.0 (Linux; Android 15; Pixel 9) ... Mobile Safari/537.36")`, &got)
// got == "mobile"
```

Prefer adding a case there over asserting that a line of markup exists.
`transport/http/admin_assets_test.go` still checks that the served page
contains the identifiers the code expects, but a needle only proves a line is
present, never that it does the right thing.
