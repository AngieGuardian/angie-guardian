# Angie Guardian build targets.
# The sidecar binaries are the primary, full-featured build; `wasm` is the
# optional stateless in-process module. Nothing here is required to use Go
# directly (`go build ./cmd/guardiand` etc. still works).

VERSION ?= dev
LDFLAGS := -X main.version=$(VERSION)

.PHONY: all build wasm test e2e fuzz vet fmt clean docs docs-dev bench-store bench-regress seed

# How long each fuzz target runs in `make fuzz`. Override it locally when
# chasing a specific parser (for example `make fuzz FUZZTIME=2m`).
FUZZTIME ?= 30s

# How long `make seed` keeps generating dashboard traffic.
SEEDTIME ?= 2m

# Build the three sidecar binaries into dist/.
build:
	go build -ldflags "$(LDFLAGS)" -o dist/guardiand         ./cmd/guardiand
	go build -ldflags "$(LDFLAGS)" -o dist/guardian-train    ./cmd/guardian-train
	go build -ldflags "$(LDFLAGS)" -o dist/guardian-loadtest ./cmd/guardian-loadtest

# Build the optional http-wasm guest (stateless WAF) for Angie's WASM support.
wasm:
	GOOS=wasip1 GOARCH=wasm go build -ldflags "$(LDFLAGS)" -o dist/guardian.wasm ./transport/wasm

# Everything: sidecar binaries + the wasm module.
all: build wasm

test:
	go test -race -count=1 ./...

# End-to-end suite: boots the real Angie + guardiand + whoami stack from
# deploy/docker/compose.yaml (via testcontainers-go) and drives it through
# Angie. Requires Docker. Gated behind the `e2e` build tag so it never runs in
# the fast unit `test` target above.
e2e:
	go test -tags e2e -count=1 -timeout 15m ./test/e2e/...

# Gated nftables kernel-offload e2e. Needs a kernel with nf_tables and a
# runtime that grants NET_ADMIN; skips cleanly where that is unavailable
# (e.g. some CI shell runners). Separate build tag so `make e2e` never
# requires elevated capabilities.
.PHONY: e2e-nft
e2e-nft:
	go test -tags e2e_nft -count=1 -timeout 15m ./test/e2e/...

# Store-engine benchmark harness: compares the sharded in-memory store against
# the durable backends (buntdb, pebble; each in async and sync mode) on Guardian's
# real write workload (single-spend CAS flood, TTL counters, mixed read/write,
# expiry reclaim). Manual, not a CI job: benchmarks want a quiet machine, and a
# red build on benchmark variance is worse than a manual run.
# To compare two runs with benchstat (not vendored; go run it directly):
#   make bench-store > new.txt   # and a baseline old.txt from another commit
#   go run golang.org/x/perf/cmd/benchstat old.txt new.txt
bench-store:
	go test -run '^$$' -bench '^Benchmark(SpentFlood|TTLCounter|MixedReadWrite|ExpiryReclaim)$$' \
		-benchmem -benchtime 2s -count 6 ./core/store/

# Hot-path allocation regression gate (also a CI job). allocs/op at a FIXED
# iteration count is deterministic for these benchmarks, so it can gate a
# pipeline; ns/op is deliberately not gated (CI machines are far too noisy for
# it, and a real throughput question belongs to guardian-loadtest). A commit
# that adds an allocation to the auth or challenge hot path fails here in
# seconds instead of surfacing as a throughput drop months later. Baselines
# live in allocs-baseline.txt, which also documents what may be gated: only
# benchmarks free of background goroutines, whose allocations would otherwise
# be charged here at a scheduler-dependent rate.
BENCH_GATE := BenchmarkEvaluateAllowDefault$$|BenchmarkEvaluateDeny$$|BenchmarkEvaluatePoWTokenCached$$|BenchmarkEvaluateChallengeDecision$$|BenchmarkVerifyTokenCached$$|BenchmarkAuthAllow$$|BenchmarkIssue$$

bench-regress:
	@go test -run '^$$' -bench '$(BENCH_GATE)' -benchmem -benchtime 10000x \
		./core/ ./core/pow/ ./transport/http/ \
	| awk 'BEGIN { \
			while ((getline line < "allocs-baseline.txt") > 0) { \
				if (line !~ /^#/ && line != "") { split(line, f, /[ \t]+/); max[f[1]] = f[2] } \
			} \
		} \
		/^Benchmark/ { \
			name = $$1; sub(/-[0-9]+$$/, "", name); allocs = $$(NF-1); \
			if (!(name in max)) { printf "FAIL %s: %d allocs/op has no baseline; add it to allocs-baseline.txt\n", name, allocs; bad = 1; next } \
			seen[name] = 1; \
			if (allocs + 0 > max[name] + 0) { printf "FAIL %s: %d allocs/op, baseline %d\n", name, allocs, max[name]; bad = 1 } \
			else { printf "ok   %-40s %3d allocs/op (baseline %d)\n", name, allocs, max[name] } \
		} \
		END { \
			for (n in max) if (!(n in seen)) { printf "FAIL baseline %s never ran (renamed or deleted?)\n", n; bad = 1 } \
			exit bad \
		}'

# Run every fuzz target for FUZZTIME each. `go test -fuzz` fuzzes exactly one
# target per package invocation, so discover them with `-list` and loop. Any
# crasher is written to testdata/fuzz/ and fails the run. A parser panic in a
# fail-open WAF silently drops protection, so this guards every untrusted-input
# parser (URI decode, WAF rules, config, anomaly model, PoW redeem).
fuzz:
	@set -e; \
	for pkg in ./core/stateless ./core/waf ./core ./core/anomaly ./core/pow; do \
		for fn in $$(go test -list '^Fuzz' $$pkg | grep '^Fuzz'); do \
			echo "=== fuzz $$pkg $$fn ($(FUZZTIME)) ==="; \
			go test -run '^$$' -fuzz "^$$fn$$" -fuzztime $(FUZZTIME) $$pkg; \
		done; \
	done

# Developer-only: fill a local guardiand with representative traffic (solved
# and failed proof-of-work, challenge/deny decisions, behavioural blocks,
# allowed traffic) so the dashboard and /metrics have something to show. Start
# the throwaway instance first, in another shell:
#
#   go run ./cmd/guardiand -config test/seed/guardian.seed.yaml
#
# then `make seed`, and open the dashboard link that config prints. Not a load
# test: cmd/guardian-loadtest is the one that measures throughput.
seed:
	go run ./test/seed -url http://127.0.0.1:18071 -d $(SEEDTIME) \
		-admin http://127.0.0.1:18072 -token seed-demo-token

vet:
	go vet ./...

# Documentation site (VitePress). `docs` builds the static site into
# docs/.vitepress/dist; `docs-dev` serves it locally with hot reload.
docs:
	cd docs && npm install && npm run build

docs-dev:
	cd docs && npm install && npm run dev

fmt:
	gofmt -w cmd core transport web test

clean:
	rm -rf dist/
