# Angie Guardian build targets.
# The sidecar binaries are the primary, full-featured build; `wasm` is the
# optional stateless in-process module. Nothing here is required to use Go
# directly (`go build ./cmd/guardiand` etc. still works).

VERSION ?= dev
LDFLAGS := -X main.version=$(VERSION)

.PHONY: all build wasm test e2e fuzz vet fmt clean docs docs-dev bench-store

# How long each fuzz target runs in `make fuzz`. Override it locally when
# chasing a specific parser (for example `make fuzz FUZZTIME=2m`).
FUZZTIME ?= 30s

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
