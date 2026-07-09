# Angie Guardian build targets.
# The sidecar binaries are the primary, full-featured build; `wasm` is the
# optional stateless in-process module. Nothing here is required to use Go
# directly (`go build ./cmd/guardiand` etc. still works).

VERSION ?= dev
LDFLAGS := -X main.version=$(VERSION)

.PHONY: all build wasm test e2e vet fmt clean docs docs-dev

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
