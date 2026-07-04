# Angie Guardian sidecar — build + minimal runtime image.
# Multi-stage: compile guardiand statically, then copy into a distroless-ish
# base. Built from the repo root: docker build -f deploy/docker/Dockerfile .
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=docker" -o /out/guardiand ./cmd/guardiand
# Seed empty writable dirs; the final stage COPYs them with --chown so the
# named volumes mounted over them inherit the nonroot uid (65532) on first
# mount and the unprivileged daemon can write the bbolt db and signing key.
RUN mkdir -p /seed/var/lib/guardian /seed/etc/guardian/keys

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/guardiand /usr/local/bin/guardiand
COPY --from=build --chown=65532:65532 /seed/var/lib/guardian /var/lib/guardian
COPY --from=build --chown=65532:65532 /seed/etc/guardian /etc/guardian
# Config is mounted read-only by compose; store + keys are named volumes.
ENTRYPOINT ["/usr/local/bin/guardiand"]
CMD ["-config", "/etc/guardian/guardian.yaml"]
