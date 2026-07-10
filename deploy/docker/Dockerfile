# Angie Guardian sidecar — build + minimal runtime image.
# Multi-stage: compile guardiand statically, then copy into a distroless-ish
# base. Built from the repo root: docker build -f deploy/docker/Dockerfile .
# Base images are pinned by digest so a release build is reproducible and
# immune to a re-tagged or poisoned upstream image. To bump: pull the tag,
# read `docker inspect --format '{{index .RepoDigests 0}}' <image>`, and paste
# the new digest here (keep the human-readable tag in the comment).
# golang:1.26-trixie
FROM golang@sha256:116489021a0d8ca3facf79f84ee69052cff88733547150a644d45c5eaa91dc43 AS build
# Version string stamped into the binary; the docker-release CI job passes the
# release tag, a local build defaults to "docker".
ARG VERSION=docker
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=${VERSION}" -o /out/guardiand ./cmd/guardiand
# Seed empty writable dirs; the final stage COPYs them with --chown so the
# named volumes mounted over them inherit the nonroot uid (65532) on first
# mount and the unprivileged daemon can write the bbolt db and signing key.
RUN mkdir -p /seed/var/lib/guardian /seed/etc/guardian/keys

# gcr.io/distroless/static-debian12:nonroot
FROM gcr.io/distroless/static-debian12@sha256:b7bb25d9f7c31d2bdd1982feb4dafcaf137703c7075dbe2febb41c24212b946f
COPY --from=build /out/guardiand /usr/local/bin/guardiand
COPY --from=build --chown=65532:65532 /seed/var/lib/guardian /var/lib/guardian
COPY --from=build --chown=65532:65532 /seed/etc/guardian /etc/guardian
# Config is mounted read-only by compose; store + keys are named volumes.
ENTRYPOINT ["/usr/local/bin/guardiand"]
CMD ["-config", "/etc/guardian/guardian.yaml"]
