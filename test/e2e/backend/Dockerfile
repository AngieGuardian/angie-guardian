FROM golang:1.27.3-trixie@sha256:fbb7ae40b62ff8afe31662df570d39b4f5052ac32b90dae8e60d7657a20a74f4 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY test/e2e/backend ./test/e2e/backend
RUN CGO_ENABLED=0 go build -o /out/e2e-backend ./test/e2e/backend

FROM gcr.io/distroless/static-debian12@sha256:b7bb25d9f7c31d2bdd1982feb4dafcaf137703c7075dbe2febb41c24212b946f
COPY --from=build /out/e2e-backend /e2e-backend
ENTRYPOINT ["/e2e-backend"]
