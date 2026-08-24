FROM golang:1.27.0-trixie@sha256:6212da3924947f4b6a939df02ea627c13f338f1a41d6c3fcb0dd9d076eef46c4 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY test/e2e/backend ./test/e2e/backend
RUN CGO_ENABLED=0 go build -o /out/e2e-backend ./test/e2e/backend

FROM gcr.io/distroless/static-debian12@sha256:b7bb25d9f7c31d2bdd1982feb4dafcaf137703c7075dbe2febb41c24212b946f
COPY --from=build /out/e2e-backend /e2e-backend
ENTRYPOINT ["/e2e-backend"]
