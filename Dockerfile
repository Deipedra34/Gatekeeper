# syntax=docker/dockerfile:1

# ---- Builder ----------------------------------------------------------
# go.mod pins `go 1.26.5`, so the builder image must match or exceed it.
# The builder always runs on the build host's platform and cross-compiles
# for the target one (CGO is off), so multi-arch builds don't need to run
# the Go toolchain under emulation.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

WORKDIR /src

# Cache module downloads separately from source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Set by docker buildx / BuildKit for the platform being built.
ARG TARGETOS
ARG TARGETARCH

# Build metadata reported by `gatekeeper -version`. The release workflow
# passes these; a plain `docker build` / `docker compose build` keeps the
# defaults.
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags="-s -w -X gatekeeper/internal/version.Version=${VERSION} -X gatekeeper/internal/version.Commit=${COMMIT} -X gatekeeper/internal/version.Date=${DATE}" \
    -o /out/gatekeeper ./cmd/gatekeeper

# ---- Final image --------------------------------------------------------
FROM alpine:3.20

RUN apk add --no-cache ca-certificates && \
    addgroup -S gatekeeper && adduser -S gatekeeper -G gatekeeper

WORKDIR /app

COPY --from=builder /out/gatekeeper ./gatekeeper
COPY configs/config.yaml ./configs/config.yaml

USER gatekeeper

# Matches server.listen_addr in configs/config.yaml.
EXPOSE 8080

ENTRYPOINT ["./gatekeeper", "-config", "configs/config.yaml"]
