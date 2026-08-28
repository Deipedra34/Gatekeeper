# syntax=docker/dockerfile:1

# ---- Builder ----------------------------------------------------------
# go.mod pins `go 1.26.5`, so the builder image must match or exceed it.
FROM golang:1.26-alpine AS builder

WORKDIR /src

# Cache module downloads separately from source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
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
