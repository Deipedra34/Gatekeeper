# syntax=docker/dockerfile:1

# Minimal mock upstream service for docker-compose.yml. Not part of the
# gatekeeper Go module — it's a standalone program with its own go.mod.

FROM golang:1.26-alpine AS builder

WORKDIR /src

COPY go.mod ./
COPY main.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/mockbackend .

FROM alpine:3.20

RUN addgroup -S mockbackend && adduser -S mockbackend -G mockbackend

WORKDIR /app
COPY --from=builder /out/mockbackend ./mockbackend

USER mockbackend

EXPOSE 9000

ENTRYPOINT ["./mockbackend"]
