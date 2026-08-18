# Contributing to Gatekeeper

## Getting started

Requires Go 1.26+ (see `go.mod`).

```bash
git clone https://github.com/Deipedra34/Gatekeeper.git
cd gatekeeper
go build -o bin/gatekeeper ./cmd/gatekeeper
go test ./...
```

## Project layout

See the "Package layout" section in [README.md](README.md) for where things live (`internal/ratelimiter`, `internal/proxy`, `internal/middleware`, etc.).

## Making changes

1. Fork the repo and create a branch off `main`.
2. Keep changes focused — one logical change per pull request.
3. Add or update tests for any behavior change. Run `go test ./...` before opening a PR.
4. Run `go vet ./...` and `gofmt -l .` to catch formatting/vet issues.
5. Update `README.md` or `configs/config.yaml` comments if you change user-facing behavior or config shape.

## Pull requests

- Describe what changed and why, not just what.
- Link any related issue.
- Make sure CI (build + tests) passes before requesting review.

## Reporting bugs / requesting features

Open a GitHub issue with steps to reproduce (for bugs) or the use case you're trying to solve (for features).

## Code style

Follow standard Go conventions (`gofmt`, effective Go naming). Match the style of the surrounding code in a package rather than introducing a new pattern.
