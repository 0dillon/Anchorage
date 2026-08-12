# Contributing to Anchorage

We welcome issues and pull requests. Please read this guide before contributing.

## PR Flow
1. Fork the repository and create a feature branch.
2. Write tests for your changes.
3. Ensure your code is formatted and passes all local checks.
4. Submit a Pull Request.

## Conventional Commits
We use [Conventional Commits](https://www.conventionalcommits.org/). Please format your commit messages accordingly.

Scopes used in this repository:
- `httpapi`: Router, middleware, and handlers
- `auth`: Challenge reading and signature verification
- `token`: JWT issuance and parsing
- `clientdomain`: TOML resolution and caching
- `store`: Postgres, replay protection
- `config`: Environment validation
- `deploy`: Docker and compose files
- `cmd`: Binary entrypoint

Example: `feat(httpapi): add POST /auth handler`

## Local Setup
Anchorage requires Go 1.25. To run the test suite and checks locally:

```bash
export GOTOOLCHAIN=go1.25.12
make check
```

## Two Day-One Gotchas
1. **The Toolchain Pin**: You **must** prefix all `go` commands (including `make check`) with `export GOTOOLCHAIN=go1.25.12`. Without this, the toolchain will fail to resolve dependencies properly.
2. **Postgres Integration Tests**: The integration tests in `internal/store` require a live database and are hidden behind the `postgres_integration` build tag. **They do not run in standard CI.** To run them locally:
   ```bash
   SEP10_TEST_DATABASE_URL=postgres://... go test -tags postgres_integration ./internal/store/ -v
   ```
