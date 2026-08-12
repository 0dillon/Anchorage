# Deployment

## Topology
The service runs as a container behind a reverse proxy, with Postgres alongside it. It makes outbound HTTPS connections to Horizon for account lookups and to client domains for TOML resolution. `deploy/docker-compose.yml` is the reference topology.

The shape is: client → reverse proxy → authd → Postgres, and authd → Horizon, authd → client domains.

## Quick start
Requires Go 1.25 and Docker.

```bash
git clone https://github.com/0dillon/Anchorage
cd Anchorage
cp .env.example .env      # fill in your values
docker compose -f deploy/docker-compose.yml up
```

## Building locally
```bash
export GOTOOLCHAIN=go1.25.12
make check                # build, vet, gofmt, test
```
The toolchain pin is required. The Stellar SDK declares a Go 1.25 requirement that resolves to a toolchain name which is not downloadable; the explicit pin is required or builds fail on a clean machine.

## Integration tests
Integration tests need a live Postgres and are behind a build tag:

```bash
SEP10_TEST_DATABASE_URL="postgres://user:pass@host:5432/db?sslmode=disable" \
  go test -tags postgres_integration ./internal/store/ -v
```

## Behind a proxy
If you terminate TLS at a reverse proxy, set `SEP10_TRUST_PROXY_HEADERS=true` and ensure the proxy overwrites `X-Forwarded-For` rather than appending to a client-supplied value.
