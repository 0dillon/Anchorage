# Anchorage

A SEP-10 Stellar Web Authentication server.

## Why this exists

The official Go SDK's challenge reader rejects spec-compliant `client_domain` challenges.
`ReadChallengeTx` requires every operation after the first to be sourced at the server account
(`txnbuild/transaction.go:1270`), but SEP-10 requires the `client_domain` operation to be
sourced at the client domain's `SIGNING_KEY`. A server built on the SDK alone would reject its
own challenges. Anchorage therefore implements its own challenge reader.

That duplication is pinned to upstream by a differential test: for every challenge shape both
readers handle, the test asserts they agree on accept or reject and on the values they return.
Divergence is a build failure, not a slow drift.

The Go SDK ships protocol primitives but no service around them. Python has django-polaris,
PHP has the Argo Navis SDK, Java has SDF's Anchor Platform. This fills that gap for Go.

## Scope

Anchorage is the authentication layer and nothing more. It is not an anchor, not a KYC system,
and it does not implement deposit or withdrawal. SEP-6, SEP-24 and SEP-31 are built on top of
SEP-10; this is what they sit on.

## Quick start

Needs Go 1.25.12 and Docker.

```bash
cp .env.example .env
# Put a real testnet signing key and a random 32-byte JWT secret in .env.
# Never commit it.

docker compose -f deploy/docker-compose.yml up --build
```

The server runs its own migrations at startup. To run it against a database without Docker:

```bash
docker compose -f deploy/docker-compose.yml up -d postgres
make run
```

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/auth` | Issue a challenge transaction |
| `POST` | `/auth` | Verify a signed challenge and return a JWT |
| `GET` | `/.well-known/stellar.toml` | Serve the SEP-1 file with this server's `SIGNING_KEY` |
| `GET` | `/health` | Process and database liveness |

### GET /auth

| Parameter | Required | Meaning |
|---|---|---|
| `account` | yes | The `G...` or `M...` account to authenticate |
| `memo` | no | ID memo. Not valid with an `M...` account |
| `home_domain` | no | One of the configured home domains. Defaults to the first |
| `client_domain` | no | The wallet's domain, whose `SIGNING_KEY` must co-sign |

Returns `{"transaction": "<base64 XDR>", "network_passphrase": "..."}`.

### POST /auth

Accepts `application/json` or `application/x-www-form-urlencoded` with one field,
`transaction`, holding the signed challenge. Returns `{"token": "<JWT>"}`.

The token is HS256. `sub` is `M...` for a muxed account, `G...:<memo>` when a memo was used, and
`G...` otherwise. `jti` is the hash of the challenge envelope, so every token traces back to the
challenge that produced it.

Failures return a JSON body naming the failure class and nothing else:

| Condition | Status |
|---|---|
| Bad account, memo with a muxed account, unknown home domain, rejected client domain | 400 |
| Unknown, consumed, expired or malformed challenge; unrecognised signature; threshold not met; client domain unsigned | 401 |
| Horizon or database unreachable | 503 |

An outage is never reported as a bad signature. A caller who is told their signature is wrong
will change their key; a caller who is told the service is unavailable will retry.

## Configuration

Every variable is validated at startup. A missing or malformed value exits with a message
naming it, and the server never starts against unvalidated config.

| Variable | Purpose | Default |
|---|---|---|
| `SEP10_SIGNING_SECRET` | Server signing key (`S...`). Never logged | required |
| `SEP10_NETWORK_PASSPHRASE` | Network passphrase | required |
| `SEP10_HORIZON_URL` | Horizon endpoint for account lookups | required |
| `SEP10_WEB_AUTH_DOMAIN` | Domain hosting this service | required |
| `SEP10_HOME_DOMAINS` | Comma-separated allowed home domains | required |
| `SEP10_CHALLENGE_TIMEOUT` | Challenge validity | `300s` |
| `SEP10_JWT_SECRET` | HS256 signing secret, at least 32 bytes. Never logged | required |
| `SEP10_JWT_ISSUER` | JWT `iss` claim | required |
| `SEP10_JWT_LIFETIME` | Token lifetime | `24h` |
| `SEP10_CLIENT_DOMAIN_REQUIRED` | Whether `client_domain` is mandatory | `false` |
| `SEP10_CLIENT_DOMAIN_ALLOWLIST` | Optional comma-separated allowlist | empty |
| `SEP10_CLIENT_DOMAIN_CACHE_TTL` | Resolver cache TTL | `5m` |
| `SEP10_DATABASE_URL` | Postgres connection string | required |
| `SEP10_LISTEN_ADDR` | Listen address | `:8080` |
| `SEP10_TOML_PATH` | Path to the SEP-1 TOML file | required |

Secrets are read from the environment only. None is accepted as a command-line flag, written to
a log line, or included in an error message.

## Security notes

**The client domain key does not count toward the account's threshold.** It has to be in the
signer list, or the challenge fails as carrying an unrecognised signature. It must be out of the
threshold sum, or any client domain could authenticate for any account — a total auth bypass.
`accountSignerWeight` in `internal/auth/verify.go` is the one function that holds this apart,
and `TestClientDomainWeightDoesNotSatisfyThreshold` fails if the exclusion is removed.

**A challenge is single-use.** Consumption is one atomic `UPDATE ... WHERE consumed_at IS NULL`,
never a read followed by a write, so two concurrent posts of the same challenge cannot both
succeed.

**The nonce is spent before signatures are checked.** Verifying first would leave the challenge
live through a failed attempt, turning one nonce into an unlimited retry oracle — the property
replay protection exists to remove. One challenge buys one attempt. A mis-signed submission
burns it and the client requests another, which is one call.

**Client domain responses are hostile input.** HTTPS only, including after redirects, at most
three redirects, a five-second timeout on the whole request, and a 100 KB body cap that rejects
rather than truncates.

## Testing

```bash
make check    # build, vet, gofmt, test
```

Every test runs offline: no network, no database. The Postgres tests sit behind a build tag and
never run in CI:

```bash
docker compose -f deploy/docker-compose.yml up -d postgres
SEP10_TEST_DATABASE_URL=postgres://anchorage:anchorage@localhost:5432/anchorage?sslmode=disable \
  go test -tags postgres_integration ./internal/store/ -v
```

## Layout

| Package | Responsibility |
|---|---|
| `internal/config` | Parse and validate every environment variable |
| `internal/auth` | Challenge issuance, reading, signature and threshold verification |
| `internal/account` | Read signers and thresholds from Horizon |
| `internal/clientdomain` | Fetch, cap, parse and cache client domain TOML |
| `internal/token` | Issue and parse HS256 JWTs |
| `internal/store` | Postgres persistence and replay protection |
| `internal/httpapi` | Routes, middleware, handlers, error mapping |
| `internal/log` | Structured JSON logging |

## What this is not

No EdDSA-signed JWTs, no token refresh or revocation, no SEP above 10, no KYC, no multi-tenancy
beyond the configured home domain list, and no management API over the session table.

## License

Apache-2.0.
