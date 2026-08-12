<!-- Optional: replace with a banner image. Keep it plain — a wordmark, not a stock illustration. -->
<h1 align="center">Anchorage</h1>

<p align="center">
  A SEP-10 authentication server for Stellar, written in Go.
</p>

<p align="center">
  <a href="https://github.com/0dillon/Anchorage/actions"><img alt="CI" src="https://github.com/0dillon/Anchorage/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License: Apache-2.0" src="https://img.shields.io/badge/License-Apache_2.0-blue.svg">
  <img alt="Go 1.25" src="https://img.shields.io/badge/go-1.25-00ADD8">
</p>

---

## What this is

SEP-10 is Stellar Web Authentication: a challenge-response protocol that proves a user controls a Stellar account, without passwords. The server issues an unsubmitted transaction, the client signs it, the server verifies the signatures and returns a JWT.

Every Stellar anchor needs it — SEP-6, SEP-24, and SEP-31 all sit on top of SEP-10 — and so does any wallet backend or service that wants "sign in with your Stellar account."

Python has django-polaris. PHP has the Argo Navis SDK. Java has SDF's Anchor Platform. Go developers get the protocol primitives in `stellar/go-stellar-sdk` and no server around them.

Anchorage is that server.

**What it is not:** an anchor, a KYC system, or a deposit and withdrawal implementation. It is the authentication layer those things are built on, and nothing else. That boundary is deliberate.

## Why the SDK is not enough

The official Go SDK ships the SEP-10 challenge primitives — `BuildChallengeTx`, `ReadChallengeTx`, `VerifyChallengeTxSigners`, `VerifyChallengeTxThreshold`. Anchorage uses them. It does not reimplement ed25519 verification or nonce generation.

It does implement its own challenge reader, for one specific reason: **the SDK's `ReadChallengeTx` rejects spec-compliant `client_domain` challenges.**

SEP-10's `client_domain` flow requires that operation to be sourced at the client domain's own signing key. The SDK requires every operation after the first to be sourced at the server account, so it rejects the challenge as unrecognized (`txnbuild/transaction.go:1265`). Both verify functions call `ReadChallengeTx` internally, so they inherit the rejection. A challenge that follows the spec cannot be read by the SDK that built it.

Stripping the operation before verification does not work, because signatures cover the whole transaction. So `internal/auth` carries its own reader.

Owning security-critical validation is a liability unless it is pinned to something. A **differential test** generates challenges across a table of shapes — valid, tampered source, bad sequence, expired, wrong nonce length, wrong home domain, unknown extra operation — and asserts that Anchorage's reader and the SDK's reader agree on every one, on accept or reject and on the account, home domain, and memo they extract. Six accepts, fourteen rejects, run against the live SDK rather than fixtures. Where the two deliberately diverge, the divergence is documented and carved out explicitly.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/auth` | Issue a challenge transaction |
| `POST` | `/auth` | Verify a signed challenge, return a JWT |
| `GET` | `/.well-known/stellar.toml` | Serve the SEP-1 info file |
| `GET` | `/health` | Liveness check |

`GET /auth` accepts `account` (required), and optionally `memo`, `home_domain`, and `client_domain`. `POST /auth` accepts either JSON or form-encoded bodies — both are used in the wild.

## Quick start

Requires Go 1.25 and Docker.

```bash
git clone https://github.com/0dillon/Anchorage
cd Anchorage
cp .env.example .env      # fill in your values
docker compose -f deploy/docker-compose.yml up
```

To build and test locally without Docker:

```bash
export GOTOOLCHAIN=go1.25.12
make check                # build, vet, gofmt, test
```

The Postgres integration tests are behind a build tag and need a live database:

```bash
SEP10_TEST_DATABASE_URL=postgres://... go test -tags postgres_integration ./internal/store/ -v
```

## Configuration

Every value comes from the environment and is validated at startup. The server refuses to start against incomplete config rather than failing at the first request.

| Variable | Purpose |
|---|---|
| `SEP10_SIGNING_SECRET` | Server signing key (`S...`). Never logged. |
| `SEP10_NETWORK_PASSPHRASE` | Network passphrase |
| `SEP10_HORIZON_URL` | Horizon endpoint for account lookups |
| `SEP10_WEB_AUTH_DOMAIN` | The domain hosting this service |
| `SEP10_HOME_DOMAINS` | Comma-separated allowed home domains |
| `SEP10_CHALLENGE_TIMEOUT` | Challenge validity, default `300s` |
| `SEP10_JWT_SECRET` | HS256 signing secret. Never logged. |
| `SEP10_JWT_ISSUER` | JWT `iss` claim |
| `SEP10_JWT_LIFETIME` | Token lifetime, default `24h` |
| `SEP10_CLIENT_DOMAIN_REQUIRED` | Whether `client_domain` is mandatory, default false |
| `SEP10_CLIENT_DOMAIN_ALLOWLIST` | Optional comma-separated allowlist |
| `SEP10_CLIENT_DOMAIN_CACHE_TTL` | Resolver cache lifetime, default `5m` |
| `SEP10_TRUST_PROXY_HEADERS` | Honour `X-Forwarded-For`. Default false. See below. |
| `SEP10_DATABASE_URL` | Postgres connection string |
| `SEP10_LISTEN_ADDR` | Default `:8080` |
| `SEP10_TOML_PATH` | Path to the SEP-1 TOML file |

## Security notes

Stated plainly, because they affect how you deploy this.

**Proxy headers are not trusted by default.** The per-IP rate limit is the only control bounding unauthenticated challenge issuance and outbound TOML fetches to attacker-named domains. If proxy headers were trusted unconditionally, an attacker could send a forged `X-Forwarded-For` per request and bypass it entirely. Set `SEP10_TRUST_PROXY_HEADERS=true` **only** when the service sits behind a proxy you control that overwrites the header.

**The client domain key proves participation, not authority.** When a challenge carries a `client_domain` operation, that key's signature must be present or verification fails as unrecognized — but its weight is excluded from the account threshold sum. Reversing this would let any client domain authenticate for any account. The exclusion is unconditional and covered by a dedicated negative test.

**A challenge is spent before its signatures are checked.** Verifying first would turn a live challenge into an unlimited retry oracle. The cost is that a client typo burns the challenge and they request a new one. This is deliberate.

**The TOML resolver fetches attacker-named domains by design** — that is what `client_domain` means. It enforces HTTPS only, a 5 second timeout, a 3 hop redirect cap, a 100 KB body cap, and deliberately uninformative errors. Private-IP blocking is not implemented; if you run this where internal hosts are reachable, put it behind an egress policy.

**This service is unaudited.** Review it before running it in front of anything that matters.

## Repository layout

```
cmd/authd                 entrypoint
internal/auth             challenge reader, signature verification
internal/account          Horizon account lookup
internal/clientdomain     TOML resolver with cache
internal/token            JWT issuance and parsing
internal/store            Postgres, replay protection, session audit
internal/httpapi          router, middleware, handlers
internal/config           environment loading and validation
deploy/                   Dockerfile, compose, TOML example
```

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and commit conventions, and [SECURITY.md](SECURITY.md) for responsible disclosure.

## Maintainer

| Name | Role | GitHub
|---|---|---|---|
| Dillon Ofili | Maintainer | [@0dillon](https://github.com/0dillon) |

## Contributors

<a href="https://github.com/0dillon/Anchorage/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=0dillon/Anchorage" />
</a>

## License

Apache-2.0. See [LICENSE](LICENSE).
