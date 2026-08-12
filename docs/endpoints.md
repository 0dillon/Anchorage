# API reference

## `GET /auth`
Issues a challenge transaction.

| Parameter | Required | Meaning |
|---|---|---|
| `account` | yes | Client's Stellar account (`G...`) or muxed account (`M...`) |
| `memo` | no | Memo ID. Valid only with a `G...` account, never with `M...` |
| `home_domain` | no | Which home domain to authenticate against; defaults to the configured one |
| `client_domain` | no | Domain of the wallet application making the request |

Returns `200 OK` with `{"transaction": "<base64 XDR>", "network_passphrase": "..."}`.
Returns `400 Bad Request` for an invalid account, a memo with a muxed account, an unknown home domain, or a client domain that could not be resolved when one is required.

## `POST /auth`
Verifies a signed challenge and returns a JWT.

Accepts `application/json` with `{"transaction": "<base64 XDR>"}` or `application/x-www-form-urlencoded` with a `transaction` field.

Returns `200 OK` with `{"token": "<jwt>"}`.
Returns `401 Unauthorized` for every verification failure, with a JSON body naming the failure class and nothing else — no signature material, no internal state.

### JWT claims

| Claim | Value |
|---|---|
| `iss` | The server's web auth endpoint URL |
| `sub` | The client account — `G...`, `M...`, or `G...:memo` when a memo was used |
| `iat` | Issue time |
| `exp` | Issue time plus the configured lifetime |
| `jti` | Hex-encoded hash of the challenge transaction envelope |
| `client_domain` | Present only when a client domain was verified |

## `GET /.well-known/stellar.toml`
Serves the SEP-1 info file with permissive CORS.

## `GET /health`
Liveness check.

## Error classes

| Error | HTTP Status |
|---|---|
| `ErrInvalidAccount` | `400` |
| `ErrMemoWithMuxed` | `400` |
| `ErrUnknownHomeDomain` | `400` |
| `ErrChallengeUnknown` | `401` |
| `ErrChallengeConsumed` | `401` |
| `ErrChallengeExpired` | `401` |
| `ErrSignatureUnrecognized` | `401` |
| `ErrThresholdNotMet` | `401` |
| `ErrClientDomainUnverified` | `401` |
| `ErrAccountLookupFailed` | `401` |
