# Anchorage — SEP-10 Stellar Authentication Server

Design document. 2026-08-10.

## 1. Scope

Anchorage is a SEP-10 Web Authentication server. It issues a challenge transaction, verifies
the client's signatures on it, and returns a JWT.

It is not an anchor. It is not a KYC system. It does not implement deposit or withdrawal.
SEP-6, SEP-24 and SEP-31 are built on top of SEP-10; this is the layer underneath them, and
nothing more.

The Go SDK ships the protocol primitives but no service around them. Python has
django-polaris, PHP has the Argo Navis SDK, Java has SDF's Anchor Platform. Go has primitives
and a gap. This fills the gap.

### README

The README leads with the concrete, checkable finding rather than a general claim about a gap:
the official SDK's challenge reader rejects spec-compliant `client_domain` challenges, at
`txnbuild/transaction.go:1270`, so this server implements its own reader. A reader can verify
that in the SDK source in under a minute.

It then states the scope boundary in the first paragraph — SEP-10 authentication only, not an
anchor, not KYC, not deposit or withdrawal — so nobody has to guess where this stops.

The differential test of section 6.4 is named in the README too. It is the answer to the
obvious reviewer question, "why did you duplicate SDK validation logic?": the duplication is
pinned to upstream by a test, so divergence is a build failure rather than a slow drift.

## 2. Findings that changed the brief

Four things were verified against the published modules and the SDK source before any code was
written. Each contradicts the original brief.

### 2.1 `github.com/stellar/go` is deprecated

The module proxy reports:

```
module github.com/stellar/go is deprecated: Use github.com/stellar/go-stellar-sdk instead
```

It also publishes no semver tags, so `go list -m -versions github.com/stellar/go` returns an
empty list and the only possible pin is a pseudo-version.

**Decision: build against `github.com/stellar/go-stellar-sdk` v0.7.1**, which is the maintained
successor and is properly tagged. Its `txnbuild` package carries the same challenge API.

### 2.2 The installed Go toolchain is below the SDK's floor

`go version` reports go1.22.2. `go-stellar-sdk` declares `go >= 1.25`, which Go resolves to a
toolchain named `go1.25`. That name is not downloadable — the resolution fails with
`toolchain not available`.

**Decision: `go.mod` declares `go 1.25.0` and pins `toolchain go1.25.12`.** CI pins the same
version. Without the explicit `toolchain` line the build breaks on a clean machine.

### 2.3 `BuildChallengeTx` takes a memo argument

The real signature carries a trailing memo the original brief's argument list omitted:

```go
func BuildChallengeTx(serverSignerSecret, clientAccountID, webAuthDomain, homeDomain,
    network string, timebound time.Duration, memo *MemoID) (*Transaction, error)
```

`ReadChallengeTx`, `VerifyChallengeTxSigners` and `VerifyChallengeTxThreshold` match the brief
as written.

### 2.4 The SDK cannot read a SEP-10 `client_domain` challenge

This is the finding that shapes the design.

`grep -rn client_domain` across the whole SDK returns nothing. `BuildChallengeTx` emits exactly
two operations and signs, with no hook for a third — anticipated, and solvable by appending the
operation and re-signing.

The read side is not solvable that way. `ReadChallengeTx` validates every operation after the
first (`txnbuild/transaction.go:1270`):

```go
default:
    // verify unknown subsequent operations are manage data ops with source account set to server account
    if op.SourceAccount != serverAccountID {
        return ..., errors.New("subsequent operations are unrecognized")
    }
```

SEP-10 requires the `client_domain` operation's source account to be the client domain's
`SIGNING_KEY`. That is the mechanism by which the client domain proves participation. So a
spec-correct challenge is rejected by the SDK's own reader, and a server that issued one would
reject it at its own `POST /auth`.

`VerifyChallengeTxSigners` calls `ReadChallengeTx` (`transaction.go:1355`) and
`VerifyChallengeTxThreshold` calls `VerifyChallengeTxSigners`, so both inherit the rejection.
Stripping the operation before verification is impossible because signatures cover the whole
transaction. No lower-level entry point is exported — `verifyTxSignatures` is unexported, and
only `tx.Hash` and `keypair.FromAddress.Verify` are public.

**Decision: `internal/auth` carries its own SEP-10 challenge reader and signature check**, used
on every request whether or not a client domain is involved. Section 6 specifies it, and section
6.4 specifies the differential test that pins it to upstream behaviour.

## 3. Module, toolchain, dependencies

Module path `github.com/0dillon/Anchorage`. Single module, no `go.work`.

| Dependency | Version | Purpose |
|---|---|---|
| `github.com/stellar/go-stellar-sdk` | v0.7.1 | Challenge primitives, keypair, strkey, XDR, Horizon client |
| `github.com/go-chi/chi/v5` | latest at commit 1 | HTTP router |
| `github.com/jackc/pgx/v5` | latest at commit 1 | Postgres driver |
| `github.com/golang-migrate/migrate/v4` | v4.19.1 | Migrations, via its `database/pgx/v5` driver |
| `github.com/golang-jwt/jwt/v5` | latest at commit 1 | JWT |
| `github.com/BurntSushi/toml` | v1.6.0 | SEP-1 TOML parsing in the client domain resolver |
| `github.com/stretchr/testify` | latest at commit 1 | Test assertions |

Versions marked "latest at commit 1" are resolved once, at the scaffold commit, and pinned in
`go.mod` and `go.sum` from then on. `BurntSushi/toml` is the one dependency added beyond the
original brief's list, for the reason given in section 7.

`golang-migrate`'s `database/pgx/v5` driver is used specifically because the default `postgres`
driver pulls in `lib/pq`; the pgx driver pulls nothing extra.

Logging is `log/slog` with the JSON handler. Configuration is environment variables only.

CI runs `go build ./...`, `go vet ./...`, a `gofmt -l .` check that fails on any output, and
`go test ./...`. It pins `go-version: 1.25.12` — the identical version named in the `toolchain`
directive, not a floating `1.25.x`, because the whole point of the pin is that the build does
not depend on what a particular machine happens to have resolved. The differential test of
section 6.4 runs as part of the ordinary test job; it needs no network and no database, so it
gates every commit like any other test.

## 4. Repository layout

```
.
├── go.mod, Makefile, .gitignore, .env.example, LICENSE (Apache-2.0), README.md
├── .github/workflows/ci.yml
├── cmd/authd/main.go
├── internal/
│   ├── config/       config.go, config_test.go
│   ├── auth/         challenge.go, read.go, verify.go, errors.go, auth_test.go
│   ├── clientdomain/ resolver.go, resolver_test.go
│   ├── token/        jwt.go, jwt_test.go
│   ├── store/        store.go, postgres.go, migrations/, store_test.go
│   ├── httpapi/      router.go, auth_handler.go, toml_handler.go,
│   │                 health_handler.go, middleware.go, httpapi_test.go
│   └── log/          log.go
└── deploy/           Dockerfile, docker-compose.yml, stellar.toml.example
```

`read.go` is the one addition to the original tree. The reader is kept separate from `verify.go`
so structural validation and signature checking are reviewed apart.

## 5. Configuration

Loaded and fully validated in `internal/config` at startup. A malformed or missing value exits
with a message naming the variable. The server never starts against unvalidated config.

| Variable | Purpose | Default |
|---|---|---|
| `SEP10_SIGNING_SECRET` | Server signing key (`S...`). Never logged. | required |
| `SEP10_NETWORK_PASSPHRASE` | Network passphrase | required |
| `SEP10_HORIZON_URL` | Horizon endpoint for account lookups | required |
| `SEP10_WEB_AUTH_DOMAIN` | Domain hosting this service | required |
| `SEP10_HOME_DOMAINS` | Comma-separated allowed home domains | required |
| `SEP10_CHALLENGE_TIMEOUT` | Challenge validity | `300s` |
| `SEP10_JWT_SECRET` | HS256 signing secret. Never logged. | required |
| `SEP10_JWT_ISSUER` | JWT `iss` claim | required |
| `SEP10_JWT_LIFETIME` | Token lifetime | `24h` |
| `SEP10_CLIENT_DOMAIN_REQUIRED` | Whether `client_domain` is mandatory | `false` |
| `SEP10_CLIENT_DOMAIN_ALLOWLIST` | Optional comma-separated allowlist | empty |
| `SEP10_CLIENT_DOMAIN_CACHE_TTL` | Resolver cache TTL | `5m` |
| `SEP10_DATABASE_URL` | Postgres connection string | required |
| `SEP10_LISTEN_ADDR` | Listen address | `:8080` |
| `SEP10_TOML_PATH` | Path to the SEP-1 TOML file | required |

`SEP10_CLIENT_DOMAIN_CACHE_TTL` is the one variable added beyond the original brief's table; the
resolver cache in section 7 needs a TTL and the brief described one without naming a variable
for it.

Validation derives the server's public key from `SEP10_SIGNING_SECRET` at load and holds it;
the secret is never logged, never accepted as a flag, and never appears in an error message.
`.env.example` documents every variable with a placeholder. A real `.env` is git-ignored.

## 6. `internal/auth`

### 6.1 Issuing — `challenge.go`

```go
func (i *Issuer) Issue(ctx context.Context, req IssueRequest) (*IssuedChallenge, error)
```

1. `account` must parse as a `G...` account or `M...` muxed address, else `ErrInvalidAccount`.
2. A memo with an `M...` account is `ErrMemoWithMuxed`. The SDK enforces this too; failing
   early gives a clearer message.
3. `home_domain`, if supplied, must be in the configured list, else `ErrUnknownHomeDomain`.
   Unset means the first configured domain.
4. `client_domain`, if supplied, is resolved by `internal/clientdomain`. A resolution failure is
   fatal to the request when `SEP10_CLIENT_DOMAIN_REQUIRED` is set, and the response names the
   reason. When a client domain is required and none is supplied, the request fails.
5. `txnbuild.BuildChallengeTx` builds and signs the two-operation challenge.
6. When a client domain resolved, the transaction is rebuilt: read back its operations,
   timebounds, memo and base fee, append a `ManageData` operation named `client_domain` whose
   value is the domain and whose **source account is the resolved signing key**, rebuild with
   `NewTransaction` at sequence 0 with `IncrementSequenceNum: false`, and sign fresh. The SDK's
   original signature is discarded because appending an operation invalidates it. The nonce and
   operation layout still come from the SDK. A comment in the code states this.
7. The nonce, account, home domain, client domain and expiry are written to the store.
8. The response carries the base64 XDR and the network passphrase.

### 6.2 Reading — `read.go`

```go
func ReadChallenge(challengeXDR, serverAccountID, network, webAuthDomain string,
    homeDomains []string) (*Challenge, error)
```

```go
type Challenge struct {
    Tx              *txnbuild.Transaction
    ClientAccountID string            // G... or M...
    HomeDomain      string
    Memo            *txnbuild.MemoID
    Nonce           string            // 64-char base64, the replay key
    ClientDomain    string            // "" when absent
    ClientDomainKey string            // G... signing key, "" when absent
}
```

Checks, in the same order as the SDK's reader:

1. Parse the XDR. Reject a fee-bump transaction.
2. Reject a muxed transaction source account.
3. Transaction source equals `serverAccountID`.
4. Sequence number is 0.
5. Timebounds are finite, and now falls within `[MinTime − 5min grace, MaxTime]`. The grace
   period covers clock drift and matches the SDK.
6. At least one operation. The first is a `ManageData` with a non-empty source account.
7. The first operation's name equals `"<domain> auth"` for some configured home domain; the
   match is recorded as `HomeDomain`.
8. The first operation's source account type is Ed25519 or muxed Ed25519. It becomes
   `ClientAccountID`.
9. A memo is permitted only with a non-muxed client account and must be a `MemoID`.
10. The nonce value is 64 characters and base64-decodes to 48 bytes.
11. Every later operation is a `ManageData` with a non-empty source account, and:
    - `web_auth_domain` — source must be the server, value must equal `webAuthDomain`.
    - `client_domain` — source must be a valid `G...` strkey, captured as `ClientDomainKey`;
      the value is captured as `ClientDomain`. **This is the rule the SDK lacks.**
    - anything else — source must be the server.
12. The server's signature is present and valid over the transaction hash.

### 6.3 Verifying — `verify.go`

Signature matching reproduces the SDK's `verifyTxSignatures`: hash once, iterate signers in the
outer loop and signatures in the inner loop, skip signatures already consumed, skip on
decorated-signature hint mismatch, verify with `keypair.FromAddress.Verify`, mark the signature
consumed, and break. Results are deduplicated in the order the signers were supplied.

Around it, the `VerifyChallengeTxSigners` logic is reproduced: drop the server account from the
client signer list, deduplicate, ignore any signer that is not a `G...` account strkey, fail if
no verifiable signer remains, verify server and client signers in a single pass so no signature
is consumed twice, require that the server signature matched, require at least one client
signature, and require that the number of matched signers equals the number of signatures on the
transaction so unrecognized signatures fail.

Two paths, selected by whether the account exists on the network:

- **Account not found on Horizon**, meaning specifically a 404 from the account endpoint. The
  challenge must be signed by the master key of the client account itself. The signer list is
  that account, plus the client domain key when present.
- **Account found.** The signer list is the account's signers plus the client domain key when
  present. After matching, weight is summed and compared against the account's medium threshold.

Any other Horizon failure — timeout, 5xx, malformed body — is not a verification failure. It
surfaces as `ErrAccountLookupFailed` and maps to 503, never to 401. Treating an outage as a bad
signature would tell a caller their key was wrong when the network was merely unreachable.

Two rules govern the client domain key, and reversing either is a security failure:

- It **must** be in the signer list when the challenge carries a `client_domain` operation.
  Otherwise its signature is unmatched and the "all signatures accounted for" check fails.
- Its weight **must not** count toward the account's threshold. The threshold sum runs over
  matched signers with the client domain key removed. Counting it would let any client domain
  satisfy any account's threshold.

This is the most dangerous arithmetic in the project, so it does not live inline. It is a named
function whose doc comment states the invariant in one sentence:

```go
// accountSignerWeight sums the weights of matched signers that belong to the account.
// The client domain key is excluded: it proves the wallet took part, never that the
// account authorised anything, and counting it would let any client domain meet any
// account's threshold.
func accountSignerWeight(found []string, summary txnbuild.SignerSummary,
    clientDomainKey string) int32
```

Deleting the exclusion must break a test, not merely fail to be caught by one. See section 11.

When the challenge carried a `client_domain` operation, the client domain key must appear among
the matched signers, else `ErrClientDomainUnverified`.

Muxed accounts are reduced to their underlying `G...` address before the Horizon lookup.

### 6.4 Differential test

`internal/auth` now owns security-critical code the SDK is meant to own. The mitigation is a
table-driven differential test.

For a table of challenge shapes that contain **no** `client_domain` operation — valid, tampered
source account, non-zero sequence, expired timebounds, infinite timebounds, wrong nonce length,
non-base64 nonce, unmatched home domain, memo on a muxed account, unknown extra operation
sourced at the server, unknown extra operation sourced elsewhere — assert that `ReadChallenge`
and `txnbuild.ReadChallengeTx` agree on accept versus reject, and on client account ID, matched
home domain and memo.

Upstream behaviour drift then surfaces as a test failure rather than a silent divergence.
Client domain cases are tested separately, since the SDK has no behaviour to compare against.

## 7. `internal/clientdomain`

```go
func (r *Resolver) Resolve(ctx context.Context, domain string) (signingKey string, err error)
```

1. If the allowlist is non-empty, a domain not on it is rejected before any network call.
2. A cached entry within TTL is returned without a fetch.
3. Fetch `https://<domain>/.well-known/stellar.toml`. Non-HTTPS is refused, including after a
   redirect. At most 3 redirects. 5-second timeout covering the whole request.
4. The body is read through an `io.LimitReader` capped at 100 KB **plus one byte**, so an
   oversized body is rejected rather than silently truncated — truncation could change how the
   file parses.
5. The buffered bytes are parsed with `BurntSushi/toml` and `SIGNING_KEY` is read. Absent, or
   not a valid `G...` strkey, is a rejection.
6. The result is cached with the configured TTL.

Every response from a client domain is treated as hostile input. The cache is a map behind a
mutex, holding successes only; failures are not cached, so a domain that recovers is picked up
on the next request.

## 8. `internal/token`

HS256 via `golang-jwt/v5`. Claims:

| Claim | Value |
|---|---|
| `iss` | `SEP10_JWT_ISSUER` |
| `sub` | `M...` for a muxed account; `G...:<memo>` when a memo was used; `G...` otherwise |
| `iat` | Issue time |
| `exp` | Issue time plus `SEP10_JWT_LIFETIME` |
| `jti` | Hex-encoded hash of the challenge transaction envelope, from `tx.HashHex` |
| `client_domain` | Present only when a client domain was verified |

Parsing rejects any algorithm other than HS256, rejects an expired token, and returns typed
errors. EdDSA is out of scope for this design.

## 9. `internal/store`

Interfaces are declared where they are consumed, in `internal/auth`, and satisfied by
`internal/store`. Handler and auth tests use a fake; the Postgres tests sit behind a build tag
and never run in CI.

```sql
CREATE TABLE challenges (
    nonce         TEXT PRIMARY KEY,
    account       TEXT NOT NULL,
    home_domain   TEXT NOT NULL,
    client_domain TEXT,
    issued_at     TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    consumed_at   TIMESTAMPTZ
);
CREATE INDEX ON challenges (expires_at);

CREATE TABLE sessions (
    jti           TEXT PRIMARY KEY,
    account       TEXT NOT NULL,
    memo          TEXT,
    home_domain   TEXT NOT NULL,
    client_domain TEXT,
    issued_at     TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL
);
CREATE INDEX ON sessions (account, issued_at DESC);
```

Consumption is one atomic statement, never read-then-write:

```sql
UPDATE challenges SET consumed_at = $2
WHERE nonce = $1 AND consumed_at IS NULL AND expires_at > $2
RETURNING account, home_domain, client_domain;
```

Zero rows means failure. Only then does a second query run, to tell unknown from already
consumed from expired for the error class. Two concurrent posts of the same challenge cannot
both succeed, because only one `UPDATE` can match.

A background goroutine deletes challenge rows past their expiry every 5 minutes, and stops on
context cancellation. Sessions are never deleted; they are the audit trail.

## 10. `internal/httpapi`

`GET /auth` and `POST /auth`, the latter accepting both `application/json` and
`application/x-www-form-urlencoded` because both are used in the wild.
`GET /.well-known/stellar.toml` serves the configured SEP-1 file as `text/plain` with permissive
CORS, substituting the server's signing public key into a `SIGNING_KEY` placeholder at load so a
mismatched key cannot be published by accident. A missing file fails startup loudly.
`GET /health` reports process and database liveness.

Middleware: request ID, structured request logging, panic recovery, a 64 KB request body limit,
and a per-IP rate limit of 60 requests per minute held in an in-process token bucket. The limit
is deliberately fixed rather than configurable — it is a guard against casual abuse, not a
traffic policy, and operators fronting this with a real gateway will set their own.

### Error mapping

Typed sentinels in `errors.go`, mapped with `errors.Is`. No string matching.

| Error | Status |
|---|---|
| `ErrInvalidAccount`, `ErrMemoWithMuxed`, `ErrUnknownHomeDomain`, `ErrClientDomainRequired`, `ErrClientDomainRejected` | 400 |
| `ErrChallengeUnknown`, `ErrChallengeConsumed`, `ErrChallengeExpired`, `ErrChallengeMalformed`, `ErrSignatureUnrecognized`, `ErrThresholdNotMet`, `ErrClientDomainUnverified` | 401 |
| `ErrAccountLookupFailed`, database failure | 503 |

Response bodies name the failure class and nothing else. No signature material, no internal
state, no secret, in any response or log line.

## 11. Testing

Every test runs offline: no network, no live database. Fixed keypairs, fakes behind the
interfaces, and explicit timestamps rather than an injected clock — a challenge with expired
timebounds or a token with a past expiry is constructed directly, so no production code carries
a clock seam it does not otherwise need. Table-driven throughout.

- **auth** — challenge issued for an existing account and for a non-existent account; missing
  signature rejected; threshold not met rejected; memo with muxed account rejected; client
  domain signature required and verified; the differential test of section 6.4.
- **threshold exclusion**, its own test, written to fail loudly if the exclusion in
  `accountSignerWeight` is removed. An account has medium threshold 2 and one signer of weight
  1. The challenge is signed by that signer and by a client domain key carrying weight 2 in the
  summary. Verification **must** fail with `ErrThresholdNotMet`: the account contributed 1
  against a threshold of 2, and the client domain's 2 is not the account's to spend. Deleting
  the exclusion makes the sum 3, the call succeeds, and this test goes red. A passing-case test
  alone would not catch it, which is why this case is specified separately.
- **replay** — a consumed nonce is rejected on second use; an expired nonce is rejected.
- **clientdomain** — `SIGNING_KEY` extracted; missing key rejected; oversized body rejected;
  non-HTTPS rejected; redirect limit enforced; cache hit avoids a second fetch. Driven by
  `httptest.Server`.
- **token** — `sub` formatting with and without a memo and for muxed accounts; expired token
  rejected on parse; wrong algorithm rejected.
- **config** — each missing or malformed variable produces an error naming it.
- **httpapi** — `GET /auth` 400 paths; `POST /auth` 401 on bad signature; success returns a
  parseable token; the TOML endpoint serves with the correct content type.

## 12. Build sequence

One commit per item, conventional commits, pushed immediately after each. Files staged by path;
never `git add .` after the scaffold. Before every commit touching logic: `go build ./...`,
`go vet ./...`, `gofmt -l .` clean, `go test ./...` green.

**Setup**
1. `chore(setup): initialise go module, gitignore, license, makefile`
2. `ci(setup): add build, vet, test, gofmt workflow`
3. `docs(setup): add README skeleton and .env.example`

**Foundations**
4. `feat(config): add environment config loading and validation`
5. `test(config): cover missing and malformed variables`
6. `feat(log): add structured slog logger`

**Core protocol**
7. `chore(auth): pin stellar SDK and record challenge API findings`
8. `feat(auth): add typed error set`
9. `feat(auth): add SEP-10 challenge reader with client_domain support`
10. `test(auth): add differential test against SDK reader`
11. `feat(auth): add signature and threshold verification`
12. `feat(auth): add challenge issuance`
13. `test(auth): cover issuance and both verification paths`

**Client domain**
14. `feat(clientdomain): add TOML resolver with timeout, size cap, and cache`
15. `test(clientdomain): cover parse, rejection, and cache behaviour`

**Token**
16. `feat(token): add JWT issuance and parsing`
17. `test(token): cover claim formatting and expiry`

**Store**
18. `feat(store): add interface and migrations`
19. `feat(store): add postgres implementation`
20. `feat(store): add expired challenge cleanup loop`
21. `test(store): cover replay rejection with a fake`

**HTTP**
22. `feat(httpapi): add router, middleware, and health endpoint`
23. `feat(httpapi): add GET /auth handler`
24. `feat(httpapi): add POST /auth handler`
25. `feat(httpapi): add stellar.toml handler`
26. `test(httpapi): cover error paths and success path`

**Deploy and docs**
27. `feat(deploy): add Dockerfile and docker-compose with postgres`
28. `feat(cmd): wire authd entrypoint`
29. `docs: complete README with quick start, endpoints, and config table`

The ordering differs from the original brief in the auth block: errors and the reader come
before verification and issuance, because both depend on them, and the differential test lands
with the reader rather than at the end.

## 13. Non-goals

EdDSA-signed JWTs. Token refresh or revocation. Any SEP above 10. KYC. Multi-tenancy beyond the
configured home domain list. A management API over the session table.
