# Anchorage SEP-10 Authentication Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a runnable SEP-10 Stellar Web Authentication server in Go that issues challenge
transactions, verifies client signatures, and returns JWTs.

**Architecture:** A chi HTTP server over four internal packages: `auth` holds the SEP-10
protocol logic, `clientdomain` resolves wallet signing keys over HTTPS, `token` mints JWTs, and
`store` provides Postgres-backed replay protection. `auth` carries its own challenge reader
because the SDK's reader rejects spec-compliant `client_domain` challenges; a differential test
pins that reader to the SDK everywhere the two overlap.

**Tech Stack:** Go 1.25.12, `github.com/stellar/go-stellar-sdk` v0.7.1, chi/v5, pgx/v5,
golang-migrate/v4, golang-jwt/v5, BurntSushi/toml, testify.

**Spec:** `docs/superpowers/specs/2026-08-10-sep10-auth-server-design.md`

## Deviation from the spec's commit list — read this first

The spec's section 12 lists `feat(x)` and `test(x)` as separate commits, but section 12 also
requires `go test ./...` green before every commit, and this plan is test-driven. Those three
rules cannot all hold: a commit containing only a new failing test is not green, and a commit
containing only implementation is not test-driven.

**Resolution: each feature and its tests land in one commit**, named with the spec's `feat(...)`
message. The commit list drops from 29 to 23. The one exception is the differential test, which
stays its own commit because it is its own deliverable, tests code committed earlier, and is
green when it lands.

No test is written after the code it tests. Every commit is green.

### Two further deviations, both verified before writing the tasks

**A new package, `internal/account`.** The spec's section 6.3 declares an `AccountFetcher`
interface but its section 4 layout gives it nowhere to be implemented. The obvious home is the
SDK's `horizonclient`, but every method on `horizonclient.Client` is context-free —
`AccountDetail(request AccountRequest) (hProtocol.Account, error)`, checked with `go doc` at
v0.7.1 — so a fetcher built on it cannot take a context and cannot be cancelled when the client
disconnects. That breaks the "context first, for every function that does I/O" rule.

Task 12 therefore makes the one `GET /accounts/{id}` call with `http.NewRequestWithContext` and
decodes into the SDK's own `protocols/horizon.Account`, using its `SignerSummary()` and
`Thresholds.MedThreshold`. No protocol logic is reimplemented: the request is one URL and the
response type is the SDK's. It is also testable offline against an `httptest.Server`, which a
`horizonclient` wrapper is not.

**Store interfaces live in `internal/httpapi`, not `internal/auth`.** Section 9 says interfaces
are "declared where they are consumed, in `internal/auth`". The first half is the principle and
the second half contradicts it: nothing in `internal/auth` touches the store — the handlers
record challenges, consume nonces, and write sessions. The interfaces go where the calls are.
`internal/store` returns the sentinels from `internal/auth/errors.go` rather than a second,
parallel error set, which points the dependency from store to protocol and never back.

## Global Constraints

Every task's requirements implicitly include this section.

- **Go version:** `go.mod` declares `go 1.25.0` and `toolchain go1.25.12`. CI pins
  `go-version: 1.25.12` exactly — never `1.25.x`.
- **SDK:** `github.com/stellar/go-stellar-sdk` v0.7.1. Never `github.com/stellar/go`, which is
  deprecated and untagged.
- **Dependencies:** chi/v5, pgx/v5, golang-migrate/v4 (via its `database/pgx/v5` driver, never
  the `postgres` driver, which pulls `lib/pq`), golang-jwt/v5, BurntSushi/toml v1.6.0, testify.
  Nothing else without asking.
- **No placeholders.** No `TODO`, no stub, no "implement later". Every function is complete when
  committed.
- **Secrets:** never in a flag, in source, in a log line, or in an error message.
- **Errors:** wrapped with `fmt.Errorf("...: %w", err)`. Typed sentinels in
  `internal/auth/errors.go`. Handlers map with `errors.Is`, never string matching.
- **Context:** `context.Context` is the first parameter of every function that does I/O.
- **No global mutable state.** Dependencies passed into constructors. Interfaces declared at the
  point of use.
- **No `panic`** outside `main` startup failure.
- **Every exported symbol has a doc comment.**
- **Tests:** table-driven, offline. No network, no live database. Postgres integration tests sit
  behind a build tag.
- **Before every commit touching logic:** `go build ./...`, `go vet ./...`, `gofmt -l .` empty,
  `go test ./...` green.
- **Module graph:** Task 1 resolved the dependency set on a module with zero packages, so every
  requirement landed in `go.mod` marked `// indirect` and `go.sum` carries only what resolution
  itself needed — not the transitive closure a real import pulls in. The first task that imports
  a dependency for real therefore hits a missing `go.sum` entry. That is expected, not a broken
  lockfile: run `go mod tidy` and stage `go.mod` and `go.sum` alongside that task's own files.
  `tidy` also drops requirements nothing imports yet, so `go.mod` shrinks before it grows; each
  later task re-adds what it imports. Never hand-edit `go.sum`. After `tidy`, confirm the two
  standing bans still hold: `grep -c "lib/pq" go.sum` and `grep -c "github.com/stellar/go " go.mod`
  must both print `0`.
- **Git:** stage by path, never `git add .` after Task 1. Conventional commits. Push immediately
  after every commit. No attribution trailers, no "generated with" footers.
- **Plain language** in comments and docs. Not "seamlessly", "robust", "powerful", "leverage".

## File Structure

| File | Responsibility |
|---|---|
| `cmd/authd/main.go` | Load config, open store, run migrations, start server and cleanup loop, shut down cleanly |
| `internal/config/config.go` | Parse and validate every environment variable |
| `internal/log/log.go` | Build the slog JSON logger |
| `internal/auth/errors.go` | Typed sentinel errors for the whole protocol layer |
| `internal/auth/read.go` | SEP-10 challenge reader, including `client_domain` |
| `internal/auth/verify.go` | Signature matching, signer path, threshold path, weight exclusion |
| `internal/auth/challenge.go` | Challenge issuance, including rebuild-and-resign |
| `internal/account/fetcher.go` | Fetch one account's signers and thresholds from Horizon |
| `internal/clientdomain/resolver.go` | Fetch, cap, parse and cache client domain TOML |
| `internal/token/jwt.go` | Issue and parse HS256 JWTs |
| `internal/store/store.go` | Record types shared by the store and its callers |
| `internal/store/postgres.go` | pgx implementation plus the cleanup loop |
| `internal/store/migrations/` | golang-migrate SQL files |
| `internal/httpapi/router.go` | Route table and dependency wiring |
| `internal/httpapi/respond.go` | JSON response and error-body writing |
| `internal/httpapi/middleware.go` | Request ID, logging, recovery, body cap, rate limit |
| `internal/httpapi/auth_handler.go` | `GET /auth`, `POST /auth`, error-to-status mapping |
| `internal/httpapi/toml_handler.go` | `GET /.well-known/stellar.toml` |
| `internal/httpapi/health_handler.go` | `GET /health` |

`read.go`, `verify.go` and `challenge.go` are separate files so structural validation, signature
checking, and issuance are reviewed apart. They are the security core.

---

## Task 1: Scaffold

**Files:**
- Create: `go.mod`, `.gitignore`, `LICENSE`, `Makefile`

**Interfaces:**
- Consumes: nothing
- Produces: a module named `github.com/0dillon/Anchorage` that builds

- [ ] **Step 1: Initialise the module and pin the toolchain**

```bash
cd /home/dillon/projects/Anchorage
go mod init github.com/0dillon/Anchorage
go mod edit -go=1.25.0 -toolchain=go1.25.12
```

- [ ] **Step 2: Add dependencies**

The `toolchain` directive means every `go` command below resolves go1.25.12 automatically.

```bash
go get github.com/stellar/go-stellar-sdk@v0.7.1
go get github.com/go-chi/chi/v5
go get github.com/jackc/pgx/v5
go get github.com/golang-migrate/migrate/v4
go get github.com/golang-migrate/migrate/v4/database/pgx/v5
go get github.com/golang-migrate/migrate/v4/source/iofs
go get github.com/golang-jwt/jwt/v5
go get github.com/BurntSushi/toml@v1.6.0
go get github.com/stretchr/testify
```

- [ ] **Step 3: Verify no forbidden dependency crept in**

```bash
grep -c "lib/pq" go.sum || true
grep -c "github.com/stellar/go " go.mod || true
```

Expected: `0` for both. If `lib/pq` appears, the wrong migrate driver was imported.

- [ ] **Step 4: Write `.gitignore`**

```
/authd
*.env
.env
!.env.example
/coverage.out
```

- [ ] **Step 5: Write `LICENSE`**

Fetch the Apache-2.0 text verbatim:

```bash
curl -sS https://www.apache.org/licenses/LICENSE-2.0.txt -o LICENSE
head -3 LICENSE
```

Expected: the Apache License header. Then set the copyright line in the appendix if the template
requires it; the plain 2.0 text does not.

- [ ] **Step 6: Write `Makefile`**

```makefile
.PHONY: build test vet fmt check run

build:
	go build ./...

test:
	go test ./...

vet:
	go vet ./...

fmt:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && echo "gofmt found unformatted files" && exit 1)

check: build vet fmt test

run:
	go run ./cmd/authd
```

The `fmt` target fails on unformatted files rather than rewriting them, so CI and a local run
mean the same thing.

- [ ] **Step 7: Verify the module builds**

The module has no Go packages yet — the first one arrives in Task 4 — so run the two targets
that are meaningful on an empty module:

Run: `go build ./... && test -z "$(gofmt -l .)" && echo ok`
Expected: `ok`, after a `matched no packages` warning from the build.

Do **not** run `make check` yet, and do not change the Makefile to make it pass. On a module
with zero packages, `go vet ./...` and `go test ./...` both exit 1 with "no packages to
vet/test" — verified on go1.25.12. That is correct behaviour, not a fault in the Makefile.
Relaxing those targets to tolerate an empty match would keep tolerating it forever, and would
later hide a genuine failure that looks identical: a build tag or `//go:build` line that
accidentally excludes every file in a package.

`make check` becomes the gate from Task 4 onward, once there is a package to check. Tasks 2 and
3 add no Go code and do not run it.

- [ ] **Step 8: Commit**

This is the only commit in the project allowed to use `git add .`.

```bash
git add .
git commit -m "chore(setup): initialise go module, gitignore, license, makefile"
git push
```

---

## Task 2: CI

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: the `Makefile` targets from Task 1
- Produces: a CI job that gates every later commit

- [ ] **Step 1: Write the workflow**

```yaml
name: ci

on:
  push:
    branches: [main]
  pull_request:

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          # Pinned exactly, not 1.25.x. The go.mod toolchain directive names
          # go1.25.12; CI must use the same build the toolchain pin produces.
          go-version: '1.25.12'
          check-latest: false

      - name: Build
        run: go build ./...

      - name: Vet
        run: go vet ./...

      - name: Gofmt
        run: test -z "$(gofmt -l .)" || (gofmt -l . && exit 1)

      - name: Test
        run: go test ./...
```

Tests need no network and no database, so there is no service container. The differential test
from Task 9 runs inside `go test ./...` like any other test.

- [ ] **Step 2: Verify the workflow parses**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('ok')"`
Expected: `ok`

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci(setup): add build, vet, test, gofmt workflow"
git push
```

---

## Task 3: README skeleton and .env.example

**Files:**
- Create: `README.md`, `.env.example`

**Interfaces:**
- Consumes: nothing
- Produces: the documented variable names Task 4 parses

- [ ] **Step 1: Write `.env.example`**

Every variable from the spec's section 5. Placeholders only — never a real secret.

```bash
# Server signing key (S...). Never commit a real value.
SEP10_SIGNING_SECRET=SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
SEP10_NETWORK_PASSPHRASE=Test SDF Network ; September 2015
SEP10_HORIZON_URL=https://horizon-testnet.stellar.org
SEP10_WEB_AUTH_DOMAIN=auth.example.com
SEP10_HOME_DOMAINS=example.com
SEP10_CHALLENGE_TIMEOUT=300s
# HS256 signing secret, at least 32 bytes. Never commit a real value.
SEP10_JWT_SECRET=replace-with-at-least-32-bytes-of-random
SEP10_JWT_ISSUER=https://auth.example.com
SEP10_JWT_LIFETIME=24h
SEP10_CLIENT_DOMAIN_REQUIRED=false
SEP10_CLIENT_DOMAIN_ALLOWLIST=
SEP10_CLIENT_DOMAIN_CACHE_TTL=5m
SEP10_DATABASE_URL=postgres://anchorage:anchorage@localhost:5432/anchorage?sslmode=disable
SEP10_LISTEN_ADDR=:8080
SEP10_TOML_PATH=./deploy/stellar.toml.example
```

- [ ] **Step 2: Write the README skeleton**

Leads with the finding, per the spec's section 1. Task 23 fills in the rest.

````markdown
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

## Status

Under construction. See `docs/superpowers/plans/2026-08-10-sep10-auth-server.md`.
````

- [ ] **Step 3: Commit**

```bash
git add README.md .env.example
git commit -m "docs(setup): add README skeleton and .env.example"
git push
```

---

## Task 4: Configuration

**Files:**
- Create: `internal/config/config.go`, `internal/config/config_test.go`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `type Config struct` with the fields listed in Step 3
  - `func Load(getenv func(string) string) (*Config, error)`

`Load` takes a `getenv` function rather than reading `os.Getenv` directly, so tests set variables
without mutating process state and can run in parallel.

- [ ] **Step 1: Write the failing test**

`internal/config/config_test.go`:

```go
package config

import (
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stretchr/testify/require"
)

// testKP is a deterministic keypair derived from a fixed raw seed. Deriving it
// rather than pasting a strkey literal keeps the test honest: a hand-written
// strkey carries a checksum and is easy to get subtly wrong.
var testKP = mustKeypair(7)

func mustKeypair(fill byte) *keypair.Full {
	var raw [32]byte
	for i := range raw {
		raw[i] = fill
	}
	kp, err := keypair.FromRawSeed(raw)
	if err != nil {
		panic(err)
	}
	return kp
}

// valid returns a complete set of environment values. Tests copy it and then
// remove or corrupt one entry.
func valid() map[string]string {
	return map[string]string{
		"SEP10_SIGNING_SECRET":     testKP.Seed(),
		"SEP10_NETWORK_PASSPHRASE": "Test SDF Network ; September 2015",
		"SEP10_HORIZON_URL":        "https://horizon-testnet.stellar.org",
		"SEP10_WEB_AUTH_DOMAIN":    "auth.example.com",
		"SEP10_HOME_DOMAINS":       "example.com, other.example.com",
		"SEP10_JWT_SECRET":         "0123456789abcdef0123456789abcdef",
		"SEP10_JWT_ISSUER":         "https://auth.example.com",
		"SEP10_DATABASE_URL":       "postgres://u:p@localhost:5432/db",
		"SEP10_TOML_PATH":          "./deploy/stellar.toml.example",
	}
}

func getenvFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(getenvFrom(valid()))
	require.NoError(t, err)

	require.Equal(t, []string{"example.com", "other.example.com"}, cfg.HomeDomains)
	require.Equal(t, 300*time.Second, cfg.ChallengeTimeout)
	require.Equal(t, 24*time.Hour, cfg.JWTLifetime)
	require.Equal(t, 5*time.Minute, cfg.ClientDomainCacheTTL)
	require.Equal(t, ":8080", cfg.ListenAddr)
	require.False(t, cfg.ClientDomainRequired)
	require.Empty(t, cfg.ClientDomainAllowlist)

	// The public key is derived at load so handlers never touch the secret.
	require.Equal(t, testKP.Address(), cfg.SigningPublicKey)
	// The secret is kept, but only where it is needed.
	require.Equal(t, testKP.Seed(), cfg.SigningSecret)
}

func TestLoadMissingRequired(t *testing.T) {
	required := []string{
		"SEP10_SIGNING_SECRET",
		"SEP10_NETWORK_PASSPHRASE",
		"SEP10_HORIZON_URL",
		"SEP10_WEB_AUTH_DOMAIN",
		"SEP10_HOME_DOMAINS",
		"SEP10_JWT_SECRET",
		"SEP10_JWT_ISSUER",
		"SEP10_DATABASE_URL",
		"SEP10_TOML_PATH",
	}

	for _, name := range required {
		t.Run(name, func(t *testing.T) {
			env := valid()
			delete(env, name)

			_, err := Load(getenvFrom(env))
			require.Error(t, err)
			require.Contains(t, err.Error(), name)
		})
	}
}

func TestLoadMalformed(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		// A public address is a well-formed strkey but not a seed.
		{"signing secret is an address", "SEP10_SIGNING_SECRET", testKP.Address()},
		{"horizon url not https", "SEP10_HORIZON_URL", "://nope"},
		{"jwt secret too short", "SEP10_JWT_SECRET", "short"},
		{"challenge timeout unparseable", "SEP10_CHALLENGE_TIMEOUT", "five minutes"},
		{"challenge timeout too small", "SEP10_CHALLENGE_TIMEOUT", "500ms"},
		{"jwt lifetime unparseable", "SEP10_JWT_LIFETIME", "forever"},
		{"cache ttl negative", "SEP10_CLIENT_DOMAIN_CACHE_TTL", "-1m"},
		{"client domain required not a bool", "SEP10_CLIENT_DOMAIN_REQUIRED", "yes please"},
		{"home domains empty after trim", "SEP10_HOME_DOMAINS", " , "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := valid()
			env[tt.key] = tt.value

			_, err := Load(getenvFrom(env))
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.key)
		})
	}
}

// A malformed secret must not leak into the error text.
func TestLoadNeverEchoesSecrets(t *testing.T) {
	const secret = "SBADSEEDVALUETHATSHOULDNEVERAPPEARINANERRORMESSAGE123456"

	env := valid()
	env["SEP10_SIGNING_SECRET"] = secret

	_, err := Load(getenvFrom(env))
	require.Error(t, err)
	require.NotContains(t, err.Error(), secret)
}
```

- [ ] **Step 2: Settle the module graph, then run the test to verify it fails**

This is the first package to import the SDK for real, so `go.sum` is missing the transitive
entries the import pulls in. Settle it first, or the compile error you get is about `go.sum`
rather than about `Load`:

Run: `go mod tidy`
Expected: some downloading, exit 0. `go.mod` shrinks — `tidy` drops the requirements nothing
imports yet, leaving `go-stellar-sdk` and `testify` as direct.

Run: `grep -c "lib/pq" go.sum; grep -c "github.com/stellar/go " go.mod`
Expected: `0` twice.

Run: `go test ./internal/config/ -v`
Expected: FAIL — `undefined: Load`

- [ ] **Step 3: Write the implementation**

`internal/config/config.go`:

```go
// Package config loads and validates the server's environment configuration.
// Nothing starts against unvalidated config.
package config

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
)

// minJWTSecretLen is the shortest HS256 secret accepted. Shorter secrets are
// brute-forceable offline once an attacker holds one issued token.
const minJWTSecretLen = 32

// Config holds every validated setting the server needs.
type Config struct {
	// SigningSecret is the server's Stellar signing key (S...). Never logged.
	SigningSecret string
	// SigningPublicKey is derived from SigningSecret at load, so callers that
	// only need the public key never handle the secret.
	SigningPublicKey string

	NetworkPassphrase string
	HorizonURL        string
	WebAuthDomain     string
	HomeDomains       []string
	ChallengeTimeout  time.Duration

	// JWTSecret is the HS256 signing secret. Never logged.
	JWTSecret   string
	JWTIssuer   string
	JWTLifetime time.Duration

	ClientDomainRequired  bool
	ClientDomainAllowlist []string
	ClientDomainCacheTTL  time.Duration

	DatabaseURL string
	ListenAddr  string
	TOMLPath    string
}

// Load reads configuration through getenv and validates all of it. The error
// names the offending variable and never contains a secret's value.
func Load(getenv func(string) string) (*Config, error) {
	cfg := &Config{}
	var err error

	if cfg.SigningSecret, err = required(getenv, "SEP10_SIGNING_SECRET"); err != nil {
		return nil, err
	}
	kp, parseErr := keypair.ParseFull(cfg.SigningSecret)
	if parseErr != nil {
		// Deliberately does not include the value.
		return nil, fmt.Errorf("SEP10_SIGNING_SECRET is not a valid Stellar secret seed")
	}
	cfg.SigningPublicKey = kp.Address()

	if cfg.NetworkPassphrase, err = required(getenv, "SEP10_NETWORK_PASSPHRASE"); err != nil {
		return nil, err
	}

	if cfg.HorizonURL, err = required(getenv, "SEP10_HORIZON_URL"); err != nil {
		return nil, err
	}
	if u, parseErr := url.Parse(cfg.HorizonURL); parseErr != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("SEP10_HORIZON_URL is not a valid absolute URL: %q", cfg.HorizonURL)
	}

	if cfg.WebAuthDomain, err = required(getenv, "SEP10_WEB_AUTH_DOMAIN"); err != nil {
		return nil, err
	}

	rawHomeDomains, err := required(getenv, "SEP10_HOME_DOMAINS")
	if err != nil {
		return nil, err
	}
	cfg.HomeDomains = splitList(rawHomeDomains)
	if len(cfg.HomeDomains) == 0 {
		return nil, fmt.Errorf("SEP10_HOME_DOMAINS contains no non-empty entries")
	}

	if cfg.ChallengeTimeout, err = duration(getenv, "SEP10_CHALLENGE_TIMEOUT", 300*time.Second); err != nil {
		return nil, err
	}
	if cfg.ChallengeTimeout < time.Second {
		return nil, fmt.Errorf("SEP10_CHALLENGE_TIMEOUT must be at least 1s, got %s", cfg.ChallengeTimeout)
	}

	if cfg.JWTSecret, err = required(getenv, "SEP10_JWT_SECRET"); err != nil {
		return nil, err
	}
	if len(cfg.JWTSecret) < minJWTSecretLen {
		return nil, fmt.Errorf("SEP10_JWT_SECRET must be at least %d bytes", minJWTSecretLen)
	}

	if cfg.JWTIssuer, err = required(getenv, "SEP10_JWT_ISSUER"); err != nil {
		return nil, err
	}

	if cfg.JWTLifetime, err = duration(getenv, "SEP10_JWT_LIFETIME", 24*time.Hour); err != nil {
		return nil, err
	}
	if cfg.JWTLifetime <= 0 {
		return nil, fmt.Errorf("SEP10_JWT_LIFETIME must be positive, got %s", cfg.JWTLifetime)
	}

	if cfg.ClientDomainRequired, err = boolean(getenv, "SEP10_CLIENT_DOMAIN_REQUIRED", false); err != nil {
		return nil, err
	}
	cfg.ClientDomainAllowlist = splitList(getenv("SEP10_CLIENT_DOMAIN_ALLOWLIST"))

	if cfg.ClientDomainCacheTTL, err = duration(getenv, "SEP10_CLIENT_DOMAIN_CACHE_TTL", 5*time.Minute); err != nil {
		return nil, err
	}
	if cfg.ClientDomainCacheTTL <= 0 {
		return nil, fmt.Errorf("SEP10_CLIENT_DOMAIN_CACHE_TTL must be positive, got %s", cfg.ClientDomainCacheTTL)
	}

	if cfg.DatabaseURL, err = required(getenv, "SEP10_DATABASE_URL"); err != nil {
		return nil, err
	}

	cfg.ListenAddr = getenv("SEP10_LISTEN_ADDR")
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8080"
	}

	if cfg.TOMLPath, err = required(getenv, "SEP10_TOML_PATH"); err != nil {
		return nil, err
	}

	return cfg, nil
}

// required reads a variable that must be present and non-empty.
func required(getenv func(string) string, name string) (string, error) {
	v := strings.TrimSpace(getenv(name))
	if v == "" {
		return "", fmt.Errorf("%s is required but not set", name)
	}
	return v, nil
}

// duration reads an optional duration, falling back to def when unset.
func duration(getenv func(string) string, name string, def time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(getenv(name))
	if raw == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s is not a valid duration: %q", name, raw)
	}
	return d, nil
}

// boolean reads an optional boolean, falling back to def when unset.
func boolean(getenv func(string) string, name string, def bool) (bool, error) {
	raw := strings.TrimSpace(getenv(name))
	if raw == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s is not a valid boolean: %q", name, raw)
	}
	return b, nil
}

// splitList splits a comma-separated list, trimming spaces and dropping empties.
func splitList(raw string) []string {
	out := []string{}
	for _, part := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/config/ -v`
Expected: PASS — all four tests, including every subtest of `TestLoadMissingRequired` and
`TestLoadMalformed`.

- [ ] **Step 5: Commit**

```bash
make check
git add go.mod go.sum internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add environment config loading and validation"
git push
```

---

## Task 5: Structured logger

**Files:**
- Create: `internal/log/log.go`

**Interfaces:**
- Consumes: nothing
- Produces: `func New(w io.Writer, level slog.Level) *slog.Logger`

- [ ] **Step 1: Write the implementation**

No test task: this is a thin constructor over the standard library with no branching worth
asserting. Its behaviour is exercised by the middleware tests in Task 17.

`internal/log/log.go`:

```go
// Package log builds the server's structured logger.
package log

import (
	"io"
	"log/slog"
)

// New returns a JSON logger writing to w at the given level.
func New(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: level,
	}))
}
```

The package exports `New` and nothing else. An earlier draft also exported a `ParseLevel` name
mapper, but nothing calls it: `main` passes `slog.LevelInfo` directly and there is no
`SEP10_LOG_LEVEL` variable to feed it. An exported function with no caller is the speculative
code the Global Constraints forbid, so it is gone. The level is a compile-time choice until
something needs it not to be.

- [ ] **Step 2: Verify it builds**

Run: `make check`
Expected: passes.

- [ ] **Step 3: Commit**

```bash
git add internal/log/log.go
git commit -m "feat(log): add structured slog logger"
git push
```

---

## Task 6: Record the SDK findings

**Files:**
- Create: `docs/sdk-findings.md`

**Interfaces:**
- Consumes: the SDK pinned in Task 1
- Produces: the document Task 23's README links to

The SDK is already pinned. This commit records what was verified about it, so a reviewer can
check the claims without re-deriving them.

- [ ] **Step 1: Re-verify each claim against the pinned module**

Do not copy these results from the spec. Re-run them, because the plan is worthless if the
pinned version behaves differently from the one that was probed.

```bash
SDK=$(go env GOMODCACHE)/github.com/stellar/go-stellar-sdk@v0.7.1
go doc github.com/stellar/go-stellar-sdk/txnbuild.BuildChallengeTx
grep -rn "client_domain" "$SDK" --include=*.go | wc -l
sed -n '1266,1276p' "$SDK/txnbuild/transaction.go"
```

Expected: the `BuildChallengeTx` signature ends `timebound time.Duration, memo *MemoID`; the
grep count is `0`; the `sed` output is the `default:` branch requiring `op.SourceAccount ==
serverAccountID`.

**If any expectation differs, stop and report it rather than continuing.** The whole design
rests on these three facts.

- [ ] **Step 2: Write `docs/sdk-findings.md`**

````markdown
# SDK findings

Verified against `github.com/stellar/go-stellar-sdk` v0.7.1.

## The module was renamed

`github.com/stellar/go` is deprecated in favour of `github.com/stellar/go-stellar-sdk`. The old
path also publishes no semver tags, so it can only be pinned by pseudo-version. Anchorage uses
the successor at v0.7.1.

## The toolchain must be pinned exactly

`go-stellar-sdk` declares `go >= 1.25`, which Go resolves to a toolchain named `go1.25`. That
name is not downloadable and the build fails with `toolchain not available`. `go.mod` therefore
pins `toolchain go1.25.12`, and CI pins the same version.

## BuildChallengeTx takes a memo

```go
func BuildChallengeTx(serverSignerSecret, clientAccountID, webAuthDomain, homeDomain,
    network string, timebound time.Duration, memo *MemoID) (*Transaction, error)
```

## ReadChallengeTx rejects spec-compliant client_domain challenges

`grep -rn client_domain` across the SDK returns nothing. `ReadChallengeTx` requires every
operation after the first to be sourced at the server account
(`txnbuild/transaction.go:1270`):

```go
default:
    // verify unknown subsequent operations are manage data ops with source account set to server account
    if op.SourceAccount != serverAccountID {
        return ..., errors.New("subsequent operations are unrecognized")
    }
```

SEP-10 requires the `client_domain` operation to be sourced at the client domain's
`SIGNING_KEY`. So the SDK cannot read a challenge that carries one.

`VerifyChallengeTxSigners` calls `ReadChallengeTx` (`transaction.go:1355`) and
`VerifyChallengeTxThreshold` calls `VerifyChallengeTxSigners`, so both inherit the rejection.
The operation cannot be stripped before verification because signatures cover the whole
transaction, and no lower-level entry point is exported — `verifyTxSignatures` is unexported.

Anchorage therefore implements its own reader in `internal/auth/read.go`, pinned to upstream
behaviour by the differential test in `internal/auth/differential_test.go`.
````

- [ ] **Step 3: Commit**

```bash
git add docs/sdk-findings.md
git commit -m "chore(auth): pin stellar SDK and record challenge API findings"
git push
```

---

## Task 7: Typed error set

**Files:**
- Create: `internal/auth/errors.go`

**Interfaces:**
- Consumes: nothing
- Produces: the sentinels every later task returns and Task 18 maps to status codes

- [ ] **Step 1: Write the implementation**

No test task: these are `errors.New` values with no behaviour. Task 18 defines the mapping from
each one to a status code and Task 19 tests every sentinel in it, which is the part that can be
wrong.

`internal/auth/errors.go`:

```go
// Package auth implements the SEP-10 challenge protocol: issuing challenges,
// reading them back, and verifying client signatures against an account.
package auth

import "errors"

// Errors that mean the caller's request was bad. Handlers map these to 400.
var (
	// ErrInvalidAccount means the account is not a G... or M... strkey.
	ErrInvalidAccount = errors.New("account is not a valid Stellar address")
	// ErrMemoWithMuxed means a memo was combined with an M... account.
	ErrMemoWithMuxed = errors.New("memo is not valid with a muxed account")
	// ErrUnknownHomeDomain means the home domain is not configured.
	ErrUnknownHomeDomain = errors.New("home domain is not served by this server")
	// ErrClientDomainRequired means client_domain is mandatory but absent.
	ErrClientDomainRequired = errors.New("client domain is required")
	// ErrClientDomainRejected means the client domain could not be resolved or
	// is not on the allowlist.
	ErrClientDomainRejected = errors.New("client domain was rejected")
)

// Errors that mean verification failed. Handlers map these to 401 and must not
// disclose which one it was beyond the failure class.
var (
	// ErrChallengeMalformed means the challenge is not a well-formed SEP-10
	// challenge for this server.
	ErrChallengeMalformed = errors.New("challenge is malformed")
	// ErrChallengeUnknown means the nonce was never issued by this server.
	ErrChallengeUnknown = errors.New("challenge is not recognised")
	// ErrChallengeConsumed means the nonce was already used. A challenge is
	// valid exactly once.
	ErrChallengeConsumed = errors.New("challenge has already been used")
	// ErrChallengeExpired means the challenge is outside its timebounds or past
	// its stored expiry.
	ErrChallengeExpired = errors.New("challenge has expired")
	// ErrSignatureUnrecognized means a signature on the challenge matched no
	// expected signer, or an expected signature was missing.
	ErrSignatureUnrecognized = errors.New("challenge signatures are not recognised")
	// ErrThresholdNotMet means the matched account signers did not reach the
	// account's medium threshold.
	ErrThresholdNotMet = errors.New("signature weight does not meet the account threshold")
	// ErrClientDomainUnverified means the challenge carried a client_domain
	// operation that the client domain's signing key did not sign.
	ErrClientDomainUnverified = errors.New("client domain signature is missing")
)

// Errors that mean a dependency failed, not the caller. Handlers map these to
// 503. An outage must never be reported as a bad signature.
var (
	// ErrAccountLookupFailed means Horizon could not be consulted. It is
	// distinct from ErrAccountNotFound, which is a normal SEP-10 case.
	ErrAccountLookupFailed = errors.New("account lookup failed")
)

// ErrAccountNotFound means the account does not exist on the network. This is
// not a failure: SEP-10 authenticates such an account by its master key alone.
// An AccountFetcher returns it; no handler maps it to a status code.
var ErrAccountNotFound = errors.New("account does not exist on the network")
```

- [ ] **Step 2: Verify it builds**

Run: `make check`
Expected: passes.

- [ ] **Step 3: Commit**

```bash
git add internal/auth/errors.go
git commit -m "feat(auth): add typed error set"
git push
```

---

## Task 8: Challenge reader

This is the security core. Read the spec's section 6.2 before starting.

**Files:**
- Create: `internal/auth/signatures.go`, `internal/auth/read.go`,
  `internal/auth/helpers_test.go`, `internal/auth/read_test.go`

**Interfaces:**
- Consumes: the sentinels from Task 7
- Produces:
  - `type Challenge struct { Tx *txnbuild.Transaction; ClientAccountID, HomeDomain, Nonce, ClientDomain, ClientDomainKey string; Memo *txnbuild.MemoID }`
  - `func ReadChallenge(challengeXDR, serverAccountID, networkPassphrase, webAuthDomain string, homeDomains []string) (*Challenge, error)`
  - `func matchSigners(tx *txnbuild.Transaction, networkPassphrase string, signers []string) ([]string, error)` — unexported, used by Task 10
  - test helpers `defaultParams()`, `buildTx()`, `serverKP`, `clientKP`, `clientDomainKP`, `otherKP`, `testNetwork`, `testWebAuthDomain`, `testHomeDomain`, `testNonce`

`matchSigners` lives here rather than in `verify.go` because the reader needs it to check the
server's signature, and one implementation of signature matching is the point.

- [ ] **Step 1: Write the test helpers**

`internal/auth/helpers_test.go`:

```go
package auth

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stretchr/testify/require"
)

const (
	testNetwork       = network.TestNetworkPassphrase
	testWebAuthDomain = "auth.example.com"
	testHomeDomain    = "example.com"
	testClientDomain  = "wallet.example.org"
)

// Keypairs are derived from fixed raw seeds so tests are reproducible without
// pasting strkey literals, which carry checksums and are easy to get wrong.
var (
	serverKP       = mustKeypair(1)
	clientKP       = mustKeypair(2)
	clientDomainKP = mustKeypair(3)
	otherKP        = mustKeypair(4)
	extraKP        = mustKeypair(5)
)

func mustKeypair(fill byte) *keypair.Full {
	var raw [32]byte
	for i := range raw {
		raw[i] = fill
	}
	kp, err := keypair.FromRawSeed(raw)
	if err != nil {
		panic(err)
	}
	return kp
}

// testNonce is a valid SEP-10 nonce: 48 raw bytes, 64 base64 characters.
func testNonce() string {
	raw := make([]byte, 48)
	for i := range raw {
		raw[i] = byte(i)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// homeDomains is the configured list every test reads against.
func homeDomains() []string {
	return []string{testHomeDomain, "second.example.com"}
}

// defaultParams returns a valid two-operation challenge. Tests mutate the
// result to build each malformed variant.
func defaultParams() txnbuild.TransactionParams {
	now := time.Now().UTC()
	return txnbuild.TransactionParams{
		SourceAccount:        &txnbuild.SimpleAccount{AccountID: serverKP.Address(), Sequence: 0},
		IncrementSequenceNum: false,
		Operations: []txnbuild.Operation{
			&txnbuild.ManageData{
				SourceAccount: clientKP.Address(),
				Name:          testHomeDomain + " auth",
				Value:         []byte(testNonce()),
			},
			&txnbuild.ManageData{
				SourceAccount: serverKP.Address(),
				Name:          "web_auth_domain",
				Value:         []byte(testWebAuthDomain),
			},
		},
		BaseFee: txnbuild.MinBaseFee,
		Preconditions: txnbuild.Preconditions{
			TimeBounds: txnbuild.NewTimebounds(now.Unix(), now.Add(5*time.Minute).Unix()),
		},
	}
}

// clientDomainOp is the third operation SEP-10 defines and the SDK rejects.
// Its source account is the client domain's signing key, not the server's.
func clientDomainOp() *txnbuild.ManageData {
	return &txnbuild.ManageData{
		SourceAccount: clientDomainKP.Address(),
		Name:          "client_domain",
		Value:         []byte(testClientDomain),
	}
}

// buildTx assembles and signs a transaction, returning its base64 XDR.
func buildTx(t *testing.T, params txnbuild.TransactionParams, signers ...*keypair.Full) string {
	t.Helper()

	tx, err := txnbuild.NewTransaction(params)
	require.NoError(t, err)

	if len(signers) > 0 {
		tx, err = tx.Sign(testNetwork, signers...)
		require.NoError(t, err)
	}

	xdrString, err := tx.Base64()
	require.NoError(t, err)
	return xdrString
}
```

- [ ] **Step 2: Write the failing reader test**

`internal/auth/read_test.go`:

```go
package auth

import (
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stretchr/testify/require"
)

func TestReadChallengeValid(t *testing.T) {
	challenge := buildTx(t, defaultParams(), serverKP)

	got, err := ReadChallenge(challenge, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
	require.NoError(t, err)

	require.Equal(t, clientKP.Address(), got.ClientAccountID)
	require.Equal(t, testHomeDomain, got.HomeDomain)
	require.Equal(t, testNonce(), got.Nonce)
	require.Nil(t, got.Memo)
	require.Empty(t, got.ClientDomain)
	require.Empty(t, got.ClientDomainKey)
}

// The case the SDK cannot handle. This is why internal/auth has its own reader.
func TestReadChallengeWithClientDomain(t *testing.T) {
	params := defaultParams()
	params.Operations = append(params.Operations, clientDomainOp())

	challenge := buildTx(t, params, serverKP)

	got, err := ReadChallenge(challenge, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
	require.NoError(t, err)
	require.Equal(t, testClientDomain, got.ClientDomain)
	require.Equal(t, clientDomainKP.Address(), got.ClientDomainKey)

	// And confirm the SDK really does reject it, so this test documents the
	// upstream behaviour rather than asserting it from memory.
	_, _, _, _, sdkErr := txnbuild.ReadChallengeTx(
		challenge, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
	require.Error(t, sdkErr)
	require.Contains(t, sdkErr.Error(), "subsequent operations are unrecognized")
}

func TestReadChallengeMemo(t *testing.T) {
	params := defaultParams()
	params.Memo = txnbuild.MemoID(1234)

	challenge := buildTx(t, params, serverKP)

	got, err := ReadChallenge(challenge, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
	require.NoError(t, err)
	require.NotNil(t, got.Memo)
	require.Equal(t, txnbuild.MemoID(1234), *got.Memo)
}

func TestReadChallengeRejections(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(p *txnbuild.TransactionParams)
		signers []*keypair.Full
		wantErr error
	}{
		{
			name:    "unsigned by server",
			mutate:  func(p *txnbuild.TransactionParams) {},
			signers: nil,
			wantErr: ErrChallengeMalformed,
		},
		{
			name:    "signed by the wrong key",
			mutate:  func(p *txnbuild.TransactionParams) {},
			signers: []*keypair.Full{otherKP},
			wantErr: ErrChallengeMalformed,
		},
		{
			name: "wrong transaction source",
			mutate: func(p *txnbuild.TransactionParams) {
				p.SourceAccount = &txnbuild.SimpleAccount{AccountID: otherKP.Address(), Sequence: 0}
			},
			signers: []*keypair.Full{otherKP},
			wantErr: ErrChallengeMalformed,
		},
		{
			name: "non-zero sequence",
			mutate: func(p *txnbuild.TransactionParams) {
				p.SourceAccount = &txnbuild.SimpleAccount{AccountID: serverKP.Address(), Sequence: 9}
			},
			signers: []*keypair.Full{serverKP},
			wantErr: ErrChallengeMalformed,
		},
		{
			name: "expired timebounds",
			mutate: func(p *txnbuild.TransactionParams) {
				past := time.Now().UTC().Add(-time.Hour)
				p.Preconditions.TimeBounds = txnbuild.NewTimebounds(past.Unix(), past.Add(time.Minute).Unix())
			},
			signers: []*keypair.Full{serverKP},
			wantErr: ErrChallengeExpired,
		},
		{
			name: "unmatched home domain",
			mutate: func(p *txnbuild.TransactionParams) {
				p.Operations[0].(*txnbuild.ManageData).Name = "attacker.example.net auth"
			},
			signers: []*keypair.Full{serverKP},
			wantErr: ErrUnknownHomeDomain,
		},
		{
			name: "nonce wrong length",
			mutate: func(p *txnbuild.TransactionParams) {
				p.Operations[0].(*txnbuild.ManageData).Value = []byte("too short")
			},
			signers: []*keypair.Full{serverKP},
			wantErr: ErrChallengeMalformed,
		},
		{
			name: "nonce not base64",
			mutate: func(p *txnbuild.TransactionParams) {
				bad := make([]byte, 64)
				for i := range bad {
					bad[i] = '!'
				}
				p.Operations[0].(*txnbuild.ManageData).Value = bad
			},
			signers: []*keypair.Full{serverKP},
			wantErr: ErrChallengeMalformed,
		},
		{
			name: "web_auth_domain value mismatch",
			mutate: func(p *txnbuild.TransactionParams) {
				p.Operations[1].(*txnbuild.ManageData).Value = []byte("attacker.example.net")
			},
			signers: []*keypair.Full{serverKP},
			wantErr: ErrChallengeMalformed,
		},
		{
			name: "web_auth_domain sourced at the client",
			mutate: func(p *txnbuild.TransactionParams) {
				p.Operations[1].(*txnbuild.ManageData).SourceAccount = clientKP.Address()
			},
			signers: []*keypair.Full{serverKP},
			wantErr: ErrChallengeMalformed,
		},
		{
			name: "unknown operation not sourced at the server",
			mutate: func(p *txnbuild.TransactionParams) {
				p.Operations = append(p.Operations, &txnbuild.ManageData{
					SourceAccount: otherKP.Address(),
					Name:          "something_else",
					Value:         []byte("x"),
				})
			},
			signers: []*keypair.Full{serverKP},
			wantErr: ErrChallengeMalformed,
		},
		{
			name: "client_domain sourced at a muxed account",
			mutate: func(p *txnbuild.TransactionParams) {
				op := clientDomainOp()
				// A muxed address is not a valid signing key.
				op.SourceAccount = "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK"
				p.Operations = append(p.Operations, op)
			},
			signers: []*keypair.Full{serverKP},
			wantErr: ErrChallengeMalformed,
		},
		{
			name: "memo with a non-ID type",
			mutate: func(p *txnbuild.TransactionParams) {
				p.Memo = txnbuild.MemoText("hello")
			},
			signers: []*keypair.Full{serverKP},
			wantErr: ErrChallengeMalformed,
		},
		{
			name: "two client_domain operations",
			mutate: func(p *txnbuild.TransactionParams) {
				// The second names a different domain and a different key.
				// Without the duplicate check it silently wins, and the
				// challenge reports a domain the first never mentioned.
				p.Operations = append(p.Operations, clientDomainOp())
				second := clientDomainOp()
				second.SourceAccount = otherKP.Address()
				second.Value = []byte("evil.example.net")
				p.Operations = append(p.Operations, second)
			},
			signers: []*keypair.Full{serverKP},
			wantErr: ErrChallengeMalformed,
		},
		{
			name: "two web_auth_domain operations",
			mutate: func(p *txnbuild.TransactionParams) {
				p.Operations = append(p.Operations, &txnbuild.ManageData{
					SourceAccount: serverKP.Address(),
					Name:          "web_auth_domain",
					Value:         []byte(testWebAuthDomain),
				})
			},
			signers: []*keypair.Full{serverKP},
			wantErr: ErrChallengeMalformed,
		},
		{
			name: "client_domain sourced at the server",
			mutate: func(p *txnbuild.TransactionParams) {
				op := clientDomainOp()
				op.SourceAccount = serverKP.Address()
				p.Operations = append(p.Operations, op)
			},
			signers: []*keypair.Full{serverKP},
			wantErr: ErrChallengeMalformed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := defaultParams()
			tt.mutate(&params)

			challenge := buildTx(t, params, tt.signers...)

			_, err := ReadChallenge(challenge, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestReadChallengeRejectsGarbageXDR(t *testing.T) {
	_, err := ReadChallenge("not base64 xdr", serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
	require.ErrorIs(t, err, ErrChallengeMalformed)
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./internal/auth/ -v`
Expected: FAIL — `undefined: ReadChallenge`

- [ ] **Step 4: Write the signature matcher**

`internal/auth/signatures.go`:

```go
package auth

import (
	"fmt"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/txnbuild"
)

// matchSigners pairs each signature on tx with at most one of signers, and
// returns the signers that were matched, in the order they were supplied.
//
// It mirrors txnbuild.verifyTxSignatures, which the SDK does not export. Every
// signature is consumed at most once, so one signature cannot satisfy two
// signers. Signers with no matching signature are simply absent from the
// result; deciding whether that is an error is the caller's job.
func matchSigners(tx *txnbuild.Transaction, networkPassphrase string, signers []string) ([]string, error) {
	txHash, err := tx.Hash(networkPassphrase)
	if err != nil {
		return nil, fmt.Errorf("hashing challenge: %w", err)
	}

	signatures := tx.Signatures()
	used := make(map[int]bool, len(signatures))
	found := make([]string, 0, len(signers))
	seen := make(map[string]bool, len(signers))

	for _, signer := range signers {
		kp, parseErr := keypair.ParseAddress(signer)
		if parseErr != nil {
			return nil, fmt.Errorf("%w: signer %q is not an address", ErrSignatureUnrecognized, signer)
		}

		for i, sig := range signatures {
			if used[i] {
				continue
			}
			// The hint is a cheap pre-filter; it is not a security check.
			if sig.Hint != kp.Hint() {
				continue
			}
			if kp.Verify(txHash[:], sig.Signature) == nil {
				used[i] = true
				if !seen[signer] {
					seen[signer] = true
					found = append(found, signer)
				}
				break
			}
		}
	}

	return found, nil
}
```

- [ ] **Step 5: Write the reader**

`internal/auth/read.go`:

```go
package auth

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/txnbuild"
)

const (
	// clockGracePeriod allows for drift between the client's clock and ours.
	// It matches the SDK's reader.
	clockGracePeriod = 5 * time.Minute
	// A SEP-10 nonce is 48 random bytes, which is 64 base64 characters.
	nonceEncodedLen = 64
	nonceRawLen     = 48

	opWebAuthDomain = "web_auth_domain"
	opClientDomain  = "client_domain"
)

// Challenge is a SEP-10 challenge transaction that has been read and
// structurally validated. Its signatures beyond the server's are not yet
// checked; see VerifyClient.
type Challenge struct {
	// Tx is the parsed transaction, needed to verify signatures and to compute
	// the JWT's jti.
	Tx *txnbuild.Transaction
	// ClientAccountID is the account being authenticated, G... or M...
	ClientAccountID string
	// HomeDomain is the configured domain the challenge matched.
	HomeDomain string
	// Memo is the ID memo, when one was used. Never set for a muxed account.
	Memo *txnbuild.MemoID
	// Nonce is the base64 nonce from the first operation. It is the replay key.
	Nonce string
	// ClientDomain is the wallet's domain, empty when the challenge carries no
	// client_domain operation.
	ClientDomain string
	// ClientDomainKey is the signing key that operation was sourced at, empty
	// when there is no client_domain operation.
	ClientDomainKey string
}

// ReadChallenge parses a SEP-10 challenge and validates its structure against
// this server's identity and configured home domains. It confirms the server
// signed the challenge; it does not check the client's signatures.
//
// It exists because txnbuild.ReadChallengeTx rejects the client_domain
// operation that SEP-10 defines. See docs/sdk-findings.md. Behaviour is
// otherwise identical to the SDK's reader, which differential_test.go asserts.
func ReadChallenge(challengeXDR, serverAccountID, networkPassphrase, webAuthDomain string, homeDomains []string) (*Challenge, error) {
	generic, err := txnbuild.TransactionFromXDR(challengeXDR)
	if err != nil {
		return nil, fmt.Errorf("%w: could not parse challenge XDR", ErrChallengeMalformed)
	}

	tx, ok := generic.Transaction()
	if !ok {
		return nil, fmt.Errorf("%w: challenge must not be a fee bump transaction", ErrChallengeMalformed)
	}

	source := tx.SourceAccount()
	if !strkey.IsValidEd25519PublicKey(source.AccountID) {
		return nil, fmt.Errorf("%w: transaction source must be a G... account", ErrChallengeMalformed)
	}
	if source.AccountID != serverAccountID {
		return nil, fmt.Errorf("%w: transaction source is not this server", ErrChallengeMalformed)
	}
	if source.Sequence != 0 {
		return nil, fmt.Errorf("%w: transaction sequence number must be 0", ErrChallengeMalformed)
	}

	bounds := tx.Timebounds()
	if bounds.MaxTime == txnbuild.TimeoutInfinite {
		return nil, fmt.Errorf("%w: challenge requires finite timebounds", ErrChallengeMalformed)
	}
	now := time.Now().UTC().Unix()
	grace := int64(clockGracePeriod / time.Second)
	if now+grace < bounds.MinTime || now > bounds.MaxTime {
		return nil, fmt.Errorf("%w: challenge is outside its timebounds", ErrChallengeExpired)
	}

	ops := tx.Operations()
	if len(ops) < 1 {
		return nil, fmt.Errorf("%w: challenge requires at least one manage_data operation", ErrChallengeMalformed)
	}

	first, ok := ops[0].(*txnbuild.ManageData)
	if !ok {
		return nil, fmt.Errorf("%w: first operation must be manage_data", ErrChallengeMalformed)
	}
	if first.SourceAccount == "" {
		return nil, fmt.Errorf("%w: first operation must have a source account", ErrChallengeMalformed)
	}

	challenge := &Challenge{Tx: tx}

	for _, homeDomain := range homeDomains {
		if first.Name == homeDomain+" auth" {
			challenge.HomeDomain = homeDomain
			break
		}
	}
	if challenge.HomeDomain == "" {
		return nil, fmt.Errorf("%w: operation key %q matches no configured home domain",
			ErrUnknownHomeDomain, first.Name)
	}

	isMuxed := strkey.IsValidMuxedAccountEd25519PublicKey(first.SourceAccount)
	if !isMuxed && !strkey.IsValidEd25519PublicKey(first.SourceAccount) {
		return nil, fmt.Errorf("%w: first operation source must be a G... or M... account", ErrChallengeMalformed)
	}
	challenge.ClientAccountID = first.SourceAccount

	if memo := tx.Memo(); memo != nil {
		if isMuxed {
			return nil, fmt.Errorf("%w: challenge carries both a memo and a muxed account", ErrMemoWithMuxed)
		}
		id, isID := memo.(txnbuild.MemoID)
		if !isID {
			return nil, fmt.Errorf("%w: only ID memos are permitted", ErrChallengeMalformed)
		}
		challenge.Memo = &id
	}

	challenge.Nonce = string(first.Value)
	if len(challenge.Nonce) != nonceEncodedLen {
		return nil, fmt.Errorf("%w: nonce must be %d base64 characters", ErrChallengeMalformed, nonceEncodedLen)
	}
	raw, err := base64.StdEncoding.DecodeString(challenge.Nonce)
	if err != nil {
		return nil, fmt.Errorf("%w: nonce is not valid base64", ErrChallengeMalformed)
	}
	if len(raw) != nonceRawLen {
		return nil, fmt.Errorf("%w: nonce must decode to %d bytes", ErrChallengeMalformed, nonceRawLen)
	}

	var sawWebAuthDomain, sawClientDomain bool
	for _, op := range ops[1:] {
		data, isManageData := op.(*txnbuild.ManageData)
		if !isManageData {
			return nil, fmt.Errorf("%w: every operation must be manage_data", ErrChallengeMalformed)
		}
		if data.SourceAccount == "" {
			return nil, fmt.Errorf("%w: operation %q must have a source account", ErrChallengeMalformed, data.Name)
		}

		switch data.Name {
		case opWebAuthDomain:
			if sawWebAuthDomain {
				return nil, fmt.Errorf("%w: challenge carries more than one web_auth_domain operation", ErrChallengeMalformed)
			}
			sawWebAuthDomain = true
			if data.SourceAccount != serverAccountID {
				return nil, fmt.Errorf("%w: web_auth_domain operation must be sourced at the server", ErrChallengeMalformed)
			}
			if string(data.Value) != webAuthDomain {
				return nil, fmt.Errorf("%w: web_auth_domain operation names a different server", ErrChallengeMalformed)
			}

		case opClientDomain:
			if sawClientDomain {
				return nil, fmt.Errorf("%w: challenge carries more than one client_domain operation", ErrChallengeMalformed)
			}
			sawClientDomain = true
			// The rule the SDK lacks. SEP-10 requires this operation to be
			// sourced at the client domain's SIGNING_KEY, not at the server,
			// because the client domain is what signs it.
			if !strkey.IsValidEd25519PublicKey(data.SourceAccount) {
				return nil, fmt.Errorf("%w: client_domain operation must be sourced at a G... signing key", ErrChallengeMalformed)
			}
			if data.SourceAccount == serverAccountID {
				return nil, fmt.Errorf("%w: client_domain operation must not be sourced at the server", ErrChallengeMalformed)
			}
			if len(data.Value) == 0 {
				return nil, fmt.Errorf("%w: client_domain operation must name a domain", ErrChallengeMalformed)
			}
			challenge.ClientDomain = string(data.Value)
			challenge.ClientDomainKey = data.SourceAccount

		default:
			if data.SourceAccount != serverAccountID {
				return nil, fmt.Errorf("%w: unrecognised operation %q", ErrChallengeMalformed, data.Name)
			}
		}
	}

	serverFound, err := matchSigners(tx, networkPassphrase, []string{serverAccountID})
	if err != nil {
		return nil, err
	}
	if len(serverFound) == 0 {
		return nil, fmt.Errorf("%w: challenge is not signed by this server", ErrChallengeMalformed)
	}

	return challenge, nil
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/auth/ -v`
Expected: PASS, every subtest.

The M-address in `client_domain sourced at a muxed account` is a real one, not a typed-out
guess: `strkey.IsValidMuxedAccountEd25519PublicKey` returns true for it against v0.7.1. Use it
as written. If it ever stops validating, derive one instead of editing characters —
`xdr.MuxedAccountFromAccountId(otherKP.Address(), 1)` then `muxed.Address()`.

- [ ] **Step 7: Commit**

```bash
make check
git add internal/auth/signatures.go internal/auth/read.go \
        internal/auth/helpers_test.go internal/auth/read_test.go
git commit -m "feat(auth): add SEP-10 challenge reader with client_domain support"
git push
```

---

## Task 9: Differential test against the SDK reader

This is the answer to "why did you duplicate SDK validation logic?". It gets its own commit
because it is its own deliverable.

**Files:**
- Create: `internal/auth/differential_test.go`

**Interfaces:**
- Consumes: `ReadChallenge` and the helpers from Task 8
- Produces: nothing consumed by later tasks

- [ ] **Step 1: Write the test**

`internal/auth/differential_test.go`:

```go
package auth

import (
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stretchr/testify/require"
)

// TestReaderMatchesSDK pins our reader to txnbuild.ReadChallengeTx on every
// challenge shape both handle, which is all of them except client_domain.
//
// Our reader exists only because the SDK rejects the client_domain operation.
// Everywhere else it must agree with upstream exactly. If a future SDK release
// changes a rule, this test fails and someone decides deliberately whether to
// follow, rather than the two readers drifting apart unnoticed.
func TestReaderMatchesSDK(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(p *txnbuild.TransactionParams)
		signers []*keypair.Full
	}{
		{"valid", func(p *txnbuild.TransactionParams) {}, []*keypair.Full{serverKP}},
		{
			"valid with memo",
			func(p *txnbuild.TransactionParams) { p.Memo = txnbuild.MemoID(42) },
			[]*keypair.Full{serverKP},
		},
		{
			"valid with a client signature too",
			func(p *txnbuild.TransactionParams) {},
			[]*keypair.Full{serverKP, clientKP},
		},
		{"unsigned", func(p *txnbuild.TransactionParams) {}, nil},
		{"signed by the wrong key", func(p *txnbuild.TransactionParams) {}, []*keypair.Full{otherKP}},
		{
			"wrong transaction source",
			func(p *txnbuild.TransactionParams) {
				p.SourceAccount = &txnbuild.SimpleAccount{AccountID: otherKP.Address(), Sequence: 0}
			},
			[]*keypair.Full{otherKP},
		},
		{
			"non-zero sequence",
			func(p *txnbuild.TransactionParams) {
				p.SourceAccount = &txnbuild.SimpleAccount{AccountID: serverKP.Address(), Sequence: 3}
			},
			[]*keypair.Full{serverKP},
		},
		{
			"expired",
			func(p *txnbuild.TransactionParams) {
				past := time.Now().UTC().Add(-2 * time.Hour)
				p.Preconditions.TimeBounds = txnbuild.NewTimebounds(past.Unix(), past.Add(time.Minute).Unix())
			},
			[]*keypair.Full{serverKP},
		},
		{
			"not yet valid",
			func(p *txnbuild.TransactionParams) {
				future := time.Now().UTC().Add(2 * time.Hour)
				p.Preconditions.TimeBounds = txnbuild.NewTimebounds(future.Unix(), future.Add(time.Minute).Unix())
			},
			[]*keypair.Full{serverKP},
		},
		{
			"infinite timebounds",
			func(p *txnbuild.TransactionParams) {
				p.Preconditions.TimeBounds = txnbuild.NewInfiniteTimeout()
			},
			[]*keypair.Full{serverKP},
		},
		{
			"unmatched home domain",
			func(p *txnbuild.TransactionParams) {
				p.Operations[0].(*txnbuild.ManageData).Name = "attacker.example.net auth"
			},
			[]*keypair.Full{serverKP},
		},
		{
			"second configured home domain",
			func(p *txnbuild.TransactionParams) {
				p.Operations[0].(*txnbuild.ManageData).Name = "second.example.com auth"
			},
			[]*keypair.Full{serverKP},
		},
		{
			"nonce too short",
			func(p *txnbuild.TransactionParams) {
				p.Operations[0].(*txnbuild.ManageData).Value = []byte("short")
			},
			[]*keypair.Full{serverKP},
		},
		{
			"nonce not base64",
			func(p *txnbuild.TransactionParams) {
				bad := make([]byte, 64)
				for i := range bad {
					bad[i] = '!'
				}
				p.Operations[0].(*txnbuild.ManageData).Value = bad
			},
			[]*keypair.Full{serverKP},
		},
		{
			"web_auth_domain mismatch",
			func(p *txnbuild.TransactionParams) {
				p.Operations[1].(*txnbuild.ManageData).Value = []byte("attacker.example.net")
			},
			[]*keypair.Full{serverKP},
		},
		{
			"web_auth_domain sourced at the client",
			func(p *txnbuild.TransactionParams) {
				p.Operations[1].(*txnbuild.ManageData).SourceAccount = clientKP.Address()
			},
			[]*keypair.Full{serverKP},
		},
		{
			"unknown op sourced at the server",
			func(p *txnbuild.TransactionParams) {
				p.Operations = append(p.Operations, &txnbuild.ManageData{
					SourceAccount: serverKP.Address(),
					Name:          "extra",
					Value:         []byte("x"),
				})
			},
			[]*keypair.Full{serverKP},
		},
		{
			"unknown op sourced elsewhere",
			func(p *txnbuild.TransactionParams) {
				p.Operations = append(p.Operations, &txnbuild.ManageData{
					SourceAccount: otherKP.Address(),
					Name:          "extra",
					Value:         []byte("x"),
				})
			},
			[]*keypair.Full{serverKP},
		},
		{
			"memo with a text type",
			func(p *txnbuild.TransactionParams) { p.Memo = txnbuild.MemoText("hi") },
			[]*keypair.Full{serverKP},
		},
		{
			"web_auth_domain operation omitted",
			func(p *txnbuild.TransactionParams) {
				p.Operations = p.Operations[:1]
			},
			[]*keypair.Full{serverKP},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := defaultParams()
			tt.mutate(&params)
			challenge := buildTx(t, params, tt.signers...)

			ours, ourErr := ReadChallenge(
				challenge, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())

			_, sdkAccount, sdkHomeDomain, sdkMemo, sdkErr := txnbuild.ReadChallengeTx(
				challenge, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())

			if sdkErr != nil {
				require.Errorf(t, ourErr,
					"SDK rejected this challenge (%v) but our reader accepted it", sdkErr)
				return
			}

			require.NoErrorf(t, ourErr,
				"SDK accepted this challenge but our reader rejected it")
			require.Equal(t, sdkAccount, ours.ClientAccountID)
			require.Equal(t, sdkHomeDomain, ours.HomeDomain)

			if sdkMemo == nil {
				require.Nil(t, ours.Memo)
			} else {
				require.NotNil(t, ours.Memo)
				require.Equal(t, *sdkMemo, *ours.Memo)
			}
		})
	}
}

// The one shape where disagreement is the point.
func TestReaderDivergesOnlyOnClientDomain(t *testing.T) {
	params := defaultParams()
	params.Operations = append(params.Operations, clientDomainOp())
	challenge := buildTx(t, params, serverKP)

	_, ourErr := ReadChallenge(challenge, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
	require.NoError(t, ourErr, "our reader must accept a spec-compliant client_domain challenge")

	_, _, _, _, sdkErr := txnbuild.ReadChallengeTx(
		challenge, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
	require.Error(t, sdkErr, "if the SDK now accepts client_domain, our reader may no longer be needed")
}
```

- [ ] **Step 2: Run the test**

Run: `go test ./internal/auth/ -run TestReader -v`
Expected: PASS.

A failure here means our reader and the SDK's disagree on a shape they should both handle. Fix
our reader to match the SDK unless the disagreement is deliberate. Do not weaken the test to
make it pass.

Two divergences are deliberate, and the corpus above avoids both on purpose. The first is
`client_domain`, which the SDK cannot read at all. The second is duplicate operations: a
challenge carrying two `client_domain` or two `web_auth_domain` operations is rejected here and
accepted by the SDK, which has no duplicate tracking and validates each occurrence
independently. Do not add a duplicate-operation case to this table — it will fail, and the
failure means nothing. Both divergences are recorded in `docs/sdk-findings.md`.

- [ ] **Step 3: Commit**

```bash
make check
git add internal/auth/differential_test.go
git commit -m "test(auth): add differential test against SDK reader"
git push
```

---

## Task 10: Signature and threshold verification

Read the spec's section 6.3 before starting. `accountSignerWeight` is the most dangerous
arithmetic in the project.

**Files:**
- Create: `internal/auth/verify.go`, `internal/auth/verify_test.go`

**Interfaces:**
- Consumes: `Challenge`, `matchSigners`, and the sentinels from Tasks 7 and 8
- Produces:
  - `type Account struct { Signers map[string]int32; MedThreshold int32 }`
  - `type AccountFetcher interface { Account(ctx context.Context, accountID string) (*Account, error) }`
  - `func VerifyClient(ctx context.Context, challenge *Challenge, networkPassphrase string, accounts AccountFetcher) ([]string, error)`

- [ ] **Step 1: Write the failing tests**

`internal/auth/verify_test.go`:

```go
package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stretchr/testify/require"
)

type fakeAccounts struct {
	account *Account
	err     error
}

func (f fakeAccounts) Account(context.Context, string) (*Account, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.account, nil
}

// readSigned builds a challenge, signs it, and reads it back.
func readSigned(t *testing.T, params txnbuild.TransactionParams, signers ...*keypair.Full) *Challenge {
	t.Helper()

	challenge, err := ReadChallenge(
		buildTx(t, params, signers...),
		serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
	require.NoError(t, err)
	return challenge
}

func TestVerifyClientAccountDoesNotExist(t *testing.T) {
	challenge := readSigned(t, defaultParams(), serverKP, clientKP)

	found, err := VerifyClient(context.Background(), challenge, testNetwork,
		fakeAccounts{err: ErrAccountNotFound})

	require.NoError(t, err)
	require.Equal(t, []string{clientKP.Address()}, found)
}

func TestVerifyClientAccountDoesNotExistWrongSigner(t *testing.T) {
	// Signed by a key that is not the account's master key.
	challenge := readSigned(t, defaultParams(), serverKP, otherKP)

	_, err := VerifyClient(context.Background(), challenge, testNetwork,
		fakeAccounts{err: ErrAccountNotFound})

	require.ErrorIs(t, err, ErrSignatureUnrecognized)
}

func TestVerifyClientThresholdMet(t *testing.T) {
	challenge := readSigned(t, defaultParams(), serverKP, clientKP, extraKP)

	found, err := VerifyClient(context.Background(), challenge, testNetwork, fakeAccounts{
		account: &Account{
			Signers: map[string]int32{
				clientKP.Address(): 1,
				extraKP.Address():  1,
			},
			MedThreshold: 2,
		},
	})

	require.NoError(t, err)
	require.ElementsMatch(t, []string{clientKP.Address(), extraKP.Address()}, found)
}

func TestVerifyClientThresholdNotMet(t *testing.T) {
	challenge := readSigned(t, defaultParams(), serverKP, clientKP)

	_, err := VerifyClient(context.Background(), challenge, testNetwork, fakeAccounts{
		account: &Account{
			Signers: map[string]int32{
				clientKP.Address(): 1,
				extraKP.Address():  1,
			},
			MedThreshold: 2,
		},
	})

	require.ErrorIs(t, err, ErrThresholdNotMet)
}

func TestVerifyClientNoClientSignature(t *testing.T) {
	challenge := readSigned(t, defaultParams(), serverKP)

	_, err := VerifyClient(context.Background(), challenge, testNetwork, fakeAccounts{
		account: &Account{
			Signers:      map[string]int32{clientKP.Address(): 1},
			MedThreshold: 1,
		},
	})

	require.ErrorIs(t, err, ErrSignatureUnrecognized)
}

func TestVerifyClientUnrecognisedSignature(t *testing.T) {
	// otherKP is not a signer on the account, so its signature is unaccounted for.
	challenge := readSigned(t, defaultParams(), serverKP, clientKP, otherKP)

	_, err := VerifyClient(context.Background(), challenge, testNetwork, fakeAccounts{
		account: &Account{
			Signers:      map[string]int32{clientKP.Address(): 5},
			MedThreshold: 1,
		},
	})

	require.ErrorIs(t, err, ErrSignatureUnrecognized)
}

func TestVerifyClientLookupFailure(t *testing.T) {
	challenge := readSigned(t, defaultParams(), serverKP, clientKP)

	_, err := VerifyClient(context.Background(), challenge, testNetwork,
		fakeAccounts{err: errors.New("horizon timed out")})

	require.ErrorIs(t, err, ErrAccountLookupFailed)
	// An outage must never look like a bad signature.
	require.NotErrorIs(t, err, ErrSignatureUnrecognized)
}

func clientDomainParams() txnbuild.TransactionParams {
	params := defaultParams()
	params.Operations = append(params.Operations, clientDomainOp())
	return params
}

func TestVerifyClientDomainSigned(t *testing.T) {
	challenge := readSigned(t, clientDomainParams(), serverKP, clientKP, clientDomainKP)

	found, err := VerifyClient(context.Background(), challenge, testNetwork, fakeAccounts{
		account: &Account{
			Signers:      map[string]int32{clientKP.Address(): 1},
			MedThreshold: 1,
		},
	})

	require.NoError(t, err)
	require.Contains(t, found, clientDomainKP.Address())
}

func TestVerifyClientDomainNotSigned(t *testing.T) {
	// The challenge names a client domain, but the client domain did not sign.
	challenge := readSigned(t, clientDomainParams(), serverKP, clientKP)

	_, err := VerifyClient(context.Background(), challenge, testNetwork, fakeAccounts{
		account: &Account{
			Signers:      map[string]int32{clientKP.Address(): 1},
			MedThreshold: 1,
		},
	})

	require.ErrorIs(t, err, ErrClientDomainUnverified)
}

// TestClientDomainWeightDoesNotSatisfyThreshold is the guard on the most
// dangerous line in the project. If the exclusion in accountSignerWeight is
// removed, the sum below becomes 3, verification succeeds, and this test fails.
//
// The account contributes weight 1 against a threshold of 2. The client domain
// key carries weight 2 in the summary, but that weight is not the account's to
// spend: a client domain proves a wallet took part, never that the account
// authorised anything. Counting it would let any client domain authenticate
// for any account.
func TestClientDomainWeightDoesNotSatisfyThreshold(t *testing.T) {
	challenge := readSigned(t, clientDomainParams(), serverKP, clientKP, clientDomainKP)

	_, err := VerifyClient(context.Background(), challenge, testNetwork, fakeAccounts{
		account: &Account{
			Signers: map[string]int32{
				clientKP.Address():       1,
				clientDomainKP.Address(): 2,
			},
			MedThreshold: 2,
		},
	})

	require.ErrorIs(t, err, ErrThresholdNotMet)
}

// The control for the test above: the same shape, but the account itself
// carries enough weight. This must pass, so the test above is failing for the
// right reason rather than because client domain challenges never verify.
func TestAccountWeightAloneSatisfiesThreshold(t *testing.T) {
	challenge := readSigned(t, clientDomainParams(), serverKP, clientKP, clientDomainKP)

	found, err := VerifyClient(context.Background(), challenge, testNetwork, fakeAccounts{
		account: &Account{
			Signers: map[string]int32{
				clientKP.Address():       2,
				clientDomainKP.Address(): 2,
			},
			MedThreshold: 2,
		},
	})

	require.NoError(t, err)
	require.Contains(t, found, clientKP.Address())
}

func TestAccountSignerWeightExcludesClientDomain(t *testing.T) {
	summary := map[string]int32{
		clientKP.Address():       1,
		clientDomainKP.Address(): 7,
	}
	found := []string{clientKP.Address(), clientDomainKP.Address()}

	require.Equal(t, int32(1), accountSignerWeight(found, summary, clientDomainKP.Address()))
	// With no client domain in play, every matched signer counts.
	require.Equal(t, int32(8), accountSignerWeight(found, summary, ""))
}

// A challenge signed by the server and the client domain alone must not
// authenticate the account. The client domain proves the wallet took part; it
// never proves the account authorised anything. A Stellar account's thresholds
// default to 0, so a zero medium threshold is the ordinary case, not an
// exotic one, and a weight of 0 must not clear it.
func TestVerifyClientDomainAloneDoesNotAuthenticate(t *testing.T) {
	challenge := readSigned(t, clientDomainParams(), serverKP, clientDomainKP)

	_, err := VerifyClient(context.Background(), challenge, testNetwork, fakeAccounts{
		account: &Account{
			Signers:      map[string]int32{clientKP.Address(): 1},
			MedThreshold: 0,
		},
	})

	require.ErrorIs(t, err, ErrSignatureUnrecognized)
}

// The same shape on the account-does-not-exist path, which returns without ever
// reaching the threshold comparison.
func TestVerifyClientDomainAloneDoesNotAuthenticateMissingAccount(t *testing.T) {
	challenge := readSigned(t, clientDomainParams(), serverKP, clientDomainKP)

	_, err := VerifyClient(context.Background(), challenge, testNetwork,
		fakeAccounts{err: ErrAccountNotFound})

	require.ErrorIs(t, err, ErrSignatureUnrecognized)
}

// The control: a zero medium threshold with a real signature from the account
// still authenticates. Without this, the tests above could pass because client
// domain challenges never verify at all.
func TestVerifyClientZeroThresholdWithAccountSignature(t *testing.T) {
	challenge := readSigned(t, clientDomainParams(), serverKP, clientKP, clientDomainKP)

	found, err := VerifyClient(context.Background(), challenge, testNetwork, fakeAccounts{
		account: &Account{
			Signers:      map[string]int32{clientKP.Address(): 1},
			MedThreshold: 0,
		},
	})

	require.NoError(t, err)
	require.Contains(t, found, clientKP.Address())
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/auth/ -run TestVerify -v`
Expected: FAIL — `undefined: VerifyClient`

- [ ] **Step 3: Write the implementation**

`internal/auth/verify.go`:

```go
package auth

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// Account is the subset of a Stellar account this package needs.
type Account struct {
	// Signers maps each signer's address to its weight.
	Signers map[string]int32
	// MedThreshold is the weight a SEP-10 authentication must reach.
	MedThreshold int32
}

// AccountFetcher looks up an account on the network. It returns
// ErrAccountNotFound when the account does not exist, which is a normal SEP-10
// case and not a failure.
type AccountFetcher interface {
	Account(ctx context.Context, accountID string) (*Account, error)
}

// VerifyClient checks the client's signatures on a challenge and returns the
// signers that were matched, excluding the server.
//
// An account that does not exist on the network is authenticated by its master
// key alone. An account that does exist must reach its medium threshold.
func VerifyClient(ctx context.Context, challenge *Challenge, networkPassphrase string, accounts AccountFetcher) ([]string, error) {
	accountID, err := baseAccountID(challenge.ClientAccountID)
	if err != nil {
		return nil, err
	}

	account, err := accounts.Account(ctx, accountID)
	switch {
	case errors.Is(err, ErrAccountNotFound):
		// No account on the network means no signer list and no thresholds.
		// The master key is the only key that can speak for it.
		return verifySigners(challenge, networkPassphrase, []string{accountID})

	case err != nil:
		// A lookup failure is our problem, not the caller's. Reporting it as a
		// signature failure would tell a caller their key was wrong when the
		// network was merely unreachable.
		return nil, fmt.Errorf("%w: %s", ErrAccountLookupFailed, err)
	}

	candidates := make([]string, 0, len(account.Signers))
	for signer := range account.Signers {
		candidates = append(candidates, signer)
	}
	// Map iteration order is random; sort so behaviour is deterministic.
	sort.Strings(candidates)

	found, err := verifySigners(challenge, networkPassphrase, candidates)
	if err != nil {
		return nil, err
	}

	weight := accountSignerWeight(found, account.Signers, challenge.ClientDomainKey)
	if weight < account.MedThreshold {
		return nil, fmt.Errorf("%w: matched weight %d against threshold %d",
			ErrThresholdNotMet, weight, account.MedThreshold)
	}

	return found, nil
}

// accountSignerWeight sums the weights of matched signers that belong to the
// account. The client domain key is excluded: it proves the wallet took part,
// never that the account authorised anything, and counting it would let any
// client domain meet any account's threshold.
//
// The exclusion applies even when the client domain key is also a signer on the
// account. That is deliberate: in the rare case where they are the same key,
// failing closed is the safe direction.
func accountSignerWeight(found []string, signers map[string]int32, clientDomainKey string) int32 {
	var weight int32
	for _, signer := range found {
		if clientDomainKey != "" && signer == clientDomainKey {
			continue
		}
		weight += signers[signer]
	}
	return weight
}

// verifySigners matches the challenge's signatures against the server and the
// given candidate signers. It mirrors txnbuild.VerifyChallengeTxSigners.
func verifySigners(challenge *Challenge, networkPassphrase string, accountSigners []string) ([]string, error) {
	serverAccountID := challenge.Tx.SourceAccount().AccountID

	clientSigners := make([]string, 0, len(accountSigners)+1)
	seen := make(map[string]bool, len(accountSigners)+1)
	add := func(signer string) {
		// The server never counts as a client signer. If an account happens to
		// have the server as a signer, the server must not authenticate on the
		// client's behalf.
		if signer == "" || signer == serverAccountID || seen[signer] {
			return
		}
		// Non-account strkeys (hash signers, pre-auth transactions) cannot sign
		// a challenge, so they are ignored rather than rejected.
		if !strkey.IsValidEd25519PublicKey(signer) {
			return
		}
		seen[signer] = true
		clientSigners = append(clientSigners, signer)
	}

	for _, signer := range accountSigners {
		add(signer)
	}
	// The client domain key must be a candidate. Its signature is on the
	// transaction, and the "all signatures accounted for" check below would
	// otherwise reject the challenge as carrying an unrecognised signature.
	add(challenge.ClientDomainKey)

	if len(clientSigners) == 0 {
		return nil, fmt.Errorf("%w: no verifiable signers for this account", ErrSignatureUnrecognized)
	}

	// Verify the server and the clients in one pass, so a single signature can
	// never be counted for two signers.
	all := make([]string, 0, len(clientSigners)+1)
	all = append(all, serverAccountID)
	all = append(all, clientSigners...)

	matched, err := matchSigners(challenge.Tx, networkPassphrase, all)
	if err != nil {
		return nil, err
	}

	serverFound := false
	found := make([]string, 0, len(matched))
	for _, signer := range matched {
		if signer == serverAccountID {
			serverFound = true
			continue
		}
		found = append(found, signer)
	}

	if !serverFound {
		return nil, fmt.Errorf("%w: challenge is not signed by this server", ErrSignatureUnrecognized)
	}
	// The client domain key does not count toward this guard. It proves the
	// wallet took part, never that the account authorised anything, and it is
	// only a candidate here so the "all signatures accounted for" check below
	// does not reject the challenge outright. Without this exclusion, a
	// challenge signed by only the server and the client domain would pass,
	// even though no signer on the account ever signed it.
	signerFound := false
	for _, signer := range found {
		if signer != challenge.ClientDomainKey {
			signerFound = true
			break
		}
	}
	if !signerFound {
		return nil, fmt.Errorf("%w: challenge carries no signature from a signer on the account", ErrSignatureUnrecognized)
	}
	if len(matched) != len(challenge.Tx.Signatures()) {
		return nil, fmt.Errorf("%w: challenge carries unrecognised signatures", ErrSignatureUnrecognized)
	}

	if challenge.ClientDomainKey != "" {
		signed := false
		for _, signer := range found {
			if signer == challenge.ClientDomainKey {
				signed = true
				break
			}
		}
		if !signed {
			return nil, fmt.Errorf("%w: client domain %q did not sign the challenge",
				ErrClientDomainUnverified, challenge.ClientDomain)
		}
	}

	return found, nil
}

// baseAccountID reduces a muxed address to the underlying G... account, which
// is what Horizon knows about. A G... address is returned unchanged.
func baseAccountID(address string) (string, error) {
	if strkey.IsValidEd25519PublicKey(address) {
		return address, nil
	}

	muxed, err := xdr.AddressToMuxedAccount(address)
	if err != nil {
		return "", fmt.Errorf("%w: %q", ErrInvalidAccount, address)
	}
	return muxed.ToAccountId().Address(), nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/auth/ -v`
Expected: PASS, every test in the package.

- [ ] **Step 5: Prove the threshold guard actually guards**

This step is the point of the task. Temporarily delete the exclusion in
`accountSignerWeight`, so the loop body is just `weight += signers[signer]`:

Run: `go test ./internal/auth/ -run 'TestClientDomainWeightDoesNotSatisfyThreshold|TestAccountSignerWeightExcludesClientDomain' -v`
Expected: **FAIL**, both tests.

If either still passes, the test does not guard what it claims to and must be fixed before the
commit. Then restore the exclusion and confirm the suite is green again:

Run: `go test ./internal/auth/ -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
make check
git add internal/auth/verify.go internal/auth/verify_test.go
git commit -m "feat(auth): add signature and threshold verification"
git push
```

---

## Task 11: Challenge issuance

Read the spec's section 6.1 before starting.

**Files:**
- Create: `internal/auth/challenge.go`, `internal/auth/challenge_test.go`

**Interfaces:**
- Consumes: `ReadChallenge`, the sentinels, `opClientDomain`
- Produces:
  - `type ClientDomainResolver interface { Resolve(ctx context.Context, domain string) (string, error) }`
  - `type IssuerConfig struct` and `func NewIssuer(cfg IssuerConfig) (*Issuer, error)`
  - `type IssueRequest struct { Account string; Memo *uint64; HomeDomain, ClientDomain string }`
  - `type IssuedChallenge struct { TransactionXDR, NetworkPassphrase, Nonce, Account, HomeDomain, ClientDomain string; ExpiresAt time.Time }`
  - `func (i *Issuer) Issue(ctx context.Context, req IssueRequest) (*IssuedChallenge, error)`

- [ ] **Step 1: Write the failing tests**

`internal/auth/challenge_test.go`:

```go
package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"
	"github.com/stretchr/testify/require"
)

type fakeResolver struct {
	key    string
	err    error
	calls  int
	domain string
}

func (f *fakeResolver) Resolve(_ context.Context, domain string) (string, error) {
	f.calls++
	f.domain = domain
	if f.err != nil {
		return "", f.err
	}
	return f.key, nil
}

func testIssuer(t *testing.T, resolver ClientDomainResolver, required bool) *Issuer {
	t.Helper()

	issuer, err := NewIssuer(IssuerConfig{
		SigningSecret:        serverKP.Seed(),
		NetworkPassphrase:    testNetwork,
		WebAuthDomain:        testWebAuthDomain,
		HomeDomains:          homeDomains(),
		ChallengeTimeout:     5 * time.Minute,
		ClientDomainRequired: required,
		Resolver:             resolver,
	})
	require.NoError(t, err)
	return issuer
}

func TestIssueRoundTrips(t *testing.T) {
	issuer := testIssuer(t, &fakeResolver{}, false)

	issued, err := issuer.Issue(context.Background(), IssueRequest{Account: clientKP.Address()})
	require.NoError(t, err)
	require.Equal(t, testNetwork, issued.NetworkPassphrase)
	require.Equal(t, clientKP.Address(), issued.Account)
	require.Equal(t, testHomeDomain, issued.HomeDomain)
	require.True(t, issued.ExpiresAt.After(time.Now()))

	// The challenge we issue must be one we can read back.
	read, err := ReadChallenge(issued.TransactionXDR, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
	require.NoError(t, err)
	require.Equal(t, clientKP.Address(), read.ClientAccountID)
	require.Equal(t, issued.Nonce, read.Nonce)
	require.Empty(t, read.ClientDomain)
}

func TestIssueWithMemo(t *testing.T) {
	issuer := testIssuer(t, &fakeResolver{}, false)
	memo := uint64(9876)

	issued, err := issuer.Issue(context.Background(), IssueRequest{
		Account: clientKP.Address(),
		Memo:    &memo,
	})
	require.NoError(t, err)

	read, err := ReadChallenge(issued.TransactionXDR, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
	require.NoError(t, err)
	require.NotNil(t, read.Memo)
	require.Equal(t, txnbuild.MemoID(9876), *read.Memo)
}

func TestIssueWithMuxedAccount(t *testing.T) {
	muxed, err := xdr.MuxedAccountFromAccountId(clientKP.Address(), 17)
	require.NoError(t, err)

	issuer := testIssuer(t, &fakeResolver{}, false)

	issued, err := issuer.Issue(context.Background(), IssueRequest{Account: muxed.Address()})
	require.NoError(t, err)

	read, err := ReadChallenge(issued.TransactionXDR, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
	require.NoError(t, err)
	require.Equal(t, muxed.Address(), read.ClientAccountID)
}

func TestIssueRejectsMemoWithMuxedAccount(t *testing.T) {
	muxed, err := xdr.MuxedAccountFromAccountId(clientKP.Address(), 17)
	require.NoError(t, err)

	issuer := testIssuer(t, &fakeResolver{}, false)
	memo := uint64(1)

	_, err = issuer.Issue(context.Background(), IssueRequest{Account: muxed.Address(), Memo: &memo})
	require.ErrorIs(t, err, ErrMemoWithMuxed)
}

func TestIssueRejectsBadAccount(t *testing.T) {
	issuer := testIssuer(t, &fakeResolver{}, false)

	for _, account := range []string{"", "not-an-address", serverKP.Seed()} {
		_, err := issuer.Issue(context.Background(), IssueRequest{Account: account})
		require.ErrorIs(t, err, ErrInvalidAccount, "account %q", account)
	}
}

func TestIssueRejectsUnknownHomeDomain(t *testing.T) {
	issuer := testIssuer(t, &fakeResolver{}, false)

	_, err := issuer.Issue(context.Background(), IssueRequest{
		Account:    clientKP.Address(),
		HomeDomain: "attacker.example.net",
	})
	require.ErrorIs(t, err, ErrUnknownHomeDomain)
}

func TestIssueWithClientDomain(t *testing.T) {
	resolver := &fakeResolver{key: clientDomainKP.Address()}
	issuer := testIssuer(t, resolver, false)

	issued, err := issuer.Issue(context.Background(), IssueRequest{
		Account:      clientKP.Address(),
		ClientDomain: testClientDomain,
	})
	require.NoError(t, err)
	require.Equal(t, 1, resolver.calls)
	require.Equal(t, testClientDomain, resolver.domain)
	require.Equal(t, testClientDomain, issued.ClientDomain)

	read, err := ReadChallenge(issued.TransactionXDR, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
	require.NoError(t, err)
	require.Equal(t, testClientDomain, read.ClientDomain)
	require.Equal(t, clientDomainKP.Address(), read.ClientDomainKey)

	// Re-signing after appending the operation must leave exactly one valid
	// server signature, not a stale one alongside it.
	require.Len(t, read.Tx.Signatures(), 1)
}

func TestIssueClientDomainResolutionFailure(t *testing.T) {
	resolver := &fakeResolver{err: errors.New("no SIGNING_KEY")}

	// Not required: a resolution failure is still fatal to a request that asked
	// for a client domain, because the caller asked for a guarantee we cannot
	// give.
	issuer := testIssuer(t, resolver, false)

	_, err := issuer.Issue(context.Background(), IssueRequest{
		Account:      clientKP.Address(),
		ClientDomain: testClientDomain,
	})
	require.ErrorIs(t, err, ErrClientDomainRejected)
}

func TestIssueClientDomainResolvesToEmptyKey(t *testing.T) {
	// A resolver that returns ("", nil) reports success but gives nothing to
	// bind the challenge to. That must be rejected, not silently downgraded to
	// a challenge without a client_domain operation.
	resolver := &fakeResolver{key: ""}

	issuer := testIssuer(t, resolver, false)

	_, err := issuer.Issue(context.Background(), IssueRequest{
		Account:      clientKP.Address(),
		ClientDomain: testClientDomain,
	})
	require.ErrorIs(t, err, ErrClientDomainRejected)
}

func TestIssueClientDomainRequiredButAbsent(t *testing.T) {
	issuer := testIssuer(t, &fakeResolver{key: clientDomainKP.Address()}, true)

	_, err := issuer.Issue(context.Background(), IssueRequest{Account: clientKP.Address()})
	require.ErrorIs(t, err, ErrClientDomainRequired)
}

func TestIssueSelectsRequestedHomeDomain(t *testing.T) {
	issuer := testIssuer(t, &fakeResolver{}, false)

	issued, err := issuer.Issue(context.Background(), IssueRequest{
		Account:    clientKP.Address(),
		HomeDomain: "second.example.com",
	})
	require.NoError(t, err)
	require.Equal(t, "second.example.com", issued.HomeDomain)

	read, err := ReadChallenge(issued.TransactionXDR, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
	require.NoError(t, err)
	require.Equal(t, "second.example.com", read.HomeDomain)
}

func TestIssueNoncesDiffer(t *testing.T) {
	issuer := testIssuer(t, &fakeResolver{}, false)

	first, err := issuer.Issue(context.Background(), IssueRequest{Account: clientKP.Address()})
	require.NoError(t, err)
	second, err := issuer.Issue(context.Background(), IssueRequest{Account: clientKP.Address()})
	require.NoError(t, err)

	require.NotEqual(t, first.Nonce, second.Nonce)
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/auth/ -run TestIssue -v`
Expected: FAIL — `undefined: NewIssuer`

- [ ] **Step 3: Write the implementation**

`internal/auth/challenge.go`:

```go
package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/txnbuild"
)

// ClientDomainResolver returns the SIGNING_KEY published by a client domain.
type ClientDomainResolver interface {
	Resolve(ctx context.Context, domain string) (signingKey string, err error)
}

// IssuerConfig holds everything needed to issue challenges.
type IssuerConfig struct {
	// SigningSecret is the server's S... key. Never logged.
	SigningSecret        string
	NetworkPassphrase    string
	WebAuthDomain        string
	HomeDomains          []string
	ChallengeTimeout     time.Duration
	ClientDomainRequired bool
	Resolver             ClientDomainResolver
}

// Issuer builds SEP-10 challenges.
type Issuer struct {
	cfg      IssuerConfig
	signer   *keypair.Full
	homeSet  map[string]bool
	firstDom string
}

// NewIssuer validates the configuration and returns an Issuer.
func NewIssuer(cfg IssuerConfig) (*Issuer, error) {
	signer, err := keypair.ParseFull(cfg.SigningSecret)
	if err != nil {
		// Deliberately does not include the value.
		return nil, fmt.Errorf("signing secret is not a valid Stellar seed")
	}
	if len(cfg.HomeDomains) == 0 {
		return nil, fmt.Errorf("at least one home domain is required")
	}
	if cfg.ChallengeTimeout < time.Second {
		return nil, fmt.Errorf("challenge timeout must be at least 1s")
	}
	if cfg.Resolver == nil {
		return nil, fmt.Errorf("a client domain resolver is required")
	}

	homeSet := make(map[string]bool, len(cfg.HomeDomains))
	for _, domain := range cfg.HomeDomains {
		homeSet[domain] = true
	}

	return &Issuer{
		cfg:      cfg,
		signer:   signer,
		homeSet:  homeSet,
		firstDom: cfg.HomeDomains[0],
	}, nil
}

// IssueRequest is a parsed GET /auth request.
type IssueRequest struct {
	// Account is the client's G... or M... address.
	Account string
	// Memo is an optional ID memo. Never valid with an M... account.
	Memo *uint64
	// HomeDomain is optional; empty means the first configured domain.
	HomeDomain string
	// ClientDomain is the optional wallet domain.
	ClientDomain string
}

// IssuedChallenge is a challenge ready to return to the client and record in
// the store.
type IssuedChallenge struct {
	TransactionXDR    string
	NetworkPassphrase string
	Nonce             string
	Account           string
	HomeDomain        string
	ClientDomain      string
	ExpiresAt         time.Time
}

// ServerAccountID returns the server's public signing key.
func (i *Issuer) ServerAccountID() string {
	return i.signer.Address()
}

// Issue builds and signs a challenge for the request.
func (i *Issuer) Issue(ctx context.Context, req IssueRequest) (*IssuedChallenge, error) {
	isMuxed := strkey.IsValidMuxedAccountEd25519PublicKey(req.Account)
	if !isMuxed && !strkey.IsValidEd25519PublicKey(req.Account) {
		return nil, fmt.Errorf("%w: %q is not a G... or M... address", ErrInvalidAccount, req.Account)
	}

	// The SDK enforces this too. Failing early gives a clearer message.
	if req.Memo != nil && isMuxed {
		return nil, fmt.Errorf("%w: a muxed account already identifies the user", ErrMemoWithMuxed)
	}

	homeDomain := req.HomeDomain
	if homeDomain == "" {
		homeDomain = i.firstDom
	} else if !i.homeSet[homeDomain] {
		return nil, fmt.Errorf("%w: %q", ErrUnknownHomeDomain, homeDomain)
	}

	clientDomainKey := ""
	if req.ClientDomain != "" {
		key, err := i.cfg.Resolver.Resolve(ctx, req.ClientDomain)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %s", ErrClientDomainRejected, req.ClientDomain, err)
		}
		if key == "" {
			// A resolver that returns no error must return a key. If it returns
			// neither, that is a bug in the resolver, and the wrong way to absorb
			// it is to issue a challenge that silently drops the client_domain
			// operation: IssuedChallenge.ClientDomain would still say the domain
			// was bound when the signed transaction does not carry that binding.
			return nil, fmt.Errorf("%w: %s: resolver returned no signing key", ErrClientDomainRejected, req.ClientDomain)
		}
		clientDomainKey = key
	} else if i.cfg.ClientDomainRequired {
		return nil, fmt.Errorf("%w: this server requires a client_domain", ErrClientDomainRequired)
	}

	var memo *txnbuild.MemoID
	if req.Memo != nil {
		m := txnbuild.MemoID(*req.Memo)
		memo = &m
	}

	tx, err := txnbuild.BuildChallengeTx(
		i.cfg.SigningSecret,
		req.Account,
		i.cfg.WebAuthDomain,
		homeDomain,
		i.cfg.NetworkPassphrase,
		i.cfg.ChallengeTimeout,
		memo,
	)
	if err != nil {
		return nil, fmt.Errorf("building challenge: %w", err)
	}

	if clientDomainKey != "" {
		tx, err = i.appendClientDomain(tx, req.ClientDomain, clientDomainKey)
		if err != nil {
			return nil, err
		}
	}

	xdrString, err := tx.Base64()
	if err != nil {
		return nil, fmt.Errorf("encoding challenge: %w", err)
	}

	nonceOp, ok := tx.Operations()[0].(*txnbuild.ManageData)
	if !ok {
		return nil, fmt.Errorf("built challenge has no manage_data operation")
	}

	return &IssuedChallenge{
		TransactionXDR:    xdrString,
		NetworkPassphrase: i.cfg.NetworkPassphrase,
		Nonce:             string(nonceOp.Value),
		Account:           req.Account,
		HomeDomain:        homeDomain,
		ClientDomain:      req.ClientDomain,
		ExpiresAt:         time.Unix(tx.Timebounds().MaxTime, 0).UTC(),
	}, nil
}

// appendClientDomain adds the SEP-10 client_domain operation and re-signs.
//
// BuildChallengeTx signs before returning, and appending an operation
// invalidates that signature, so the transaction is rebuilt from its own parts
// and signed again. The discarded signature is the price of keeping nonce
// generation inside the SDK, where a subtle error would be both catastrophic
// and invisible. Do not "optimise" this by building the transaction directly.
func (i *Issuer) appendClientDomain(tx *txnbuild.Transaction, domain, signingKey string) (*txnbuild.Transaction, error) {
	if !strkey.IsValidEd25519PublicKey(signingKey) {
		return nil, fmt.Errorf("%w: %s published an invalid SIGNING_KEY", ErrClientDomainRejected, domain)
	}

	// The source account is the client domain's signing key, not the server's.
	// That is what makes the operation meaningful, and what the SDK's reader
	// rejects. See docs/sdk-findings.md.
	operations := append(tx.Operations(), &txnbuild.ManageData{
		SourceAccount: signingKey,
		Name:          opClientDomain,
		Value:         []byte(domain),
	})

	params := txnbuild.TransactionParams{
		SourceAccount: &txnbuild.SimpleAccount{
			AccountID: tx.SourceAccount().AccountID,
			Sequence:  0,
		},
		IncrementSequenceNum: false,
		Operations:           operations,
		BaseFee:              tx.BaseFee(),
		Preconditions: txnbuild.Preconditions{
			TimeBounds: tx.Timebounds(),
		},
	}
	// Assigned conditionally: a nil Memo in a struct literal is not a nil
	// interface. See https://go.dev/doc/faq#nil_error
	if memo := tx.Memo(); memo != nil {
		params.Memo = memo
	}

	rebuilt, err := txnbuild.NewTransaction(params)
	if err != nil {
		return nil, fmt.Errorf("rebuilding challenge with client domain: %w", err)
	}

	signed, err := rebuilt.Sign(i.cfg.NetworkPassphrase, i.signer)
	if err != nil {
		return nil, fmt.Errorf("re-signing challenge: %w", err)
	}
	return signed, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/auth/ -v`
Expected: PASS, every test in the package.

- [ ] **Step 5: Commit**

```bash
make check
git add internal/auth/challenge.go internal/auth/challenge_test.go
git commit -m "feat(auth): add challenge issuance"
git push
```

---

## Task 12: Horizon account fetcher

Read the "Two further deviations" section above before starting. This package exists because
`horizonclient` takes no `context.Context`.

**Files:**
- Create: `internal/account/fetcher.go`, `internal/account/fetcher_test.go`

**Interfaces:**
- Consumes: `auth.Account`, `auth.AccountFetcher`, `auth.ErrAccountNotFound`,
  `auth.ErrAccountLookupFailed` from Tasks 7 and 10
- Produces:
  - `func NewFetcher(horizonURL string, client *http.Client) (*Fetcher, error)`
  - `func (f *Fetcher) Account(ctx context.Context, accountID string) (*auth.Account, error)`

`*Fetcher` satisfies `auth.AccountFetcher`. A compile-time assertion in the test file proves it.

- [ ] **Step 1: Write the failing tests**

`internal/account/fetcher_test.go`:

```go
package account

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0dillon/Anchorage/internal/auth"
	"github.com/stretchr/testify/require"
)

// Fetcher must satisfy the interface internal/auth declares.
var _ auth.AccountFetcher = (*Fetcher)(nil)

const accountID = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"

// accountJSON is a trimmed Horizon account response. Only the fields the
// fetcher reads are present; Horizon sends many more and the decoder ignores
// them.
const accountJSON = `{
  "id": "` + accountID + `",
  "account_id": "` + accountID + `",
  "sequence": "12345",
  "thresholds": {"low_threshold": 0, "med_threshold": 2, "high_threshold": 3},
  "signers": [
    {"key": "` + accountID + `", "weight": 1, "type": "ed25519_public_key"},
    {"key": "GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H", "weight": 2, "type": "ed25519_public_key"}
  ]
}`

// newTestFetcher points a Fetcher at a test server and returns both.
func newTestFetcher(t *testing.T, h http.HandlerFunc) (*Fetcher, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	f, err := NewFetcher(srv.URL, srv.Client())
	require.NoError(t, err)
	return f, srv
}

func TestAccountReadsSignersAndThreshold(t *testing.T) {
	var gotPath string
	f, _ := newTestFetcher(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(accountJSON))
	})

	acct, err := f.Account(context.Background(), accountID)
	require.NoError(t, err)

	require.Equal(t, "/accounts/"+accountID, gotPath)
	require.Equal(t, int32(2), acct.MedThreshold)
	require.Equal(t, map[string]int32{
		accountID: 1,
		"GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H": 2,
	}, acct.Signers)
}

// A 404 is not a failure. SEP-10 authenticates a non-existent account by its
// master key alone, so the caller needs to tell this apart from an outage.
func TestAccountNotFound(t *testing.T) {
	f, _ := newTestFetcher(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"status": 404, "title": "Resource Missing"}`))
	})

	_, err := f.Account(context.Background(), accountID)
	require.ErrorIs(t, err, auth.ErrAccountNotFound)
}

// Every other Horizon failure is an outage. It must never be reported as a
// missing account, because that would authenticate on the master key alone.
func TestAccountLookupFailures(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "server error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
		},
		{
			name: "rate limited",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusTooManyRequests)
			},
		},
		{
			name: "body is not json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("<html>gateway</html>"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, _ := newTestFetcher(t, tt.handler)

			_, err := f.Account(context.Background(), accountID)
			require.ErrorIs(t, err, auth.ErrAccountLookupFailed)
			require.NotErrorIs(t, err, auth.ErrAccountNotFound)
		})
	}
}

// An oversized body is refused rather than truncated. A truncated JSON body
// would fail to decode anyway, but failing on the size is the honest error.
func TestAccountRejectsOversizedBody(t *testing.T) {
	f, _ := newTestFetcher(t, func(w http.ResponseWriter, r *http.Request) {
		big := make([]byte, maxAccountBytes+1)
		for i := range big {
			big[i] = ' '
		}
		_, _ = w.Write(big)
	})

	_, err := f.Account(context.Background(), accountID)
	require.ErrorIs(t, err, auth.ErrAccountLookupFailed)
	require.Contains(t, err.Error(), "too large")
}

// The context is honoured. This is the whole reason the package exists.
func TestAccountHonoursContextCancellation(t *testing.T) {
	f, _ := newTestFetcher(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(accountJSON))
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := f.Account(ctx, accountID)
	require.ErrorIs(t, err, auth.ErrAccountLookupFailed)
	require.ErrorIs(t, err, context.Canceled)
}

// A 200 whose body is valid JSON but not an account decodes without error into
// an account with no signers and a zero threshold. That must be a lookup
// failure, not a usable account, and never a missing account.
func TestAccountRejectsResponseWithNoSigners(t *testing.T) {
	f, _ := newTestFetcher(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})

	_, err := f.Account(context.Background(), accountID)
	require.ErrorIs(t, err, auth.ErrAccountLookupFailed)
	require.NotErrorIs(t, err, auth.ErrAccountNotFound)
}

func TestNewFetcherRejectsBadURL(t *testing.T) {
	_, err := NewFetcher("", http.DefaultClient)
	require.Error(t, err)

	_, err = NewFetcher("not-a-url", http.DefaultClient)
	require.Error(t, err)
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/account/ -v`
Expected: FAIL — `undefined: NewFetcher`

- [ ] **Step 3: Write the implementation**

`internal/account/fetcher.go`:

```go
// Package account reads account signers and thresholds from Horizon.
//
// It makes the one request SEP-10 needs rather than using the SDK's
// horizonclient, whose methods take no context.Context and so cannot be
// cancelled. The response is decoded into the SDK's own account type, so the
// field names and the signer summary come from the SDK, not from here.
package account

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/0dillon/Anchorage/internal/auth"
	hProtocol "github.com/stellar/go-stellar-sdk/protocols/horizon"
)

// maxAccountBytes caps the response body. An account holds at most 20 signers,
// so a real response is a few kilobytes; anything near this cap is not one.
const maxAccountBytes = 256 * 1024

// defaultTimeout bounds a lookup when the caller supplies no HTTP client. A
// caller that passes its own client owns that client's timeout, and the
// request's context bounds it either way.
const defaultTimeout = 10 * time.Second

// Fetcher reads accounts from one Horizon instance.
type Fetcher struct {
	baseURL string
	client  *http.Client
}

// NewFetcher returns a Fetcher for the given Horizon URL. Passing nil for the
// client uses a client with a default timeout.
func NewFetcher(horizonURL string, client *http.Client) (*Fetcher, error) {
	u, err := url.Parse(horizonURL)
	if err != nil {
		return nil, fmt.Errorf("horizon url is not a valid URL: %q", horizonURL)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("horizon url must be absolute: %q", horizonURL)
	}
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}
	return &Fetcher{baseURL: horizonURL, client: client}, nil
}

// Account returns the account's signers and medium threshold.
//
// A 404 returns auth.ErrAccountNotFound, which is a normal SEP-10 case. Every
// other failure returns auth.ErrAccountLookupFailed. The two must never be
// confused: reporting an outage as a missing account would authenticate the
// account on its master key alone.
func (f *Fetcher) Account(ctx context.Context, accountID string) (*auth.Account, error) {
	endpoint, err := url.JoinPath(f.baseURL, "accounts", accountID)
	if err != nil {
		return nil, fmt.Errorf("%w: building url: %w", auth.ErrAccountLookupFailed, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: building request: %w", auth.ErrAccountLookupFailed, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		// Unwrapping keeps context.Canceled and context.DeadlineExceeded
		// visible to errors.Is, so a cancelled request is not mistaken for a
		// Horizon fault in the logs.
		return nil, fmt.Errorf("%w: %w", auth.ErrAccountLookupFailed, unwrapURLError(err))
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: %s", auth.ErrAccountNotFound, accountID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: horizon returned %d", auth.ErrAccountLookupFailed, resp.StatusCode)
	}

	// One byte over the cap, so an oversized body is detected rather than
	// silently truncated into something that might still decode.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAccountBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: reading body: %w", auth.ErrAccountLookupFailed, err)
	}
	if len(body) > maxAccountBytes {
		return nil, fmt.Errorf("%w: response body is too large", auth.ErrAccountLookupFailed)
	}

	var decoded hProtocol.Account
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, fmt.Errorf("%w: decoding body: %w", auth.ErrAccountLookupFailed, err)
	}

	signers := decoded.SignerSummary()
	if len(signers) == 0 {
		return nil, fmt.Errorf("%w: horizon returned an account with no signers", auth.ErrAccountLookupFailed)
	}

	return &auth.Account{
		Signers:      signers,
		MedThreshold: int32(decoded.Thresholds.MedThreshold),
	}, nil
}

// unwrapURLError returns the cause inside a *url.Error so callers can test for
// context.Canceled with errors.Is.
func unwrapURLError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return urlErr.Err
	}
	return err
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/account/ -v`
Expected: PASS, including every subtest of `TestAccountLookupFailures`.

- [ ] **Step 5: Commit**

```bash
make check
git add internal/account/fetcher.go internal/account/fetcher_test.go
git commit -m "feat(account): add context-aware horizon account fetcher"
git push
```

---

## Task 13: Client domain resolver

Read the spec's section 7 before starting. Every response from a client domain is hostile input.

**Files:**
- Create: `internal/clientdomain/resolver.go`, `internal/clientdomain/resolver_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks
- Produces:
  - `func NewResolver(cfg ResolverConfig) *Resolver`
  - `type ResolverConfig struct { Allowlist []string; CacheTTL time.Duration; Client *http.Client }`
  - `func (r *Resolver) Resolve(ctx context.Context, domain string) (string, error)`

`*Resolver` satisfies `auth.ClientDomainResolver` from Task 11.

Tests drive an `httptest.Server`, so the resolver must be able to fetch over plain HTTP from a
test. It does that by allowing the caller to override the URL builder — not by relaxing the
HTTPS rule, which stays unconditional in the exported path.

- [ ] **Step 1: Write the failing tests**

`internal/clientdomain/resolver_test.go`:

```go
package clientdomain

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const signingKey = "GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H"

// newTestResolver points a resolver at a test server. The url builder is
// overridden because httptest serves plain HTTP; the HTTPS rule itself is
// tested separately, through the exported path.
func newTestResolver(t *testing.T, ttl time.Duration, h http.Handler) (*Resolver, *int) {
	t.Helper()

	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	r := NewResolver(ResolverConfig{CacheTTL: ttl, Client: srv.Client()})
	r.urlFor = func(domain string) string { return srv.URL + "/.well-known/stellar.toml" }
	return r, &calls
}

func tomlHandler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(body))
	})
}

func TestResolveReadsSigningKey(t *testing.T) {
	r, calls := newTestResolver(t, time.Minute, tomlHandler(
		"VERSION=\"2.0.0\"\nSIGNING_KEY=\""+signingKey+"\"\n"))

	got, err := r.Resolve(context.Background(), "wallet.example.org")
	require.NoError(t, err)
	require.Equal(t, signingKey, got)
	require.Equal(t, 1, *calls)
}

func TestResolveRejectsBadTOML(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"no signing key", "VERSION=\"2.0.0\"\n"},
		{"empty signing key", "SIGNING_KEY=\"\"\n"},
		{"signing key is not a strkey", "SIGNING_KEY=\"not-a-key\"\n"},
		{"signing key is a secret seed", "SIGNING_KEY=\"SBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7O5RT\"\n"},
		{"body is not toml", "<html>404 not found</html>\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newTestResolver(t, time.Minute, tomlHandler(tt.body))

			_, err := r.Resolve(context.Background(), "wallet.example.org")
			require.Error(t, err)
			// The domain is named; the body is never echoed back.
			require.Contains(t, err.Error(), "wallet.example.org")
			require.NotContains(t, err.Error(), tt.body)
		})
	}
}

func TestResolveRejectsNon200(t *testing.T) {
	r, _ := newTestResolver(t, time.Minute, http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))

	_, err := r.Resolve(context.Background(), "wallet.example.org")
	require.Error(t, err)
	require.Contains(t, err.Error(), "404")
}

func TestResolveRejectsOversizedBody(t *testing.T) {
	body := strings.Repeat("# padding\n", (maxTOMLBytes/10)+1)
	r, _ := newTestResolver(t, time.Minute, tomlHandler(body))

	_, err := r.Resolve(context.Background(), "wallet.example.org")
	require.Error(t, err)
	require.Contains(t, err.Error(), "too large")
}

// A success is cached, so a second call inside the TTL makes no request.
func TestResolveCachesSuccess(t *testing.T) {
	r, calls := newTestResolver(t, time.Minute, tomlHandler(
		"SIGNING_KEY=\""+signingKey+"\"\n"))

	for range 3 {
		got, err := r.Resolve(context.Background(), "wallet.example.org")
		require.NoError(t, err)
		require.Equal(t, signingKey, got)
	}
	require.Equal(t, 1, *calls)
}

// A stale entry is refetched. The TTL is one nanosecond, so the entry written
// by the first call is already expired by the second. No sleep, no clock seam.
func TestResolveRefetchesAfterTTL(t *testing.T) {
	r, calls := newTestResolver(t, time.Nanosecond, tomlHandler(
		"SIGNING_KEY=\""+signingKey+"\"\n"))

	_, err := r.Resolve(context.Background(), "wallet.example.org")
	require.NoError(t, err)
	_, err = r.Resolve(context.Background(), "wallet.example.org")
	require.NoError(t, err)

	require.Equal(t, 2, *calls)
}

// Failures are not cached, so a domain that recovers is picked up at once.
func TestResolveDoesNotCacheFailures(t *testing.T) {
	fail := true
	r, calls := newTestResolver(t, time.Minute, http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			if fail {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_, _ = w.Write([]byte("SIGNING_KEY=\"" + signingKey + "\"\n"))
		}))

	_, err := r.Resolve(context.Background(), "wallet.example.org")
	require.Error(t, err)

	fail = false
	got, err := r.Resolve(context.Background(), "wallet.example.org")
	require.NoError(t, err)
	require.Equal(t, signingKey, got)
	require.Equal(t, 2, *calls)
}

// An allowlisted resolver rejects an unlisted domain before any network call.
func TestResolveEnforcesAllowlist(t *testing.T) {
	r, calls := newTestResolver(t, time.Minute, tomlHandler(
		"SIGNING_KEY=\""+signingKey+"\"\n"))
	r.allowlist = map[string]bool{"allowed.example.org": true}

	_, err := r.Resolve(context.Background(), "wallet.example.org")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not on the allowlist")
	require.Equal(t, 0, *calls)

	_, err = r.Resolve(context.Background(), "allowed.example.org")
	require.NoError(t, err)
	require.Equal(t, 1, *calls)
}

// The cache is bounded. Distinct domains cost a caller nothing to generate, so
// an unbounded map would grow for as long as it kept asking.
func TestResolveCacheIsBounded(t *testing.T) {
	r, calls := newTestResolver(t, time.Minute, tomlHandler(
		"SIGNING_KEY=\""+signingKey+"\"\n"))

	for i := range maxCacheEntries + 10 {
		_, err := r.Resolve(context.Background(), fmt.Sprintf("d%d.example.org", i))
		require.NoError(t, err)
	}

	r.mu.Lock()
	size := len(r.cache)
	r.mu.Unlock()

	require.LessOrEqual(t, size, maxCacheEntries)
	// Every domain was distinct, so every one was fetched and none was served
	// from the cache.
	require.Equal(t, maxCacheEntries+10, *calls)
}

// An expired entry is dropped on the next write rather than kept for the life of
// the process.
func TestResolvePurgesExpiredEntries(t *testing.T) {
	r, _ := newTestResolver(t, time.Nanosecond, tomlHandler(
		"SIGNING_KEY=\""+signingKey+"\"\n"))

	_, err := r.Resolve(context.Background(), "first.example.org")
	require.NoError(t, err)
	_, err = r.Resolve(context.Background(), "second.example.org")
	require.NoError(t, err)

	r.mu.Lock()
	_, firstStillCached := r.cache["first.example.org"]
	r.mu.Unlock()

	require.False(t, firstStillCached, "an expired entry must be purged on the next write")
}

func TestResolveRejectsEmptyDomain(t *testing.T) {
	r, calls := newTestResolver(t, time.Minute, tomlHandler(""))

	_, err := r.Resolve(context.Background(), "")
	require.Error(t, err)
	require.Equal(t, 0, *calls)
}

// The default url builder is HTTPS and nothing can change it from outside the
// package. This is the test that pins the exported behaviour.
func TestDefaultURLIsHTTPS(t *testing.T) {
	r := NewResolver(ResolverConfig{CacheTTL: time.Minute})
	require.Equal(t,
		"https://wallet.example.org/.well-known/stellar.toml",
		r.urlFor("wallet.example.org"))
}

// A redirect to plain HTTP is refused, and so is a redirect chain longer than
// three hops.
func TestRedirectPolicy(t *testing.T) {
	tests := []struct {
		name string
		via  int
		url  string
		ok   bool
	}{
		{"first https hop", 0, "https://a.example.org/x", true},
		{"third https hop", 2, "https://a.example.org/x", true},
		{"fourth https hop", 3, "https://a.example.org/x", false},
		{"http hop", 0, "http://a.example.org/x", false},
		{"non-http scheme", 0, "file:///etc/passwd", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.url, nil)
			via := make([]*http.Request, tt.via)

			err := checkRedirect(req, via)
			if tt.ok {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
		})
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/clientdomain/ -v`
Expected: FAIL — `undefined: NewResolver`

- [ ] **Step 3: Write the implementation**

`internal/clientdomain/resolver.go`:

```go
// Package clientdomain resolves the SIGNING_KEY a wallet publishes in its
// SEP-1 stellar.toml.
//
// This is the part of the server most exposed to the outside world: it fetches
// a file from a domain the caller names. Every response is treated as hostile.
// The scheme is HTTPS and stays HTTPS across redirects, the redirect chain is
// bounded, the whole request is bounded by a timeout, and the body is read
// through a cap.
package clientdomain

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/stellar/go-stellar-sdk/strkey"
)

const (
	// maxTOMLBytes caps the stellar.toml body at 100 KB.
	maxTOMLBytes = 100 * 1024
	// maxRedirects is the longest redirect chain followed.
	maxRedirects = 3
	// fetchTimeout bounds the whole request, including redirects.
	fetchTimeout = 5 * time.Second
	// maxCacheEntries caps the cache. A domain is caller-supplied input and
	// wildcard DNS makes distinct domains free to generate, so an unbounded map
	// would grow for as long as a caller kept feeding it new names. A full cache
	// is not a correctness problem: an uncached domain is simply refetched.
	maxCacheEntries = 1024
)

// ResolverConfig configures a Resolver.
type ResolverConfig struct {
	// Allowlist, when non-empty, is the only set of domains that may be
	// resolved. A domain outside it is refused before any network call.
	Allowlist []string
	// CacheTTL is how long a resolved key is reused.
	CacheTTL time.Duration
	// Client is the HTTP client. Nil means a client built to this package's
	// timeout and redirect policy.
	Client *http.Client
}

// Resolver fetches and caches client domain signing keys.
type Resolver struct {
	allowlist map[string]bool
	ttl       time.Duration
	client    *http.Client

	// urlFor builds the stellar.toml URL. It is a field only so tests can
	// point it at an httptest server; nothing outside this package can set it,
	// and the default is always HTTPS.
	urlFor func(domain string) string

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	signingKey string
	expiresAt  time.Time
}

// NewResolver returns a Resolver. An empty allowlist means every domain is
// allowed.
func NewResolver(cfg ResolverConfig) *Resolver {
	allowlist := make(map[string]bool, len(cfg.Allowlist))
	for _, domain := range cfg.Allowlist {
		allowlist[domain] = true
	}

	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: fetchTimeout}
	}
	// The policy is applied whether or not the caller supplied the client, so a
	// caller cannot hand in a client that follows redirects to plain HTTP. The
	// client is copied before the policy is set: assigning CheckRedirect on the
	// caller's own client would change how that client behaves everywhere else
	// it is used, and a caller passing http.DefaultClient would change it for
	// the whole process. The copy shares the Transport, so the connection pool
	// is still shared.
	policed := *client
	policed.CheckRedirect = checkRedirect
	client = &policed

	return &Resolver{
		allowlist: allowlist,
		ttl:       cfg.CacheTTL,
		client:    client,
		urlFor:    defaultURL,
		cache:     make(map[string]cacheEntry),
	}
}

// defaultURL builds the SEP-1 well-known URL over HTTPS.
func defaultURL(domain string) string {
	return "https://" + domain + "/.well-known/stellar.toml"
}

// checkRedirect refuses a redirect chain longer than maxRedirects and any hop
// that is not HTTPS. A wallet that downgrades to plain HTTP is not trusted to
// state its own signing key.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("refusing redirect to non-https scheme %q", req.URL.Scheme)
	}
	return nil
}

// Resolve returns the SIGNING_KEY published by the domain. A cached entry
// inside the TTL is returned without a fetch. Failures are never cached, so a
// domain that recovers is picked up on the next request.
func (r *Resolver) Resolve(ctx context.Context, domain string) (string, error) {
	if domain == "" {
		return "", fmt.Errorf("client domain is empty")
	}
	if len(r.allowlist) > 0 && !r.allowlist[domain] {
		return "", fmt.Errorf("%s is not on the allowlist", domain)
	}

	if key, ok := r.cached(domain); ok {
		return key, nil
	}

	key, err := r.fetch(ctx, domain)
	if err != nil {
		return "", err
	}

	r.store(domain, key)

	return key, nil
}

// store caches a resolved key. Expired entries are dropped first, so the map
// does not keep every domain ever asked about. If the cache is still full the
// new entry is not stored: that costs a refetch next time and never evicts a
// live entry to make room.
func (r *Resolver) store(domain, key string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for cached, entry := range r.cache {
		if !now.Before(entry.expiresAt) {
			delete(r.cache, cached)
		}
	}
	if len(r.cache) >= maxCacheEntries {
		return
	}
	r.cache[domain] = cacheEntry{signingKey: key, expiresAt: now.Add(r.ttl)}
}

// cached returns a live cache entry, if there is one.
func (r *Resolver) cached(domain string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.cache[domain]
	if !ok || !time.Now().Before(entry.expiresAt) {
		return "", false
	}
	return entry.signingKey, true
}

// fetch performs one bounded request and parses the result.
func (r *Resolver) fetch(ctx context.Context, domain string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	endpoint := r.urlFor(domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("%s: building request: %w", domain, err)
	}
	req.Header.Set("Accept", "text/plain")

	resp, err := r.client.Do(req)
	if err != nil {
		// A *url.Error carries the full URL, which is the caller's own input;
		// it is safe to report, but the message stays short.
		return "", fmt.Errorf("%s: fetching stellar.toml failed", domain)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: stellar.toml returned %d", domain, resp.StatusCode)
	}

	// One byte over the cap, so an oversized file is rejected rather than
	// truncated. Truncation could change how the file parses.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTOMLBytes+1))
	if err != nil {
		return "", fmt.Errorf("%s: reading stellar.toml failed", domain)
	}
	if len(body) > maxTOMLBytes {
		return "", fmt.Errorf("%s: stellar.toml is too large", domain)
	}

	var doc struct {
		SigningKey string `toml:"SIGNING_KEY"`
	}
	if _, err := toml.Decode(string(body), &doc); err != nil {
		// The parse error quotes the offending line, so it is not included.
		return "", fmt.Errorf("%s: stellar.toml is not valid TOML", domain)
	}
	if doc.SigningKey == "" {
		return "", fmt.Errorf("%s: stellar.toml has no SIGNING_KEY", domain)
	}
	if !strkey.IsValidEd25519PublicKey(doc.SigningKey) {
		return "", fmt.Errorf("%s: SIGNING_KEY is not a valid G... address", domain)
	}

	return doc.SigningKey, nil
}
```

The `Resolve` errors name the domain, which is the caller's own input, and never quote the body
or the TOML parse error. A parse error from `BurntSushi/toml` quotes the offending line, which
would echo a hostile file back to the caller.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/clientdomain/ -v`
Expected: PASS, including every subtest of `TestResolveRejectsBadTOML` and
`TestRedirectPolicy`.

- [ ] **Step 5: Commit**

```bash
make check
git add internal/clientdomain/resolver.go internal/clientdomain/resolver_test.go
git commit -m "feat(clientdomain): add TOML resolver with timeout, size cap, and cache"
git push
```

---

## Task 14: JWT issuance and parsing

Read the spec's section 8 before starting.

**Files:**
- Create: `internal/token/jwt.go`, `internal/token/jwt_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks
- Produces:
  - `type Claims struct` embedding `jwt.RegisteredClaims` plus `ClientDomain string`
  - `type IssuerConfig struct { Secret []byte; Issuer string; Lifetime time.Duration }`
  - `func NewIssuer(cfg IssuerConfig) (*Issuer, error)`
  - `type Request struct { Account string; Memo *uint64; ClientDomain, JTI string; IssuedAt time.Time }`
  - `func (i *Issuer) Issue(req Request) (string, error)`
  - `func (i *Issuer) Parse(raw string, now time.Time) (*Claims, error)`
  - `func Subject(account string, memo *uint64) string`
  - `var ErrTokenInvalid`, `var ErrTokenExpired`

`Issue` and `Parse` take explicit timestamps rather than reading the clock, so an expired token
is constructed directly in a test and no production code carries a clock seam.

- [ ] **Step 1: Write the failing tests**

`internal/token/jwt_test.go`:

```go
package token

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"
	"github.com/stretchr/testify/require"
)

var (
	testSecret = []byte("0123456789abcdef0123456789abcdef")
	testNow    = time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)

	// Derived, not pasted. A muxed strkey carries a checksum over the base
	// account and the id, and a hand-written one does not parse.
	testAccount = mustAddress(5)
	testMuxed   = mustMuxed(testAccount, 17)
)

func mustAddress(fill byte) string {
	var raw [32]byte
	for i := range raw {
		raw[i] = fill
	}
	kp, err := keypair.FromRawSeed(raw)
	if err != nil {
		panic(err)
	}
	return kp.Address()
}

func mustMuxed(address string, id uint64) string {
	muxed, err := xdr.MuxedAccountFromAccountId(address, id)
	if err != nil {
		panic(err)
	}
	return muxed.Address()
}

func newTestIssuer(t *testing.T) *Issuer {
	t.Helper()
	i, err := NewIssuer(IssuerConfig{
		Secret:   testSecret,
		Issuer:   "https://auth.example.com",
		Lifetime: time.Hour,
	})
	require.NoError(t, err)
	return i
}

func TestSubject(t *testing.T) {
	memo := uint64(1234)

	tests := []struct {
		name    string
		account string
		memo    *uint64
		want    string
	}{
		{"plain account", testAccount, nil, testAccount},
		{"account with memo", testAccount, &memo, testAccount + ":1234"},
		// A muxed account already carries the user id, so no memo is appended
		// and none can be: the issuer rejects that combination.
		{"muxed account", testMuxed, nil, testMuxed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, Subject(tt.account, tt.memo))
		})
	}
}

func TestIssueAndParse(t *testing.T) {
	i := newTestIssuer(t)
	memo := uint64(99)

	raw, err := i.Issue(Request{
		Account:      testAccount,
		Memo:         &memo,
		ClientDomain: "wallet.example.org",
		JTI:          "abc123",
		IssuedAt:     testNow,
	})
	require.NoError(t, err)

	claims, err := i.Parse(raw, testNow.Add(time.Minute))
	require.NoError(t, err)

	require.Equal(t, "https://auth.example.com", claims.Issuer)
	require.Equal(t, testAccount+":99", claims.Subject)
	require.Equal(t, "abc123", claims.ID)
	require.Equal(t, "wallet.example.org", claims.ClientDomain)
	require.Equal(t, testNow.Unix(), claims.IssuedAt.Unix())
	require.Equal(t, testNow.Add(time.Hour).Unix(), claims.ExpiresAt.Unix())
}

// client_domain is omitted entirely when no client domain was verified, rather
// than being present and empty.
func TestIssueOmitsEmptyClientDomain(t *testing.T) {
	i := newTestIssuer(t)

	raw, err := i.Issue(Request{Account: testAccount, JTI: "abc123", IssuedAt: testNow})
	require.NoError(t, err)

	claims, err := i.Parse(raw, testNow)
	require.NoError(t, err)
	require.Empty(t, claims.ClientDomain)
	require.Equal(t, testAccount, claims.Subject)
}

func TestParseRejectsExpiredToken(t *testing.T) {
	i := newTestIssuer(t)

	raw, err := i.Issue(Request{Account: testAccount, JTI: "abc123", IssuedAt: testNow})
	require.NoError(t, err)

	_, err = i.Parse(raw, testNow.Add(time.Hour+time.Second))
	require.ErrorIs(t, err, ErrTokenExpired)
}

// A token signed with a different algorithm is refused even when the attacker
// controls the header. This is the "alg" confusion guard.
func TestParseRejectsWrongAlgorithm(t *testing.T) {
	claims := Claims{RegisteredClaims: jwt.RegisteredClaims{
		Issuer:    "https://auth.example.com",
		Subject:   testAccount,
		ID:        "abc123",
		IssuedAt:  jwt.NewNumericDate(testNow),
		ExpiresAt: jwt.NewNumericDate(testNow.Add(time.Hour)),
	}}

	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS512, claims).SignedString(testSecret)
	require.NoError(t, err)

	i := newTestIssuer(t)
	_, err = i.Parse(raw, testNow)
	require.ErrorIs(t, err, ErrTokenInvalid)
}

func TestParseRejectsTamperedToken(t *testing.T) {
	i := newTestIssuer(t)

	raw, err := i.Issue(Request{Account: testAccount, JTI: "abc123", IssuedAt: testNow})
	require.NoError(t, err)

	tests := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"not a jwt", "not.a.jwt"},
		{"signature flipped", raw[:len(raw)-1] + "A"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := i.Parse(tt.raw, testNow)
			require.ErrorIs(t, err, ErrTokenInvalid)
		})
	}
}

// A token minted by a different issuer and signed with a different secret is
// refused. This only shows that the signature check rejects the token; it
// does not by itself show that the issuer is checked.
func TestParseRejectsForeignIssuer(t *testing.T) {
	other, err := NewIssuer(IssuerConfig{
		Secret:   []byte("ffffffffffffffffffffffffffffffff"),
		Issuer:   "https://evil.example.com",
		Lifetime: time.Hour,
	})
	require.NoError(t, err)

	raw, err := other.Issue(Request{Account: testAccount, JTI: "abc123", IssuedAt: testNow})
	require.NoError(t, err)

	_, err = newTestIssuer(t).Parse(raw, testNow)
	require.ErrorIs(t, err, ErrTokenInvalid)
}

// The iss claim is checked on its own, not merely as a side effect of the
// signature check. This token is signed with the SAME secret as the parsing
// issuer, so the only thing wrong with it is the issuer, and it must still be
// refused. Without this test, deleting the issuer check from Parse breaks
// nothing.
func TestParseRejectsForeignIssuerWithSameSecret(t *testing.T) {
	other, err := NewIssuer(IssuerConfig{
		Secret:   testSecret,
		Issuer:   "https://evil.example.com",
		Lifetime: time.Hour,
	})
	require.NoError(t, err)

	raw, err := other.Issue(Request{Account: testAccount, JTI: "abc123", IssuedAt: testNow})
	require.NoError(t, err)

	_, err = newTestIssuer(t).Parse(raw, testNow)
	require.ErrorIs(t, err, ErrTokenInvalid)
}

func TestNewIssuerValidates(t *testing.T) {
	tests := []struct {
		name string
		cfg  IssuerConfig
	}{
		{"short secret", IssuerConfig{Secret: []byte("short"), Issuer: "iss", Lifetime: time.Hour}},
		{"no issuer", IssuerConfig{Secret: testSecret, Lifetime: time.Hour}},
		{"no lifetime", IssuerConfig{Secret: testSecret, Issuer: "iss"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewIssuer(tt.cfg)
			require.Error(t, err)
			// The secret must not appear in the message.
			require.NotContains(t, err.Error(), string(tt.cfg.Secret))
		})
	}
}

func TestIssueRequiresJTI(t *testing.T) {
	i := newTestIssuer(t)

	_, err := i.Issue(Request{Account: testAccount, IssuedAt: testNow})
	require.Error(t, err)
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/token/ -v`
Expected: FAIL — `undefined: NewIssuer`

- [ ] **Step 3: Write the implementation**

`internal/token/jwt.go`:

```go
// Package token issues and parses the HS256 session tokens returned by
// POST /auth.
package token

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// minSecretLen is the shortest HS256 secret accepted, matching the check in
// internal/config.
const minSecretLen = 32

// Errors returned by Parse. A caller must not be told which check failed
// beyond these two classes.
var (
	// ErrTokenInvalid means the token is malformed, signed with the wrong key,
	// or signed with an algorithm other than HS256.
	ErrTokenInvalid = errors.New("token is invalid")
	// ErrTokenExpired means the token parsed and verified but has expired.
	ErrTokenExpired = errors.New("token has expired")
)

// Claims are the SEP-10 session claims.
type Claims struct {
	jwt.RegisteredClaims
	// ClientDomain is set only when a client domain was verified.
	ClientDomain string `json:"client_domain,omitempty"`
}

// IssuerConfig configures an Issuer.
type IssuerConfig struct {
	// Secret is the HS256 signing secret. Never logged.
	Secret []byte
	// Issuer is the iss claim.
	Issuer string
	// Lifetime is how long an issued token is valid.
	Lifetime time.Duration
}

// Issuer mints and verifies session tokens.
type Issuer struct {
	cfg IssuerConfig
}

// NewIssuer validates the configuration and returns an Issuer.
func NewIssuer(cfg IssuerConfig) (*Issuer, error) {
	if len(cfg.Secret) < minSecretLen {
		// Deliberately does not include the value.
		return nil, fmt.Errorf("jwt secret must be at least %d bytes", minSecretLen)
	}
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("jwt issuer is required")
	}
	if cfg.Lifetime <= 0 {
		return nil, fmt.Errorf("jwt lifetime must be positive")
	}
	return &Issuer{cfg: cfg}, nil
}

// Request describes one token to mint.
type Request struct {
	// Account is the authenticated account, G... or M...
	Account string
	// Memo is the ID memo, when one was used. Never set for a muxed account.
	Memo *uint64
	// ClientDomain is set only when a client domain was verified.
	ClientDomain string
	// JTI is the hex-encoded hash of the challenge transaction envelope.
	JTI string
	// IssuedAt is the iat claim. Passed in rather than read from the clock so
	// tests construct any token they need without a clock seam in production.
	IssuedAt time.Time
}

// Issue returns a signed token for the request.
func (i *Issuer) Issue(req Request) (string, error) {
	if req.Account == "" {
		return "", fmt.Errorf("account is required")
	}
	if req.JTI == "" {
		return "", fmt.Errorf("jti is required")
	}

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.cfg.Issuer,
			Subject:   Subject(req.Account, req.Memo),
			ID:        req.JTI,
			IssuedAt:  jwt.NewNumericDate(req.IssuedAt),
			ExpiresAt: jwt.NewNumericDate(req.IssuedAt.Add(i.cfg.Lifetime)),
		},
		ClientDomain: req.ClientDomain,
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(i.cfg.Secret)
	if err != nil {
		return "", fmt.Errorf("signing token: %w", err)
	}
	return signed, nil
}

// Parse verifies a token as of now and returns its claims.
//
// Only HS256 is accepted. Allowing the token's own header to choose the
// algorithm is the classic JWT forgery, so the accepted set is fixed here and
// the key function ignores the header entirely.
func (i *Issuer) Parse(raw string, now time.Time) (*Claims, error) {
	var claims Claims

	_, err := jwt.ParseWithClaims(raw, &claims,
		func(*jwt.Token) (any, error) { return i.cfg.Secret, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(i.cfg.Issuer),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(func() time.Time { return now }),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("%w", ErrTokenExpired)
		}
		return nil, fmt.Errorf("%w", ErrTokenInvalid)
	}

	return &claims, nil
}

// Subject formats the sub claim: the muxed address for an M... account, the
// address and memo joined by a colon when a memo was used, and the plain
// address otherwise.
func Subject(account string, memo *uint64) string {
	if memo == nil {
		return account
	}
	return account + ":" + strconv.FormatUint(*memo, 10)
}
```

`Parse` returns a bare sentinel rather than wrapping the library's error, so nothing about which
check failed reaches the caller.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/token/ -v`
Expected: PASS, including every subtest of `TestSubject`, `TestParseRejectsTamperedToken` and
`TestNewIssuerValidates`.

- [ ] **Step 5: Commit**

```bash
make check
git add internal/token/jwt.go internal/token/jwt_test.go
git commit -m "feat(token): add JWT issuance and parsing"
git push
```

---

## Task 15: Store records and migrations

Read the spec's section 9 before starting.

**Files:**
- Create: `internal/store/store.go`, `internal/store/store_test.go`,
  `internal/store/migrations/000001_init.up.sql`,
  `internal/store/migrations/000001_init.down.sql`

**Interfaces:**
- Consumes: nothing from earlier tasks
- Produces:
  - `type ChallengeRecord struct { Nonce, Account, HomeDomain, ClientDomain string; IssuedAt, ExpiresAt time.Time }`
  - `type ConsumedChallenge struct { Account, HomeDomain, ClientDomain string }`
  - `type SessionRecord struct { JTI, Account, Memo, HomeDomain, ClientDomain string; IssuedAt, ExpiresAt time.Time }`
  - `func migrationURL(databaseURL string) (string, error)` — unexported, used by Task 16
  - `migrationsFS`, the embedded SQL

- [ ] **Step 1: Write the migrations**

`internal/store/migrations/000001_init.up.sql`:

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

CREATE INDEX challenges_expires_at_idx ON challenges (expires_at);

CREATE TABLE sessions (
    jti           TEXT PRIMARY KEY,
    account       TEXT NOT NULL,
    memo          TEXT,
    home_domain   TEXT NOT NULL,
    client_domain TEXT,
    issued_at     TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL
);

CREATE INDEX sessions_account_issued_at_idx ON sessions (account, issued_at DESC);
```

The indexes are named rather than left to Postgres, so the down migration and any later
migration can refer to them.

`internal/store/migrations/000001_init.down.sql`:

```sql
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS challenges;
```

- [ ] **Step 2: Write the failing test**

`internal/store/store_test.go`:

```go
package store

import (
	"io/fs"
	"testing"

	"github.com/stretchr/testify/require"
)

// The migrate driver in database/pgx/v5 registers itself under the scheme
// "pgx5". A postgres:// URL would select the lib/pq driver instead, which this
// project does not depend on, so the scheme is rewritten before use.
func TestMigrationURL(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{
			name: "postgres scheme",
			in:   "postgres://u:p@localhost:5432/db?sslmode=disable",
			want: "pgx5://u:p@localhost:5432/db?sslmode=disable",
		},
		{
			name: "postgresql scheme",
			in:   "postgresql://u:p@localhost:5432/db",
			want: "pgx5://u:p@localhost:5432/db",
		},
		{
			name: "already pgx5",
			in:   "pgx5://u:p@localhost:5432/db",
			want: "pgx5://u:p@localhost:5432/db",
		},
		{name: "unsupported scheme", in: "mysql://u:p@localhost/db", wantErr: true},
		{name: "no scheme", in: "localhost:5432/db", wantErr: true},
		{name: "empty", in: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := migrationURL(tt.in)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// A rejection must not echo the connection string, which carries the password.
func TestMigrationURLNeverEchoesCredentials(t *testing.T) {
	_, err := migrationURL("mysql://user:hunter2@localhost/db")
	require.Error(t, err)
	require.NotContains(t, err.Error(), "hunter2")
}

// The migrations are embedded, so the binary carries its own schema and no
// files have to be shipped alongside it.
func TestMigrationsAreEmbedded(t *testing.T) {
	entries, err := fs.Glob(migrationsFS, "migrations/*.sql")
	require.NoError(t, err)
	require.ElementsMatch(t, []string{
		"migrations/000001_init.up.sql",
		"migrations/000001_init.down.sql",
	}, entries)

	up, err := fs.ReadFile(migrationsFS, "migrations/000001_init.up.sql")
	require.NoError(t, err)
	require.Contains(t, string(up), "CREATE TABLE challenges")
	require.Contains(t, string(up), "CREATE TABLE sessions")
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `go test ./internal/store/ -v`
Expected: FAIL — `undefined: migrationURL`

- [ ] **Step 4: Write the implementation**

`internal/store/store.go`:

```go
// Package store persists issued challenges and the sessions they produce.
//
// A challenge is valid exactly once. Consumption is a single atomic statement,
// never a read followed by a write, so two concurrent posts of the same
// challenge cannot both succeed.
package store

import (
	"embed"
	"fmt"
	"net/url"
	"time"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// ChallengeRecord is a challenge as issued, before any client has answered it.
type ChallengeRecord struct {
	// Nonce is the base64 value of the challenge's first manage_data operation.
	Nonce string
	// Account is the account the challenge was issued for, G... or M...
	Account string
	HomeDomain string
	// ClientDomain is empty when the challenge carried no client_domain.
	ClientDomain string
	IssuedAt     time.Time
	ExpiresAt    time.Time
}

// ConsumedChallenge is what a successful consumption returns. The stored values
// are authoritative: the client cannot change which account or home domain a
// nonce was issued for by editing the transaction it posts back.
type ConsumedChallenge struct {
	Account      string
	HomeDomain   string
	ClientDomain string
}

// SessionRecord is one issued token. Sessions are never deleted; they are the
// audit trail.
type SessionRecord struct {
	// JTI is the token's jti claim, the hex hash of the challenge envelope.
	JTI     string
	Account string
	// Memo is the ID memo as a decimal string, empty when none was used.
	Memo         string
	HomeDomain   string
	ClientDomain string
	IssuedAt     time.Time
	ExpiresAt    time.Time
}

// migrationURL rewrites a Postgres connection string to the scheme the
// golang-migrate database/pgx/v5 driver registers, which is "pgx5". Leaving it
// as postgres:// would select the lib/pq-backed driver, which this project does
// not depend on.
//
// The error never includes the connection string, which carries the password.
func migrationURL(databaseURL string) (string, error) {
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		// err is discarded on purpose, against the usual %w convention:
		// url.Parse quotes the input it could not parse, so wrapping it here
		// would put the connection string, and the password in it, into the
		// error. Do not add %w back.
		return "", fmt.Errorf("database url is not a valid URL")
	}

	switch parsed.Scheme {
	case "postgres", "postgresql":
		parsed.Scheme = "pgx5"
	case "pgx5":
		// Already the driver's scheme.
	default:
		return "", fmt.Errorf("database url scheme %q is not supported; use postgres://", parsed.Scheme)
	}

	return parsed.String(), nil
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `go test ./internal/store/ -v`
Expected: PASS, including every subtest of `TestMigrationURL`.

- [ ] **Step 6: Commit**

```bash
make check
git add internal/store/store.go internal/store/store_test.go internal/store/migrations/
git commit -m "feat(store): add records and migrations"
git push
```

---

## Task 16: Postgres store and cleanup loop

**Files:**
- Create: `internal/store/postgres.go`, `internal/store/postgres_integration_test.go`

**Interfaces:**
- Consumes: the record types from Task 15, the sentinels from Task 7
- Produces:
  - `func Open(ctx context.Context, databaseURL string) (*Postgres, error)`
  - `func (p *Postgres) Close()`
  - `func (p *Postgres) Ping(ctx context.Context) error`
  - `func (p *Postgres) Migrate() error`
  - `func (p *Postgres) RecordChallenge(ctx context.Context, rec ChallengeRecord) error`
  - `func (p *Postgres) ConsumeChallenge(ctx context.Context, nonce string, now time.Time) (*ConsumedChallenge, error)`
  - `func (p *Postgres) RecordSession(ctx context.Context, rec SessionRecord) error`
  - `func (p *Postgres) DeleteExpiredChallenges(ctx context.Context, before time.Time) (int64, error)`
  - `func (p *Postgres) CleanupExpiredChallenges(ctx context.Context, interval time.Duration, logger *slog.Logger)`

The replay *behaviour* is tested at the handler level in Task 19, against a fake that mimics the
atomic update. The SQL itself is tested here, behind a build tag, against a real Postgres. There
is no unit test of a fake in this package: a test of a fake asserts nothing about the SQL.

- [ ] **Step 1: Write the build-tagged integration test**

This never runs in CI. It is the only thing that proves the SQL is right, so it must exist and
must be runnable on demand.

`internal/store/postgres_integration_test.go`:

```go
//go:build postgres_integration

// Run with a live database:
//
//	docker compose -f deploy/docker-compose.yml up -d postgres
//	SEP10_TEST_DATABASE_URL=postgres://anchorage:anchorage@localhost:5432/anchorage?sslmode=disable \
//	  go test -tags postgres_integration ./internal/store/ -v
package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/0dillon/Anchorage/internal/auth"
	"github.com/stretchr/testify/require"
)

func openTestStore(t *testing.T) *Postgres {
	t.Helper()

	dsn := os.Getenv("SEP10_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SEP10_TEST_DATABASE_URL is not set")
	}

	p, err := Open(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(p.Close)

	require.NoError(t, p.Migrate())

	// Each test starts from an empty table.
	_, err = p.pool.Exec(context.Background(), "TRUNCATE challenges, sessions")
	require.NoError(t, err)

	return p
}

func testChallenge(nonce string, now time.Time) ChallengeRecord {
	return ChallengeRecord{
		Nonce:        nonce,
		Account:      "GBXHUHG5FGYLPD6RHL2MKWMP572O6KUXCZXDZJXS4T57ZTMAKBN7DWXN",
		HomeDomain:   "example.com",
		ClientDomain: "wallet.example.org",
		IssuedAt:     now,
		ExpiresAt:    now.Add(5 * time.Minute),
	}
}

func TestConsumeChallengeSucceedsOnce(t *testing.T) {
	p := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	require.NoError(t, p.RecordChallenge(ctx, testChallenge("nonce-1", now)))

	got, err := p.ConsumeChallenge(ctx, "nonce-1", now)
	require.NoError(t, err)
	require.Equal(t, "example.com", got.HomeDomain)
	require.Equal(t, "wallet.example.org", got.ClientDomain)

	// The second use is the replay, and it must fail.
	_, err = p.ConsumeChallenge(ctx, "nonce-1", now)
	require.ErrorIs(t, err, auth.ErrChallengeConsumed)
}

func TestConsumeChallengeRejectsUnknownNonce(t *testing.T) {
	p := openTestStore(t)

	_, err := p.ConsumeChallenge(context.Background(), "never-issued", time.Now().UTC())
	require.ErrorIs(t, err, auth.ErrChallengeUnknown)
}

func TestConsumeChallengeRejectsExpired(t *testing.T) {
	p := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	require.NoError(t, p.RecordChallenge(ctx, testChallenge("nonce-2", now)))

	_, err := p.ConsumeChallenge(ctx, "nonce-2", now.Add(10*time.Minute))
	require.ErrorIs(t, err, auth.ErrChallengeExpired)
}

// Only one of many concurrent consumers can win. This is the property the
// single-statement update exists for.
func TestConsumeChallengeIsAtomic(t *testing.T) {
	p := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	require.NoError(t, p.RecordChallenge(ctx, testChallenge("nonce-3", now)))

	const racers = 8
	results := make(chan error, racers)
	start := make(chan struct{})

	for range racers {
		go func() {
			<-start
			_, err := p.ConsumeChallenge(ctx, "nonce-3", now)
			results <- err
		}()
	}
	close(start)

	succeeded := 0
	for range racers {
		if err := <-results; err == nil {
			succeeded++
		}
	}
	require.Equal(t, 1, succeeded)
}

func TestRecordChallengeRejectsDuplicateNonce(t *testing.T) {
	p := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	require.NoError(t, p.RecordChallenge(ctx, testChallenge("nonce-4", now)))
	require.Error(t, p.RecordChallenge(ctx, testChallenge("nonce-4", now)))
}

func TestDeleteExpiredChallenges(t *testing.T) {
	p := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	require.NoError(t, p.RecordChallenge(ctx, testChallenge("old", now.Add(-time.Hour))))
	require.NoError(t, p.RecordChallenge(ctx, testChallenge("new", now)))

	deleted, err := p.DeleteExpiredChallenges(ctx, now)
	require.NoError(t, err)
	require.Equal(t, int64(1), deleted)

	// The live one survived.
	_, err = p.ConsumeChallenge(ctx, "new", now)
	require.NoError(t, err)
}

func TestRecordSession(t *testing.T) {
	p := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	rec := SessionRecord{
		JTI:        "abc123",
		Account:    "GBXHUHG5FGYLPD6RHL2MKWMP572O6KUXCZXDZJXS4T57ZTMAKBN7DWXN",
		HomeDomain: "example.com",
		IssuedAt:   now,
		ExpiresAt:  now.Add(24 * time.Hour),
	}
	require.NoError(t, p.RecordSession(ctx, rec))
	// Sessions are the audit trail, so a duplicate jti is a bug, not a retry.
	require.Error(t, p.RecordSession(ctx, rec))
}
```

- [ ] **Step 2: Confirm the tagged file is excluded from the ordinary build**

Run: `go vet ./internal/store/`
Expected: passes, and does not report `undefined: Postgres` — the build tag excludes the file.

Run: `go vet -tags postgres_integration ./internal/store/`
Expected: FAIL — `undefined: Open`. That proves the tag is spelled correctly and the file is
being compiled when it is asked for.

- [ ] **Step 3: Write the implementation**

`internal/store/postgres.go`:

```go
package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/0dillon/Anchorage/internal/auth"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres is the Postgres-backed store.
type Postgres struct {
	pool        *pgxpool.Pool
	databaseURL string
}

// Open connects to the database and verifies the connection.
func Open(ctx context.Context, databaseURL string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		// The connection string carries the password, so it is not included.
		return nil, fmt.Errorf("connecting to the database failed")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database ping failed: %w", err)
	}
	return &Postgres{pool: pool, databaseURL: databaseURL}, nil
}

// Close releases the connection pool.
func (p *Postgres) Close() {
	p.pool.Close()
}

// Ping reports whether the database is reachable. The health endpoint uses it.
func (p *Postgres) Ping(ctx context.Context) error {
	if err := p.pool.Ping(ctx); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}
	return nil
}

// Migrate applies the embedded migrations. Running it when the schema is
// already current is not an error.
func (p *Postgres) Migrate() error {
	source, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("reading embedded migrations: %w", err)
	}

	dsn, err := migrationURL(p.databaseURL)
	if err != nil {
		return err
	}

	m, err := migrate.NewWithSourceInstance("iofs", source, dsn)
	if err != nil {
		return fmt.Errorf("preparing migrations failed")
	}
	defer m.Close()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("applying migrations: %w", err)
	}
	return nil
}

// RecordChallenge stores a newly issued challenge. The nonce is the primary
// key, so a repeat insert fails rather than overwriting the original.
func (p *Postgres) RecordChallenge(ctx context.Context, rec ChallengeRecord) error {
	const query = `
		INSERT INTO challenges (nonce, account, home_domain, client_domain, issued_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`

	_, err := p.pool.Exec(ctx, query,
		rec.Nonce, rec.Account, rec.HomeDomain,
		nullable(rec.ClientDomain), rec.IssuedAt, rec.ExpiresAt)
	if err != nil {
		return fmt.Errorf("recording challenge: %w", err)
	}
	return nil
}

// ConsumeChallenge marks a challenge used and returns what it was issued for.
//
// The update is one statement. It matches only a row that is unconsumed and
// unexpired, so two concurrent callers cannot both succeed: the second finds
// consumed_at already set and matches nothing. Reading the row first and
// writing it after would let both through.
func (p *Postgres) ConsumeChallenge(ctx context.Context, nonce string, now time.Time) (*ConsumedChallenge, error) {
	const consume = `
		UPDATE challenges SET consumed_at = $2
		WHERE nonce = $1 AND consumed_at IS NULL AND expires_at > $2
		RETURNING account, home_domain, client_domain`

	var (
		out          ConsumedChallenge
		clientDomain *string
	)
	err := p.pool.QueryRow(ctx, consume, nonce, now).
		Scan(&out.Account, &out.HomeDomain, &clientDomain)
	if err == nil {
		if clientDomain != nil {
			out.ClientDomain = *clientDomain
		}
		return &out, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("consuming challenge: %w", err)
	}

	// Nothing matched. Only now is a second query worth running, to say which
	// of the three reasons it was.
	return nil, p.classifyFailure(ctx, nonce, now)
}

// classifyFailure tells an unknown nonce from a consumed one from an expired
// one. It runs only after the update matched nothing, so it never races with a
// successful consumption.
func (p *Postgres) classifyFailure(ctx context.Context, nonce string, now time.Time) error {
	const inspect = `SELECT consumed_at, expires_at FROM challenges WHERE nonce = $1`

	var (
		consumedAt *time.Time
		expiresAt  time.Time
	)
	err := p.pool.QueryRow(ctx, inspect, nonce).Scan(&consumedAt, &expiresAt)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return fmt.Errorf("%w", auth.ErrChallengeUnknown)
	case err != nil:
		return fmt.Errorf("inspecting challenge: %w", err)
	case consumedAt != nil:
		return fmt.Errorf("%w", auth.ErrChallengeConsumed)
	case !expiresAt.After(now):
		return fmt.Errorf("%w", auth.ErrChallengeExpired)
	default:
		// The row is live and unconsumed, so the update should have matched.
		// Reaching here means another caller consumed it between the two
		// queries, which is still a replay from this caller's point of view.
		return fmt.Errorf("%w", auth.ErrChallengeConsumed)
	}
}

// RecordSession stores an issued token. Sessions are never deleted.
func (p *Postgres) RecordSession(ctx context.Context, rec SessionRecord) error {
	const query = `
		INSERT INTO sessions (jti, account, memo, home_domain, client_domain, issued_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := p.pool.Exec(ctx, query,
		rec.JTI, rec.Account, nullable(rec.Memo), rec.HomeDomain,
		nullable(rec.ClientDomain), rec.IssuedAt, rec.ExpiresAt)
	if err != nil {
		return fmt.Errorf("recording session: %w", err)
	}
	return nil
}

// DeleteExpiredChallenges removes challenge rows that expired before the given
// time and returns how many were removed.
func (p *Postgres) DeleteExpiredChallenges(ctx context.Context, before time.Time) (int64, error) {
	const query = `DELETE FROM challenges WHERE expires_at < $1`

	tag, err := p.pool.Exec(ctx, query, before)
	if err != nil {
		return 0, fmt.Errorf("deleting expired challenges: %w", err)
	}
	return tag.RowsAffected(), nil
}

// CleanupExpiredChallenges deletes expired challenges on a loop until the
// context is cancelled. It blocks, so callers run it in its own goroutine.
//
// A failed sweep is logged and the loop continues: the next tick retries, and
// a stale challenge row is harmless because expiry is enforced by the consume
// statement, not by this loop.
func (p *Postgres) CleanupExpiredChallenges(ctx context.Context, interval time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			deleted, err := p.DeleteExpiredChallenges(ctx, time.Now().UTC())
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				logger.Error("challenge cleanup failed", "error", err)
				continue
			}
			if deleted > 0 {
				logger.Info("deleted expired challenges", "count", deleted)
			}
		}
	}
}

// nullable maps an empty string to SQL NULL, so an absent client domain is
// stored as NULL rather than as an empty string.
func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
```

- [ ] **Step 4: Verify the ordinary build and the tagged build both compile**

Run: `go build ./... && go vet ./...`
Expected: passes.

Run: `go vet -tags postgres_integration ./internal/store/`
Expected: passes. The integration test now compiles even though it will not run without a
database.

Run: `go test ./internal/store/ -v`
Expected: PASS — the Task 15 tests. No integration test runs.

- [ ] **Step 5: Confirm lib/pq was not pulled in**

The forbidden dependency can only appear once something imports a migrate driver, which is now.

Run: `go list -deps ./... | grep lib/pq`
Expected: no output, exit status 1. If `lib/pq` appears here, the `database/postgres` driver was
imported instead of `database/pgx/v5`. This command is the authoritative check, because it lists
what the build actually links.

The Global Constraints also require `grep -c "lib/pq" go.sum` to print `0`, and that check is
weaker than it looks from this task onward. `golang-migrate`'s own `go.mod` requires `lib/pq` for
the driver Anchorage does not use, so `go mod tidy` may record a `github.com/lib/pq vX.Y.Z/go.mod`
hash line for module-graph bookkeeping even though nothing links it. A `/go.mod` line alone is not
a violation; an `h1:` line for `lib/pq`, which is the hash of the module's source, means it really
is in the build.

If `go list -deps` is clean but `go.sum` gains a `lib/pq` `/go.mod` line, stop and report it rather
than acting. Never hand-edit `go.sum`, and never relax either check to get a green run.

- [ ] **Step 6: Commit**

This task is the first real import of `pgx/v5` and `golang-migrate/v4`, so `go mod tidy` changes
`go.mod` and `go.sum`. Both are staged with this task's own files: leaving them out would push a
tree whose `go.mod` does not require what the code imports, and CI would fail on a fresh checkout.

```bash
make check
git add go.mod go.sum internal/store/postgres.go internal/store/postgres_integration_test.go
git commit -m "feat(store): add postgres implementation and cleanup loop"
git push
```

---

## Task 17: Router, middleware, and health endpoint

Read the spec's section 10 before starting.

**Files:**
- Create: `internal/httpapi/respond.go`, `internal/httpapi/middleware.go`,
  `internal/httpapi/router.go`, `internal/httpapi/health_handler.go`,
  `internal/httpapi/middleware_test.go`, `internal/httpapi/health_handler_test.go`

**Interfaces:**
- Consumes: `auth.Issuer`, `auth.AccountFetcher`, `token.Issuer`, the `store` record types
- Produces:
  - `type ChallengeStore interface` — the store contract, declared here because here is where
    it is called
  - `type Pinger interface { Ping(ctx context.Context) error }`
  - `type Deps struct` — every dependency the handlers need
  - `func NewRouter(d Deps) (http.Handler, error)`
  - `func writeJSON(w http.ResponseWriter, logger *slog.Logger, status int, body any)`
  - `func writeError(w http.ResponseWriter, logger *slog.Logger, status int, message string)`
  - `newRateLimiter`, `limitBody`, `requestLogger`, `recoverPanic` — unexported, used by Tasks
    18 to 20

`Deps` is defined in full here even though only `/health` is mounted, so Tasks 18, 19 and 20 add
one route line each instead of rewriting the wiring three times.

- [ ] **Step 1: Write the failing tests**

`internal/httpapi/middleware_test.go`:

```go
package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// discardLogger keeps test output clean while still exercising the logging
// path.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// captureLogger returns a logger and the buffer it writes to.
func captureLogger() (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return slog.New(slog.NewJSONHandler(buf, nil)), buf
}

func TestLimitBodyRejectsOversizedRequest(t *testing.T) {
	handler := limitBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name string
		size int
		want int
	}{
		{"within the cap", maxBodyBytes - 1, http.StatusOK},
		{"over the cap", maxBodyBytes + 1, http.StatusRequestEntityTooLarge},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := strings.NewReader(strings.Repeat("a", tt.size))
			req := httptest.NewRequest(http.MethodPost, "/auth", body)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)
			require.Equal(t, tt.want, rec.Code)
		})
	}
}

// A panic becomes a 500 with a JSON body, and the panic value is logged but
// never sent to the client.
func TestRecoverPanic(t *testing.T) {
	logger, logs := captureLogger()

	handler := recoverPanic(logger)(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			panic("secret internal detail")
		}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth", nil))

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	require.NotContains(t, rec.Body.String(), "secret internal detail")

	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "internal server error", body["error"])

	// The operator still gets the detail.
	require.Contains(t, logs.String(), "secret internal detail")
}

// The logger records the outcome and never the query string, which carries the
// caller's account and client domain.
func TestRequestLoggerRecordsOutcome(t *testing.T) {
	logger, logs := captureLogger()

	handler := requestLogger(logger)(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		}))

	req := httptest.NewRequest(http.MethodGet, "/auth?account=GABC&client_domain=wallet.example.org", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	var entry map[string]any
	require.NoError(t, json.Unmarshal(logs.Bytes(), &entry))
	require.Equal(t, "GET", entry["method"])
	require.Equal(t, "/auth", entry["path"])
	require.Equal(t, float64(http.StatusTeapot), entry["status"])
	require.NotContains(t, logs.String(), "wallet.example.org")
}

// The bucket refills over time and is capped at the burst size.
func TestRateLimiter(t *testing.T) {
	base := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	limiter := newRateLimiter(60)

	// The burst is the per-minute allowance, so the first 60 are allowed and
	// the 61st in the same instant is not.
	for i := range 60 {
		require.True(t, limiter.allow("1.2.3.4", base), "request %d should be allowed", i)
	}
	require.False(t, limiter.allow("1.2.3.4", base))

	// One second later exactly one token has refilled.
	require.True(t, limiter.allow("1.2.3.4", base.Add(time.Second)))
	require.False(t, limiter.allow("1.2.3.4", base.Add(time.Second)))

	// A different address has its own bucket.
	require.True(t, limiter.allow("5.6.7.8", base))

	// The bucket never refills past the burst, however long it idles.
	for i := range 60 {
		require.True(t, limiter.allow("1.2.3.4", base.Add(time.Hour)), "request %d should be allowed", i)
	}
	require.False(t, limiter.allow("1.2.3.4", base.Add(time.Hour)))
}

func TestRateLimitMiddlewareReturns429(t *testing.T) {
	limiter := newRateLimiter(1)
	handler := limiter.middleware(discardLogger())(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

	newReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/auth", nil)
		req.RemoteAddr = "1.2.3.4:5678"
		return req
	}

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, newReq())
	require.Equal(t, http.StatusOK, first.Code)

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, newReq())
	require.Equal(t, http.StatusTooManyRequests, second.Code)
}

// Idle buckets are dropped, so a long-running server does not accumulate one
// map entry per address it has ever seen.
func TestRateLimiterSweepsIdleBuckets(t *testing.T) {
	base := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	limiter := newRateLimiter(60)

	require.True(t, limiter.allow("1.2.3.4", base))
	require.Len(t, limiter.buckets, 1)

	require.True(t, limiter.allow("5.6.7.8", base.Add(2*bucketIdleTTL)))
	require.Len(t, limiter.buckets, 1)
	require.Contains(t, limiter.buckets, "5.6.7.8")
}
```

`internal/httpapi/health_handler_test.go`:

```go
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

type fakePinger struct{ err error }

func (f fakePinger) Ping(context.Context) error { return f.err }

func TestHealthEndpoint(t *testing.T) {
	tests := []struct {
		name       string
		pingErr    error
		wantStatus int
		wantDB     string
	}{
		{"database up", nil, http.StatusOK, "ok"},
		{"database down", errors.New("connection refused"), http.StatusServiceUnavailable, "unavailable"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router, err := NewRouter(Deps{
				Logger: discardLogger(),
				Health: fakePinger{err: tt.pingErr},
			})
			require.NoError(t, err)

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

			require.Equal(t, tt.wantStatus, rec.Code)

			var body map[string]string
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			require.Equal(t, tt.wantDB, body["database"])

			// The underlying error is never disclosed.
			if tt.pingErr != nil {
				require.NotContains(t, rec.Body.String(), "connection refused")
			}
		})
	}
}

func TestNewRouterRequiresDependencies(t *testing.T) {
	_, err := NewRouter(Deps{Health: fakePinger{}})
	require.Error(t, err)

	_, err = NewRouter(Deps{Logger: discardLogger()})
	require.Error(t, err)
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/httpapi/ -v`
Expected: FAIL — `undefined: limitBody`, `undefined: NewRouter`

- [ ] **Step 3: Write the response helpers**

`internal/httpapi/respond.go`:

```go
// Package httpapi serves the SEP-10 endpoints.
package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// errorBody is the shape of every error response. It names the failure class
// and nothing else: no signature material, no internal state, no secret.
type errorBody struct {
	Error string `json:"error"`
}

// writeJSON writes a JSON response. A failure to encode is logged, not
// returned: the status line has already gone out and there is nothing useful
// left to tell the client.
func writeJSON(w http.ResponseWriter, logger *slog.Logger, status int, body any) {
	encoded, err := json.Marshal(body)
	if err != nil {
		logger.Error("encoding response failed", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal server error"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(encoded); err != nil {
		logger.Warn("writing response failed", "error", err)
	}
}

// writeError writes an error response carrying only the failure class.
func writeError(w http.ResponseWriter, logger *slog.Logger, status int, message string) {
	writeJSON(w, logger, status, errorBody{Error: message})
}
```

- [ ] **Step 4: Write the middleware**

`internal/httpapi/middleware.go`:

```go
package httpapi

import (
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

const (
	// maxBodyBytes caps a request body. No SEP-10 request is near this size; a
	// challenge envelope is a few kilobytes.
	maxBodyBytes = 64 * 1024

	// requestsPerMinute is the per-IP rate limit. It is fixed rather than
	// configurable on purpose: it guards against casual abuse, and an operator
	// fronting this with a real gateway will set their own policy there.
	requestsPerMinute = 60

	// bucketIdleTTL is how long an unused rate-limit bucket is kept.
	bucketIdleTTL = 10 * time.Minute

	// sweepInterval is the shortest gap between sweeps of idle buckets.
	sweepInterval = time.Minute
)

// limitBody caps the request body. Reads past the cap fail in the handler,
// which is where the error can still be turned into a response.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// requestLogger logs one line per request after it completes.
//
// The path is logged; the query string is not. On GET /auth the query carries
// the caller's account and client domain, and neither belongs in a log file.
func requestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			started := time.Now()
			wrapped := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			next.ServeHTTP(wrapped, r)

			logger.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", wrapped.Status(),
				"bytes", wrapped.BytesWritten(),
				"duration_ms", time.Since(started).Milliseconds(),
				"request_id", middleware.GetReqID(r.Context()),
			)
		})
	}
}

// recoverPanic turns a panic into a 500 and logs it. The panic value is for
// the operator; the client is told only that something failed.
func recoverPanic(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				recovered := recover()
				if recovered == nil {
					return
				}
				// http.ErrAbortHandler is the standard library's way of saying
				// the response was deliberately abandoned. Re-panic so the
				// server handles it as intended.
				if recovered == http.ErrAbortHandler {
					panic(recovered)
				}

				logger.Error("panic recovered",
					"panic", recovered,
					"path", r.URL.Path,
					"request_id", middleware.GetReqID(r.Context()),
				)
				writeError(w, logger, http.StatusInternalServerError, "internal server error")
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// rateLimiter is a per-key token bucket held in this process. It is not shared
// between instances; behind a load balancer each instance enforces its own.
type rateLimiter struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	perSecond float64
	burst     float64
	lastSweep time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// newRateLimiter returns a limiter allowing perMinute requests per key per
// minute, with a burst of the same size.
func newRateLimiter(perMinute int) *rateLimiter {
	return &rateLimiter{
		buckets:   make(map[string]*bucket),
		perSecond: float64(perMinute) / 60,
		burst:     float64(perMinute),
	}
}

// allow reports whether the key may make a request at the given time, and
// spends a token if it may.
func (l *rateLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweep(now)

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}

	// Refill for the time since the last request, capped at the burst.
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.perSecond
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweep drops buckets that have been idle longer than bucketIdleTTL, so the
// map does not grow once per address the server has ever seen. The caller
// holds the lock.
func (l *rateLimiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < sweepInterval {
		return
	}
	l.lastSweep = now

	for key, b := range l.buckets {
		if now.Sub(b.last) > bucketIdleTTL {
			delete(l.buckets, key)
		}
	}
}

// middleware applies the limit per client address.
func (l *rateLimiter) middleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !l.allow(clientIP(r), time.Now()) {
				writeError(w, logger, http.StatusTooManyRequests, "too many requests")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// clientIP returns the address to rate-limit on. chi's RealIP middleware has
// already applied any forwarded headers, so RemoteAddr is the right source
// here.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
```

`middleware.NewWrapResponseWriter` and `middleware.GetReqID` come from chi, verified with
`go doc` — `RequestIDHeader` is `X-Request-Id`.

- [ ] **Step 5: Write the health handler**

`internal/httpapi/health_handler.go`:

```go
package httpapi

import (
	"log/slog"
	"net/http"
)

// healthResponse is the body of GET /health.
type healthResponse struct {
	Status   string `json:"status"`
	Database string `json:"database"`
}

// healthHandler reports process and database liveness. The database error is
// logged but never returned: it can name hosts and users.
func healthHandler(pinger Pinger, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := pinger.Ping(r.Context()); err != nil {
			logger.Error("health check failed", "error", err)
			writeJSON(w, logger, http.StatusServiceUnavailable,
				healthResponse{Status: "degraded", Database: "unavailable"})
			return
		}
		writeJSON(w, logger, http.StatusOK,
			healthResponse{Status: "ok", Database: "ok"})
	}
}
```

- [ ] **Step 6: Write the router**

`internal/httpapi/router.go`:

```go
package httpapi

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/0dillon/Anchorage/internal/auth"
	"github.com/0dillon/Anchorage/internal/store"
	"github.com/0dillon/Anchorage/internal/token"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// ChallengeStore is the persistence the handlers need. It is declared here,
// where it is called, and satisfied by *store.Postgres.
type ChallengeStore interface {
	// RecordChallenge stores a newly issued challenge.
	RecordChallenge(ctx context.Context, rec store.ChallengeRecord) error
	// ConsumeChallenge marks a nonce used and returns what it was issued for.
	// A second call for the same nonce must fail.
	ConsumeChallenge(ctx context.Context, nonce string, now time.Time) (*store.ConsumedChallenge, error)
	// RecordSession stores an issued token.
	RecordSession(ctx context.Context, rec store.SessionRecord) error
}

// Pinger reports whether a dependency is reachable.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Deps holds everything the routes need. NewRouter checks only the fields the
// mounted routes actually use, so a route added later brings its own check
// with it.
type Deps struct {
	Logger *slog.Logger

	// Issuer builds and signs challenges. Required by GET /auth.
	Issuer *auth.Issuer
	// Tokens mints session tokens. Required by POST /auth.
	Tokens *token.Issuer
	// Accounts looks up signers and thresholds. Required by POST /auth.
	Accounts auth.AccountFetcher
	// Challenges persists challenges and sessions. Required by both /auth
	// routes.
	Challenges ChallengeStore
	// Health backs GET /health.
	Health Pinger

	// NetworkPassphrase is the network challenges are built for.
	NetworkPassphrase string
	// WebAuthDomain is the domain hosting this service. A challenge naming a
	// different one is not ours.
	WebAuthDomain string
	// HomeDomains is the set of home domains this server authenticates for.
	HomeDomains []string
	// TOMLPath is the SEP-1 file served at /.well-known/stellar.toml.
	TOMLPath string
	// SigningPublicKey is substituted into the SEP-1 file's SIGNING_KEY.
	SigningPublicKey string
}

// NewRouter wires the routes. It returns an error rather than panicking so a
// misconfigured server fails at startup with a message.
func NewRouter(d Deps) (http.Handler, error) {
	if d.Logger == nil {
		return nil, fmt.Errorf("a logger is required")
	}
	if d.Health == nil {
		return nil, fmt.Errorf("a health pinger is required")
	}

	limiter := newRateLimiter(requestsPerMinute)

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(recoverPanic(d.Logger))
	r.Use(requestLogger(d.Logger))
	r.Use(limitBody)
	r.Use(limiter.middleware(d.Logger))

	r.Get("/health", healthHandler(d.Health, d.Logger))

	return r, nil
}
```

`recoverPanic` is registered before `requestLogger` so a panic is still logged as a completed
request with its 500 status, rather than escaping the logger.

- [ ] **Step 7: Run the tests to verify they pass**

Run: `go test ./internal/httpapi/ -v`
Expected: PASS, including every subtest of `TestLimitBodyRejectsOversizedRequest` and
`TestHealthEndpoint`.

- [ ] **Step 8: Commit**

```bash
make check
git add internal/httpapi/respond.go internal/httpapi/middleware.go internal/httpapi/router.go \
  internal/httpapi/health_handler.go internal/httpapi/middleware_test.go \
  internal/httpapi/health_handler_test.go
git commit -m "feat(httpapi): add router, middleware, and health endpoint"
git push
```

---

## Task 18: GET /auth

**Files:**
- Create: `internal/httpapi/auth_handler.go`, `internal/httpapi/fakes_test.go`,
  `internal/httpapi/auth_get_test.go`
- Modify: `internal/httpapi/router.go` (add the route and two dependency checks),
  `internal/httpapi/health_handler_test.go` (use the shared test deps)

**Interfaces:**
- Consumes: `auth.Issuer`, `ChallengeStore`, `store.ChallengeRecord`, every sentinel
- Produces:
  - `func classify(err error) (error, int)` — the sentinel-to-status mapping, tested
    exhaustively in Task 19
  - `func respondError(w http.ResponseWriter, logger *slog.Logger, err error)`
  - `func respondStoreError(w http.ResponseWriter, logger *slog.Logger, err error)`
  - `func getAuthHandler(d Deps) http.HandlerFunc`
  - test helpers `newTestDeps(t)`, `fakeStore`, `fakeResolver`, `testIssuer`

- [ ] **Step 1: Write the shared test fakes**

`internal/httpapi/fakes_test.go`:

```go
package httpapi

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/0dillon/Anchorage/internal/auth"
	"github.com/0dillon/Anchorage/internal/store"
	"github.com/0dillon/Anchorage/internal/token"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stretchr/testify/require"
)

const (
	testNetwork       = network.TestNetworkPassphrase
	testWebAuthDomain = "auth.example.com"
	testHomeDomain    = "example.com"
	testClientDomain  = "wallet.example.org"
)

// Keypairs are derived from fixed raw seeds, never pasted: a strkey carries a
// checksum and a hand-written one does not parse.
var (
	serverKP       = mustKeypair(1)
	clientKP       = mustKeypair(2)
	clientDomainKP = mustKeypair(3)
)

func mustKeypair(fill byte) *keypair.Full {
	var raw [32]byte
	for i := range raw {
		raw[i] = fill
	}
	kp, err := keypair.FromRawSeed(raw)
	if err != nil {
		panic(err)
	}
	return kp
}

// fakeResolver stands in for the client domain resolver. It never touches the
// network.
type fakeResolver struct {
	key string
	err error
}

func (f fakeResolver) Resolve(context.Context, string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.key, nil
}

// fakeStore mimics the Postgres store, including the part that matters: a
// nonce can be consumed exactly once, and consumption is guarded by a lock so
// two concurrent consumers cannot both win.
type fakeStore struct {
	mu sync.Mutex

	challenges map[string]store.ChallengeRecord
	consumed   map[string]bool
	sessions   []store.SessionRecord

	// recordErr and consumeErr force an infrastructure failure, which must be
	// reported as 503 and never as a bad signature.
	recordErr  error
	consumeErr error
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		challenges: make(map[string]store.ChallengeRecord),
		consumed:   make(map[string]bool),
	}
}

func (f *fakeStore) RecordChallenge(_ context.Context, rec store.ChallengeRecord) error {
	if f.recordErr != nil {
		return f.recordErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	f.challenges[rec.Nonce] = rec
	return nil
}

func (f *fakeStore) ConsumeChallenge(_ context.Context, nonce string, now time.Time) (*store.ConsumedChallenge, error) {
	if f.consumeErr != nil {
		return nil, f.consumeErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	rec, ok := f.challenges[nonce]
	if !ok {
		return nil, auth.ErrChallengeUnknown
	}
	if f.consumed[nonce] {
		return nil, auth.ErrChallengeConsumed
	}
	if !rec.ExpiresAt.After(now) {
		return nil, auth.ErrChallengeExpired
	}

	f.consumed[nonce] = true
	return &store.ConsumedChallenge{
		Account:      rec.Account,
		HomeDomain:   rec.HomeDomain,
		ClientDomain: rec.ClientDomain,
	}, nil
}

func (f *fakeStore) RecordSession(_ context.Context, rec store.SessionRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.sessions = append(f.sessions, rec)
	return nil
}

// testIssuer builds a challenge issuer wired to the fake resolver.
func testIssuer(t *testing.T, resolver auth.ClientDomainResolver) *auth.Issuer {
	t.Helper()

	issuer, err := auth.NewIssuer(auth.IssuerConfig{
		SigningSecret:     serverKP.Seed(),
		NetworkPassphrase: testNetwork,
		WebAuthDomain:     testWebAuthDomain,
		HomeDomains:       []string{testHomeDomain},
		ChallengeTimeout:  5 * time.Minute,
		Resolver:          resolver,
	})
	require.NoError(t, err)
	return issuer
}

// newTestDeps returns a complete Deps and the fake store behind it. Tests
// override individual fields before calling NewRouter.
func newTestDeps(t *testing.T) (Deps, *fakeStore) {
	t.Helper()

	tokens, err := token.NewIssuer(token.IssuerConfig{
		Secret:   []byte("0123456789abcdef0123456789abcdef"),
		Issuer:   "https://auth.example.com",
		Lifetime: time.Hour,
	})
	require.NoError(t, err)

	fake := newFakeStore()

	return Deps{
		Logger:            discardLogger(),
		Issuer:            testIssuer(t, fakeResolver{key: clientDomainKP.Address()}),
		Tokens:            tokens,
		Challenges:        fake,
		Health:            fakePinger{},
		NetworkPassphrase: testNetwork,
		WebAuthDomain:     testWebAuthDomain,
		HomeDomains:       []string{testHomeDomain},
	}, fake
}
```

- [ ] **Step 2: Update the two health tests to use the shared deps**

In `internal/httpapi/health_handler_test.go`, replace the body of the `t.Run` in
`TestHealthEndpoint`:

```go
			deps, _ := newTestDeps(t)
			deps.Health = fakePinger{err: tt.pingErr}

			router, err := NewRouter(deps)
			require.NoError(t, err)
```

and replace `TestNewRouterRequiresDependencies` entirely:

```go
func TestNewRouterRequiresDependencies(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Deps)
	}{
		{"no logger", func(d *Deps) { d.Logger = nil }},
		{"no health pinger", func(d *Deps) { d.Health = nil }},
		{"no issuer", func(d *Deps) { d.Issuer = nil }},
		{"no challenge store", func(d *Deps) { d.Challenges = nil }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, _ := newTestDeps(t)
			tt.mutate(&deps)

			_, err := NewRouter(deps)
			require.Error(t, err)
		})
	}
}
```

- [ ] **Step 3: Write the failing tests for the handler**

`internal/httpapi/auth_get_test.go`:

```go
package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/0dillon/Anchorage/internal/auth"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stretchr/testify/require"
)

// getAuth issues a challenge through the router and returns the recorder.
func getAuth(t *testing.T, deps Deps, query url.Values) *httptest.ResponseRecorder {
	t.Helper()

	router, err := NewRouter(deps)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth?"+query.Encode(), nil))
	return rec
}

func TestGetAuthReturnsAChallenge(t *testing.T) {
	deps, fake := newTestDeps(t)

	rec := getAuth(t, deps, url.Values{"account": {clientKP.Address()}})
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var body struct {
		Transaction       string `json:"transaction"`
		NetworkPassphrase string `json:"network_passphrase"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, testNetwork, body.NetworkPassphrase)
	require.NotEmpty(t, body.Transaction)

	// The challenge is readable and was recorded under its own nonce.
	challenge, err := auth.ReadChallenge(body.Transaction, serverKP.Address(),
		testNetwork, testWebAuthDomain, []string{testHomeDomain})
	require.NoError(t, err)

	require.Len(t, fake.challenges, 1)
	recorded, ok := fake.challenges[challenge.Nonce]
	require.True(t, ok, "the challenge was recorded under its nonce")
	require.Equal(t, clientKP.Address(), recorded.Account)
	require.Equal(t, testHomeDomain, recorded.HomeDomain)
	require.Empty(t, recorded.ClientDomain)
}

func TestGetAuthWithClientDomain(t *testing.T) {
	deps, fake := newTestDeps(t)

	rec := getAuth(t, deps, url.Values{
		"account":       {clientKP.Address()},
		"client_domain": {testClientDomain},
	})
	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Transaction string `json:"transaction"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	challenge, err := auth.ReadChallenge(body.Transaction, serverKP.Address(),
		testNetwork, testWebAuthDomain, []string{testHomeDomain})
	require.NoError(t, err)
	require.Equal(t, testClientDomain, challenge.ClientDomain)
	require.Equal(t, clientDomainKP.Address(), challenge.ClientDomainKey)

	require.Equal(t, testClientDomain, fake.challenges[challenge.Nonce].ClientDomain)
}

func TestGetAuthWithMemo(t *testing.T) {
	deps, _ := newTestDeps(t)

	rec := getAuth(t, deps, url.Values{
		"account": {clientKP.Address()},
		"memo":    {"1234"},
	})
	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Transaction string `json:"transaction"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	challenge, err := auth.ReadChallenge(body.Transaction, serverKP.Address(),
		testNetwork, testWebAuthDomain, []string{testHomeDomain})
	require.NoError(t, err)
	require.NotNil(t, challenge.Memo)
	require.Equal(t, txnbuild.MemoID(1234), *challenge.Memo)
}

func TestGetAuthBadRequests(t *testing.T) {
	tests := []struct {
		name  string
		query url.Values
		want  string
	}{
		{
			name:  "no account",
			query: url.Values{},
			want:  "account is required",
		},
		{
			name:  "account is not a strkey",
			query: url.Values{"account": {"not-an-account"}},
			want:  auth.ErrInvalidAccount.Error(),
		},
		{
			name:  "memo is not a number",
			query: url.Values{"account": {clientKP.Address()}, "memo": {"abc"}},
			want:  "memo must be a positive integer",
		},
		{
			name:  "memo is negative",
			query: url.Values{"account": {clientKP.Address()}, "memo": {"-1"}},
			want:  "memo must be a positive integer",
		},
		{
			name:  "unknown home domain",
			query: url.Values{"account": {clientKP.Address()}, "home_domain": {"evil.example.com"}},
			want:  auth.ErrUnknownHomeDomain.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, _ := newTestDeps(t)

			rec := getAuth(t, deps, tt.query)
			require.Equal(t, http.StatusBadRequest, rec.Code)

			var body map[string]string
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			require.Equal(t, tt.want, body["error"])
		})
	}
}

// A client domain that cannot be resolved is the caller's problem, not ours.
func TestGetAuthRejectsUnresolvableClientDomain(t *testing.T) {
	deps, _ := newTestDeps(t)
	deps.Issuer = testIssuer(t, fakeResolver{err: errors.New("dns failure")})

	rec := getAuth(t, deps, url.Values{
		"account":       {clientKP.Address()},
		"client_domain": {testClientDomain},
	})
	require.Equal(t, http.StatusBadRequest, rec.Code)

	// The resolver's own message must not reach the caller.
	require.NotContains(t, rec.Body.String(), "dns failure")

	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, auth.ErrClientDomainRejected.Error(), body["error"])
}

// A store outage is 503. It must never look like a rejected request, because
// the caller would retry with different input and get nowhere.
func TestGetAuthStoreFailureIs503(t *testing.T) {
	deps, fake := newTestDeps(t)
	fake.recordErr = errors.New("connection refused")

	rec := getAuth(t, deps, url.Values{"account": {clientKP.Address()}})
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	require.NotContains(t, rec.Body.String(), "connection refused")
}
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `go test ./internal/httpapi/ -v`
Expected: FAIL — the `/auth` route is not mounted, so every request returns 404.

- [ ] **Step 5: Write the handler**

`internal/httpapi/auth_handler.go`:

```go
package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/0dillon/Anchorage/internal/auth"
	"github.com/0dillon/Anchorage/internal/store"
)

// sentinelStatus is the whole error mapping. Nothing else in this package
// assigns a status to a protocol error, and nothing matches on error strings.
//
// auth.ErrAccountNotFound is deliberately absent: a non-existent account is a
// normal SEP-10 case, authenticated by its master key, not a failure.
var sentinelStatus = []struct {
	err    error
	status int
}{
	{auth.ErrInvalidAccount, http.StatusBadRequest},
	{auth.ErrMemoWithMuxed, http.StatusBadRequest},
	{auth.ErrUnknownHomeDomain, http.StatusBadRequest},
	{auth.ErrClientDomainRequired, http.StatusBadRequest},
	{auth.ErrClientDomainRejected, http.StatusBadRequest},

	{auth.ErrChallengeMalformed, http.StatusUnauthorized},
	{auth.ErrChallengeUnknown, http.StatusUnauthorized},
	{auth.ErrChallengeConsumed, http.StatusUnauthorized},
	{auth.ErrChallengeExpired, http.StatusUnauthorized},
	{auth.ErrSignatureUnrecognized, http.StatusUnauthorized},
	{auth.ErrThresholdNotMet, http.StatusUnauthorized},
	{auth.ErrClientDomainUnverified, http.StatusUnauthorized},

	{auth.ErrAccountLookupFailed, http.StatusServiceUnavailable},
}

// classify returns the protocol sentinel err matches and the status it maps
// to, or (nil, 0) when err is not a protocol error at all. Callers decide what
// an unrecognised error means in their own context.
func classify(err error) (error, int) {
	for _, entry := range sentinelStatus {
		if errors.Is(err, entry.err) {
			return entry.err, entry.status
		}
	}
	return nil, 0
}

// respondError writes the failure class for a protocol error. The sentinel's
// own text is sent, not the wrapped error, so no internal detail leaks.
func respondError(w http.ResponseWriter, logger *slog.Logger, err error) {
	if sentinel, status := classify(err); sentinel != nil {
		writeError(w, logger, status, sentinel.Error())
		return
	}
	logger.Error("unhandled error", "error", err)
	writeError(w, logger, http.StatusInternalServerError, "internal server error")
}

// respondStoreError is respondError for a call into the store, where an
// unrecognised error is an outage rather than a bug.
func respondStoreError(w http.ResponseWriter, logger *slog.Logger, err error) {
	if sentinel, status := classify(err); sentinel != nil {
		writeError(w, logger, status, sentinel.Error())
		return
	}
	logger.Error("store failure", "error", err)
	writeError(w, logger, http.StatusServiceUnavailable, "service unavailable")
}

// challengeResponse is the body of GET /auth, as SEP-10 defines it.
type challengeResponse struct {
	Transaction       string `json:"transaction"`
	NetworkPassphrase string `json:"network_passphrase"`
}

// getAuthHandler serves GET /auth: build a challenge, record it, return it.
func getAuthHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()

		account := query.Get("account")
		if account == "" {
			writeError(w, d.Logger, http.StatusBadRequest, "account is required")
			return
		}

		memo, err := parseMemo(query.Get("memo"))
		if err != nil {
			writeError(w, d.Logger, http.StatusBadRequest, err.Error())
			return
		}

		issued, err := d.Issuer.Issue(r.Context(), auth.IssueRequest{
			Account:      account,
			Memo:         memo,
			HomeDomain:   query.Get("home_domain"),
			ClientDomain: query.Get("client_domain"),
		})
		if err != nil {
			respondError(w, d.Logger, err)
			return
		}

		// The challenge is recorded before it is returned. A challenge the
		// client holds but the server has no record of would be rejected as
		// unknown on the way back, so the write has to happen first.
		err = d.Challenges.RecordChallenge(r.Context(), store.ChallengeRecord{
			Nonce:        issued.Nonce,
			Account:      issued.Account,
			HomeDomain:   issued.HomeDomain,
			ClientDomain: issued.ClientDomain,
			IssuedAt:     time.Now().UTC(),
			ExpiresAt:    issued.ExpiresAt,
		})
		if err != nil {
			respondStoreError(w, d.Logger, err)
			return
		}

		writeJSON(w, d.Logger, http.StatusOK, challengeResponse{
			Transaction:       issued.TransactionXDR,
			NetworkPassphrase: issued.NetworkPassphrase,
		})
	}
}

// parseMemo reads the optional memo query parameter. SEP-10 memos are ID
// memos, so the value is an unsigned integer.
func parseMemo(raw string) (*uint64, error) {
	if raw == "" {
		return nil, nil
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return nil, errors.New("memo must be a positive integer")
	}
	return &value, nil
}
```

- [ ] **Step 6: Mount the route and require its dependencies**

In `internal/httpapi/router.go`, add to `NewRouter` after the existing checks:

```go
	if d.Issuer == nil {
		return nil, fmt.Errorf("a challenge issuer is required")
	}
	if d.Challenges == nil {
		return nil, fmt.Errorf("a challenge store is required")
	}
```

and add the route below `r.Get("/health", ...)`:

```go
	r.Get("/auth", getAuthHandler(d))
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `go test ./internal/httpapi/ -v`
Expected: PASS, including every subtest of `TestGetAuthBadRequests` and
`TestNewRouterRequiresDependencies`.

- [ ] **Step 8: Commit**

```bash
make check
git add internal/httpapi/auth_handler.go internal/httpapi/fakes_test.go \
  internal/httpapi/auth_get_test.go internal/httpapi/router.go \
  internal/httpapi/health_handler_test.go
git commit -m "feat(httpapi): add GET /auth handler"
git push
```

---

## Task 19: POST /auth

This is where a mistake authenticates the wrong person. Read the spec's sections 6.3 and 10
before starting.

**Files:**
- Create: `internal/httpapi/auth_post_test.go`
- Modify: `internal/httpapi/auth_handler.go` (add the handler),
  `internal/httpapi/router.go` (add the route and two dependency checks),
  `internal/httpapi/fakes_test.go` (add the account fetcher fake)

**Interfaces:**
- Consumes: `auth.ReadChallenge`, `auth.VerifyClient`, `auth.AccountFetcher`, `token.Issuer`,
  `ChallengeStore`
- Produces: `func postAuthHandler(d Deps) http.HandlerFunc`

**Order of operations, and why.** The nonce is consumed *before* the signatures are checked. A
challenge answered once, rightly or wrongly, is spent. Verifying first and consuming after would
let a caller submit the same live challenge repeatedly, which is exactly the unlimited-attempts
position the single-use rule exists to prevent.

- [ ] **Step 1: Add the account fetcher fake**

Append to `internal/httpapi/fakes_test.go`:

```go
// fakeAccounts stands in for Horizon.
type fakeAccounts struct {
	account *auth.Account
	err     error
}

func (f fakeAccounts) Account(context.Context, string) (*auth.Account, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.account, nil
}
```

and add the field to the `Deps` returned by `newTestDeps`, immediately after `Challenges`:

```go
		Accounts: fakeAccounts{account: &auth.Account{
			Signers:      map[string]int32{clientKP.Address(): 1},
			MedThreshold: 1,
		}},
```

- [ ] **Step 2: Write the failing tests**

`internal/httpapi/auth_post_test.go`:

```go
package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/0dillon/Anchorage/internal/auth"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stretchr/testify/require"
)

// issueChallenge runs GET /auth through the router and returns the envelope.
func issueChallenge(t *testing.T, router http.Handler, query url.Values) string {
	t.Helper()

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth?"+query.Encode(), nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Transaction string `json:"transaction"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	return body.Transaction
}

// signChallenge adds signatures to an envelope and re-encodes it.
func signChallenge(t *testing.T, envelope string, signers ...*keypair.Full) string {
	t.Helper()

	parsed, err := txnbuild.TransactionFromXDR(envelope)
	require.NoError(t, err)
	tx, ok := parsed.Transaction()
	require.True(t, ok)

	signed, err := tx.Sign(testNetwork, signers...)
	require.NoError(t, err)

	encoded, err := signed.Base64()
	require.NoError(t, err)
	return encoded
}

// postAuthJSON posts a signed envelope as JSON.
func postAuthJSON(t *testing.T, router http.Handler, envelope string) *httptest.ResponseRecorder {
	t.Helper()

	body, err := json.Marshal(map[string]string{"transaction": envelope})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestPostAuthReturnsAToken(t *testing.T) {
	deps, fake := newTestDeps(t)
	router, err := NewRouter(deps)
	require.NoError(t, err)

	envelope := issueChallenge(t, router, url.Values{"account": {clientKP.Address()}})
	rec := postAuthJSON(t, router, signChallenge(t, envelope, clientKP))
	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.NotEmpty(t, body.Token)

	claims, err := deps.Tokens.Parse(body.Token, time.Now())
	require.NoError(t, err)
	require.Equal(t, clientKP.Address(), claims.Subject)
	require.Empty(t, claims.ClientDomain)
	require.NotEmpty(t, claims.ID)

	// The session was recorded, keyed by the same jti the token carries.
	require.Len(t, fake.sessions, 1)
	require.Equal(t, claims.ID, fake.sessions[0].JTI)
	require.Equal(t, testHomeDomain, fake.sessions[0].HomeDomain)
}

// The same challenge cannot be answered twice. This is the replay check.
func TestPostAuthRejectsReplay(t *testing.T) {
	deps, _ := newTestDeps(t)
	router, err := NewRouter(deps)
	require.NoError(t, err)

	envelope := issueChallenge(t, router, url.Values{"account": {clientKP.Address()}})
	signed := signChallenge(t, envelope, clientKP)

	require.Equal(t, http.StatusOK, postAuthJSON(t, router, signed).Code)

	second := postAuthJSON(t, router, signed)
	require.Equal(t, http.StatusUnauthorized, second.Code)

	var body map[string]string
	require.NoError(t, json.Unmarshal(second.Body.Bytes(), &body))
	require.Equal(t, auth.ErrChallengeConsumed.Error(), body["error"])
}

// The form encoding is accepted too. Both are used in the wild.
func TestPostAuthAcceptsFormEncoding(t *testing.T) {
	deps, _ := newTestDeps(t)
	router, err := NewRouter(deps)
	require.NoError(t, err)

	envelope := issueChallenge(t, router, url.Values{"account": {clientKP.Address()}})
	form := url.Values{"transaction": {signChallenge(t, envelope, clientKP)}}

	req := httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestPostAuthWithMemoAndClientDomain(t *testing.T) {
	deps, fake := newTestDeps(t)
	router, err := NewRouter(deps)
	require.NoError(t, err)

	envelope := issueChallenge(t, router, url.Values{
		"account":       {clientKP.Address()},
		"memo":          {"1234"},
		"client_domain": {testClientDomain},
	})
	rec := postAuthJSON(t, router, signChallenge(t, envelope, clientKP, clientDomainKP))
	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	claims, err := deps.Tokens.Parse(body.Token, time.Now())
	require.NoError(t, err)
	require.Equal(t, clientKP.Address()+":1234", claims.Subject)
	require.Equal(t, testClientDomain, claims.ClientDomain)

	require.Len(t, fake.sessions, 1)
	require.Equal(t, "1234", fake.sessions[0].Memo)
	require.Equal(t, testClientDomain, fake.sessions[0].ClientDomain)
}

// A challenge carrying client_domain that the client domain did not sign is
// refused, even when the account's own signature is perfectly good.
func TestPostAuthRequiresClientDomainSignature(t *testing.T) {
	deps, _ := newTestDeps(t)
	router, err := NewRouter(deps)
	require.NoError(t, err)

	envelope := issueChallenge(t, router, url.Values{
		"account":       {clientKP.Address()},
		"client_domain": {testClientDomain},
	})
	rec := postAuthJSON(t, router, signChallenge(t, envelope, clientKP))
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPostAuthUnauthorized(t *testing.T) {
	other := mustKeypair(9)

	tests := []struct {
		name    string
		signers []*keypair.Full
		want    error
	}{
		{"no client signature", nil, auth.ErrSignatureUnrecognized},
		{"wrong signer", []*keypair.Full{other}, auth.ErrSignatureUnrecognized},
		{"account signer plus a stranger", []*keypair.Full{clientKP, other}, auth.ErrSignatureUnrecognized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, _ := newTestDeps(t)
			router, err := NewRouter(deps)
			require.NoError(t, err)

			envelope := issueChallenge(t, router, url.Values{"account": {clientKP.Address()}})
			rec := postAuthJSON(t, router, signChallenge(t, envelope, tt.signers...))
			require.Equal(t, http.StatusUnauthorized, rec.Code)

			var body map[string]string
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			require.Equal(t, tt.want.Error(), body["error"])
		})
	}
}

// An account whose signer does not carry enough weight is refused.
func TestPostAuthRejectsInsufficientWeight(t *testing.T) {
	deps, _ := newTestDeps(t)
	deps.Accounts = fakeAccounts{account: &auth.Account{
		Signers:      map[string]int32{clientKP.Address(): 1},
		MedThreshold: 5,
	}}

	router, err := NewRouter(deps)
	require.NoError(t, err)

	envelope := issueChallenge(t, router, url.Values{"account": {clientKP.Address()}})
	rec := postAuthJSON(t, router, signChallenge(t, envelope, clientKP))
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, auth.ErrThresholdNotMet.Error(), body["error"])
}

// A non-existent account authenticates on its master key alone.
func TestPostAuthAcceptsNonExistentAccount(t *testing.T) {
	deps, _ := newTestDeps(t)
	deps.Accounts = fakeAccounts{err: auth.ErrAccountNotFound}

	router, err := NewRouter(deps)
	require.NoError(t, err)

	envelope := issueChallenge(t, router, url.Values{"account": {clientKP.Address()}})
	rec := postAuthJSON(t, router, signChallenge(t, envelope, clientKP))
	require.Equal(t, http.StatusOK, rec.Code)
}

// A Horizon outage is 503, never 401. Reporting it as a bad signature would
// tell a caller their key is wrong when it is not.
func TestPostAuthHorizonOutageIs503(t *testing.T) {
	deps, _ := newTestDeps(t)
	deps.Accounts = fakeAccounts{err: auth.ErrAccountLookupFailed}

	router, err := NewRouter(deps)
	require.NoError(t, err)

	envelope := issueChallenge(t, router, url.Values{"account": {clientKP.Address()}})
	rec := postAuthJSON(t, router, signChallenge(t, envelope, clientKP))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestPostAuthBadRequests(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		wantStatus  int
	}{
		{"empty json body", "application/json", `{}`, http.StatusBadRequest},
		{"malformed json", "application/json", `{`, http.StatusBadRequest},
		{"empty form", "application/x-www-form-urlencoded", "", http.StatusBadRequest},
		{"unsupported content type", "text/plain", "whatever", http.StatusBadRequest},
		{"transaction is not xdr", "application/json", `{"transaction":"not-xdr"}`, http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, _ := newTestDeps(t)
			router, err := NewRouter(deps)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			require.Equal(t, tt.wantStatus, rec.Code)
		})
	}
}

// A challenge this server never issued is unknown, however well it is signed.
func TestPostAuthRejectsForeignChallenge(t *testing.T) {
	deps, _ := newTestDeps(t)
	router, err := NewRouter(deps)
	require.NoError(t, err)

	// Issued by a router with its own store, so this router has no record of
	// the nonce.
	otherDeps, _ := newTestDeps(t)
	otherRouter, err := NewRouter(otherDeps)
	require.NoError(t, err)

	envelope := issueChallenge(t, otherRouter, url.Values{"account": {clientKP.Address()}})
	rec := postAuthJSON(t, router, signChallenge(t, envelope, clientKP))
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, auth.ErrChallengeUnknown.Error(), body["error"])
}

// A store outage during consumption is 503, not a replay rejection.
func TestPostAuthStoreFailureIs503(t *testing.T) {
	deps, fake := newTestDeps(t)
	router, err := NewRouter(deps)
	require.NoError(t, err)

	envelope := issueChallenge(t, router, url.Values{"account": {clientKP.Address()}})
	fake.consumeErr = errors.New("connection refused")

	rec := postAuthJSON(t, router, signChallenge(t, envelope, clientKP))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	require.NotContains(t, rec.Body.String(), "connection refused")
}

// Every sentinel has a status, and the table has no entries beyond them. This
// is the test that fails when a sentinel is added and left unmapped.
func TestClassifyCoversEverySentinel(t *testing.T) {
	tests := []struct {
		err    error
		status int
	}{
		{auth.ErrInvalidAccount, http.StatusBadRequest},
		{auth.ErrMemoWithMuxed, http.StatusBadRequest},
		{auth.ErrUnknownHomeDomain, http.StatusBadRequest},
		{auth.ErrClientDomainRequired, http.StatusBadRequest},
		{auth.ErrClientDomainRejected, http.StatusBadRequest},
		{auth.ErrChallengeMalformed, http.StatusUnauthorized},
		{auth.ErrChallengeUnknown, http.StatusUnauthorized},
		{auth.ErrChallengeConsumed, http.StatusUnauthorized},
		{auth.ErrChallengeExpired, http.StatusUnauthorized},
		{auth.ErrSignatureUnrecognized, http.StatusUnauthorized},
		{auth.ErrThresholdNotMet, http.StatusUnauthorized},
		{auth.ErrClientDomainUnverified, http.StatusUnauthorized},
		{auth.ErrAccountLookupFailed, http.StatusServiceUnavailable},
	}

	require.Len(t, sentinelStatus, len(tests),
		"a sentinel was added to or removed from the mapping without updating this test")

	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			// Wrapped, because that is how handlers receive them.
			sentinel, status := classify(errors.Join(errors.New("context"), tt.err))
			require.Equal(t, tt.err, sentinel)
			require.Equal(t, tt.status, status)
		})
	}
}

// ErrAccountNotFound is deliberately unmapped. It is a normal SEP-10 case, not
// a failure, and giving it a status would turn a valid login into an error.
func TestClassifyIgnoresAccountNotFound(t *testing.T) {
	sentinel, status := classify(auth.ErrAccountNotFound)
	require.Nil(t, sentinel)
	require.Zero(t, status)
}

// An error that is not a protocol error at all falls through to the caller's
// own default.
func TestClassifyIgnoresUnknownErrors(t *testing.T) {
	sentinel, status := classify(errors.New("connection refused"))
	require.Nil(t, sentinel)
	require.Zero(t, status)
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./internal/httpapi/ -v`
Expected: FAIL — `POST /auth` is not mounted, so the posts return 405.

- [ ] **Step 4: Write the handler**

Append to `internal/httpapi/auth_handler.go`:

```go
// tokenResponse is the body of POST /auth, as SEP-10 defines it.
type tokenResponse struct {
	Token string `json:"token"`
}

// postAuthHandler serves POST /auth: read the challenge, spend the nonce,
// verify the signatures, and mint a token.
func postAuthHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		envelope, err := readTransactionField(r)
		if err != nil {
			writeError(w, d.Logger, http.StatusBadRequest, err.Error())
			return
		}

		challenge, err := auth.ReadChallenge(envelope, d.Issuer.ServerAccountID(),
			d.NetworkPassphrase, d.WebAuthDomain, d.HomeDomains)
		if err != nil {
			respondError(w, d.Logger, err)
			return
		}

		// The nonce is spent BEFORE the signatures are checked. This ordering
		// is deliberate; do not reverse it.
		//
		// Verifying first would leave the challenge live through a failed
		// attempt, turning it into an unlimited retry oracle against a single
		// nonce — exactly the property replay protection exists to remove.
		// Spending first means one challenge buys one attempt.
		//
		// The cost is that a malformed or mis-signed submission burns the
		// challenge and the client must request another. That is one call, and
		// it is the cheaper side of the trade.
		now := time.Now().UTC()
		consumed, err := d.Challenges.ConsumeChallenge(r.Context(), challenge.Nonce, now)
		if err != nil {
			respondStoreError(w, d.Logger, err)
			return
		}

		// The stored record is authoritative. The server's signature already
		// proves the envelope is the one issued, so a mismatch here means the
		// two records disagree, which is a malformed challenge, not a client
		// error to explain.
		if consumed.Account != challenge.ClientAccountID ||
			consumed.ClientDomain != challenge.ClientDomain {
			d.Logger.Error("stored challenge disagrees with the posted envelope",
				"nonce", challenge.Nonce)
			respondError(w, d.Logger, auth.ErrChallengeMalformed)
			return
		}

		if _, err := auth.VerifyClient(r.Context(), challenge, d.NetworkPassphrase, d.Accounts); err != nil {
			respondError(w, d.Logger, err)
			return
		}

		// The jti is the hash of the challenge envelope, so a token can always
		// be traced back to the exact challenge that produced it.
		jti, err := challenge.Tx.HashHex(d.NetworkPassphrase)
		if err != nil {
			d.Logger.Error("hashing the challenge failed", "error", err)
			writeError(w, d.Logger, http.StatusInternalServerError, "internal server error")
			return
		}

		memo := memoValue(challenge.Memo)
		signed, err := d.Tokens.Issue(token.Request{
			Account:      challenge.ClientAccountID,
			Memo:         memo,
			ClientDomain: challenge.ClientDomain,
			JTI:          jti,
			IssuedAt:     now,
		})
		if err != nil {
			d.Logger.Error("issuing the token failed", "error", err)
			writeError(w, d.Logger, http.StatusInternalServerError, "internal server error")
			return
		}

		// The session is the audit trail. A failure to record it must not hand
		// out a token that was never written down.
		err = d.Challenges.RecordSession(r.Context(), store.SessionRecord{
			JTI:          jti,
			Account:      challenge.ClientAccountID,
			Memo:         memoString(memo),
			HomeDomain:   consumed.HomeDomain,
			ClientDomain: challenge.ClientDomain,
			IssuedAt:     now,
			ExpiresAt:    now.Add(d.Tokens.Lifetime()),
		})
		if err != nil {
			respondStoreError(w, d.Logger, err)
			return
		}

		writeJSON(w, d.Logger, http.StatusOK, tokenResponse{Token: signed})
	}
}

// readTransactionField reads the transaction from a JSON or form body. Both
// encodings are used in the wild.
func readTransactionField(r *http.Request) (string, error) {
	contentType := r.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", errors.New("content-type is not valid")
	}

	switch mediaType {
	case "application/json":
		var body struct {
			Transaction string `json:"transaction"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			// The decode error can quote the body, so it is not passed on.
			return "", errors.New("request body is not valid JSON")
		}
		if body.Transaction == "" {
			return "", errors.New("transaction is required")
		}
		return body.Transaction, nil

	case "application/x-www-form-urlencoded":
		if err := r.ParseForm(); err != nil {
			return "", errors.New("request body is not a valid form")
		}
		value := r.PostForm.Get("transaction")
		if value == "" {
			return "", errors.New("transaction is required")
		}
		return value, nil

	default:
		return "", errors.New("content-type must be application/json or application/x-www-form-urlencoded")
	}
}

// memoValue converts the challenge's memo to the token package's form.
func memoValue(memo *txnbuild.MemoID) *uint64 {
	if memo == nil {
		return nil
	}
	value := uint64(*memo)
	return &value
}

// memoString renders a memo for the session row, empty when there is none.
func memoString(memo *uint64) string {
	if memo == nil {
		return ""
	}
	return strconv.FormatUint(*memo, 10)
}
```

Add to the imports of `internal/httpapi/auth_handler.go`:

```go
	"encoding/json"
	"mime"

	"github.com/0dillon/Anchorage/internal/token"
	"github.com/stellar/go-stellar-sdk/txnbuild"
```

- [ ] **Step 5: Add `Lifetime` to the token issuer**

`postAuthHandler` needs the token lifetime to write the session's expiry, and the issuer already
holds it. Append to `internal/token/jwt.go`:

```go
// Lifetime returns how long an issued token is valid.
func (i *Issuer) Lifetime() time.Duration {
	return i.cfg.Lifetime
}
```

- [ ] **Step 6: Mount the route and require its dependencies**

In `internal/httpapi/router.go`, add to `NewRouter` after the existing checks:

```go
	if d.Tokens == nil {
		return nil, fmt.Errorf("a token issuer is required")
	}
	if d.Accounts == nil {
		return nil, fmt.Errorf("an account fetcher is required")
	}
	if d.WebAuthDomain == "" {
		return nil, fmt.Errorf("a web auth domain is required")
	}
	if len(d.HomeDomains) == 0 {
		return nil, fmt.Errorf("at least one home domain is required")
	}
	if d.NetworkPassphrase == "" {
		return nil, fmt.Errorf("a network passphrase is required")
	}
```

and add the route below `r.Get("/auth", ...)`:

```go
	r.Post("/auth", postAuthHandler(d))
```

Add the matching cases to `TestNewRouterRequiresDependencies` in
`internal/httpapi/health_handler_test.go`:

```go
		{"no token issuer", func(d *Deps) { d.Tokens = nil }},
		{"no account fetcher", func(d *Deps) { d.Accounts = nil }},
		{"no web auth domain", func(d *Deps) { d.WebAuthDomain = "" }},
		{"no home domains", func(d *Deps) { d.HomeDomains = nil }},
		{"no network passphrase", func(d *Deps) { d.NetworkPassphrase = "" }},
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `go test ./internal/httpapi/ -v`
Expected: PASS, including every subtest of `TestPostAuthUnauthorized`,
`TestPostAuthBadRequests` and `TestClassifyCoversEverySentinel`.

- [ ] **Step 8: Commit**

```bash
make check
git add internal/httpapi/auth_handler.go internal/httpapi/auth_post_test.go \
  internal/httpapi/fakes_test.go internal/httpapi/router.go \
  internal/httpapi/health_handler_test.go internal/token/jwt.go
git commit -m "feat(httpapi): add POST /auth handler"
git push
```

---

## Task 20: stellar.toml endpoint

**Files:**
- Create: `internal/httpapi/toml_handler.go`, `internal/httpapi/toml_handler_test.go`,
  `deploy/stellar.toml.example`
- Modify: `internal/httpapi/router.go` (load the file and add the route)

**Interfaces:**
- Consumes: `Deps.TOMLPath`, `Deps.SigningPublicKey`
- Produces:
  - `func loadTOML(path, signingKey string) ([]byte, error)`
  - `func tomlHandler(body []byte, logger *slog.Logger) http.HandlerFunc`
  - `const signingKeyPlaceholder = "${SIGNING_KEY}"`

The file must contain the placeholder. A file with a hard-coded `SIGNING_KEY` fails startup:
that is the whole point of substituting at load, and accepting the file anyway would let a
server publish a key it cannot sign with.

- [ ] **Step 1: Write the example TOML**

`deploy/stellar.toml.example`:

```toml
# SEP-1 stellar.toml. The SIGNING_KEY placeholder is replaced at startup with
# the public key derived from SEP10_SIGNING_SECRET, so this file can never
# publish a key the server cannot sign with.
VERSION = "2.0.0"

NETWORK_PASSPHRASE = "Test SDF Network ; September 2015"
WEB_AUTH_ENDPOINT = "https://auth.example.com/auth"
SIGNING_KEY = "${SIGNING_KEY}"

[DOCUMENTATION]
ORG_NAME = "Example"
ORG_URL = "https://example.com"
```

- [ ] **Step 2: Write the failing tests**

`internal/httpapi/toml_handler_test.go`:

```go
package httpapi

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeTOML writes a temporary SEP-1 file and returns its path.
func writeTOML(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "stellar.toml")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func TestTOMLEndpointServesTheFile(t *testing.T) {
	deps, _ := newTestDeps(t)
	deps.TOMLPath = writeTOML(t, "VERSION = \"2.0.0\"\nSIGNING_KEY = \"${SIGNING_KEY}\"\n")
	deps.SigningPublicKey = serverKP.Address()

	router, err := NewRouter(deps)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/stellar.toml", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "text/plain; charset=utf-8", rec.Header().Get("Content-Type"))
	require.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))

	// The placeholder is gone and the real key is in its place.
	require.NotContains(t, rec.Body.String(), signingKeyPlaceholder)
	require.Contains(t, rec.Body.String(), serverKP.Address())
}

// A missing file fails startup. It must not produce a server that serves an
// empty or wrong SEP-1 document.
func TestNewRouterFailsOnMissingTOML(t *testing.T) {
	deps, _ := newTestDeps(t)
	deps.TOMLPath = filepath.Join(t.TempDir(), "does-not-exist.toml")
	deps.SigningPublicKey = serverKP.Address()

	_, err := NewRouter(deps)
	require.Error(t, err)
	require.Contains(t, err.Error(), "does-not-exist.toml")
}

// A file with a hard-coded key fails startup too. Substituting at load is what
// stops a mismatched key being published, and a file with nothing to
// substitute defeats it.
func TestNewRouterFailsWithoutPlaceholder(t *testing.T) {
	deps, _ := newTestDeps(t)
	deps.TOMLPath = writeTOML(t, "VERSION = \"2.0.0\"\nSIGNING_KEY = \"GSOMEOTHERKEY\"\n")
	deps.SigningPublicKey = serverKP.Address()

	_, err := NewRouter(deps)
	require.Error(t, err)
	require.Contains(t, err.Error(), signingKeyPlaceholder)
}

func TestNewRouterRequiresTOMLSettings(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Deps)
	}{
		{"no toml path", func(d *Deps) { d.TOMLPath = "" }},
		{"no signing public key", func(d *Deps) { d.SigningPublicKey = "" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, _ := newTestDeps(t)
			tt.mutate(&deps)

			_, err := NewRouter(deps)
			require.Error(t, err)
		})
	}
}

func TestLoadTOMLReplacesEveryOccurrence(t *testing.T) {
	path := writeTOML(t, "A = \"${SIGNING_KEY}\"\nB = \"${SIGNING_KEY}\"\n")

	body, err := loadTOML(path, serverKP.Address())
	require.NoError(t, err)
	require.NotContains(t, string(body), signingKeyPlaceholder)
	require.Equal(t,
		"A = \""+serverKP.Address()+"\"\nB = \""+serverKP.Address()+"\"\n",
		string(body))
}
```

Every existing test in the package now needs a TOML path, because `NewRouter` will require one.
Add these two lines to the `Deps` returned by `newTestDeps` in
`internal/httpapi/fakes_test.go`:

```go
		TOMLPath:         writeTOML(t, "VERSION = \"2.0.0\"\nSIGNING_KEY = \"${SIGNING_KEY}\"\n"),
		SigningPublicKey: serverKP.Address(),
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./internal/httpapi/ -v`
Expected: FAIL — `undefined: loadTOML`

- [ ] **Step 4: Write the handler**

`internal/httpapi/toml_handler.go`:

```go
package httpapi

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"os"
)

// signingKeyPlaceholder is replaced with the server's public signing key when
// the SEP-1 file is loaded.
const signingKeyPlaceholder = "${SIGNING_KEY}"

// loadTOML reads the SEP-1 file and substitutes the signing key.
//
// The placeholder is required. A file that hard-codes SIGNING_KEY could name a
// key this server cannot sign with, and every client that read it would build
// challenges nobody can answer.
func loadTOML(path, signingKey string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the SEP-1 file at %s: %w", path, err)
	}

	placeholder := []byte(signingKeyPlaceholder)
	if !bytes.Contains(raw, placeholder) {
		return nil, fmt.Errorf(
			"the SEP-1 file at %s must contain the %s placeholder, not a literal signing key",
			path, signingKeyPlaceholder)
	}

	return bytes.ReplaceAll(raw, placeholder, []byte(signingKey)), nil
}

// tomlHandler serves the SEP-1 file. It is read once at startup, so a request
// never touches the disk and a file changed underneath a running server has no
// effect until it restarts.
//
// The CORS header is permissive because the file is public by design: wallets
// fetch it from arbitrary origins to discover this server.
func tomlHandler(body []byte, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)

		if _, err := w.Write(body); err != nil {
			logger.Warn("writing stellar.toml failed", "error", err)
		}
	}
}
```

- [ ] **Step 5: Load the file and mount the route**

In `internal/httpapi/router.go`, add to `NewRouter` after the existing checks:

```go
	if d.TOMLPath == "" {
		return nil, fmt.Errorf("a SEP-1 toml path is required")
	}
	if d.SigningPublicKey == "" {
		return nil, fmt.Errorf("a signing public key is required")
	}

	tomlBody, err := loadTOML(d.TOMLPath, d.SigningPublicKey)
	if err != nil {
		return nil, err
	}
```

and add the route below `r.Post("/auth", ...)`:

```go
	r.Get("/.well-known/stellar.toml", tomlHandler(tomlBody, d.Logger))
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/httpapi/ -v`
Expected: PASS, the whole package.

- [ ] **Step 7: Commit**

```bash
make check
git add internal/httpapi/toml_handler.go internal/httpapi/toml_handler_test.go \
  internal/httpapi/router.go internal/httpapi/fakes_test.go deploy/stellar.toml.example
git commit -m "feat(httpapi): add stellar.toml handler"
git push
```

---

## Task 21: Entrypoint

**Files:**
- Create: `cmd/authd/main.go`

**Interfaces:**
- Consumes: every package built so far
- Produces: a runnable binary

- [ ] **Step 1: Write `main.go`**

There is no test task. `main` is wiring: every branch in it is a startup failure that the
packages below already test, and a test of `main` would test the standard library's HTTP server.

`cmd/authd/main.go`:

```go
// Command authd runs the Anchorage SEP-10 authentication server.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/0dillon/Anchorage/internal/account"
	"github.com/0dillon/Anchorage/internal/auth"
	"github.com/0dillon/Anchorage/internal/clientdomain"
	"github.com/0dillon/Anchorage/internal/config"
	"github.com/0dillon/Anchorage/internal/httpapi"
	applog "github.com/0dillon/Anchorage/internal/log"
	"github.com/0dillon/Anchorage/internal/store"
	"github.com/0dillon/Anchorage/internal/token"
)

const (
	// cleanupInterval is how often expired challenges are swept.
	cleanupInterval = 5 * time.Minute
	// shutdownTimeout bounds the wait for in-flight requests to finish.
	shutdownTimeout = 15 * time.Second
	// readHeaderTimeout bounds how long a client may take to send headers.
	readHeaderTimeout = 10 * time.Second
)

func main() {
	if err := run(); err != nil {
		// The logger may not exist yet, so this goes to stderr directly. The
		// error never carries a secret: every package that handles one omits
		// the value from its messages.
		fmt.Fprintf(os.Stderr, "authd: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}

	logger := applog.New(os.Stdout, slog.LevelInfo)

	// Cancelled on SIGINT or SIGTERM. Everything with a background loop takes
	// this context.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := db.Migrate(); err != nil {
		return err
	}

	accounts, err := account.NewFetcher(cfg.HorizonURL, nil)
	if err != nil {
		return err
	}

	resolver := clientdomain.NewResolver(clientdomain.ResolverConfig{
		Allowlist: cfg.ClientDomainAllowlist,
		CacheTTL:  cfg.ClientDomainCacheTTL,
	})

	issuer, err := auth.NewIssuer(auth.IssuerConfig{
		SigningSecret:        cfg.SigningSecret,
		NetworkPassphrase:    cfg.NetworkPassphrase,
		WebAuthDomain:        cfg.WebAuthDomain,
		HomeDomains:          cfg.HomeDomains,
		ChallengeTimeout:     cfg.ChallengeTimeout,
		ClientDomainRequired: cfg.ClientDomainRequired,
		Resolver:             resolver,
	})
	if err != nil {
		return err
	}

	tokens, err := token.NewIssuer(token.IssuerConfig{
		Secret:   []byte(cfg.JWTSecret),
		Issuer:   cfg.JWTIssuer,
		Lifetime: cfg.JWTLifetime,
	})
	if err != nil {
		return err
	}

	router, err := httpapi.NewRouter(httpapi.Deps{
		Logger:            logger,
		Issuer:            issuer,
		Tokens:            tokens,
		Accounts:          accounts,
		Challenges:        db,
		Health:            db,
		NetworkPassphrase: cfg.NetworkPassphrase,
		WebAuthDomain:     cfg.WebAuthDomain,
		HomeDomains:       cfg.HomeDomains,
		TOMLPath:          cfg.TOMLPath,
		SigningPublicKey:  cfg.SigningPublicKey,
	})
	if err != nil {
		return err
	}

	go db.CleanupExpiredChallenges(ctx, cleanupInterval, logger)

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           router,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	// The server runs in its own goroutine so this one can wait on the signal
	// context and shut it down.
	serverErr := make(chan error, 1)
	go func() {
		// No secret is logged here: SigningPublicKey is public and the rest is
		// operational detail.
		logger.Info("starting",
			"addr", cfg.ListenAddr,
			"web_auth_domain", cfg.WebAuthDomain,
			"home_domains", cfg.HomeDomains,
			"signing_key", cfg.SigningPublicKey,
		)
		serverErr <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("http server: %w", err)
		}
		return nil

	case <-ctx.Done():
		logger.Info("shutting down")

		// A fresh context: the signal context is already cancelled, and
		// shutdown needs time of its own to drain in-flight requests.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutting down: %w", err)
		}
		return nil
	}
}
```

- [ ] **Step 2: Verify it builds and starts far enough to fail on config**

Run: `make check`
Expected: passes.

Run: `go run ./cmd/authd`
Expected: exits 1 with `authd: SEP10_SIGNING_SECRET is required but not set`. That proves
config validation runs before anything opens a socket or a database connection.

- [ ] **Step 3: Commit**

```bash
git add cmd/authd/main.go
git commit -m "feat(cmd): wire authd entrypoint"
git push
```

---

## Task 22: Dockerfile and compose

**Files:**
- Create: `deploy/Dockerfile`, `deploy/docker-compose.yml`, `.dockerignore`

**Interfaces:**
- Consumes: the binary from Task 21
- Produces: a runnable container and a local Postgres to run it against

- [ ] **Step 1: Write `.dockerignore`**

```
.git
.env
*.env
docs
README.md
```

`.env` is excluded so a real secrets file can never be baked into an image.

- [ ] **Step 2: Write `deploy/Dockerfile`**

```dockerfile
# The builder pins the same toolchain as go.mod and CI. A floating tag would
# reintroduce the version drift the pin exists to prevent.
FROM golang:1.25.12-alpine AS build

WORKDIR /src

# Dependencies are copied first so a source-only change does not refetch them.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO is off so the binary runs in a scratch-style image with no libc.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/authd ./cmd/authd

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/authd /authd
COPY deploy/stellar.toml.example /etc/anchorage/stellar.toml

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/authd"]
```

The image carries no shell and runs as a non-root user. Secrets arrive as environment
variables at run time, never in a layer.

- [ ] **Step 3: Write `deploy/docker-compose.yml`**

```yaml
name: anchorage

services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: anchorage
      POSTGRES_PASSWORD: anchorage
      POSTGRES_DB: anchorage
    ports:
      - "5432:5432"
    volumes:
      - postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U anchorage"]
      interval: 5s
      timeout: 5s
      retries: 10

  authd:
    build:
      context: ..
      dockerfile: deploy/Dockerfile
    # Secrets come from a local .env, which is git-ignored. The credentials
    # below are for a throwaway local database and nothing else.
    env_file:
      - ../.env
    environment:
      SEP10_DATABASE_URL: postgres://anchorage:anchorage@postgres:5432/anchorage?sslmode=disable
      SEP10_LISTEN_ADDR: ":8080"
      SEP10_TOML_PATH: /etc/anchorage/stellar.toml
    ports:
      - "8080:8080"
    depends_on:
      postgres:
        condition: service_healthy

volumes:
  postgres-data:
```

`authd` runs migrations at startup, so no separate migration step is needed.

- [ ] **Step 4: Verify the compose file parses and the image builds**

Run: `docker compose -f deploy/docker-compose.yml config >/dev/null && echo ok`
Expected: `ok`

Run: `docker build -f deploy/Dockerfile -t anchorage:local .`
Expected: the build succeeds and the final image is the distroless one.

If Docker is not available in the environment, run the compose check only and record that the
image build was not exercised. Do not skip both.

- [ ] **Step 5: Commit**

```bash
git add deploy/Dockerfile deploy/docker-compose.yml .dockerignore
git commit -m "feat(deploy): add Dockerfile and docker-compose with postgres"
git push
```

---

## Task 23: Complete the README

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: everything
- Produces: the document a reviewer reads first

Keep the opening from Task 3 exactly as it is — it leads with the SDK finding and the scope
boundary, which is the point. Replace only the `## Status` section, and add the rest below it.

- [ ] **Step 1: Replace the Status section and append the body**

Delete this from `README.md`:

```markdown
## Status

Under construction. See `docs/superpowers/plans/2026-08-10-sep10-auth-server.md`.
```

and append:

````markdown
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
````

- [ ] **Step 2: Check every claim in the README against the code**

This is not a formatting pass. For each item, open the file and confirm:

- `accountSignerWeight` is in `internal/auth/verify.go` and
  `TestClientDomainWeightDoesNotSatisfyThreshold` is in `internal/auth/verify_test.go`.
- The `UPDATE ... WHERE consumed_at IS NULL` statement is in `internal/store/postgres.go`.
- The resolver's timeout, redirect count and body cap match the constants in
  `internal/clientdomain/resolver.go`.
- Every variable in the configuration table exists in `internal/config/config.go`, with the
  default shown.
- The status table matches `sentinelStatus` in `internal/httpapi/auth_handler.go`.
- The `txnbuild/transaction.go:1270` reference in the opening section still points at the
  `default` branch that rejects `client_domain`:

```bash
go doc github.com/stellar/go-stellar-sdk/txnbuild.ReadChallengeTx
sed -n '1266,1276p' "$(go env GOMODCACHE)/github.com/stellar/go-stellar-sdk@v0.7.1/txnbuild/transaction.go"
```

If any claim is wrong, fix the README, not the check.

- [ ] **Step 3: Run the full suite one last time**

Run: `make check`
Expected: passes.

Run: `go test ./... -count=1`
Expected: PASS for every package.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: complete README with quick start, endpoints, and config table"
git push
```

---

## Done

23 commits. The server builds, its tests pass offline, and `docker compose up` runs it against a
local Postgres.
