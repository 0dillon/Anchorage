# Anchorage — handoff

State as of commit `08cfb04`, branch `main`, pushed. Working tree clean, `make check` green.

Plan: `docs/superpowers/plans/2026-08-10-sep10-auth-server.md` (23 tasks).
Execution ledger with full per-task detail: `.superpowers/sdd/progress.md` (git-ignored).

## Complete and reviewed

Tasks 1-16. Each passed a spec-compliance and a code-quality verdict.

| # | Task | Commit |
|---|------|--------|
| 1 | Go module, gitignore, licence, Makefile | `60b583d` |
| 2 | CI workflow | `9170fab` |
| 3 | README skeleton, `.env.example` | `4c768b9` |
| 4 | `internal/config` | `042893a` |
| 5 | `internal/log` | `8825ea8` |
| 6 | `docs/sdk-findings.md` | `7c2f60f`, `8479b79` |
| 7 | `internal/auth/errors.go` | `c69c28e` |
| 8 | SEP-10 challenge reader | `96ac6e7`, `55f944c`, `8708a6a` |
| 9 | Differential test against the SDK | `d0ac49b` |
| 10 | Signature and threshold verification | `facded4`, `e7f83db` |
| 11 | Challenge issuance | `dbf37e9`, `d1cc5a3` |
| 12 | `internal/account` Horizon fetcher | `0c6f90a`, `a7328ca` |
| 13 | `internal/clientdomain` resolver | `3c743a4` |
| 14 | `internal/token` JWT | `b824ce2`, `073383c` |
| 15 | Store records and migrations | `2204d5c`, `3cf779d` |
| 16 | Postgres store and cleanup loop | `34361b7`, `08cfb04` |

## Next

Task 17, `internal/httpapi` — router, middleware, and the health endpoint.

## MUST DO BEFORE SUBMISSION: run the store integration tests

**The replay-protection SQL has never been executed.** Task 16's nine build-tagged tests
compile and have never run: this environment has no Docker, no `psql`, no Postgres. Every
statement in `internal/store/postgres.go` is unexercised, including the single atomic
`UPDATE` that is the whole of the replay protection. Task 19 tests replay *behaviour*
against a fake that mimics the atomic update, and a fake cannot validate SQL.

Run this against a real Postgres before trusting the store:

```bash
SEP10_TEST_DATABASE_URL=postgres://... \
  go test -tags postgres_integration ./internal/store/ -v
```

`TestConsumeChallengeIsAtomic` is the one that matters — it races eight consumers of one
challenge and requires exactly one to win. Static review says the statement is correct.
That is not the same as knowing it is.

## Open findings not recorded in the plan

**The `AccountFetcher` error text must not carry Horizon detail.** `VerifyClient` wraps a lookup
failure as `fmt.Errorf("%w: %s", ErrAccountLookupFailed, err)`, interpolating whatever the
fetcher returned. That is by design, so the production fetcher in Task 12 is responsible for not
putting a raw Horizon response body into its error. Flagged as Minor during the Task 10 review.
The same applies to the client domain resolver in Task 13, whose error is flattened into
`ErrClientDomainRejected` with `%s`. Neither may carry an upstream response body — status code
and a fixed description only.

**A resolver must never return an empty signing key without an error.** `Issue` now rejects that
case with `ErrClientDomainRejected` (commit `d1cc5a3`), because silently issuing a challenge
that is not bound to the wallet is the wrong way to absorb a resolver bug. Task 13's resolver
must also error rather than return `("", nil)`.

**Two deliberate divergences from the SDK.** Anchorage rejects duplicate `client_domain` and
duplicate `web_auth_domain` operations; `txnbuild.ReadChallengeTx` accepts them. It also reads
`client_domain` at all, which the SDK cannot. Both are recorded in `docs/sdk-findings.md`, and
Task 9's differential corpus deliberately excludes both shapes. Do not add a duplicate-operation
case to that table — it will fail, and the failure means nothing.

**Report arithmetic has been unreliable.** Implementer subagents miscounted their own test
totals in four separate tasks. The artifacts were correct every time; only the summaries were
wrong. Count from the source and cross-check against `--- PASS` lines rather than trusting a
report.

**`go.sum` carries checksums for superseded versions** touched during resolution. Normal, not
hand-editable, no action.

**`lib/pq` appears in `go.sum` from Task 16 onward, including an `h1:` source hash, and that is
not a violation.** `go mod why -m github.com/lib/pq` traces the path through
`golang-migrate/v4/source/iofs.test`: upstream's own external test for the `iofs` package
blank-imports `database/postgres`, and `go mod tidy` records the hashes needed to run
`go test all`. Anchorage imports only `database/pgx/v5` and nothing links `lib/pq`. The ban is
now `go list -deps ./... | grep lib/pq`, which must print nothing — that is what the ban always
meant. Do not chase the `go.sum` grep to `0`, do not hand-edit `go.sum`, and do not drop
`source/iofs` to satisfy it.

**A security control needs a mutation test, not just a test named after it.** Two defects in this
project were guards that no test actually reached, each hidden because something else did the
rejecting: the client-domain authentication bypass in `verify.go` (the exclusion was only ever
tested at thresholds of 1 and 2, never at 0, which is the Stellar default) and the JWT issuer
check (its test also varied the secret, so the signature check rejected first). Both passed
review. For every security control, delete the line, run the suite, confirm something fails,
restore it.

## Things that will waste your time otherwise

- `GOTOOLCHAIN=go1.25.12` must be exported for every `go` command, `make check` included.
  Without it the toolchain fails to resolve.
- A task that adds a first-time import needs `go mod tidy`, and `go.mod`/`go.sum` are then
  staged with that task's commit. This is expected, not a workaround.
- The plan is the source of truth and has been corrected many times when it was wrong, in both
  directions: prose that misdescribed its own code, and code blocks that had drifted from what
  shipped. Fix the plan, not the Makefile or the CI workflow, and never relax a check to make a
  build pass. When a fix changes shipped behaviour, sync the plan's code block in the same commit.

## Deferred until after submission

File an upstream issue against `go-stellar-sdk` for the `client_domain` rejection at
`txnbuild/transaction.go:1270`. The user wants this held until Anchorage is submitted.
