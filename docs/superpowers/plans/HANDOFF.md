# Anchorage — handoff

State as of commit `dbf37e9`, branch `main`, pushed. Working tree clean, `make check` green.

Plan: `docs/superpowers/plans/2026-08-10-sep10-auth-server.md` (23 tasks).
Execution ledger with full per-task detail: `.superpowers/sdd/progress.md` (git-ignored).

## Complete and reviewed

Tasks 1-10. Each passed a spec-compliance and a code-quality verdict.

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
| 10 | Signature and threshold verification | `facded4` |

## Implemented but NOT reviewed

**Task 11, challenge issuance, commit `dbf37e9`.** The code is written, committed and pushed,
and the suite is green, but the review gate never ran. It is the one gap in the chain. Run the
Task 11 review before starting Task 12, using
`.superpowers/sdd/task-11-brief.md` and `.superpowers/sdd/task-11-report.md`.

## Next

Task 12, `internal/account` — the Horizon account fetcher. Its brief has not been generated yet.

## Open findings not recorded in the plan

**The `AccountFetcher` error text must not carry Horizon detail.** `VerifyClient` wraps a lookup
failure as `fmt.Errorf("%w: %s", ErrAccountLookupFailed, err)`, interpolating whatever the
fetcher returned. That is by design, so the production fetcher in Task 12 is responsible for not
putting a raw Horizon response body into its error. Flagged as Minor during the Task 10 review.

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

## Things that will waste your time otherwise

- `GOTOOLCHAIN=go1.25.12` must be exported for every `go` command, `make check` included.
  Without it the toolchain fails to resolve.
- A task that adds a first-time import needs `go mod tidy`, and `go.mod`/`go.sum` are then
  staged with that task's commit. This is expected, not a workaround.
- The plan is the source of truth and has been corrected five times when it was wrong. Fix the
  plan, not the Makefile or the CI workflow, and never relax a check to make a build pass.

## Deferred until after submission

File an upstream issue against `go-stellar-sdk` for the `client_domain` rejection at
`txnbuild/transaction.go:1270`. The user wants this held until Anchorage is submitted.
