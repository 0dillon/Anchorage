# Divergence from the Go SDK

## The problem
SEP-10's `client_domain` flow requires that operation to be sourced at the client domain's own signing key — that is the mechanism by which the wallet proves its identity. The Go SDK's `ReadChallengeTx` requires every operation after the first to be sourced at the server account, and rejects anything else as unrecognized. Both `VerifyChallengeTxSigners` and `VerifyChallengeTxThreshold` call `ReadChallengeTx` internally, inheriting the rejection.

The consequence: a spec-compliant challenge cannot be read by the SDK that built it. Stripping the operation before verification does not work, because signatures cover the whole transaction.

## The response
Anchorage implements its own challenge reader in `internal/auth`. It uses the SDK for what the SDK does correctly: `BuildChallengeTx` for challenge construction and nonce generation, `tx.Hash` and `keypair.Verify` for cryptography. It does not reimplement ed25519.

## Why one code path, not two
The reader handles every challenge, whether or not a `client_domain` operation is present. Branching on the presence of that operation would mean inspecting attacker-supplied XDR to decide which validator to run, before either validator has run — a branch on untrusted input at the security boundary, and the classic shape of a parser-differential bug.

## How the divergence is contained
A differential test generates challenges across a table of shapes — valid, tampered source, bad sequence, expired, wrong nonce length, wrong home domain, unknown extra operation — and asserts that Anchorage's reader and the SDK's reader agree on every one: on accept or reject, and on the account, home domain, and memo extracted. Twenty comparison cases, six accepts and fourteen rejects, run against live SDK output rather than fixtures. Drift from upstream shows up as a test failure.

## Where the divergence is deliberate
Deliberate divergence is documented and carved out of the differential corpus: duplicate operation rejection, and `client_domain` handling itself, which the SDK has no opinion on because it rejects it outright.

## The long-term fix
The long-term fix is upstream. An issue against `go-stellar-sdk` proposing that `ReadChallengeTx` accept spec-compliant `client_domain` operations would let Anchorage retire its own reader and reduce duplicated validation across the ecosystem. This is tracked as an open issue.
