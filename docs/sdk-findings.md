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
