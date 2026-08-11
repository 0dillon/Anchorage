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
