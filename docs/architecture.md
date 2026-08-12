# Architecture

## Request flow

**Issuing a challenge (`GET /auth`)**: The service validates the account strkey, rejects a memo combined with a muxed account, checks the home domain is allowed, and resolves the client domain if one was supplied. It builds the challenge, appends the `client_domain` operation if applicable and re-signs, stores the nonce, and returns the transaction XDR.

**Verifying a challenge (`POST /auth`)**: The service reads and structurally validates the challenge, consumes the nonce atomically, fetches the account from Horizon, and verifies signatures against either the master key or the account's signers and threshold. It requires the client domain key among the verified signers if the challenge carried one, issues a JWT, and records the session.

## Packages

| Package | Responsibility |
|---|---|
| `internal/auth` | Challenge reading, structural validation, signature verification |
| `internal/account` | Horizon account lookup, signers and thresholds |
| `internal/clientdomain` | Client domain TOML resolution with caching |
| `internal/token` | JWT issuance and parsing |
| `internal/store` | Postgres: replay protection, session audit |
| `internal/httpapi` | Router, middleware, handlers |
| `internal/config` | Environment loading and validation |
| `cmd/authd` | Entrypoint and wiring |

## Design decisions

**The nonce is spent before signatures are checked.** Verifying first would turn a live challenge into an unlimited retry oracle, allowing an attacker to try signatures against the same challenge indefinitely. The cost is that a client typo burns the challenge and they must request a new one.

**Consumption is a single atomic SQL statement**, not a read-then-write:
`UPDATE challenges SET consumed_at = $2 WHERE nonce = $1 AND consumed_at IS NULL AND expires_at > $2 RETURNING ...`
Two concurrent requests for the same challenge cannot both succeed. This is verified by an integration test with eight racing consumers where exactly one must win.
