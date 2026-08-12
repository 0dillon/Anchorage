# Security

**Proxy headers are untrusted by default.** The per-IP rate limit is the only control bounding unauthenticated challenge issuance and outbound TOML fetches to attacker-named domains. If proxy headers were trusted unconditionally, an attacker could send a forged `X-Forwarded-For` per request and bypass it entirely. The gate is config-controlled and defaults to false. Two tests pin it in both directions — one asserting a forged header is ignored by default, and a control asserting it is honoured when trusted.

**The client domain key proves participation, not authority.** When a challenge carries a `client_domain` operation, that key's signature must be present or verification fails as unrecognized — but its weight is excluded from the account threshold sum. Reversing this would let any client domain authenticate for any account. The exclusion is unconditional, failing closed even when the client domain key is also a signer on the account. A dedicated negative test asserts client-domain weight alone does not satisfy the threshold. This was a real bypass found during development: Stellar's default medium threshold is zero, so a challenge signed by the server plus any attacker-controlled client domain would have authenticated any account.

**A challenge is spent before its signatures are checked.** This is deliberate to prevent unlimited retry oracles.

**Duplicate operations are rejected.** A second `client_domain` or `web_auth_domain` operation in one challenge is rejected rather than silently overwriting the first. This diverges from the SDK, which accepts duplicates with last-one-wins semantics. Last-wins on a security-relevant operation is operation smuggling.

**The TOML resolver fetches attacker-named domains by design.** It enforces HTTPS only, a 5 second timeout, a 3 hop redirect cap, a 100 KB body cap, and deliberately uninformative errors. Private-IP blocking is not implemented and is not in the SEP-10 spec; if you run this where internal hosts are reachable, put it behind an egress policy. This is an open issue.

**Secrets are never logged.** The signing secret and JWT secret are never written to logs, never accepted as command-line flags, and never echoed in errors. Database connection errors are redacted of credentials.

**The service is unaudited.** Review it before running it in front of anything that matters.

