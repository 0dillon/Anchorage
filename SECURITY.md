# Security Policy

## Reporting a Vulnerability
If you discover a security vulnerability in Anchorage, please DO NOT file a public issue. Instead, disclose it privately by contacting: `<CONTACT>`.

## Scope
This scope covers the Anchorage SEP-10 server and its core packages (`internal/auth`, `internal/token`, `internal/clientdomain`, `internal/store`). It does not cover the official Stellar SDK (`go-stellar-sdk`).

## Unaudited Disclaimer
**This service is unaudited.** You are strongly encouraged to review it yourself before running it in front of anything that handles real funds or sensitive accounts.

## Known Limitations (Not Vulnerabilities)
The following behaviors are deliberate and known design decisions. Please do not report them as vulnerabilities:

- **Proxy headers are untrusted by default:** `X-Forwarded-For` is ignored unless `SEP10_TRUST_PROXY_HEADERS=true` is set. If enabled directly on the open internet without a trusted reverse proxy, rate limits can be bypassed.
- **No private-IP blocking in the TOML resolver:** The resolver fetches attacker-named domains to resolve `client_domain` SEP-1 TOML files. It enforces HTTPS-only, 5s timeout, 3-hop redirect caps, and a 100 KB body cap, but **it does not block private IP addresses**. Deploy this service behind a strict egress firewall policy to prevent SSRF against internal services.
