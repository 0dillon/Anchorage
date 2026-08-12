#!/usr/bin/env bash
set -e

DRY_RUN=${DRY_RUN:-true}

echo "Creating labels..."
if [ "$DRY_RUN" = "false" ]; then
  gh label create "area/security" --force -c "#E4E669" || true
  gh label create "area/protocol" --force -c "#D4C5F9" || true
  gh label create "area/operability" --force -c "#B60205" || true
  gh label create "type/feature" --force -c "#0E8A16" || true
  gh label create "type/bug" --force -c "#D93F0B" || true
  gh label create "type/debt" --force -c "#FBCA04" || true
  gh label create "complexity/low" --force -c "#C2E0C6" || true
  gh label create "complexity/medium" --force -c "#F9D0C4" || true
  gh label create "complexity/high" --force -c "#5319E7" || true
else
  echo "(Dry run) gh label create ..."
fi

create_issue() {
  local title="$1"
  local labels="$2"
  local body="$3"

  echo "Creating issue: $title"
  if [ "$DRY_RUN" = "false" ]; then
    gh issue create --title "$title" --label "$labels" --body "$body"
  else
    echo "(Dry run) gh issue create --title \"$title\" --label \"$labels\""
  fi
}

create_issue "feat(clientdomain): add optional private-IP blocking to TOML resolver" "area/security,type/feature,complexity/medium" "### Summary
The client-domain TOML resolver currently enforces HTTPS-only, a 5-second timeout, a 3-hop redirect cap, and a 100 KB body limit. However, it does not block resolution to private/internal IP addresses.

### Acceptance Criteria
- [ ] Add an optional config boolean to block private IP resolution.
- [ ] Update the HTTP client transport to reject internal IPs during DNS resolution.
- [ ] Add tests ensuring internal IPs are rejected when enabled.

### Tech Stack
Go, \`net/http\`"

create_issue "refactor(auth): tighten error wrapping in challenge.go" "area/security,type/debt,complexity/low" "### Summary
Sentinel errors in \`challenge.go\` are currently wrapped using \`fmt.Errorf(\"%s: ...\", err)\` instead of \`%w\`. While this flattens the error chain and ensures internal third-party errors don't leak, we should evaluate if we can use \`%w\` safely while maintaining the boundary.

### Acceptance Criteria
- [ ] Review \`fmt.Errorf\` usages in \`challenge.go\`.
- [ ] Switch to \`%w\` where safe without exposing internal errors to the handler.
- [ ] Test that sentinel matching (\`errors.Is\`) remains intact.

### Tech Stack
Go, \`errors\`"

create_issue "refactor(store): enforce NOT NULL on nullable text columns" "area/security,type/debt,complexity/low" "### Summary
Three TEXT columns in the PostgreSQL schema are currently nullable. For consistency and stricter data integrity, they should be changed to \`NOT NULL DEFAULT ''\` where the absence of a value implies an empty string rather than NULL.

### Acceptance Criteria
- [ ] Create a new \`golang-migrate\` migration to alter the columns.
- [ ] Update \`internal/store\` to reflect the schema changes.
- [ ] Ensure integration tests pass.

### Tech Stack
PostgreSQL, \`golang-migrate\`, Go"

create_issue "feat(token): add support for EdDSA-signed JWTs" "area/protocol,type/feature,complexity/medium" "### Summary
Anchorage currently issues and verifies HS256 JWTs. The SEP-10 specification also permits EdDSA. Adding EdDSA support would provide stronger asymmetric guarantees for tokens.

### Acceptance Criteria
- [ ] Add config for EdDSA public/private keys.
- [ ] Update \`internal/token\` to support signing and parsing EdDSA.
- [ ] Add comprehensive tests for EdDSA issuance and verification.

### Tech Stack
Go, \`golang-jwt/jwt\`"

create_issue "feat(log): add configurable log levels" "area/operability,type/feature,complexity/low" "### Summary
The logging package currently logs at a fixed level. We should allow operators to configure the log level via an environment variable (e.g. \`SEP10_LOG_LEVEL\`).

### Acceptance Criteria
- [ ] Add \`SEP10_LOG_LEVEL\` to \`internal/config\`.
- [ ] Update \`internal/log\` to respect the configured level (debug, info, warn, error).
- [ ] Validate config correctly defaults to \`info\`.

### Tech Stack
Go, \`log/slog\`"

create_issue "feat(httpapi): add Prometheus metrics endpoint" "area/operability,type/feature,complexity/medium" "### Summary
To better monitor the service in production, we need a metrics endpoint (e.g. \`/metrics\`) that exposes challenge issuance rates, verification success/failure rates, and TOML resolver latencies.

### Acceptance Criteria
- [ ] Add a \`/metrics\` handler.
- [ ] Track GET /auth and POST /auth request counts and latencies.
- [ ] Expose the metrics in Prometheus format.

### Tech Stack
Go, \`prometheus/client_golang\`"

create_issue "ci: run Postgres integration tests in CI" "area/operability,type/feature,complexity/medium" "### Summary
The \`internal/store\` Postgres integration tests are currently hidden behind the \`postgres_integration\` build tag and only run locally. We should spin up a Postgres service container in GitHub Actions and run these tests automatically.

### Acceptance Criteria
- [ ] Update \`.github/workflows/ci.yml\` to include a Postgres service.
- [ ] Add a step to run \`go test -tags postgres_integration ./internal/store/\`.

### Tech Stack
GitHub Actions, Docker, Go"

create_issue "fix(upstream): ReadChallengeTx rejects spec-compliant client_domain" "area/protocol,type/bug,complexity/high" "### Summary
The official Go SDK's \`ReadChallengeTx\` rejects spec-compliant \`client_domain\` challenges because it expects every operation after the first to be sourced at the server account. SEP-10 requires the \`client_domain\` manage data operation to be sourced at the client domain's key. We should submit a PR upstream to fix this.

### Acceptance Criteria
- [ ] Fork \`stellar/go-stellar-sdk\` and fix \`ReadChallengeTx\`.
- [ ] Submit PR to upstream repository.
- [ ] Once merged, update Anchorage to use the fixed SDK and retire our custom reader if possible.

### Tech Stack
Go, Stellar SDK"

echo "Done."
