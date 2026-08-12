# Configuration

Every variable comes from the environment and is validated at startup. The server refuses to start against incomplete configuration rather than failing at the first request.

| Variable | Purpose | Default |
|---|---|---|
| `SEP10_SIGNING_SECRET` | Server signing key (`S...`). Never logged. | required |
| `SEP10_NETWORK_PASSPHRASE` | Network passphrase | required |
| `SEP10_HORIZON_URL` | Horizon endpoint for account lookups | required |
| `SEP10_WEB_AUTH_DOMAIN` | Domain hosting this service | required |
| `SEP10_HOME_DOMAINS` | Comma-separated allowed home domains | required |
| `SEP10_CHALLENGE_TIMEOUT` | Challenge validity | `300s` |
| `SEP10_JWT_SECRET` | HS256 signing secret. Never logged. | required |
| `SEP10_JWT_ISSUER` | JWT `iss` claim | required |
| `SEP10_JWT_LIFETIME` | Token lifetime | `24h` |
| `SEP10_CLIENT_DOMAIN_REQUIRED` | Whether `client_domain` is mandatory | `false` |
| `SEP10_CLIENT_DOMAIN_ALLOWLIST` | Optional comma-separated allowlist | empty |
| `SEP10_CLIENT_DOMAIN_CACHE_TTL` | Resolver cache lifetime | `5m` |
| `SEP10_TRUST_PROXY_HEADERS` | Honour `X-Forwarded-For` | `false` |
| `SEP10_DATABASE_URL` | Postgres connection string | required |
| `SEP10_LISTEN_ADDR` | Listen address | `:8080` |
| `SEP10_TOML_PATH` | Path to the SEP-1 TOML file | required |

**Warning**: Set `SEP10_TRUST_PROXY_HEADERS` to true **only** behind a proxy you control that overwrites the header. See the security page for why.
