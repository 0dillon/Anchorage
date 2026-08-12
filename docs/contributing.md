# Contributing

Please see the repository's [CONTRIBUTING.md](../CONTRIBUTING.md) for full details. 

In summary:
* We use conventional commits.
* PRs are opened against a protected `main` branch.
* Ensure `make check` runs clean locally before every commit.

Two things to watch out for:
1. **The toolchain pin**: You must run `export GOTOOLCHAIN=go1.25.12` before running any Go command.
2. **Postgres tests**: The Postgres integration tests are behind the `postgres_integration` build tag and do not run in standard CI.

Issues carry area, type, and complexity labels, and each has acceptance criteria as checkboxes.
