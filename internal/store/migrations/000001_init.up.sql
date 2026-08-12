CREATE TABLE challenges (
    nonce         TEXT PRIMARY KEY,
    account       TEXT NOT NULL,
    home_domain   TEXT NOT NULL,
    client_domain TEXT,
    issued_at     TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    consumed_at   TIMESTAMPTZ
);

CREATE INDEX challenges_expires_at_idx ON challenges (expires_at);

CREATE TABLE sessions (
    jti           TEXT PRIMARY KEY,
    account       TEXT NOT NULL,
    memo          TEXT,
    home_domain   TEXT NOT NULL,
    client_domain TEXT,
    issued_at     TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL
);

CREATE INDEX sessions_account_issued_at_idx ON sessions (account, issued_at DESC);
