package store

import (
	"io/fs"
	"testing"

	"github.com/stretchr/testify/require"
)

// The migrate driver in database/pgx/v5 registers itself under the scheme
// "pgx5". A postgres:// URL would select the lib/pq driver instead, which this
// project does not depend on, so the scheme is rewritten before use.
func TestMigrationURL(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{
			name: "postgres scheme",
			in:   "postgres://u:p@localhost:5432/db?sslmode=disable",
			want: "pgx5://u:p@localhost:5432/db?sslmode=disable",
		},
		{
			name: "postgresql scheme",
			in:   "postgresql://u:p@localhost:5432/db",
			want: "pgx5://u:p@localhost:5432/db",
		},
		{
			name: "already pgx5",
			in:   "pgx5://u:p@localhost:5432/db",
			want: "pgx5://u:p@localhost:5432/db",
		},
		{name: "unsupported scheme", in: "mysql://u:p@localhost/db", wantErr: true},
		{name: "no scheme", in: "localhost:5432/db", wantErr: true},
		{name: "empty", in: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := migrationURL(tt.in)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// A rejection must not echo the connection string, which carries the password.
func TestMigrationURLNeverEchoesCredentials(t *testing.T) {
	_, err := migrationURL("mysql://user:hunter2@localhost/db")
	require.Error(t, err)
	require.NotContains(t, err.Error(), "hunter2")
}

// The migrations are embedded, so the binary carries its own schema and no
// files have to be shipped alongside it.
func TestMigrationsAreEmbedded(t *testing.T) {
	entries, err := fs.Glob(migrationsFS, "migrations/*.sql")
	require.NoError(t, err)
	require.ElementsMatch(t, []string{
		"migrations/000001_init.up.sql",
		"migrations/000001_init.down.sql",
	}, entries)

	up, err := fs.ReadFile(migrationsFS, "migrations/000001_init.up.sql")
	require.NoError(t, err)
	require.Contains(t, string(up), "CREATE TABLE challenges")
	require.Contains(t, string(up), "CREATE TABLE sessions")
}
