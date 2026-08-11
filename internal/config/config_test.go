package config

import (
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stretchr/testify/require"
)

// testKP is a deterministic keypair derived from a fixed raw seed. Deriving it
// rather than pasting a strkey literal keeps the test honest: a hand-written
// strkey carries a checksum and is easy to get subtly wrong.
var testKP = mustKeypair(7)

func mustKeypair(fill byte) *keypair.Full {
	var raw [32]byte
	for i := range raw {
		raw[i] = fill
	}
	kp, err := keypair.FromRawSeed(raw)
	if err != nil {
		panic(err)
	}
	return kp
}

// valid returns a complete set of environment values. Tests copy it and then
// remove or corrupt one entry.
func valid() map[string]string {
	return map[string]string{
		"SEP10_SIGNING_SECRET":     testKP.Seed(),
		"SEP10_NETWORK_PASSPHRASE": "Test SDF Network ; September 2015",
		"SEP10_HORIZON_URL":        "https://horizon-testnet.stellar.org",
		"SEP10_WEB_AUTH_DOMAIN":    "auth.example.com",
		"SEP10_HOME_DOMAINS":       "example.com, other.example.com",
		"SEP10_JWT_SECRET":         "0123456789abcdef0123456789abcdef",
		"SEP10_JWT_ISSUER":         "https://auth.example.com",
		"SEP10_DATABASE_URL":       "postgres://u:p@localhost:5432/db",
		"SEP10_TOML_PATH":          "./deploy/stellar.toml.example",
	}
}

func getenvFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(getenvFrom(valid()))
	require.NoError(t, err)

	require.Equal(t, []string{"example.com", "other.example.com"}, cfg.HomeDomains)
	require.Equal(t, 300*time.Second, cfg.ChallengeTimeout)
	require.Equal(t, 24*time.Hour, cfg.JWTLifetime)
	require.Equal(t, 5*time.Minute, cfg.ClientDomainCacheTTL)
	require.Equal(t, ":8080", cfg.ListenAddr)
	require.False(t, cfg.ClientDomainRequired)
	require.Empty(t, cfg.ClientDomainAllowlist)

	// The public key is derived at load so handlers never touch the secret.
	require.Equal(t, testKP.Address(), cfg.SigningPublicKey)
	// The secret is kept, but only where it is needed.
	require.Equal(t, testKP.Seed(), cfg.SigningSecret)
}

func TestLoadMissingRequired(t *testing.T) {
	required := []string{
		"SEP10_SIGNING_SECRET",
		"SEP10_NETWORK_PASSPHRASE",
		"SEP10_HORIZON_URL",
		"SEP10_WEB_AUTH_DOMAIN",
		"SEP10_HOME_DOMAINS",
		"SEP10_JWT_SECRET",
		"SEP10_JWT_ISSUER",
		"SEP10_DATABASE_URL",
		"SEP10_TOML_PATH",
	}

	for _, name := range required {
		t.Run(name, func(t *testing.T) {
			env := valid()
			delete(env, name)

			_, err := Load(getenvFrom(env))
			require.Error(t, err)
			require.Contains(t, err.Error(), name)
		})
	}
}

func TestLoadMalformed(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		// A public address is a well-formed strkey but not a seed.
		{"signing secret is an address", "SEP10_SIGNING_SECRET", testKP.Address()},
		{"horizon url not https", "SEP10_HORIZON_URL", "://nope"},
		{"jwt secret too short", "SEP10_JWT_SECRET", "short"},
		{"challenge timeout unparseable", "SEP10_CHALLENGE_TIMEOUT", "five minutes"},
		{"challenge timeout too small", "SEP10_CHALLENGE_TIMEOUT", "500ms"},
		{"jwt lifetime unparseable", "SEP10_JWT_LIFETIME", "forever"},
		{"cache ttl negative", "SEP10_CLIENT_DOMAIN_CACHE_TTL", "-1m"},
		{"client domain required not a bool", "SEP10_CLIENT_DOMAIN_REQUIRED", "yes please"},
		{"home domains empty after trim", "SEP10_HOME_DOMAINS", " , "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := valid()
			env[tt.key] = tt.value

			_, err := Load(getenvFrom(env))
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.key)
		})
	}
}

// A malformed secret must not leak into the error text.
func TestLoadNeverEchoesSecrets(t *testing.T) {
	const secret = "SBADSEEDVALUETHATSHOULDNEVERAPPEARINANERRORMESSAGE123456"

	env := valid()
	env["SEP10_SIGNING_SECRET"] = secret

	_, err := Load(getenvFrom(env))
	require.Error(t, err)
	require.NotContains(t, err.Error(), secret)
}
