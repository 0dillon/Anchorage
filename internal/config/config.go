// Package config loads and validates the server's environment configuration.
// Nothing starts against unvalidated config.
package config

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
)

// minJWTSecretLen is the shortest HS256 secret accepted. Shorter secrets are
// brute-forceable offline once an attacker holds one issued token.
const minJWTSecretLen = 32

// Config holds every validated setting the server needs.
type Config struct {
	// SigningSecret is the server's Stellar signing key (S...). Never logged.
	SigningSecret string
	// SigningPublicKey is derived from SigningSecret at load, so callers that
	// only need the public key never handle the secret.
	SigningPublicKey string

	NetworkPassphrase string
	HorizonURL        string
	WebAuthDomain     string
	HomeDomains       []string
	ChallengeTimeout  time.Duration

	// JWTSecret is the HS256 signing secret. Never logged.
	JWTSecret   string
	JWTIssuer   string
	JWTLifetime time.Duration

	ClientDomainRequired  bool
	ClientDomainAllowlist []string
	ClientDomainCacheTTL  time.Duration

	DatabaseURL string
	ListenAddr  string
	TOMLPath    string

	TrustProxyHeaders bool
}

// Load reads configuration through getenv and validates all of it. The error
// names the offending variable and never contains a secret's value.
func Load(getenv func(string) string) (*Config, error) {
	cfg := &Config{}
	var err error

	if cfg.SigningSecret, err = required(getenv, "SEP10_SIGNING_SECRET"); err != nil {
		return nil, err
	}
	kp, parseErr := keypair.ParseFull(cfg.SigningSecret)
	if parseErr != nil {
		// Deliberately does not include the value.
		return nil, fmt.Errorf("SEP10_SIGNING_SECRET is not a valid Stellar secret seed")
	}
	cfg.SigningPublicKey = kp.Address()

	if cfg.NetworkPassphrase, err = required(getenv, "SEP10_NETWORK_PASSPHRASE"); err != nil {
		return nil, err
	}

	if cfg.HorizonURL, err = required(getenv, "SEP10_HORIZON_URL"); err != nil {
		return nil, err
	}
	if u, parseErr := url.Parse(cfg.HorizonURL); parseErr != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("SEP10_HORIZON_URL is not a valid absolute URL: %q", cfg.HorizonURL)
	}

	if cfg.WebAuthDomain, err = required(getenv, "SEP10_WEB_AUTH_DOMAIN"); err != nil {
		return nil, err
	}

	rawHomeDomains, err := required(getenv, "SEP10_HOME_DOMAINS")
	if err != nil {
		return nil, err
	}
	cfg.HomeDomains = splitList(rawHomeDomains)
	if len(cfg.HomeDomains) == 0 {
		return nil, fmt.Errorf("SEP10_HOME_DOMAINS contains no non-empty entries")
	}

	if cfg.ChallengeTimeout, err = duration(getenv, "SEP10_CHALLENGE_TIMEOUT", 300*time.Second); err != nil {
		return nil, err
	}
	if cfg.ChallengeTimeout < time.Second {
		return nil, fmt.Errorf("SEP10_CHALLENGE_TIMEOUT must be at least 1s, got %s", cfg.ChallengeTimeout)
	}

	if cfg.JWTSecret, err = required(getenv, "SEP10_JWT_SECRET"); err != nil {
		return nil, err
	}
	if len(cfg.JWTSecret) < minJWTSecretLen {
		return nil, fmt.Errorf("SEP10_JWT_SECRET must be at least %d bytes", minJWTSecretLen)
	}

	if cfg.JWTIssuer, err = required(getenv, "SEP10_JWT_ISSUER"); err != nil {
		return nil, err
	}

	if cfg.JWTLifetime, err = duration(getenv, "SEP10_JWT_LIFETIME", 24*time.Hour); err != nil {
		return nil, err
	}
	if cfg.JWTLifetime <= 0 {
		return nil, fmt.Errorf("SEP10_JWT_LIFETIME must be positive, got %s", cfg.JWTLifetime)
	}

	if cfg.ClientDomainRequired, err = boolean(getenv, "SEP10_CLIENT_DOMAIN_REQUIRED", false); err != nil {
		return nil, err
	}
	cfg.ClientDomainAllowlist = splitList(getenv("SEP10_CLIENT_DOMAIN_ALLOWLIST"))

	if cfg.ClientDomainCacheTTL, err = duration(getenv, "SEP10_CLIENT_DOMAIN_CACHE_TTL", 5*time.Minute); err != nil {
		return nil, err
	}
	if cfg.ClientDomainCacheTTL <= 0 {
		return nil, fmt.Errorf("SEP10_CLIENT_DOMAIN_CACHE_TTL must be positive, got %s", cfg.ClientDomainCacheTTL)
	}

	if cfg.DatabaseURL, err = required(getenv, "SEP10_DATABASE_URL"); err != nil {
		return nil, err
	}

	cfg.ListenAddr = getenv("SEP10_LISTEN_ADDR")
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8080"
	}

	if cfg.TOMLPath, err = required(getenv, "SEP10_TOML_PATH"); err != nil {
		return nil, err
	}

	if cfg.TrustProxyHeaders, err = boolean(getenv, "SEP10_TRUST_PROXY_HEADERS", false); err != nil {
		return nil, err
	}

	return cfg, nil
}

// required reads a variable that must be present and non-empty.
func required(getenv func(string) string, name string) (string, error) {
	v := strings.TrimSpace(getenv(name))
	if v == "" {
		return "", fmt.Errorf("%s is required but not set", name)
	}
	return v, nil
}

// duration reads an optional duration, falling back to def when unset.
func duration(getenv func(string) string, name string, def time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(getenv(name))
	if raw == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s is not a valid duration: %q", name, raw)
	}
	return d, nil
}

// boolean reads an optional boolean, falling back to def when unset.
func boolean(getenv func(string) string, name string, def bool) (bool, error) {
	raw := strings.TrimSpace(getenv(name))
	if raw == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s is not a valid boolean: %q", name, raw)
	}
	return b, nil
}

// splitList splits a comma-separated list, trimming spaces and dropping empties.
func splitList(raw string) []string {
	out := []string{}
	for _, part := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
