package token

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"
	"github.com/stretchr/testify/require"
)

var (
	testSecret = []byte("0123456789abcdef0123456789abcdef")
	testNow    = time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)

	// Derived, not pasted. A muxed strkey carries a checksum over the base
	// account and the id, and a hand-written one does not parse.
	testAccount = mustAddress(5)
	testMuxed   = mustMuxed(testAccount, 17)
)

func mustAddress(fill byte) string {
	var raw [32]byte
	for i := range raw {
		raw[i] = fill
	}
	kp, err := keypair.FromRawSeed(raw)
	if err != nil {
		panic(err)
	}
	return kp.Address()
}

func mustMuxed(address string, id uint64) string {
	muxed, err := xdr.MuxedAccountFromAccountId(address, id)
	if err != nil {
		panic(err)
	}
	return muxed.Address()
}

func newTestIssuer(t *testing.T) *Issuer {
	t.Helper()
	i, err := NewIssuer(IssuerConfig{
		Secret:   testSecret,
		Issuer:   "https://auth.example.com",
		Lifetime: time.Hour,
	})
	require.NoError(t, err)
	return i
}

func TestSubject(t *testing.T) {
	memo := uint64(1234)

	tests := []struct {
		name    string
		account string
		memo    *uint64
		want    string
	}{
		{"plain account", testAccount, nil, testAccount},
		{"account with memo", testAccount, &memo, testAccount + ":1234"},
		// A muxed account already carries the user id, so no memo is appended
		// and none can be: the issuer rejects that combination.
		{"muxed account", testMuxed, nil, testMuxed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, Subject(tt.account, tt.memo))
		})
	}
}

func TestIssueAndParse(t *testing.T) {
	i := newTestIssuer(t)
	memo := uint64(99)

	raw, err := i.Issue(Request{
		Account:      testAccount,
		Memo:         &memo,
		ClientDomain: "wallet.example.org",
		JTI:          "abc123",
		IssuedAt:     testNow,
	})
	require.NoError(t, err)

	claims, err := i.Parse(raw, testNow.Add(time.Minute))
	require.NoError(t, err)

	require.Equal(t, "https://auth.example.com", claims.Issuer)
	require.Equal(t, testAccount+":99", claims.Subject)
	require.Equal(t, "abc123", claims.ID)
	require.Equal(t, "wallet.example.org", claims.ClientDomain)
	require.Equal(t, testNow.Unix(), claims.IssuedAt.Unix())
	require.Equal(t, testNow.Add(time.Hour).Unix(), claims.ExpiresAt.Unix())
}

// client_domain is omitted entirely when no client domain was verified, rather
// than being present and empty.
func TestIssueOmitsEmptyClientDomain(t *testing.T) {
	i := newTestIssuer(t)

	raw, err := i.Issue(Request{Account: testAccount, JTI: "abc123", IssuedAt: testNow})
	require.NoError(t, err)

	claims, err := i.Parse(raw, testNow)
	require.NoError(t, err)
	require.Empty(t, claims.ClientDomain)
	require.Equal(t, testAccount, claims.Subject)
}

func TestParseRejectsExpiredToken(t *testing.T) {
	i := newTestIssuer(t)

	raw, err := i.Issue(Request{Account: testAccount, JTI: "abc123", IssuedAt: testNow})
	require.NoError(t, err)

	_, err = i.Parse(raw, testNow.Add(time.Hour+time.Second))
	require.ErrorIs(t, err, ErrTokenExpired)
}

// A token signed with a different algorithm is refused even when the attacker
// controls the header. This is the "alg" confusion guard.
func TestParseRejectsWrongAlgorithm(t *testing.T) {
	claims := Claims{RegisteredClaims: jwt.RegisteredClaims{
		Issuer:    "https://auth.example.com",
		Subject:   testAccount,
		ID:        "abc123",
		IssuedAt:  jwt.NewNumericDate(testNow),
		ExpiresAt: jwt.NewNumericDate(testNow.Add(time.Hour)),
	}}

	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS512, claims).SignedString(testSecret)
	require.NoError(t, err)

	i := newTestIssuer(t)
	_, err = i.Parse(raw, testNow)
	require.ErrorIs(t, err, ErrTokenInvalid)
}

func TestParseRejectsTamperedToken(t *testing.T) {
	i := newTestIssuer(t)

	raw, err := i.Issue(Request{Account: testAccount, JTI: "abc123", IssuedAt: testNow})
	require.NoError(t, err)

	tests := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"not a jwt", "not.a.jwt"},
		{"signature flipped", raw[:len(raw)-1] + "A"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := i.Parse(tt.raw, testNow)
			require.ErrorIs(t, err, ErrTokenInvalid)
		})
	}
}

// A token minted by a different issuer and signed with a different secret is
// refused. This only shows that the signature check rejects the token; it
// does not by itself show that the issuer is checked.
func TestParseRejectsForeignIssuer(t *testing.T) {
	other, err := NewIssuer(IssuerConfig{
		Secret:   []byte("ffffffffffffffffffffffffffffffff"),
		Issuer:   "https://evil.example.com",
		Lifetime: time.Hour,
	})
	require.NoError(t, err)

	raw, err := other.Issue(Request{Account: testAccount, JTI: "abc123", IssuedAt: testNow})
	require.NoError(t, err)

	_, err = newTestIssuer(t).Parse(raw, testNow)
	require.ErrorIs(t, err, ErrTokenInvalid)
}

// The iss claim is checked on its own, not merely as a side effect of the
// signature check. This token is signed with the SAME secret as the parsing
// issuer, so the only thing wrong with it is the issuer, and it must still be
// refused. Without this test, deleting the issuer check from Parse breaks
// nothing.
func TestParseRejectsForeignIssuerWithSameSecret(t *testing.T) {
	other, err := NewIssuer(IssuerConfig{
		Secret:   testSecret,
		Issuer:   "https://evil.example.com",
		Lifetime: time.Hour,
	})
	require.NoError(t, err)

	raw, err := other.Issue(Request{Account: testAccount, JTI: "abc123", IssuedAt: testNow})
	require.NoError(t, err)

	_, err = newTestIssuer(t).Parse(raw, testNow)
	require.ErrorIs(t, err, ErrTokenInvalid)
}

func TestNewIssuerValidates(t *testing.T) {
	tests := []struct {
		name string
		cfg  IssuerConfig
	}{
		{"short secret", IssuerConfig{Secret: []byte("short"), Issuer: "iss", Lifetime: time.Hour}},
		{"no issuer", IssuerConfig{Secret: testSecret, Lifetime: time.Hour}},
		{"no lifetime", IssuerConfig{Secret: testSecret, Issuer: "iss"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewIssuer(tt.cfg)
			require.Error(t, err)
			// The secret must not appear in the message.
			require.NotContains(t, err.Error(), string(tt.cfg.Secret))
		})
	}
}

func TestIssueRequiresJTI(t *testing.T) {
	i := newTestIssuer(t)

	_, err := i.Issue(Request{Account: testAccount, IssuedAt: testNow})
	require.Error(t, err)
}
