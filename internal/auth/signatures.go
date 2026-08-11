package auth

import (
	"fmt"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/txnbuild"
)

// matchSigners pairs each signature on tx with at most one of signers, and
// returns the signers that were matched, in the order they were supplied.
//
// It mirrors txnbuild.verifyTxSignatures, which the SDK does not export. Every
// signature is consumed at most once, so one signature cannot satisfy two
// signers. Signers with no matching signature are simply absent from the
// result; deciding whether that is an error is the caller's job.
func matchSigners(tx *txnbuild.Transaction, networkPassphrase string, signers []string) ([]string, error) {
	txHash, err := tx.Hash(networkPassphrase)
	if err != nil {
		return nil, fmt.Errorf("hashing challenge: %w", err)
	}

	signatures := tx.Signatures()
	used := make(map[int]bool, len(signatures))
	found := make([]string, 0, len(signers))
	seen := make(map[string]bool, len(signers))

	for _, signer := range signers {
		kp, parseErr := keypair.ParseAddress(signer)
		if parseErr != nil {
			return nil, fmt.Errorf("%w: signer %q is not an address", ErrSignatureUnrecognized, signer)
		}

		for i, sig := range signatures {
			if used[i] {
				continue
			}
			// The hint is a cheap pre-filter; it is not a security check.
			if sig.Hint != kp.Hint() {
				continue
			}
			if kp.Verify(txHash[:], sig.Signature) == nil {
				used[i] = true
				if !seen[signer] {
					seen[signer] = true
					found = append(found, signer)
				}
				break
			}
		}
	}

	return found, nil
}
