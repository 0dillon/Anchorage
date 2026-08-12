// Package account reads account signers and thresholds from Horizon.
//
// It makes the one request SEP-10 needs rather than using the SDK's
// horizonclient, whose methods take no context.Context and so cannot be
// cancelled. The response is decoded into the SDK's own account type, so the
// field names and the signer summary come from the SDK, not from here.
package account

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/0dillon/Anchorage/internal/auth"
	hProtocol "github.com/stellar/go-stellar-sdk/protocols/horizon"
)

// maxAccountBytes caps the response body. An account holds at most 20 signers,
// so a real response is a few kilobytes; anything near this cap is not one.
const maxAccountBytes = 256 * 1024

// defaultTimeout bounds a lookup when the caller supplies no HTTP client. A
// caller that passes its own client owns that client's timeout.
const defaultTimeout = 10 * time.Second

// Fetcher reads accounts from one Horizon instance.
type Fetcher struct {
	baseURL string
	client  *http.Client
}

// NewFetcher returns a Fetcher for the given Horizon URL. Passing nil for the
// client uses a client with a default timeout.
func NewFetcher(horizonURL string, client *http.Client) (*Fetcher, error) {
	u, err := url.Parse(horizonURL)
	if err != nil {
		return nil, fmt.Errorf("horizon url is not a valid URL: %q", horizonURL)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("horizon url must be absolute: %q", horizonURL)
	}
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}
	return &Fetcher{baseURL: horizonURL, client: client}, nil
}

// Account returns the account's signers and medium threshold.
//
// A 404 returns auth.ErrAccountNotFound, which is a normal SEP-10 case. Every
// other failure returns auth.ErrAccountLookupFailed. The two must never be
// confused: reporting an outage as a missing account would authenticate the
// account on its master key alone.
func (f *Fetcher) Account(ctx context.Context, accountID string) (*auth.Account, error) {
	endpoint, err := url.JoinPath(f.baseURL, "accounts", accountID)
	if err != nil {
		return nil, fmt.Errorf("%w: building url: %w", auth.ErrAccountLookupFailed, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: building request: %w", auth.ErrAccountLookupFailed, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		// Unwrapping keeps context.Canceled and context.DeadlineExceeded
		// visible to errors.Is, so a cancelled request is not mistaken for a
		// Horizon fault in the logs.
		return nil, fmt.Errorf("%w: %w", auth.ErrAccountLookupFailed, unwrapURLError(err))
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: %s", auth.ErrAccountNotFound, accountID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: horizon returned %d", auth.ErrAccountLookupFailed, resp.StatusCode)
	}

	// One byte over the cap, so an oversized body is detected rather than
	// silently truncated into something that might still decode.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAccountBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: reading body: %w", auth.ErrAccountLookupFailed, err)
	}
	if len(body) > maxAccountBytes {
		return nil, fmt.Errorf("%w: response body is too large", auth.ErrAccountLookupFailed)
	}

	var decoded hProtocol.Account
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, fmt.Errorf("%w: decoding body: %w", auth.ErrAccountLookupFailed, err)
	}

	return &auth.Account{
		Signers:      decoded.SignerSummary(),
		MedThreshold: int32(decoded.Thresholds.MedThreshold),
	}, nil
}

// unwrapURLError returns the cause inside a *url.Error so callers can test for
// context.Canceled with errors.Is.
func unwrapURLError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return urlErr.Err
	}
	return err
}
