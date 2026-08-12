// Command authd runs the Anchorage SEP-10 authentication server.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/0dillon/Anchorage/internal/account"
	"github.com/0dillon/Anchorage/internal/auth"
	"github.com/0dillon/Anchorage/internal/clientdomain"
	"github.com/0dillon/Anchorage/internal/config"
	"github.com/0dillon/Anchorage/internal/httpapi"
	applog "github.com/0dillon/Anchorage/internal/log"
	"github.com/0dillon/Anchorage/internal/store"
	"github.com/0dillon/Anchorage/internal/token"
)

const (
	// cleanupInterval is how often expired challenges are swept.
	cleanupInterval = 5 * time.Minute
	// shutdownTimeout bounds the wait for in-flight requests to finish.
	shutdownTimeout = 15 * time.Second
	// readHeaderTimeout bounds how long a client may take to send headers.
	readHeaderTimeout = 10 * time.Second
)

func main() {
	if err := run(); err != nil {
		// The logger may not exist yet, so this goes to stderr directly. The
		// error never carries a secret: every package that handles one omits
		// the value from its messages.
		fmt.Fprintf(os.Stderr, "authd: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}

	logger := applog.New(os.Stdout, slog.LevelInfo)

	// Cancelled on SIGINT or SIGTERM. Everything with a background loop takes
	// this context.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := db.Migrate(); err != nil {
		return err
	}

	accounts, err := account.NewFetcher(cfg.HorizonURL, nil)
	if err != nil {
		return err
	}

	resolver := clientdomain.NewResolver(clientdomain.ResolverConfig{
		Allowlist: cfg.ClientDomainAllowlist,
		CacheTTL:  cfg.ClientDomainCacheTTL,
	})

	issuer, err := auth.NewIssuer(auth.IssuerConfig{
		SigningSecret:        cfg.SigningSecret,
		NetworkPassphrase:    cfg.NetworkPassphrase,
		WebAuthDomain:        cfg.WebAuthDomain,
		HomeDomains:          cfg.HomeDomains,
		ChallengeTimeout:     cfg.ChallengeTimeout,
		ClientDomainRequired: cfg.ClientDomainRequired,
		Resolver:             resolver,
	})
	if err != nil {
		return err
	}

	tokens, err := token.NewIssuer(token.IssuerConfig{
		Secret:   []byte(cfg.JWTSecret),
		Issuer:   cfg.JWTIssuer,
		Lifetime: cfg.JWTLifetime,
	})
	if err != nil {
		return err
	}

	router, err := httpapi.NewRouter(httpapi.Deps{
		Logger:            logger,
		Issuer:            issuer,
		Tokens:            tokens,
		Accounts:          accounts,
		Challenges:        db,
		Health:            db,
		NetworkPassphrase: cfg.NetworkPassphrase,
		WebAuthDomain:     cfg.WebAuthDomain,
		HomeDomains:       cfg.HomeDomains,
		TOMLPath:          cfg.TOMLPath,
		SigningPublicKey:  cfg.SigningPublicKey,
		TrustProxyHeaders: cfg.TrustProxyHeaders,
	})
	if err != nil {
		return err
	}

	go db.CleanupExpiredChallenges(ctx, cleanupInterval, logger)

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           router,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	// The server runs in its own goroutine so this one can wait on the signal
	// context and shut it down.
	serverErr := make(chan error, 1)
	go func() {
		// No secret is logged here: SigningPublicKey is public and the rest is
		// operational detail.
		logger.Info("starting",
			"addr", cfg.ListenAddr,
			"web_auth_domain", cfg.WebAuthDomain,
			"home_domains", cfg.HomeDomains,
			"signing_key", cfg.SigningPublicKey,
		)
		serverErr <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("http server: %w", err)
		}
		return nil

	case <-ctx.Done():
		logger.Info("shutting down")

		// A fresh context: the signal context is already cancelled, and
		// shutdown needs time of its own to drain in-flight requests.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutting down: %w", err)
		}
		return nil
	}
}
