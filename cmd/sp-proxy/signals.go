package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/fidlabs/paid-retrievals/internal/dealstore"
)

// startSIGUSR1StateDump logs deals and settlement ledger rows when the process receives SIGUSR1.
// Example: kill -USR1 $(pidof sp-proxy)
func startSIGUSR1StateDump(store dealstore.DealStore, logger *slog.Logger) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	go func() {
		for range ch {
			logger.Info("SIGUSR1 received; dumping deals and settlement ledger state")
			if err := store.DumpState(context.Background(), os.Stderr); err != nil {
				logger.Error("state dump failed", "error", err)
			}
		}
	}()
}
