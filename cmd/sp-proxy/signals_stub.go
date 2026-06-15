//go:build !unix

package main

import (
	"log/slog"

	"github.com/fidlabs/paid-retrievals/internal/dealstore"
)

// startSIGUSR1StateDump is a no-op on platforms without SIGUSR1 (e.g. Windows).
func startSIGUSR1StateDump(_ dealstore.DealStore, _ *slog.Logger) {}
