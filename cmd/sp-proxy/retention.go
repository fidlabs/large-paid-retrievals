package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/fidlabs/paid-retrievals/internal/sqlitestore"
)

const dbPruneInterval = time.Hour

// startDBRetentionPruner runs Prune on a background ticker. retention <= 0 disables pruning.
func startDBRetentionPruner(store *sqlitestore.Store, retention time.Duration, logger *slog.Logger) {
	if retention <= 0 {
		logger.Info("db retention pruning disabled", "db_retention", retention.String())
		return
	}
	logger.Info("db retention pruning enabled",
		"db_retention", retention.String(),
		"prune_interval", dbPruneInterval.String(),
	)
	go func() {
		prune := func() {
			stats, err := store.Prune(context.Background(), retention)
			if err != nil {
				logger.Error("db retention prune failed", "error", err)
				return
			}
			if stats.UsedNonces == 0 && stats.DealAllocations == 0 && stats.Deals == 0 &&
				stats.SettlementCredits == 0 && stats.SettlementPools == 0 {
				logger.Debug("db retention prune complete", "removed", stats)
				return
			}
			logger.Info("db retention prune complete",
				"used_nonces", stats.UsedNonces,
				"deal_allocations", stats.DealAllocations,
				"deals", stats.Deals,
				"settlement_credits", stats.SettlementCredits,
				"settlement_pools", stats.SettlementPools,
			)
		}
		prune()
		ticker := time.NewTicker(dbPruneInterval)
		defer ticker.Stop()
		for range ticker.C {
			prune()
		}
	}()
}
