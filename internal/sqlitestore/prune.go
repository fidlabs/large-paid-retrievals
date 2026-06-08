package sqlitestore

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// PruneStats counts rows removed by Prune.
type PruneStats struct {
	UsedNonces        int64
	DealAllocations   int64
	Deals             int64
	SettlementCredits int64
	SettlementPools   int64
}

// Prune deletes SQLite rows older than retention and runs VACUUM to reclaim disk.
// Retention is measured from last activity timestamps (quote, allocation expiry, pool close).
// Open settlement pools and deals with active allocations are never removed.
func (s *Store) Prune(ctx context.Context, retention time.Duration) (PruneStats, error) {
	if retention <= 0 {
		return PruneStats{}, nil
	}
	cutoff := time.Now().Add(-retention).Unix()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PruneStats{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var stats PruneStats
	stats.UsedNonces, err = execDelete(ctx, tx, `DELETE FROM used_nonces WHERE expires_unix < ?`, cutoff)
	if err != nil {
		return stats, fmt.Errorf("prune used_nonces: %w", err)
	}
	stats.DealAllocations, err = execDelete(ctx, tx, `DELETE FROM deal_allocations WHERE access_expires_at < ?`, cutoff)
	if err != nil {
		return stats, fmt.Errorf("prune deal_allocations: %w", err)
	}
	stats.Deals, err = execDelete(ctx, tx, `
		DELETE FROM deals
		WHERE last_quoted_at < ?
		  AND deal_uuid NOT IN (SELECT deal_uuid FROM deal_allocations)
	`, cutoff)
	if err != nil {
		return stats, fmt.Errorf("prune deals: %w", err)
	}
	stats.SettlementCredits, err = execDelete(ctx, tx, `
		DELETE FROM settlement_credits
		WHERE pool_id IN (
			SELECT pool_id FROM settlement_pools
			WHERE closed_at IS NOT NULL AND closed_at < ?
		)
	`, cutoff)
	if err != nil {
		return stats, fmt.Errorf("prune settlement_credits: %w", err)
	}
	stats.SettlementPools, err = execDelete(ctx, tx, `
		DELETE FROM settlement_pools
		WHERE closed_at IS NOT NULL AND closed_at < ?
	`, cutoff)
	if err != nil {
		return stats, fmt.Errorf("prune settlement_pools: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return stats, err
	}
	if _, err := s.db.ExecContext(ctx, `VACUUM`); err != nil {
		return stats, fmt.Errorf("prune vacuum: %w", err)
	}
	return stats, nil
}

func execDelete(ctx context.Context, tx *sql.Tx, query string, args ...any) (int64, error) {
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
