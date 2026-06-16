package sqlitestore

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/fidlabs/paid-retrievals/internal/dealstore"
)

// PruneStats counts rows removed by Prune.
type PruneStats struct {
	UsedNonces      int64
	PoolAllocations int64
	Deals           int64
	PoolCredits     int64
	Pools           int64
}

// Prune deletes SQLite rows older than retention and runs VACUUM to reclaim disk.
// Retention is measured from last activity timestamps (quote, allocation expiry, pool close).
// Open settlement pools and deals with active allocations are never removed.
//
// pool_credits and pools use max(retention, dealstore.PaidAccessTTL) so idempotency rows
// outlive the on-chain payment freshness window even if retention is misconfigured short.
func (s *Store) Prune(ctx context.Context, retention time.Duration) (PruneStats, error) {
	if retention <= 0 {
		return PruneStats{}, nil
	}
	cutoff, poolCutoff := pruneCutoffs(retention)

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
	stats.PoolAllocations, err = execDelete(ctx, tx, `DELETE FROM pool_allocations WHERE access_expires_at < ?`, cutoff)
	if err != nil {
		return stats, fmt.Errorf("prune pool_allocations: %w", err)
	}
	stats.Deals, err = execDelete(ctx, tx, `
		DELETE FROM deals
		WHERE last_quoted_at < ?
		  AND deal_uuid NOT IN (SELECT deal_uuid FROM pool_allocations)
	`, cutoff)
	if err != nil {
		return stats, fmt.Errorf("prune deals: %w", err)
	}
	stats.PoolCredits, err = execDelete(ctx, tx, `
		DELETE FROM pool_credits
		WHERE pool_id IN (
			SELECT pool_id FROM pools
			WHERE closed_at IS NOT NULL AND closed_at < ?
		)
	`, poolCutoff)
	if err != nil {
		return stats, fmt.Errorf("prune pool_credits: %w", err)
	}
	stats.Pools, err = execDelete(ctx, tx, `
		DELETE FROM pools
		WHERE closed_at IS NOT NULL AND closed_at < ?
	`, poolCutoff)
	if err != nil {
		return stats, fmt.Errorf("prune pools: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return stats, err
	}
	if stats.UsedNonces == 0 && stats.PoolAllocations == 0 && stats.Deals == 0 &&
		stats.PoolCredits == 0 && stats.Pools == 0 {
		return stats, nil
	}
	if _, err := s.db.ExecContext(ctx, `VACUUM`); err != nil {
		return stats, fmt.Errorf("prune vacuum: %w", err)
	}
	return stats, nil
}

func pruneCutoffs(retention time.Duration) (cutoff, poolCutoff int64) {
	now := time.Now()
	cutoff = now.Add(-retention).Unix()
	poolRetention := retention
	if poolRetention < dealstore.PaidAccessTTL {
		poolRetention = dealstore.PaidAccessTTL
	}
	poolCutoff = now.Add(-poolRetention).Unix()
	return cutoff, poolCutoff
}

func execDelete(ctx context.Context, tx *sql.Tx, query string, args ...any) (int64, error) {
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
