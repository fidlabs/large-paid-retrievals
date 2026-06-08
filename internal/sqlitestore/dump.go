package sqlitestore

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"time"
)

// DumpState writes all deals (quotes) and settlement ledger rows to w for operator diagnostics.
func (s *Store) DumpState(ctx context.Context, w io.Writer) error {
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := fmt.Fprintf(w, "=== sp-proxy state dump (%s) ===\n", now); err != nil {
		return err
	}
	if err := s.dumpDeals(ctx, w); err != nil {
		return err
	}
	if err := s.dumpSettlementPools(ctx, w); err != nil {
		return err
	}
	if err := s.dumpSettlementCredits(ctx, w); err != nil {
		return err
	}
	if err := s.dumpDealAllocations(ctx, w); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w)
	return err
}

func (s *Store) dumpDeals(ctx context.Context, w io.Writer) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT deal_uuid, client, cid, price_usdfc, payee_0x, created_at, last_quoted_at,
		       last_paid_at, last_paid_tx_hash
		FROM deals
		ORDER BY last_quoted_at DESC, deal_uuid
	`)
	if err != nil {
		return fmt.Errorf("dump deals: %w", err)
	}
	defer rows.Close()

	if _, err := fmt.Fprintln(w, "--- deals ---"); err != nil {
		return err
	}
	n := 0
	for rows.Next() {
		var (
			dealUUID, client, cid, priceUSDFC, payee0x, lastPaidTx string
			createdAt, lastQuotedAt                                  int64
			lastPaidAt                                               sql.NullInt64
		)
		if err := rows.Scan(&dealUUID, &client, &cid, &priceUSDFC, &payee0x, &createdAt, &lastQuotedAt,
			&lastPaidAt, &lastPaidTx); err != nil {
			return fmt.Errorf("dump deals scan: %w", err)
		}
		_, err := fmt.Fprintf(w,
			"deal_uuid=%s client=%s cid=%s price_usdfc=%s payee_0x=%s created_at=%s last_quoted_at=%s last_paid_at=%s last_paid_tx_hash=%s\n",
			dealUUID, client, cid, priceUSDFC, payee0x,
			formatUnix(createdAt), formatUnix(lastQuotedAt), formatNullUnix(lastPaidAt),
			lastPaidTx,
		)
		if err != nil {
			return err
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("dump deals: %w", err)
	}
	_, err = fmt.Fprintf(w, "(%d deal(s))\n", n)
	return err
}

func (s *Store) dumpSettlementPools(ctx context.Context, w io.Writer) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT pool_id, payer, payee, settled_base_units, remaining_base_units, created_at, closed_at
		FROM settlement_pools
		ORDER BY created_at DESC, pool_id
	`)
	if err != nil {
		return fmt.Errorf("dump settlement_pools: %w", err)
	}
	defer rows.Close()

	if _, err := fmt.Fprintln(w, "--- settlement_pools ---"); err != nil {
		return err
	}
	n := 0
	for rows.Next() {
		var poolID, payer, payee, settled, remaining string
		var createdAt int64
		var closedAt sql.NullInt64
		if err := rows.Scan(&poolID, &payer, &payee, &settled, &remaining, &createdAt, &closedAt); err != nil {
			return fmt.Errorf("dump settlement_pools scan: %w", err)
		}
		status := "open"
		if closedAt.Valid {
			status = "closed"
		}
		_, err := fmt.Fprintf(w,
			"pool_id=%s payer=%s payee=%s settled_base_units=%s remaining_base_units=%s status=%s created_at=%s closed_at=%s\n",
			poolID, payer, payee, settled, remaining, status,
			formatUnix(createdAt), formatNullUnix(closedAt),
		)
		if err != nil {
			return err
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("dump settlement_pools: %w", err)
	}
	_, err = fmt.Fprintf(w, "(%d pool(s))\n", n)
	return err
}

func (s *Store) dumpSettlementCredits(ctx context.Context, w io.Writer) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT credit_id, pool_id, settle_tx_hash, credited_base_units, credited_at
		FROM settlement_credits
		ORDER BY credited_at DESC, credit_id
	`)
	if err != nil {
		return fmt.Errorf("dump settlement_credits: %w", err)
	}
	defer rows.Close()

	if _, err := fmt.Fprintln(w, "--- settlement_credits ---"); err != nil {
		return err
	}
	n := 0
	for rows.Next() {
		var creditID, poolID, settleTx, credited string
		var creditedAt int64
		if err := rows.Scan(&creditID, &poolID, &settleTx, &credited, &creditedAt); err != nil {
			return fmt.Errorf("dump settlement_credits scan: %w", err)
		}
		_, err := fmt.Fprintf(w,
			"credit_id=%s pool_id=%s settle_tx_hash=%s credited_base_units=%s credited_at=%s\n",
			creditID, poolID, settleTx, credited, formatUnix(creditedAt),
		)
		if err != nil {
			return err
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("dump settlement_credits: %w", err)
	}
	_, err = fmt.Fprintf(w, "(%d credit(s))\n", n)
	return err
}

func (s *Store) dumpDealAllocations(ctx context.Context, w io.Writer) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT deal_uuid, pool_id, client, cid, price_base_units, settle_tx_hash, allocated_at, access_expires_at
		FROM deal_allocations
		ORDER BY allocated_at DESC, deal_uuid
	`)
	if err != nil {
		return fmt.Errorf("dump deal_allocations: %w", err)
	}
	defer rows.Close()

	if _, err := fmt.Fprintln(w, "--- deal_allocations ---"); err != nil {
		return err
	}
	n := 0
	for rows.Next() {
		var dealUUID, poolID, client, cid, price, settleTx string
		var allocatedAt, accessExpiresAt int64
		if err := rows.Scan(&dealUUID, &poolID, &client, &cid, &price, &settleTx, &allocatedAt, &accessExpiresAt); err != nil {
			return fmt.Errorf("dump deal_allocations scan: %w", err)
		}
		_, err := fmt.Fprintf(w,
			"deal_uuid=%s pool_id=%s client=%s cid=%s price_base_units=%s settle_tx_hash=%s allocated_at=%s access_expires_at=%s\n",
			dealUUID, poolID, client, cid, price, settleTx,
			formatUnix(allocatedAt), formatUnix(accessExpiresAt),
		)
		if err != nil {
			return err
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("dump deal_allocations: %w", err)
	}
	_, err = fmt.Fprintf(w, "(%d allocation(s))\n", n)
	return err
}

func formatUnix(ts int64) string {
	if ts <= 0 {
		return "-"
	}
	return time.Unix(ts, 0).UTC().Format(time.RFC3339)
}

func formatNullUnix(n sql.NullInt64) string {
	if !n.Valid {
		return "-"
	}
	return formatUnix(n.Int64)
}
