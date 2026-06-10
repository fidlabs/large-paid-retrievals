package sqlitestore

import (
	"context"
	"database/sql"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/fidlabs/paid-retrievals/internal/dealstore"
	"github.com/google/uuid"
)

func (s *Store) OpenPool(ctx context.Context, payer, payee string) (*dealstore.PoolSnapshot, error) {
	var poolID, remainingStr, settledStr string
	err := s.db.QueryRowContext(ctx, `
		SELECT pool_id, remaining_base_units, settled_base_units
		FROM pools
		WHERE payer = ? AND payee = ? AND closed_at IS NULL
		ORDER BY created_at DESC
		LIMIT 1
	`, payer, payee).Scan(&poolID, &remainingStr, &settledStr)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &dealstore.PoolSnapshot{
		PoolID:             poolID,
		RemainingBaseUnits: strings.TrimSpace(remainingStr),
		SettledBaseUnits:   strings.TrimSpace(settledStr),
	}, nil
}

func (s *Store) GetActiveAllocation(ctx context.Context, dealUUID, client, cid string, nowUnix int64) (*dealstore.DealAllocation, error) {
	var a dealstore.DealAllocation
	err := s.db.QueryRowContext(ctx, `
		SELECT deal_uuid, pool_id, client, cid, price_base_units, settle_tx_hash, allocated_at, access_expires_at
		FROM pool_allocations
		WHERE deal_uuid = ? AND client = ? AND cid = ? AND access_expires_at > ?
	`, dealUUID, client, cid, nowUnix).Scan(
		&a.DealUUID, &a.PoolID, &a.Client, &a.CID, &a.PriceBaseUnits, &a.SettleTxHash, &a.AllocatedAt, &a.AccessExpiresAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *Store) CreditPool(ctx context.Context, credit dealstore.PoolCredit) error {
	if credit.CreditedBaseUnits == nil || credit.CreditedBaseUnits.Sign() <= 0 {
		return dealstore.ErrZeroPoolCredit
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var existingPoolID string
	err = tx.QueryRowContext(ctx, `
		SELECT pool_id FROM pool_credits WHERE settle_tx_hash = ?
	`, credit.SettleTxHash).Scan(&existingPoolID)
	if err == nil {
		return tx.Commit()
	}
	if err != sql.ErrNoRows {
		return err
	}

	poolID, remaining, err := openPoolForPair(ctx, tx, credit.Payer, credit.Payee)
	if err != nil {
		return err
	}
	if poolID == "" {
		poolID = uuid.NewString()
		now := time.Now().Unix()
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO pools(pool_id, payer, payee, settled_base_units, remaining_base_units, created_at)
			VALUES(?,?,?,?,?,?)
		`, poolID, credit.Payer, credit.Payee, "0", "0", now); err != nil {
			return err
		}
		remaining = big.NewInt(0)
	}

	newRemaining := new(big.Int).Add(remaining, credit.CreditedBaseUnits)
	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO pool_credits(credit_id, pool_id, settle_tx_hash, credited_base_units, credited_at)
		VALUES(?,?,?,?,?)
	`, uuid.NewString(), poolID, credit.SettleTxHash, credit.CreditedBaseUnits.String(), now); err != nil {
		return err
	}
	var settledSoFar string
	if err := tx.QueryRowContext(ctx, `
		SELECT settled_base_units FROM pools WHERE pool_id = ?
	`, poolID).Scan(&settledSoFar); err != nil {
		return err
	}
	totalSettled, err := addBaseUnitsString(settledSoFar, credit.CreditedBaseUnits)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE pools
		SET settled_base_units = ?, remaining_base_units = ?, closed_at = NULL
		WHERE pool_id = ?
	`, totalSettled.String(), newRemaining.String(), poolID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) TryAllocateDeal(ctx context.Context, req dealstore.AllocateDealRequest) (*dealstore.DealAllocation, error) {
	if req.PriceBaseUnits == nil || req.PriceBaseUnits.Sign() <= 0 {
		return nil, fmt.Errorf("sqlitestore: invalid price base units")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().Unix()
	var existing dealstore.DealAllocation
	err = tx.QueryRowContext(ctx, `
		SELECT deal_uuid, pool_id, client, cid, price_base_units, settle_tx_hash, allocated_at, access_expires_at
		FROM pool_allocations WHERE deal_uuid = ?
	`, req.DealUUID).Scan(
		&existing.DealUUID, &existing.PoolID, &existing.Client, &existing.CID,
		&existing.PriceBaseUnits, &existing.SettleTxHash, &existing.AllocatedAt, &existing.AccessExpiresAt,
	)
	if err == nil {
		if existing.Client == req.Client && existing.CID == req.CID && existing.AccessExpiresAt > now {
			return &existing, tx.Commit()
		}
		return nil, fmt.Errorf("sqlitestore: deal already allocated")
	}
	if err != sql.ErrNoRows {
		return nil, err
	}

	poolID, remaining, err := openPoolForPair(ctx, tx, req.Payer, req.Payee)
	if err != nil {
		return nil, err
	}
	if poolID == "" || remaining.Cmp(req.PriceBaseUnits) < 0 {
		return nil, dealstore.ErrInsufficientPool
	}

	newRemaining := new(big.Int).Sub(remaining, req.PriceBaseUnits)
	closedAt := interface{}(nil)
	if newRemaining.Sign() == 0 {
		closedAt = now
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE pools SET remaining_base_units = ?, closed_at = ? WHERE pool_id = ?
	`, newRemaining.String(), closedAt, poolID); err != nil {
		return nil, err
	}

	settleTx := strings.TrimSpace(req.SettleTxHash)
	if settleTx == "" {
		if err := tx.QueryRowContext(ctx, `
			SELECT settle_tx_hash FROM pool_credits
			WHERE pool_id = ? ORDER BY credited_at DESC LIMIT 1
		`, poolID).Scan(&settleTx); err != nil && err != sql.ErrNoRows {
			return nil, err
		}
	}

	accessExpires := now + int64(req.AccessTTL.Seconds())
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO pool_allocations(deal_uuid, pool_id, client, cid, price_base_units, settle_tx_hash, allocated_at, access_expires_at)
		VALUES(?,?,?,?,?,?,?,?)
	`, req.DealUUID, poolID, req.Client, req.CID, req.PriceBaseUnits.String(), settleTx, now, accessExpires); err != nil {
		return nil, err
	}

	res, err := tx.ExecContext(ctx, `
		UPDATE deals
		SET last_paid_at = ?, last_paid_tx_hash = ?, client = ?
		WHERE deal_uuid = ?
	`, now, settleTx, req.Client, req.DealUUID)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, dealstore.ErrDealNotFound
	}

	alloc := &dealstore.DealAllocation{
		DealUUID:        req.DealUUID,
		PoolID:          poolID,
		Client:          req.Client,
		CID:             req.CID,
		PriceBaseUnits:  req.PriceBaseUnits.String(),
		SettleTxHash:    settleTx,
		AllocatedAt:     now,
		AccessExpiresAt: accessExpires,
	}
	return alloc, tx.Commit()
}

func openPoolForPair(ctx context.Context, tx *sql.Tx, payer, payee string) (poolID string, remaining *big.Int, err error) {
	var remainingStr string
	err = tx.QueryRowContext(ctx, `
		SELECT pool_id, remaining_base_units
		FROM pools
		WHERE payer = ? AND payee = ? AND closed_at IS NULL
		ORDER BY created_at DESC
		LIMIT 1
	`, payer, payee).Scan(&poolID, &remainingStr)
	if err == sql.ErrNoRows {
		return "", big.NewInt(0), nil
	}
	if err != nil {
		return "", nil, err
	}
	remaining, ok := new(big.Int).SetString(remainingStr, 10)
	if !ok {
		return "", nil, fmt.Errorf("sqlitestore: invalid remaining_base_units %q", remainingStr)
	}
	if remaining.Sign() <= 0 {
		return "", big.NewInt(0), nil
	}
	return poolID, remaining, nil
}

func addBaseUnitsString(current string, add *big.Int) (*big.Int, error) {
	base, ok := new(big.Int).SetString(strings.TrimSpace(current), 10)
	if !ok {
		return nil, fmt.Errorf("sqlitestore: invalid settled_base_units %q", current)
	}
	_, total, err := addBaseUnits(base, add)
	return total, err
}

func addBaseUnits(current, add *big.Int) (*big.Int, *big.Int, error) {
	if add == nil || add.Sign() <= 0 {
		return nil, nil, fmt.Errorf("sqlitestore: invalid base units to add")
	}
	newTotal := new(big.Int).Add(new(big.Int).Set(current), add)
	return newTotal, new(big.Int).Set(newTotal), nil
}
