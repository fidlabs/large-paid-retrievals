package sqlitestore

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	piecepayment "github.com/fidlabs/paid-retrievals/internal/piecepayment"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(time.Hour)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS deals (
			deal_uuid TEXT PRIMARY KEY,
			client TEXT NOT NULL,
			cid TEXT NOT NULL,
			price_usdfc TEXT NOT NULL,
			payee_0x TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			last_quoted_at INTEGER NOT NULL,
			last_paid_at INTEGER,
			last_paid_tx_hash TEXT NOT NULL DEFAULT '',
			quoted_seen INTEGER NOT NULL DEFAULT 1,
			paid_seen INTEGER NOT NULL DEFAULT 0
		);`,
		`CREATE INDEX IF NOT EXISTS idx_deals_cid_client ON deals(cid, client);`,
		`CREATE TABLE IF NOT EXISTS used_nonces (
			deal_uuid TEXT NOT NULL,
			nonce TEXT NOT NULL,
			expires_unix INTEGER NOT NULL,
			used_at INTEGER NOT NULL,
			PRIMARY KEY(deal_uuid, nonce)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_used_nonces_exp ON used_nonces(expires_unix);`,
	}
	for _, q := range queries {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	// additive column for DBs created before payee_0x existed
	if _, err := s.db.Exec(`ALTER TABLE deals ADD COLUMN payee_0x TEXT NOT NULL DEFAULT ''`); err != nil {
		low := strings.ToLower(err.Error())
		if !strings.Contains(low, "duplicate column") && !strings.Contains(low, "already exists") {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	// additive column for DBs created before last_paid_tx_hash existed
	if _, err := s.db.Exec(`ALTER TABLE deals ADD COLUMN last_paid_tx_hash TEXT NOT NULL DEFAULT ''`); err != nil {
		low := strings.ToLower(err.Error())
		if !strings.Contains(low, "duplicate column") && !strings.Contains(low, "already exists") {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return nil
}

func (s *Store) InsertQuote(ctx context.Context, dealUUID, client, cid, priceUSDFC, payee0x string) error {
	now := time.Now().Unix()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO deals(deal_uuid, client, cid, price_usdfc, payee_0x, created_at, last_quoted_at, quoted_seen)
		VALUES(?,?,?,?,?,?,?,1)
	`, dealUUID, client, cid, priceUSDFC, payee0x, now, now)
	return err
}

func (s *Store) GetDeal(ctx context.Context, dealUUID string) (*piecepayment.Deal, error) {
	var d piecepayment.Deal
	err := s.db.QueryRowContext(ctx, `
		SELECT deal_uuid, client, cid, price_usdfc, COALESCE(payee_0x, ''), COALESCE(last_paid_tx_hash, '')
		FROM deals WHERE deal_uuid = ?
	`, dealUUID).Scan(
		&d.DealUUID, &d.Client, &d.CID, &d.PriceUSDFC, &d.Payee0x, &d.LastPaidTxHash,
	)
	if err == sql.ErrNoRows {
		return nil, piecepayment.ErrDealNotFound
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (s *Store) IsDealPaidSince(ctx context.Context, dealUUID, client, cid string, sinceUnix int64) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(1)
		FROM deals
		WHERE deal_uuid = ? AND client = ? AND cid = ?
			AND last_paid_at IS NOT NULL AND last_paid_at >= ?
			AND last_paid_tx_hash != ''
	`, dealUUID, client, cid, sinceUnix).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *Store) MarkPaid(ctx context.Context, dealUUID, client, txHash string) error {
	now := time.Now().Unix()
	res, err := s.db.ExecContext(ctx, `
		UPDATE deals
		SET last_paid_at = ?, last_paid_tx_hash = ?, paid_seen = paid_seen + 1, client = ?
		WHERE deal_uuid = ?
	`, now, txHash, client, dealUUID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return piecepayment.ErrDealNotFound
	}
	return nil
}

func (s *Store) ConsumeNonce(ctx context.Context, dealUUID, nonce string, expiresUnix int64) error {
	now := time.Now().Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM used_nonces WHERE expires_unix < ?`, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO used_nonces(deal_uuid, nonce, expires_unix, used_at)
		VALUES(?,?,?,?)
	`, dealUUID, nonce, expiresUnix, now); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return piecepayment.ErrReplayNonce
		}
		return err
	}
	return tx.Commit()
}
