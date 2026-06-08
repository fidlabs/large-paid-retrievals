package sqlitestore

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/fidlabs/paid-retrievals/internal/dealstore"

	_ "modernc.org/sqlite"
)

var _ dealstore.DealStore = (*Store)(nil)

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
		`CREATE TABLE IF NOT EXISTS settlement_pools (
			pool_id TEXT PRIMARY KEY,
			payer TEXT NOT NULL,
			payee TEXT NOT NULL,
			settled_base_units TEXT NOT NULL DEFAULT '0',
			remaining_base_units TEXT NOT NULL DEFAULT '0',
			created_at INTEGER NOT NULL,
			closed_at INTEGER
		);`,
		`CREATE INDEX IF NOT EXISTS idx_settlement_pools_pair ON settlement_pools(payer, payee, closed_at);`,
		`CREATE TABLE IF NOT EXISTS settlement_credits (
			credit_id TEXT PRIMARY KEY,
			pool_id TEXT NOT NULL,
			settle_tx_hash TEXT NOT NULL UNIQUE,
			credited_base_units TEXT NOT NULL,
			credited_at INTEGER NOT NULL,
			FOREIGN KEY(pool_id) REFERENCES settlement_pools(pool_id)
		);`,
		`CREATE TABLE IF NOT EXISTS deal_allocations (
			deal_uuid TEXT PRIMARY KEY,
			pool_id TEXT NOT NULL,
			client TEXT NOT NULL,
			cid TEXT NOT NULL,
			price_base_units TEXT NOT NULL,
			settle_tx_hash TEXT NOT NULL DEFAULT '',
			allocated_at INTEGER NOT NULL,
			access_expires_at INTEGER NOT NULL,
			FOREIGN KEY(pool_id) REFERENCES settlement_pools(pool_id)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_deal_allocations_access ON deal_allocations(client, cid, access_expires_at);`,
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

func (s *Store) GetDeal(ctx context.Context, dealUUID string) (*dealstore.Deal, error) {
	var d dealstore.Deal
	err := s.db.QueryRowContext(ctx, `
		SELECT deal_uuid, client, cid, price_usdfc, COALESCE(payee_0x, ''), COALESCE(last_paid_tx_hash, '')
		FROM deals WHERE deal_uuid = ?
	`, dealUUID).Scan(
		&d.DealUUID, &d.Client, &d.CID, &d.PriceUSDFC, &d.Payee0x, &d.LastPaidTxHash,
	)
	if err == sql.ErrNoRows {
		return nil, dealstore.ErrDealNotFound
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
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
			return dealstore.ErrReplayNonce
		}
		return err
	}
	return tx.Commit()
}
