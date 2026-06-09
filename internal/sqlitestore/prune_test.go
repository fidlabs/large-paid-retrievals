package sqlitestore

import (
	"context"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	pp "github.com/fidlabs/paid-retrievals/internal/piecepayment"
)

func TestPruneRemovesOldRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sp.db")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()

	const (
		oldDeal    = "11111111-2222-3333-4444-555555555555"
		recentDeal = "22222222-3333-4444-5555-666666666666"
		payer      = "0x1111111111111111111111111111111111111111"
		payee      = "0x2222222222222222222222222222222222222222"
		cid        = "bafkreic3gqso3booyry4fwc5wfnhaio574lami3am6nv4k6q6u2legzzdm"
	)
	if err := s.InsertQuote(ctx, oldDeal, payer, cid, "0.01", payee); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertQuote(ctx, recentDeal, payer, cid, "0.01", payee); err != nil {
		t.Fatal(err)
	}
	oldCutoff := time.Now().Add(-8 * 24 * time.Hour).Unix()
	if err := setDealQuotedAt(ctx, s, oldDeal, oldCutoff); err != nil {
		t.Fatal(err)
	}

	price := big.NewInt(50_000)
	if err := s.CreditPool(ctx, pp.PoolCredit{
		Payer: payer, Payee: payee, SettleTxHash: "0xsettle-old", CreditedBaseUnits: price,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TryAllocateDeal(ctx, pp.AllocateDealRequest{
		DealUUID: oldDeal, Payer: payer, Payee: payee, Client: payer, CID: cid,
		PriceBaseUnits: price, SettleTxHash: "0xsettle-old", AccessTTL: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	expiredAllocAt := time.Now().Add(-8 * 24 * time.Hour).Unix()
	if err := setAllocationAccessExpires(ctx, s, oldDeal, expiredAllocAt); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeNonce(ctx, oldDeal, "old-nonce", expiredAllocAt); err != nil {
		t.Fatal(err)
	}

	stats, err := s.Prune(ctx, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Deals == 0 || stats.PoolAllocations == 0 {
		t.Fatalf("expected old deal/allocation pruned, stats=%+v", stats)
	}

	if _, err := s.GetDeal(ctx, oldDeal); err != pp.ErrDealNotFound {
		t.Fatalf("old deal still present: %v", err)
	}
	if got, err := s.GetDeal(ctx, recentDeal); err != nil || got.DealUUID != recentDeal {
		t.Fatalf("recent deal missing: %v %+v", err, got)
	}
}

func TestPruneClosedPools(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sp.db")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()

	const (
		dealUUID = "11111111-2222-3333-4444-555555555555"
		payer    = "0x1111111111111111111111111111111111111111"
		payee    = "0x2222222222222222222222222222222222222222"
		cid      = "bafkreic3gqso3booyry4fwc5wfnhaio574lami3am6nv4k6q6u2legzzdm"
	)
	if err := s.InsertQuote(ctx, dealUUID, payer, cid, "0.01", payee); err != nil {
		t.Fatal(err)
	}
	price := big.NewInt(100_000)
	if err := s.CreditPool(ctx, pp.PoolCredit{
		Payer: payer, Payee: payee, SettleTxHash: "0xsettle-closed", CreditedBaseUnits: price,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TryAllocateDeal(ctx, pp.AllocateDealRequest{
		DealUUID: dealUUID, Payer: payer, Payee: payee, Client: payer, CID: cid,
		PriceBaseUnits: price, SettleTxHash: "0xsettle-closed", AccessTTL: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	oldClosed := time.Now().Add(-8 * 24 * time.Hour).Unix()
	if err := setPoolClosedAt(ctx, s, payer, payee, oldClosed); err != nil {
		t.Fatal(err)
	}
	if err := setDealQuotedAt(ctx, s, dealUUID, oldClosed); err != nil {
		t.Fatal(err)
	}
	if err := setAllocationAccessExpires(ctx, s, dealUUID, oldClosed); err != nil {
		t.Fatal(err)
	}

	stats, err := s.Prune(ctx, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Pools == 0 || stats.PoolCredits == 0 {
		t.Fatalf("expected closed pool pruned, stats=%+v", stats)
	}
}

// TestReplayBlockedAfterPrune verifies that an on-chain payment tx cannot be re-credited
// after its pool/credit rows are pruned. The permanent spent_payment_tx ledger must keep
// the spend recorded forever, even though pool_credits and pools are removed.
func TestReplayBlockedAfterPrune(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sp.db")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()

	const (
		dealUUID = "11111111-2222-3333-4444-555555555555"
		newDeal  = "99999999-8888-7777-6666-555555555555"
		payer    = "0x1111111111111111111111111111111111111111"
		payee    = "0x2222222222222222222222222222222222222222"
		cid      = "bafkreic3gqso3booyry4fwc5wfnhaio574lami3am6nv4k6q6u2legzzdm"
		replayTx = "0xreplay-me"
	)
	if err := s.InsertQuote(ctx, dealUUID, payer, cid, "0.01", payee); err != nil {
		t.Fatal(err)
	}
	price := big.NewInt(100_000)
	if err := s.CreditPool(ctx, pp.PoolCredit{
		Payer: payer, Payee: payee, SettleTxHash: replayTx, CreditedBaseUnits: price,
	}); err != nil {
		t.Fatal(err)
	}
	// Drain the pool to exactly zero so it closes.
	if _, err := s.TryAllocateDeal(ctx, pp.AllocateDealRequest{
		DealUUID: dealUUID, Payer: payer, Payee: payee, Client: payer, CID: cid,
		PriceBaseUnits: price, SettleTxHash: replayTx, AccessTTL: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}

	// Age everything past retention and prune away the closed pool and its credit rows.
	old := time.Now().Add(-8 * 24 * time.Hour).Unix()
	if err := setPoolClosedAt(ctx, s, payer, payee, old); err != nil {
		t.Fatal(err)
	}
	if err := setDealQuotedAt(ctx, s, dealUUID, old); err != nil {
		t.Fatal(err)
	}
	if err := setAllocationAccessExpires(ctx, s, dealUUID, old); err != nil {
		t.Fatal(err)
	}
	stats, err := s.Prune(ctx, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Pools == 0 || stats.PoolCredits == 0 {
		t.Fatalf("expected closed pool and credits pruned, stats=%+v", stats)
	}

	// Replay the same on-chain tx hash: it must NOT re-credit the pool.
	if err := s.CreditPool(ctx, pp.PoolCredit{
		Payer: payer, Payee: payee, SettleTxHash: replayTx, CreditedBaseUnits: price,
	}); err != nil {
		t.Fatalf("replay credit should be a no-op, not an error: %v", err)
	}
	pool, err := s.OpenPool(ctx, payer, payee)
	if err != nil {
		t.Fatal(err)
	}
	if pool != nil {
		t.Fatalf("replayed payment re-funded a pool after prune: %+v", pool)
	}
	// And a fresh allocation must fail for lack of funds.
	if err := s.InsertQuote(ctx, newDeal, payer, cid, "0.01", payee); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TryAllocateDeal(ctx, pp.AllocateDealRequest{
		DealUUID: newDeal, Payer: payer, Payee: payee, Client: payer, CID: cid,
		PriceBaseUnits: price, AccessTTL: time.Hour,
	}); err != pp.ErrInsufficientPool {
		t.Fatalf("expected ErrInsufficientPool after replay, got %v", err)
	}
}

func setPoolClosedAt(ctx context.Context, s *Store, payer, payee string, closedAt int64) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE pools SET closed_at = ?, created_at = ? WHERE payer = ? AND payee = ?
	`, closedAt, closedAt, payer, payee)
	return err
}

func TestPruneDisabledWhenRetentionZero(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "sp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	dealUUID := "11111111-2222-3333-4444-555555555555"
	if err := s.InsertQuote(ctx, dealUUID, "0x1", "bafy", "0.01", "0x2"); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-30 * 24 * time.Hour).Unix()
	if err := setDealQuotedAt(ctx, s, dealUUID, old); err != nil {
		t.Fatal(err)
	}
	stats, err := s.Prune(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if stats != (PruneStats{}) {
		t.Fatalf("expected empty stats, got %+v", stats)
	}
	if _, err := s.GetDeal(ctx, dealUUID); err != nil {
		t.Fatal(err)
	}
}

func setDealQuotedAt(ctx context.Context, s *Store, dealUUID string, quotedAt int64) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE deals SET last_quoted_at = ?, created_at = ? WHERE deal_uuid = ?
	`, quotedAt, quotedAt, dealUUID)
	return err
}

func setAllocationAccessExpires(ctx context.Context, s *Store, dealUUID string, accessExpiresAt int64) error {
	return s.SetAllocationAccessExpiresForTest(ctx, dealUUID, accessExpiresAt)
}
