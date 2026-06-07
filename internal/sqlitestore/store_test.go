package sqlitestore_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	pp "github.com/fidlabs/paid-retrievals/internal/piecepayment"
	"github.com/fidlabs/paid-retrievals/internal/sqlitestore"
)

func openTestStore(t *testing.T) *sqlitestore.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sp.db")
	s, err := sqlitestore.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func seedDeal(t *testing.T, s *sqlitestore.Store, dealUUID, client, cid, price, payee string) {
	t.Helper()
	ctx := context.Background()
	if err := s.InsertQuote(ctx, dealUUID, client, cid, price, payee); err != nil {
		t.Fatal(err)
	}
}

func TestOpenStoreAndMigrateIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sp.db")

	s1, err := sqlitestore.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	// Re-open same file: migrate must tolerate existing schema (incl. duplicate payee_0x ALTER).
	s2, err := sqlitestore.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	seedDeal(t, s2, "11111111-2222-3333-4444-555555555555", "0xClient", "bafytest", "0.01", "0xPayee")
}

func TestOpenStoreMemory(t *testing.T) {
	s, err := sqlitestore.OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
}

func TestInsertQuoteAndGetDeal(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	const (
		dealUUID = "11111111-2222-3333-4444-555555555555"
		client   = "0x1111111111111111111111111111111111111111"
		cid      = "bafkreic3gqso3booyry4fwc5wfnhaio574lami3am6nv4k6q6u2legzzdm"
		price    = "0.42"
		payee    = "0x2222222222222222222222222222222222222222"
	)
	seedDeal(t, s, dealUUID, client, cid, price, payee)

	got, err := s.GetDeal(ctx, dealUUID)
	if err != nil {
		t.Fatal(err)
	}
	if got.DealUUID != dealUUID || got.Client != client || got.CID != cid || got.PriceUSDFC != price || got.Payee0x != payee {
		t.Fatalf("deal mismatch: %+v", got)
	}
}

func TestGetDealNotFound(t *testing.T) {
	s := openTestStore(t)
	_, err := s.GetDeal(context.Background(), "00000000-0000-0000-0000-000000000000")
	if !errors.Is(err, pp.ErrDealNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestInsertQuoteDuplicateDealUUID(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	dealUUID := "11111111-2222-3333-4444-555555555555"
	seedDeal(t, s, dealUUID, "0xa", "bafy1", "0.01", "")
	if err := s.InsertQuote(ctx, dealUUID, "0xb", "bafy2", "0.02", ""); err == nil {
		t.Fatal("expected duplicate primary key error")
	}
}

func TestMarkPaid(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	dealUUID := "11111111-2222-3333-4444-555555555555"
	seedDeal(t, s, dealUUID, "0xClient", "bafy", "0.01", "")

	if err := s.MarkPaid(ctx, dealUUID, "0xClient", "0xtx-1"); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDeal(ctx, dealUUID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastPaidTxHash != "0xtx-1" {
		t.Fatalf("tx hash mismatch: %q", got.LastPaidTxHash)
	}
	if err := s.MarkPaid(ctx, dealUUID, "0xClient", "0xtx-2"); err != nil {
		t.Fatal("second mark paid should succeed")
	}
	got, err = s.GetDeal(ctx, dealUUID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastPaidTxHash != "0xtx-2" {
		t.Fatalf("tx hash mismatch after second mark: %q", got.LastPaidTxHash)
	}
}

func TestMarkPaidBindsAnonymousClient(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	const (
		dealUUID = "11111111-2222-3333-4444-555555555555"
		payer    = "0x1111111111111111111111111111111111111111"
		cid      = "bafkreic3gqso3booyry4fwc5wfnhaio574lami3am6nv4k6q6u2legzzdm"
	)
	seedDeal(t, s, dealUUID, "", cid, "0.01", "")
	if err := s.MarkPaid(ctx, dealUUID, payer, "0xtx-anon"); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDeal(ctx, dealUUID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Client != payer {
		t.Fatalf("client=%q want payer bound", got.Client)
	}
}

func TestIsDealPaidSinceRequiresDealClientAndCIDMatch(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	const (
		dealUUID = "11111111-2222-3333-4444-555555555555"
		client   = "0x1111111111111111111111111111111111111111"
		cid      = "bafkreic3gqso3booyry4fwc5wfnhaio574lami3am6nv4k6q6u2legzzdm"
	)
	seedDeal(t, s, dealUUID, client, cid, "0.01", "")
	if err := s.MarkPaid(ctx, dealUUID, client, "0xtx-abc"); err != nil {
		t.Fatal(err)
	}
	since := time.Now().Add(-time.Minute).Unix()

	paid, err := s.IsDealPaidSince(ctx, dealUUID, client, cid, since)
	if err != nil {
		t.Fatal(err)
	}
	if !paid {
		t.Fatal("expected paid=true for exact deal/client/cid")
	}

	paid, err = s.IsDealPaidSince(ctx, dealUUID, client, "bafydifferentcid", since)
	if err != nil {
		t.Fatal(err)
	}
	if paid {
		t.Fatal("expected paid=false for mismatched cid")
	}

	paid, err = s.IsDealPaidSince(ctx, dealUUID, "0x2222222222222222222222222222222222222222", cid, since)
	if err != nil {
		t.Fatal(err)
	}
	if paid {
		t.Fatal("expected paid=false for mismatched client")
	}
}

func TestMarkPaidNotFound(t *testing.T) {
	s := openTestStore(t)
	err := s.MarkPaid(context.Background(), "00000000-0000-0000-0000-000000000000", "0xClient", "0xtx-missing")
	if !errors.Is(err, pp.ErrDealNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestConsumeNonceSuccess(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	dealUUID := "11111111-2222-3333-4444-555555555555"
	exp := time.Now().Add(time.Hour).Unix()

	if err := s.ConsumeNonce(ctx, dealUUID, "nonce-a", exp); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeNonce(ctx, dealUUID, "nonce-b", exp); err != nil {
		t.Fatal(err)
	}
}

func TestConsumeNonceReplay(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	dealUUID := "11111111-2222-3333-4444-555555555555"
	exp := time.Now().Add(time.Hour).Unix()
	nonce := "replay-me"

	if err := s.ConsumeNonce(ctx, dealUUID, nonce, exp); err != nil {
		t.Fatal(err)
	}
	err := s.ConsumeNonce(ctx, dealUUID, nonce, exp)
	if !errors.Is(err, pp.ErrReplayNonce) {
		t.Fatalf("got %v", err)
	}
}

func TestConsumeNoncePrunesExpired(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	dealUUID := "11111111-2222-3333-4444-555555555555"
	past := time.Now().Add(-time.Hour).Unix()
	future := time.Now().Add(time.Hour).Unix()

	if err := s.ConsumeNonce(ctx, dealUUID, "old-nonce", past); err != nil {
		t.Fatal(err)
	}
	// Re-using old-nonce should succeed after prune on next ConsumeNonce (expired row deleted first).
	if err := s.ConsumeNonce(ctx, dealUUID, "old-nonce", future); err != nil {
		t.Fatalf("expected expired nonce pruned before insert: %v", err)
	}
}

func TestConsumeNonceDifferentDealsSameNonce(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	exp := time.Now().Add(time.Hour).Unix()
	nonce := "shared-nonce"

	if err := s.ConsumeNonce(ctx, "11111111-2222-3333-4444-555555555555", nonce, exp); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeNonce(ctx, "22222222-3333-4444-5555-666666666666", nonce, exp); err != nil {
		t.Fatal(err)
	}
}

func TestClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sp.db")
	s, err := sqlitestore.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Second close is allowed by database/sql (may return error on some drivers; sqlite typically ok).
	_ = s.Close()
}
