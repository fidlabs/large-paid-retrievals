package sqlitestore_test

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	pp "github.com/fidlabs/paid-retrievals/internal/piecepayment"
)

func TestPoolCreditAndAllocate(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	const (
		dealUUID = "11111111-2222-3333-4444-555555555555"
		payer    = "0x1111111111111111111111111111111111111111"
		payee    = "0x2222222222222222222222222222222222222222"
		cid      = "bafkreic3gqso3booyry4fwc5wfnhaio574lami3am6nv4k6q6u2legzzdm"
	)
	seedDeal(t, s, dealUUID, payer, cid, "0.01", payee)

	price := big.NewInt(100_000)
	credit := big.NewInt(300_000)
	if err := s.CreditPool(ctx, pp.PoolCredit{
		Payer: payer, Payee: payee, SettleTxHash: "0xsettle-1", CreditedBaseUnits: credit,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreditPool(ctx, pp.PoolCredit{
		Payer: payer, Payee: payee, SettleTxHash: "0xsettle-1", CreditedBaseUnits: credit,
	}); err != nil {
		t.Fatal("duplicate credit should be idempotent")
	}

	alloc1, err := s.TryAllocateDeal(ctx, pp.AllocateDealRequest{
		DealUUID: dealUUID, Payer: payer, Payee: payee, Client: payer, CID: cid,
		PriceBaseUnits: price, SettleTxHash: "0xsettle-1", AccessTTL: 12 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if alloc1.SettleTxHash != "0xsettle-1" {
		t.Fatalf("settle tx %q", alloc1.SettleTxHash)
	}

	now := time.Now().Unix()
	active, err := s.GetActiveAllocation(ctx, dealUUID, payer, cid, now)
	if err != nil || active == nil {
		t.Fatalf("active allocation missing: %v", err)
	}

	alloc2, err := s.TryAllocateDeal(ctx, pp.AllocateDealRequest{
		DealUUID: dealUUID, Payer: payer, Payee: payee, Client: payer, CID: cid,
		PriceBaseUnits: price, AccessTTL: 12 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if alloc2.DealUUID != dealUUID {
		t.Fatalf("idempotent allocate: %+v", alloc2)
	}
}

func TestTryAllocateDealInsufficientPool(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	const (
		dealUUID = "11111111-2222-3333-4444-555555555555"
		payer    = "0x1111111111111111111111111111111111111111"
		payee    = "0x2222222222222222222222222222222222222222"
		cid      = "bafkreic3gqso3booyry4fwc5wfnhaio574lami3am6nv4k6q6u2legzzdm"
	)
	seedDeal(t, s, dealUUID, payer, cid, "0.01", payee)

	_, err := s.TryAllocateDeal(ctx, pp.AllocateDealRequest{
		DealUUID: dealUUID, Payer: payer, Payee: payee, Client: payer, CID: cid,
		PriceBaseUnits: big.NewInt(100_000), AccessTTL: 12 * time.Hour,
	})
	if !errors.Is(err, pp.ErrInsufficientPool) {
		t.Fatalf("got %v", err)
	}
}

func TestOpenPool(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	const (
		payer = "0x1111111111111111111111111111111111111111"
		payee = "0x2222222222222222222222222222222222222222"
	)
	pool, err := s.OpenPool(ctx, payer, payee)
	if err != nil || pool != nil {
		t.Fatalf("empty store: pool=%+v err=%v", pool, err)
	}
	if err := s.CreditPool(ctx, pp.PoolCredit{
		Payer: payer, Payee: payee, SettleTxHash: "0xcr-1", CreditedBaseUnits: big.NewInt(42),
	}); err != nil {
		t.Fatal(err)
	}
	pool, err = s.OpenPool(ctx, payer, payee)
	if err != nil || pool == nil || pool.RemainingBaseUnits != "42" {
		t.Fatalf("open pool=%+v err=%v", pool, err)
	}
}

func TestCreditPoolRejectsZero(t *testing.T) {
	s := openTestStore(t)
	err := s.CreditPool(context.Background(), pp.PoolCredit{
		Payer: "0x1", Payee: "0x2", SettleTxHash: "0x0", CreditedBaseUnits: big.NewInt(0),
	})
	if !errors.Is(err, pp.ErrZeroPoolCredit) {
		t.Fatalf("got %v", err)
	}
}

func TestTryAllocateDealInvalidPrice(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_, err := s.TryAllocateDeal(ctx, pp.AllocateDealRequest{
		DealUUID:       "11111111-2222-3333-4444-555555555555",
		PriceBaseUnits: nil,
	})
	if err == nil {
		t.Fatal("expected error for nil price")
	}
}

func TestTryAllocateDealAlreadyAllocatedConflict(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	const (
		dealUUID = "11111111-2222-3333-4444-555555555555"
		payer    = "0x1111111111111111111111111111111111111111"
		payee    = "0x2222222222222222222222222222222222222222"
		cid      = "bafkreic3gqso3booyry4fwc5wfnhaio574lami3am6nv4k6q6u2legzzdm"
	)
	seedDeal(t, s, dealUUID, payer, cid, "0.01", payee)
	if err := s.CreditPool(ctx, pp.PoolCredit{
		Payer: payer, Payee: payee, SettleTxHash: "0xsettle-1", CreditedBaseUnits: big.NewInt(200_000),
	}); err != nil {
		t.Fatal(err)
	}
	price := big.NewInt(100_000)
	if _, err := s.TryAllocateDeal(ctx, pp.AllocateDealRequest{
		DealUUID: dealUUID, Payer: payer, Payee: payee, Client: payer, CID: cid,
		PriceBaseUnits: price, AccessTTL: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	_, err := s.TryAllocateDeal(ctx, pp.AllocateDealRequest{
		DealUUID: dealUUID, Payer: payer, Payee: payee, Client: "0x3333333333333333333333333333333333333333",
		CID: cid, PriceBaseUnits: price, AccessTTL: time.Hour,
	})
	if err == nil {
		t.Fatal("expected conflict for different client")
	}
}

func TestTryAllocateDealResolvesSettleTxFromCredit(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	const (
		dealUUID = "11111111-2222-3333-4444-555555555555"
		payer    = "0x1111111111111111111111111111111111111111"
		payee    = "0x2222222222222222222222222222222222222222"
		cid      = "bafkreic3gqso3booyry4fwc5wfnhaio574lami3am6nv4k6q6u2legzzdm"
	)
	seedDeal(t, s, dealUUID, payer, cid, "0.01", payee)
	if err := s.CreditPool(ctx, pp.PoolCredit{
		Payer: payer, Payee: payee, SettleTxHash: "0xauto-tx", CreditedBaseUnits: big.NewInt(200_000),
	}); err != nil {
		t.Fatal(err)
	}
	alloc, err := s.TryAllocateDeal(ctx, pp.AllocateDealRequest{
		DealUUID: dealUUID, Payer: payer, Payee: payee, Client: payer, CID: cid,
		PriceBaseUnits: big.NewInt(100_000), AccessTTL: time.Hour,
	})
	if err != nil || alloc.SettleTxHash != "0xauto-tx" {
		t.Fatalf("alloc=%+v err=%v", alloc, err)
	}
}

func TestGetActiveAllocationExpired(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	const (
		dealUUID = "11111111-2222-3333-4444-555555555555"
		payer    = "0x1111111111111111111111111111111111111111"
		payee    = "0x2222222222222222222222222222222222222222"
		cid      = "bafkreic3gqso3booyry4fwc5wfnhaio574lami3am6nv4k6q6u2legzzdm"
	)
	seedDeal(t, s, dealUUID, payer, cid, "0.01", payee)
	if err := s.CreditPool(ctx, pp.PoolCredit{
		Payer: payer, Payee: payee, SettleTxHash: "0xsettle-1", CreditedBaseUnits: big.NewInt(200_000),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TryAllocateDeal(ctx, pp.AllocateDealRequest{
		DealUUID: dealUUID, Payer: payer, Payee: payee, Client: payer, CID: cid,
		PriceBaseUnits: big.NewInt(100_000), AccessTTL: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	alloc, err := s.GetActiveAllocation(ctx, dealUUID, payer, cid, time.Now().Add(2*time.Hour).Unix())
	if err != nil || alloc != nil {
		t.Fatalf("expected no active allocation: %+v err=%v", alloc, err)
	}
}

func TestTryAllocateDealNotFound(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	const (
		payer = "0x1111111111111111111111111111111111111111"
		payee = "0x2222222222222222222222222222222222222222"
	)
	if err := s.CreditPool(ctx, pp.PoolCredit{
		Payer: payer, Payee: payee, SettleTxHash: "0xsettle-orphan", CreditedBaseUnits: big.NewInt(200_000),
	}); err != nil {
		t.Fatal(err)
	}
	_, err := s.TryAllocateDeal(ctx, pp.AllocateDealRequest{
		DealUUID: "00000000-0000-0000-0000-000000000000",
		Payer:    payer, Payee: payee, Client: payer, CID: "bafy",
		PriceBaseUnits: big.NewInt(100_000), AccessTTL: time.Hour,
	})
	if !errors.Is(err, pp.ErrDealNotFound) {
		t.Fatalf("got %v", err)
	}
}
