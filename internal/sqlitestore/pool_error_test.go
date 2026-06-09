package sqlitestore

import (
	"context"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pp "github.com/fidlabs/paid-retrievals/internal/piecepayment"
)

func TestCreditPoolInvalidSettled(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "sp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	const (
		payer = "0x1111111111111111111111111111111111111111"
		payee = "0x2222222222222222222222222222222222222222"
	)
	if err := s.CreditPool(ctx, pp.PoolCredit{
		Payer: payer, Payee: payee, SettleTxHash: "0xcr-1", CreditedBaseUnits: big.NewInt(1),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE pools SET settled_base_units = 'bad' WHERE payer = ? AND payee = ?`, payer, payee); err != nil {
		t.Fatal(err)
	}
	err = s.CreditPool(ctx, pp.PoolCredit{
		Payer: payer, Payee: payee, SettleTxHash: "0xcr-2", CreditedBaseUnits: big.NewInt(1),
	})
	if err == nil || !strings.Contains(err.Error(), "invalid settled_base_units") {
		t.Fatalf("got %v", err)
	}
}

func TestTryAllocateDealInvalidRemaining(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "sp.db"))
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
	if err := s.CreditPool(ctx, pp.PoolCredit{
		Payer: payer, Payee: payee, SettleTxHash: "0xcr-bad-rem", CreditedBaseUnits: big.NewInt(100_000),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE pools SET remaining_base_units = 'bad' WHERE payer = ? AND payee = ?`, payer, payee); err != nil {
		t.Fatal(err)
	}
	_, err = s.TryAllocateDeal(ctx, pp.AllocateDealRequest{
		DealUUID: dealUUID, Payer: payer, Payee: payee, Client: payer, CID: cid,
		PriceBaseUnits: big.NewInt(50_000), AccessTTL: time.Hour,
	})
	if err == nil || !strings.Contains(err.Error(), "invalid remaining_base_units") {
		t.Fatalf("got %v", err)
	}
}
