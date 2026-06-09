package sqlitestore_test

import (
	"bytes"
	"context"
	"math/big"
	"strings"
	"testing"
	"time"

	pp "github.com/fidlabs/paid-retrievals/internal/piecepayment"
)

func TestDumpState(t *testing.T) {
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
		Payer: payer, Payee: payee, SettleTxHash: "0xsettle-1", CreditedBaseUnits: big.NewInt(100_000),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TryAllocateDeal(ctx, pp.AllocateDealRequest{
		DealUUID: dealUUID, Payer: payer, Payee: payee, Client: payer, CID: cid,
		PriceBaseUnits: big.NewInt(50_000), SettleTxHash: "0xsettle-1", AccessTTL: 12 * time.Hour,
	}); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := s.DumpState(ctx, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"=== sp-proxy state dump",
		"--- deals ---",
		"deal_uuid=" + dealUUID,
		"price_usdfc=0.01",
		"--- pools ---",
		"payer=" + payer,
		"status=open",
		"remaining_base_units=50000",
		"--- pool_credits ---",
		"settle_tx_hash=0xsettle-1",
		"--- pool_allocations ---",
		"price_base_units=50000",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("dump missing %q:\n%s", want, out)
		}
	}
}

func TestDumpStateEmpty(t *testing.T) {
	s := openTestStore(t)
	var buf bytes.Buffer
	if err := s.DumpState(context.Background(), &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"--- deals ---",
		"(0 deal(s))",
		"--- pools ---",
		"(0 pool(s))",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestDumpStateClosedPool(t *testing.T) {
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
	if err := s.CreditPool(ctx, pp.PoolCredit{
		Payer: payer, Payee: payee, SettleTxHash: "0xsettle-drain", CreditedBaseUnits: price,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TryAllocateDeal(ctx, pp.AllocateDealRequest{
		DealUUID: dealUUID, Payer: payer, Payee: payee, Client: payer, CID: cid,
		PriceBaseUnits: price, SettleTxHash: "0xsettle-drain", AccessTTL: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := s.DumpState(ctx, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "status=closed") {
		t.Fatalf("dump:\n%s", buf.String())
	}
}
