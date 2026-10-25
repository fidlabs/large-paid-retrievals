package sqlitestore_test

import (
	"context"
	"math/big"
	"testing"

	pp "github.com/fidlabs/paid-retrievals/internal/dealstore"
)

// Regression: one on-chain payment must credit a pool exactly once regardless of
// how the caller spells the tx hash. SQLite's UNIQUE is case-sensitive, so
// without canonicalization 0xab… and 0xAB… are two credits for one receipt.
func TestCreditPoolDedupesTxHashCasing(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	const (
		payer = "0x1111111111111111111111111111111111111111"
		payee = "0x2222222222222222222222222222222222222222"
		lower = "0xa9099dde09926a1761676029f23e8a87b49ead28ac09e6578a9c992c8d4773d8"
		upper = "0xA9099DDE09926A1761676029F23E8A87B49EAD28AC09E6578A9C992C8D4773D8"
	)
	amt := big.NewInt(10_000_000_000_000_000)
	for _, h := range []string{lower, upper} {
		if err := s.CreditPool(ctx, pp.PoolCredit{Payer: payer, Payee: payee, SettleTxHash: h, CreditedBaseUnits: amt}); err != nil {
			t.Fatal(err)
		}
	}
	snap, err := s.OpenPool(ctx, payer, payee)
	if err != nil {
		t.Fatal(err)
	}
	if snap == nil {
		t.Fatal("no open pool after credit")
	}
	if snap.RemainingBaseUnits != amt.String() {
		t.Fatalf("same receipt credited twice: remaining=%s want=%s", snap.RemainingBaseUnits, amt)
	}
}
