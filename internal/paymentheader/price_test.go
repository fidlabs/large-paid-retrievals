package paymentheader

import (
	"math/big"
	"testing"
)

func TestPriceUSDFCForBytes(t *testing.T) {
	t.Run("32 GiB at 0.01 per GB", func(t *testing.T) {
		got, err := PriceUSDFCForBytes("0.01", 32<<30)
		if err != nil {
			t.Fatal(err)
		}
		if got != "0.32" {
			t.Fatalf("got %q", got)
		}
		units, err := ParseTokenToBaseUnits(got)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := ParseTokenToBaseUnits("0.32")
		if units.Cmp(want) != 0 {
			t.Fatalf("base units %s want %s", units, want)
		}
	})
	t.Run("small piece round-trips base units", func(t *testing.T) {
		const pieceBytes = 13
		got, err := PriceUSDFCForBytes("0.01", pieceBytes)
		if err != nil {
			t.Fatal(err)
		}
		units, err := ParseTokenToBaseUnits(got)
		if err != nil {
			t.Fatal(err)
		}
		if units.Sign() <= 0 {
			t.Fatalf("expected positive settlement units, got %s from price %q", units, got)
		}
		perGB, _ := ParseTokenToBaseUnits("0.01")
		want := new(big.Int).Quo(new(big.Int).Mul(perGB, big.NewInt(pieceBytes)), big.NewInt(GiB))
		if want.Sign() == 0 {
			want = big.NewInt(1)
		}
		if units.Cmp(want) != 0 {
			t.Fatalf("round-trip units %s want %s", units, want)
		}
	})
	t.Run("unknown size", func(t *testing.T) {
		if _, err := PriceUSDFCForBytes("0.01", -1); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("zero bytes", func(t *testing.T) {
		got, err := PriceUSDFCForBytes("0.01", 0)
		if err != nil {
			t.Fatal(err)
		}
		if got != "0" {
			t.Fatalf("got %q", got)
		}
	})
}

func TestFormatTokenValueQuoted(t *testing.T) {
	one := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	if formatTokenValueQuoted(one) != "1" {
		t.Fatalf("got %q", formatTokenValueQuoted(one))
	}
	tiny := big.NewInt(1)
	got := formatTokenValueQuoted(tiny)
	parsed, err := ParseTokenToBaseUnits(got)
	if err != nil || parsed.Cmp(tiny) != 0 {
		t.Fatalf("quoted %q parsed %v err %v", got, parsed, err)
	}
}
