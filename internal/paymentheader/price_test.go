package paymentheader

import (
	"testing"
)

func TestPriceUSDFCForBytes(t *testing.T) {
	t.Run("32 GiB at 0.01 per GB", func(t *testing.T) {
		got, err := PriceUSDFCForBytes("0.01", 32<<30)
		if err != nil {
			t.Fatal(err)
		}
		if got != "0.320000" {
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
		if got != "0.000000" {
			t.Fatalf("got %q", got)
		}
	})
}
