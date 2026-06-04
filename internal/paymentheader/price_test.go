package paymentheader

import (
	"math/big"
	"testing"
)

func TestGibsBilled(t *testing.T) {
	if GibsBilled(0) != 0 {
		t.Fatal("zero bytes")
	}
	if GibsBilled(13) != 1 {
		t.Fatal("partial GiB counts as one")
	}
	if GibsBilled(GiB) != 1 {
		t.Fatal("exactly one GiB")
	}
	if GibsBilled(GiB+1) != 2 {
		t.Fatal("one byte over one GiB bills two")
	}
	if GibsBilled(32<<30) != 32 {
		t.Fatal("32 GiB")
	}
}

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
	t.Run("partial GiB bills one GiB", func(t *testing.T) {
		got, err := PriceUSDFCForBytes("0.01", 13)
		if err != nil {
			t.Fatal(err)
		}
		if got != "0.01" {
			t.Fatalf("got %q want 0.01", got)
		}
	})
	t.Run("one byte over GiB bills two", func(t *testing.T) {
		got, err := PriceUSDFCForBytes("0.01", GiB+1)
		if err != nil {
			t.Fatal(err)
		}
		if got != "0.02" {
			t.Fatalf("got %q want 0.02", got)
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
