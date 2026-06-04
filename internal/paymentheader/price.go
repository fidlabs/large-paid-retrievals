package paymentheader

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// GiB is the byte count used for per-GB pricing (binary gigabyte, 1024^3).
const GiB int64 = 1 << 30

// GibsBilled returns the number of whole GiB charged for pieceBytes: each GiB or
// part thereof counts as one GiB (ceiling division).
func GibsBilled(pieceBytes int64) int64 {
	if pieceBytes <= 0 {
		return 0
	}
	return (pieceBytes + GiB - 1) / GiB
}

// PriceUSDFCForBytes returns the total USDFC charge for pieceBytes at pricePerGB USDFC per GiB.
// Billing is per whole GiB (or part thereof): total = GibsBilled(pieceBytes) * pricePerGB.
// pieceBytes must be non-negative; a negative value means the size is unknown.
func PriceUSDFCForBytes(pricePerGB string, pieceBytes int64) (string, error) {
	if pieceBytes < 0 {
		return "", errors.New("piece size unknown")
	}
	perGB, err := ParseTokenToBaseUnits(pricePerGB)
	if err != nil {
		return "", fmt.Errorf("parse price per GB: %w", err)
	}
	if perGB.Sign() < 0 {
		return "", errors.New("price per GB must be non-negative")
	}
	gibs := GibsBilled(pieceBytes)
	if gibs == 0 || perGB.Sign() == 0 {
		return formatTokenValueQuoted(big.NewInt(0)), nil
	}
	priceUnits := new(big.Int).Mul(perGB, big.NewInt(gibs))
	return formatTokenValueQuoted(priceUnits), nil
}

// formatTokenValueQuoted formats base units for MPP price_usdfc with up to 18 fractional
// digits so ParseTokenToBaseUnits round-trips (unlike FormatTokenValue's 6-digit display).
func formatTokenValueQuoted(baseUnits *big.Int) string {
	if baseUnits == nil || baseUnits.Sign() == 0 {
		return "0"
	}
	r := new(big.Rat).SetInt(baseUnits)
	d := new(big.Rat).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	r.Quo(r, d)
	s := r.FloatString(18)
	if i := strings.IndexByte(s, '.'); i >= 0 {
		s = strings.TrimRight(s, "0")
		s = strings.TrimRight(s, ".")
	}
	return s
}
