package paymentheader

import (
	"errors"
	"fmt"
	"math/big"
)

// GiB is the byte count used for per-GB pricing (binary gigabyte, 1024^3).
const GiB int64 = 1 << 30

// PriceUSDFCForBytes returns the total USDFC charge for pieceBytes at pricePerGB USDFC per GiB.
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
	if pieceBytes == 0 {
		return FormatTokenValue(big.NewInt(0)), nil
	}
	num := new(big.Int).Mul(perGB, big.NewInt(pieceBytes))
	priceUnits := new(big.Int).Quo(num, big.NewInt(GiB))
	return FormatTokenValue(priceUnits), nil
}
