package pieceaccess

import (
	"fmt"
	"strings"

	"github.com/data-preservation-programs/go-synapse/constants"
	"github.com/ethereum/go-ethereum/common"
)

// TODO(BIG): Replace these PLACEHOLDER PoRep Market contract addresses with the
// real mainnet and Calibration deployments once they are known / finalized.
// Until then, voucher EIP-712 domain pinning on those networks uses these
// dummies — they are NOT the live market contracts. Do not ship production
// voucher flows against mainnet/calib relying on these values.
//
// Devnet (and any other chain) has no built-in default; pass
// --porep-market-address / SP_PROXY_POREP_MARKET_ADDRESS / POREP_MARKET.
var (
	// PorepMarketMainnetPlaceholder is a temporary stand-in for chain 314.
	PorepMarketMainnetPlaceholder = common.HexToAddress("0x0000000000000000000000000000000000a1a1a1")
	// PorepMarketCalibrationPlaceholder is a temporary stand-in for chain 314159.
	PorepMarketCalibrationPlaceholder = common.HexToAddress("0x0000000000000000000000000000000000b2b2b2")
)

// PorepMarketAddressesByChainID maps well-known networks to the PoRep Market
// contract used as EIP-712 verifyingContract for access vouchers.
//
// TODO(BIG): Update entries when real mainnet/Calibration addresses land
// (see PorepMarketMainnetPlaceholder / PorepMarketCalibrationPlaceholder).
var PorepMarketAddressesByChainID = map[int64]common.Address{
	constants.ChainIDMainnet:     PorepMarketMainnetPlaceholder,
	constants.ChainIDCalibration: PorepMarketCalibrationPlaceholder,
}

// ResolvePorepMarketAddress returns the PoRep Market contract for voucher
// domain pinning. A non-empty override (flag/env) wins; otherwise the
// chain-default from PorepMarketAddressesByChainID is used. Devnet and
// unknown chains have no default — callers must supply an override.
func ResolvePorepMarketAddress(override string, chainID int64) (common.Address, error) {
	if s := strings.TrimSpace(override); s != "" {
		if !common.IsHexAddress(s) {
			return common.Address{}, fmt.Errorf("pieceaccess: invalid PoRep market address %q", s)
		}
		addr := common.HexToAddress(s)
		if addr == (common.Address{}) {
			return common.Address{}, fmt.Errorf("pieceaccess: invalid PoRep market address %q", s)
		}
		return addr, nil
	}
	if addr, ok := PorepMarketAddressesByChainID[chainID]; ok && addr != (common.Address{}) {
		return addr, nil
	}
	return common.Address{}, nil
}
