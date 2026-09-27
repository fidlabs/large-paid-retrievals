package pieceaccess

import (
	"fmt"
	"strings"

	"github.com/data-preservation-programs/go-synapse/constants"
	"github.com/ethereum/go-ethereum/common"
)

// Finalized PoRep Market UUPS proxies from
// https://github.com/fidlabs/porep-market/tree/main/deployments
// (mainnet/calibnet latest.json, status=finalized). Used as EIP-712
// verifyingContract for access credentials.
//
// Devnet (and any other chain) has no built-in default; pass
// --porep-market-address / SP_PROXY_POREP_MARKET_ADDRESS / POREP_MARKET.
var (
	// PorepMarketMainnet is the PoRepMarket proxy on chain 314.
	PorepMarketMainnet = common.HexToAddress("0x02328379543e47bA8AeD039B08aA8cC836584E74")
	// PorepMarketCalibration is the PoRepMarket proxy on chain 314159.
	PorepMarketCalibration = common.HexToAddress("0xF895b2Af3B238E7D05A44cd7FBeBE10cBeb3F34b")
)

// PorepMarketAddressesByChainID maps well-known networks to the PoRep Market
// contract used as EIP-712 verifyingContract for access vouchers.
var PorepMarketAddressesByChainID = map[int64]common.Address{
	constants.ChainIDMainnet:     PorepMarketMainnet,
	constants.ChainIDCalibration: PorepMarketCalibration,
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
