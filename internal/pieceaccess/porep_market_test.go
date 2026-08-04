package pieceaccess

import (
	"testing"

	"github.com/data-preservation-programs/go-synapse/constants"
	"github.com/ethereum/go-ethereum/common"
)

func TestResolvePorepMarketAddress(t *testing.T) {
	t.Parallel()

	mainnet, err := ResolvePorepMarketAddress("", constants.ChainIDMainnet)
	if err != nil {
		t.Fatal(err)
	}
	if mainnet != PorepMarketMainnetPlaceholder {
		t.Fatalf("mainnet: got %s want placeholder", mainnet.Hex())
	}

	calib, err := ResolvePorepMarketAddress("", constants.ChainIDCalibration)
	if err != nil {
		t.Fatal(err)
	}
	if calib != PorepMarketCalibrationPlaceholder {
		t.Fatalf("calib: got %s want placeholder", calib.Hex())
	}

	devnet, err := ResolvePorepMarketAddress("", constants.ChainIDDevnet)
	if err != nil {
		t.Fatal(err)
	}
	if devnet != (common.Address{}) {
		t.Fatalf("devnet should have no default, got %s", devnet.Hex())
	}

	override := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	got, err := ResolvePorepMarketAddress(override.Hex(), constants.ChainIDDevnet)
	if err != nil {
		t.Fatal(err)
	}
	if got != override {
		t.Fatalf("override: got %s want %s", got.Hex(), override.Hex())
	}

	// Override wins over chain default.
	got, err = ResolvePorepMarketAddress(override.Hex(), constants.ChainIDMainnet)
	if err != nil {
		t.Fatal(err)
	}
	if got != override {
		t.Fatalf("override on mainnet: got %s", got.Hex())
	}

	if _, err := ResolvePorepMarketAddress("not-an-address", constants.ChainIDMainnet); err == nil {
		t.Fatal("expected invalid address error")
	}
}
