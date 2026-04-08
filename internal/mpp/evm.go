package mpp

import (
	"crypto/ecdsa"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type EVMVerifier struct{}

func (EVMVerifier) Verify(clientAddr string, msg []byte, signature string) error {
	if !common.IsHexAddress(strings.TrimSpace(clientAddr)) {
		return fmt.Errorf("invalid 0x client address for evm verify")
	}
	expected := common.HexToAddress(clientAddr)
	sig := common.FromHex(strings.TrimSpace(signature))
	if len(sig) != 65 {
		return fmt.Errorf("evm signature must be 65 bytes hex, got %d", len(sig))
	}
	h := crypto.Keccak256Hash(msg)
	pub, err := crypto.Ecrecover(h.Bytes(), sig)
	if err != nil {
		return fmt.Errorf("ecrecover: %w", err)
	}
	pubKey, err := crypto.UnmarshalPubkey(pub)
	if err != nil {
		return err
	}
	recovered := crypto.PubkeyToAddress(*pubKey)
	if recovered != expected {
		return fmt.Errorf("signature does not match client address")
	}
	return nil
}

func SignEVM(priv *ecdsa.PrivateKey, msg []byte) (sigType string, signature string, err error) {
	if priv == nil {
		return "", "", fmt.Errorf("nil private key")
	}
	h := crypto.Keccak256Hash(msg)
	sig, err := crypto.Sign(h.Bytes(), priv)
	if err != nil {
		return "", "", err
	}
	return SigTypeEVM, common.Bytes2Hex(sig), nil
}
