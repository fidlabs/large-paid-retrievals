package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/fidlabs/paid-retrievals/internal/pieceaccess"
)

func TestAuthHeadersForPieceDelegated(t *testing.T) {
	t.Parallel()
	ownerKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	granteeKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	domain := pieceaccess.NewDomain(big.NewInt(1), common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"))
	grantee := crypto.PubkeyToAddress(granteeKey.PublicKey)
	voucher := pieceaccess.BuildVoucherTypedData(domain, grantee, big.NewInt(9), now, now+86400)
	capTok := encodeCapabilityToken(t, voucher, pieceaccess.MustSignEIP712(ownerKey, voucher))

	cfg := &retrievalAuthConfig{key: granteeKey, capabilities: []string{capTok}}
	headers, err := cfg.authHeadersForPiece(context.Background(), "baga6ea4seaqtest")
	if err != nil {
		t.Fatal(err)
	}
	// One RetrievalProof (minted) + one RetrievalVoucher (forwarded verbatim).
	if len(headers) != 2 {
		t.Fatalf("headers=%v", headers)
	}
	if !strings.HasPrefix(headers[0], "RetrievalProof ") {
		t.Fatalf("headers[0]=%q want RetrievalProof", headers[0])
	}
	if !strings.HasPrefix(headers[1], "RetrievalVoucher ") {
		t.Fatalf("headers[1]=%q want RetrievalVoucher", headers[1])
	}
	// The forwarded voucher must be the original capability token, verbatim.
	if headers[1] != "RetrievalVoucher "+capTok {
		t.Fatalf("voucher not forwarded verbatim: %q", headers[1])
	}
}

func TestAuthHeadersForPieceOwnerDirect(t *testing.T) {
	t.Parallel()
	ownerKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &retrievalAuthConfig{
		key:    ownerKey,
		domain: pieceaccessDomain{chainID: big.NewInt(314159), market: common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")},
	}
	headers, err := cfg.authHeadersForPiece(context.Background(), "baga6ea4seaqtest")
	if err != nil {
		t.Fatal(err)
	}
	if len(headers) != 1 || !strings.HasPrefix(headers[0], "RetrievalProof ") {
		t.Fatalf("owner-direct headers=%v", headers)
	}
}

func TestAuthHeadersForPieceOwnerDirectRequiresDomain(t *testing.T) {
	t.Parallel()
	ownerKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, err = (&retrievalAuthConfig{key: ownerKey}).authHeadersForPiece(context.Background(), "baga6ea4seaqtest")
	if err == nil {
		t.Fatal("expected error when owner-direct domain is unset")
	}
	if !strings.Contains(err.Error(), "porep-market-address") {
		t.Fatalf("err=%v", err)
	}
}

func TestValidateCapabilityFlags(t *testing.T) {
	t.Parallel()
	ownerKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	granteeKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	domain := pieceaccess.NewDomain(big.NewInt(1), common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"))
	grantee := crypto.PubkeyToAddress(granteeKey.PublicKey)
	voucher := pieceaccess.BuildVoucherTypedData(domain, grantee, big.NewInt(9), now, now+86400)
	capTok := encodeCapabilityToken(t, voucher, pieceaccess.MustSignEIP712(ownerKey, voucher))

	got, err := validateCapabilityFlags([]string{"RetrievalVoucher " + capTok}, pieceaccessDomain{})
	if err != nil || len(got) != 1 || got[0] != capTok {
		t.Fatalf("got %v err=%v", got, err)
	}

	if _, err := validateCapabilityFlags([]string{"not-a-token"}, pieceaccessDomain{}); err == nil {
		t.Fatal("expected malformed reject")
	}
	expired := pieceaccess.BuildVoucherTypedData(domain, grantee, big.NewInt(9), now-100, now-1)
	expiredTok := encodeCapabilityToken(t, expired, pieceaccess.MustSignEIP712(ownerKey, expired))
	if _, err := validateCapabilityFlags([]string{expiredTok}, pieceaccessDomain{}); err == nil {
		t.Fatal("expected expired reject")
	}
	// Bad signature: flip last hex nibble of a valid token's signature by re-encoding garbage.
	badSig := encodeCapabilityToken(t, voucher, "0x"+strings.Repeat("ab", 65))
	if _, err := validateCapabilityFlags([]string{badSig}, pieceaccessDomain{}); err == nil {
		t.Fatal("expected signature reject")
	}
}

func TestParseDealScope(t *testing.T) {
	t.Parallel()
	n, err := parseDealScope("1001")
	if err != nil || n.Cmp(big.NewInt(1001)) != 0 {
		t.Fatalf("got %v err=%v", n, err)
	}
	n, err = parseDealScope("0x10")
	if err != nil || n.Cmp(big.NewInt(16)) != 0 {
		t.Fatalf("got %v err=%v", n, err)
	}
}

func encodeCapabilityToken(t *testing.T, voucher apitypes.TypedData, sig string) string {
	t.Helper()
	types := apitypes.Types{}
	for k, v := range voucher.Types {
		if k == "EIP712Domain" {
			continue
		}
		types[k] = v
	}
	msg := make(map[string]any, len(voucher.Message))
	for k, v := range voucher.Message {
		msg[k] = v
	}
	payload := map[string]any{
		"domain":      voucher.Domain,
		"types":       types,
		"primaryType": voucher.PrimaryType,
		"message":     msg,
		"signature":   sig,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
