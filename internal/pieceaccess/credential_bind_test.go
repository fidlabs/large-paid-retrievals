package pieceaccess

import (
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

func TestParseCapabilityTokenRoundTrip(t *testing.T) {
	t.Parallel()
	ownerKey, _ := mustKey(t)
	_, grantee := mustKey(t)
	now := time.Now().Unix()
	tok := mustVoucherToken(t, ownerKey, grantee, 1001, now, now+86400, 314159)

	cap, err := ParseCapabilityToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	if !sameAddress(cap.Grantee, grantee) {
		t.Fatalf("grantee %s", cap.Grantee.Hex())
	}
	if cap.Scope.Cmp(big.NewInt(1001)) != 0 {
		t.Fatalf("scope=%s", cap.Scope)
	}
	if cap.Token != tok {
		t.Fatal("Token must be preserved verbatim for forwarding")
	}
	// The domain is preserved so the client can mint a matching proof.
	got, err := verifyVoucherToken(cap.Token, now, credentialTestPin(314159))
	if err != nil {
		t.Fatal(err)
	}
	if !sameAddress(got.Grantee, grantee) {
		t.Fatalf("verify grantee %s", got.Grantee.Hex())
	}
}

func TestVerifyCapabilityToken(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustKey(t)
	_, grantee := mustKey(t)
	now := time.Now().Unix()
	tok := mustVoucherToken(t, ownerKey, grantee, 1001, now, now+86400, 314159)

	cap, verified, err := VerifyCapabilityToken(tok, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !sameAddress(verified.Owner, owner) || !sameAddress(verified.Grantee, grantee) {
		t.Fatalf("owner=%s grantee=%s", verified.Owner.Hex(), verified.Grantee.Hex())
	}
	if cap.Token != tok {
		t.Fatal("Token must be preserved verbatim")
	}

	pin := &DomainPin{ChainID: big.NewInt(314159), Contract: common.HexToAddress(testContract)}
	if _, _, err := VerifyCapabilityToken(tok, now, pin); err != nil {
		t.Fatalf("pin match: %v", err)
	}
	badPin := &DomainPin{ChainID: big.NewInt(1), Contract: common.HexToAddress(testContract)}
	if _, _, err := VerifyCapabilityToken(tok, now, badPin); err == nil {
		t.Fatal("expected domain pin mismatch")
	}
	if _, _, err := VerifyCapabilityToken(tok, now+86400+1, nil); err == nil {
		t.Fatal("expected expired")
	}
	if _, _, err := VerifyCapabilityToken("not-a-token", now, nil); err == nil {
		t.Fatal("expected malformed")
	}
}

func TestParseCapabilityTokenRejectsLegacyDealID(t *testing.T) {
	t.Parallel()
	// Legacy voucher shape (dealId, no issuedAt) must be rejected.
	tok := encodeRawToken(t, map[string]any{
		"domain": map[string]any{
			"name": eip712DomainName, "version": eip712DomainVer,
			"chainId": 1, "verifyingContract": testContract,
		},
		"types": map[string]any{
			"RetrievalVoucher": []map[string]string{
				{"name": "grantee", "type": "address"},
				{"name": "dealId", "type": "uint256"},
				{"name": "deadline", "type": "uint256"},
			},
		},
		"primaryType": "RetrievalVoucher",
		"message": map[string]any{
			"grantee": "0x0000000000000000000000000000000000000001",
			"dealId":  "1", "deadline": time.Now().Unix() + 3600,
		},
		"signature": "0x00",
	})
	if _, err := ParseCapabilityToken(tok); err == nil {
		t.Fatal("expected legacy dealId capability to be rejected")
	}
}

func TestMintProofForPiece(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustKey(t)
	now := time.Now().Unix()
	domain := NewDomain(big.NewInt(1), common.HexToAddress(testContract))
	tok, err := MintProofForPiece(domain, big.NewInt(42), testPieceCID, ownerKey, now+3600)
	if err != nil {
		t.Fatal(err)
	}
	got, err := verifyProofToken(tok, testPieceCID, now, credentialTestPin(1))
	if err != nil {
		t.Fatal(err)
	}
	if !sameAddress(got.Requester, owner) || got.Scope.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestMintProofForPieceDefaultsDeadline(t *testing.T) {
	t.Parallel()
	ownerKey, _ := mustKey(t)
	now := time.Now().Unix()
	domain := NewDomain(big.NewInt(1), common.HexToAddress(testContract))
	tok, err := MintProofForPiece(domain, nil, testPieceCID, ownerKey, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyProofToken(tok, testPieceCID, now, credentialTestPin(1)); err != nil {
		t.Fatalf("default deadline must verify: %v", err)
	}
}
