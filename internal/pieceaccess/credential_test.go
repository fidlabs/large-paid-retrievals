package pieceaccess

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	testPieceCID = "baga6ea4seaqabc"
	testContract = "0x1234567890abcdef1234567890abcdef12345678"
)

func TestVerifyProofTokenOwnerDirect(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustKey(t)
	now := time.Now().Unix()
	tok := mustProofToken(t, ownerKey, 1001, testPieceCID, now+3600, 314159)

	got, err := verifyProofToken(tok, testPieceCID, now, credentialTestPin(314159))
	if err != nil {
		t.Fatal(err)
	}
	if !sameAddress(got.Requester, owner) {
		t.Fatalf("requester: got %s want %s", got.Requester.Hex(), owner.Hex())
	}
	if got.Scope.Cmp(big.NewInt(1001)) != 0 || got.Resource != testPieceCID {
		t.Fatalf("got %+v", got)
	}
}

func TestVerifyProofTokenLargeScope(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustKey(t)
	now := time.Now().Unix()
	scope := new(big.Int).Lsh(big.NewInt(1), 80)
	domain := NewDomain(big.NewInt(1), common.HexToAddress(testContract))
	td := BuildProofTypedData(domain, scope, testPieceCID, now+3600)
	tok := MustEncodeSignedToken(td, MustSignEIP712(ownerKey, td))

	got, err := verifyProofToken(tok, testPieceCID, now, credentialTestPin(1))
	if err != nil {
		t.Fatal(err)
	}
	if !sameAddress(got.Requester, owner) || got.Scope.Cmp(scope) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestVerifyProofTokenSadPaths(t *testing.T) {
	t.Parallel()
	ownerKey, _ := mustKey(t)
	now := time.Now().Unix()
	pin := credentialTestPin(1)

	cases := []struct {
		name    string
		token   func(t *testing.T) string
		piece   string
		now     int64
		pin     *voucherDomainPin
		wantSub string
	}{
		{
			name:  "expired proof",
			token: func(t *testing.T) string { return mustProofToken(t, ownerKey, 1, testPieceCID, now-60, 1) },
			piece: testPieceCID, now: now, pin: pin, wantSub: "proof expired",
		},
		{
			name:  "proof deadline equals now",
			token: func(t *testing.T) string { return mustProofToken(t, ownerKey, 1, testPieceCID, now, 1) },
			piece: testPieceCID, now: now, pin: pin, wantSub: "proof expired",
		},
		{
			name: "proof deadline too far",
			token: func(t *testing.T) string {
				return mustProofToken(t, ownerKey, 1, testPieceCID, now+int64(MaxProofTTL.Seconds())+60, 1)
			},
			piece: testPieceCID, now: now, pin: pin, wantSub: "MAX_PROOF_TTL",
		},
		{
			name:  "wrong resource",
			token: func(t *testing.T) string { return mustProofToken(t, ownerKey, 1, "othercid", now+3600, 1) },
			piece: testPieceCID, now: now, pin: pin, wantSub: "proof.resource",
		},
		{
			name:  "domain pin missing",
			token: func(t *testing.T) string { return mustProofToken(t, ownerKey, 1, testPieceCID, now+3600, 1) },
			piece: testPieceCID, now: now, pin: nil, wantSub: "domain pin not configured",
		},
		{
			name:  "wrong chain domain",
			token: func(t *testing.T) string { return mustProofToken(t, ownerKey, 1, testPieceCID, now+3600, 999) },
			piece: testPieceCID, now: now, pin: pin, wantSub: "domain.chainId",
		},
		{
			name: "bad proof signature",
			token: func(t *testing.T) string {
				domain := NewDomain(big.NewInt(1), common.HexToAddress(testContract))
				td := BuildProofTypedData(domain, big.NewInt(1), testPieceCID, now+3600)
				return MustEncodeSignedToken(td, "0x"+strings.Repeat("00", 65))
			},
			piece: testPieceCID, now: now, pin: pin, wantSub: "signature",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := verifyProofToken(tc.token(t), tc.piece, tc.now, tc.pin)
			if !errors.Is(err, ErrInvalidVoucher) || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("got %v want substring %q", err, tc.wantSub)
			}
		})
	}
}

func TestVerifyVoucherToken(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustKey(t)
	_, grantee := mustKey(t)
	now := time.Now().Unix()

	t.Run("ok", func(t *testing.T) {
		t.Parallel()
		tok := mustVoucherToken(t, ownerKey, grantee, 1001, now, now+86400, 1)
		got, err := verifyVoucherToken(tok, now, credentialTestPin(1))
		if err != nil {
			t.Fatal(err)
		}
		if !sameAddress(got.Owner, owner) || !sameAddress(got.Grantee, grantee) {
			t.Fatalf("got %+v", got)
		}
		if got.Scope.Cmp(big.NewInt(1001)) != 0 {
			t.Fatalf("scope=%v", got.Scope)
		}
	})
	t.Run("expired", func(t *testing.T) {
		t.Parallel()
		tok := mustVoucherToken(t, ownerKey, grantee, 1, now, now-60, 1)
		_, err := verifyVoucherToken(tok, now, credentialTestPin(1))
		if !errors.Is(err, ErrInvalidVoucher) || !strings.Contains(err.Error(), "voucher expired") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("wrong chain", func(t *testing.T) {
		t.Parallel()
		tok := mustVoucherToken(t, ownerKey, grantee, 1, now, now+86400, 999)
		_, err := verifyVoucherToken(tok, now, credentialTestPin(1))
		if !errors.Is(err, ErrInvalidVoucher) || !strings.Contains(err.Error(), "domain.chainId") {
			t.Fatalf("got %v", err)
		}
	})
}

func TestVerifyProofDeadlineBoundary(t *testing.T) {
	t.Parallel()
	ownerKey, _ := mustKey(t)
	const now int64 = 1_700_000_000
	maxOK := now + int64(MaxProofTTL.Seconds())
	tok := mustProofToken(t, ownerKey, 1, testPieceCID, maxOK, 1)
	if _, err := verifyProofToken(tok, testPieceCID, now, credentialTestPin(1)); err != nil {
		t.Fatalf("deadline=now+MAX_PROOF_TTL must accept: %v", err)
	}
	tokFar := mustProofToken(t, ownerKey, 1, testPieceCID, maxOK+1, 1)
	if _, err := verifyProofToken(tokFar, testPieceCID, now, credentialTestPin(1)); err == nil || !strings.Contains(err.Error(), "MAX_PROOF_TTL") {
		t.Fatalf("deadline=now+MAX_PROOF_TTL+1 must reject: %v", err)
	}
}

func TestParseAndVerifyAccessProofAndVouchers(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustKey(t)
	granteeKey, grantee := mustKey(t)
	otherKey, _ := mustKey(t)
	now := time.Now().Unix()

	proof := mustProofToken(t, granteeKey, 0, testPieceCID, now+3600, 1)
	v1 := mustVoucherToken(t, ownerKey, grantee, 1001, now, now+86400, 1)
	v2 := mustVoucherToken(t, otherKey, grantee, 1002, now, now+86400, 1)

	req := httptest.NewRequest(http.MethodGet, "/piece/"+testPieceCID, nil)
	req.Header.Add("Authorization", "RetrievalProof "+proof)
	req.Header.Add("Authorization", "Payment ignored")
	req.Header.Add("Authorization", "RetrievalVoucher "+v1)
	req.Header.Add("Authorization", "RetrievalVoucher "+v2)

	access, err := parseAndVerifyAccess(req, testPieceCID, credentialTestPin(1))
	if err != nil {
		t.Fatal(err)
	}
	if access == nil || access.Proof == nil {
		t.Fatal("expected proof")
	}
	if !sameAddress(access.Proof.Requester, grantee) {
		t.Fatalf("requester %s", access.Proof.Requester.Hex())
	}
	if len(access.Vouchers) != 2 {
		t.Fatalf("vouchers=%d", len(access.Vouchers))
	}
	if !sameAddress(access.Vouchers[0].Owner, owner) {
		t.Fatalf("voucher[0] owner %s", access.Vouchers[0].Owner.Hex())
	}
}

func TestParseAndVerifyAccessFatalOnBadProof(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/piece/"+testPieceCID, nil)
	req.Header.Add("Authorization", "RetrievalProof not-valid-base64!!!")

	_, err := parseAndVerifyAccess(req, testPieceCID, credentialTestPin(1))
	if !errors.Is(err, ErrInvalidVoucher) {
		t.Fatalf("got %v", err)
	}
}

func TestParseAndVerifyAccessVouchersBestEffort(t *testing.T) {
	t.Parallel()
	ownerKey, _ := mustKey(t)
	granteeKey, grantee := mustKey(t)
	now := time.Now().Unix()

	proof := mustProofToken(t, granteeKey, 0, testPieceCID, now+3600, 1)
	good := mustVoucherToken(t, ownerKey, grantee, 1001, now, now+86400, 1)

	req := httptest.NewRequest(http.MethodGet, "/piece/"+testPieceCID, nil)
	req.Header.Add("Authorization", "RetrievalProof "+proof)
	req.Header.Add("Authorization", "RetrievalVoucher "+good)
	req.Header.Add("Authorization", "RetrievalVoucher garbage!!!")

	access, err := parseAndVerifyAccess(req, testPieceCID, credentialTestPin(1))
	if err != nil {
		t.Fatalf("invalid vouchers must not fail the request: %v", err)
	}
	if len(access.Vouchers) != 1 || len(access.voucherErrors) != 1 {
		t.Fatalf("valid=%d errs=%d", len(access.Vouchers), len(access.voucherErrors))
	}
	if access.voucherErrors[0].Index != 1 {
		t.Fatalf("err index=%d", access.voucherErrors[0].Index)
	}
}

func TestParseAndVerifyAccessIgnoresBearer(t *testing.T) {
	t.Parallel()
	ownerKey, _ := mustKey(t)
	now := time.Now().Unix()
	proof := mustProofToken(t, ownerKey, 1, testPieceCID, now+3600, 1)

	req := httptest.NewRequest(http.MethodGet, "/piece/"+testPieceCID, nil)
	req.Header.Add("Authorization", "Bearer "+proof)
	access, err := parseAndVerifyAccess(req, testPieceCID, credentialTestPin(1))
	if err != nil {
		t.Fatal(err)
	}
	if access != nil {
		t.Fatalf("legacy Bearer scheme must be ignored, got %+v", access)
	}
}

func TestRetrievalSchemeCapitalization(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustKey(t)
	now := time.Now().Unix()
	proof := mustProofToken(t, ownerKey, 7, testPieceCID, now+3600, 1)

	cases := []struct {
		name       string
		headerName string
		value      string
	}{
		{name: "canonical", headerName: "Authorization", value: "RetrievalProof " + proof},
		{name: "lowercase", headerName: "authorization", value: "retrievalproof " + proof},
		{name: "uppercase", headerName: "AUTHORIZATION", value: "RETRIEVALPROOF " + proof},
		{name: "mixed", headerName: "AuThOrIzAtIoN", value: "ReTrIeVaLpRoOf " + proof},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/piece/"+testPieceCID, nil)
			req.Header.Add(tc.headerName, tc.value)
			access, err := parseAndVerifyAccess(req, testPieceCID, credentialTestPin(1))
			if err != nil {
				t.Fatal(err)
			}
			if access == nil || access.Proof == nil || !sameAddress(access.Proof.Requester, owner) {
				t.Fatalf("got %+v", access)
			}
		})
	}
}

func TestWriteVoucherErrorJSON(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	writeVoucherError(rec, &voucherVerifyError{details: []voucherErrorDetail{{
		Index: 0, Error: "proof_expired", Message: "proof expired",
	}}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("content-type=%q", ct)
	}
	var body voucherErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error != "invalid_voucher" || len(body.Details) != 1 {
		t.Fatalf("body=%+v", body)
	}
}

func TestSignAndEncodeRoundTrip(t *testing.T) {
	t.Parallel()
	key, addr := mustKey(t)
	domain := NewDomain(big.NewInt(314159), common.HexToAddress(testContract))
	proof := BuildProofTypedData(domain, big.NewInt(42), testPieceCID, time.Now().Add(time.Hour).Unix())
	sig := MustSignEIP712(key, proof)
	tok := MustEncodeSignedToken(proof, sig)
	got, err := verifyProofToken(tok, testPieceCID, time.Now().Unix(), credentialTestPin(314159))
	if err != nil {
		t.Fatal(err)
	}
	if !sameAddress(got.Requester, addr) {
		t.Fatalf("got %s want %s", got.Requester.Hex(), addr.Hex())
	}
}

func credentialTestPin(chainID int64) *voucherDomainPin {
	return &voucherDomainPin{
		chainID:  big.NewInt(chainID),
		contract: common.HexToAddress(testContract),
	}
}

func mustKey(t *testing.T) (*ecdsa.PrivateKey, common.Address) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key, crypto.PubkeyToAddress(key.PublicKey)
}

func mustProofToken(t *testing.T, key *ecdsa.PrivateKey, scope int64, resource string, deadline, chainID int64) string {
	t.Helper()
	domain := NewDomain(big.NewInt(chainID), common.HexToAddress(testContract))
	td := BuildProofTypedData(domain, big.NewInt(scope), resource, deadline)
	return MustEncodeSignedToken(td, MustSignEIP712(key, td))
}

func mustVoucherToken(t *testing.T, ownerKey *ecdsa.PrivateKey, grantee common.Address, scope, issuedAt, deadline, chainID int64) string {
	t.Helper()
	domain := NewDomain(big.NewInt(chainID), common.HexToAddress(testContract))
	td := BuildVoucherTypedData(domain, grantee, big.NewInt(scope), issuedAt, deadline)
	return MustEncodeSignedToken(td, MustSignEIP712(ownerKey, td))
}

// encodeRawToken base64url-encodes an arbitrary JSON map (malformed-token tests).
func encodeRawToken(t *testing.T, payload map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
