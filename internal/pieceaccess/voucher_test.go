package pieceaccess

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

func TestVerifyBearerVoucherRoundTrip(t *testing.T) {
	t.Parallel()

	ownerKey, owner := mustKey(t)
	grantee := common.HexToAddress("0xabc0000000000000000000000000000000000123")
	deadline := time.Now().Add(time.Hour).Unix()

	token := mustSignVoucher(t, ownerKey, voucherFields{
		grantee:  grantee,
		dealID:   1001,
		deadline: deadline,
		chainID:  314159,
	})

	got, err := verifyBearerVoucher(token, time.Now().Unix(), voucherTestPin(314159))
	if err != nil {
		t.Fatal(err)
	}
	if !sameAddress(got.Owner, owner) {
		t.Fatalf("owner: got %s want %s", got.Owner.Hex(), owner.Hex())
	}
	if !sameAddress(got.Grantee, grantee) {
		t.Fatalf("grantee: got %s want %s", got.Grantee.Hex(), grantee.Hex())
	}
	if got.DealID.Cmp(big.NewInt(1001)) != 0 {
		t.Fatalf("dealId: got %s", got.DealID)
	}
	if got.Deadline != deadline {
		t.Fatalf("deadline: got %d want %d", got.Deadline, deadline)
	}
}

func TestVerifyBearerVoucherLargeDealID(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustKey(t)
	grantee := common.HexToAddress("0xabc0000000000000000000000000000000000123")
	deadline := time.Now().Add(time.Hour).Unix()
	dealID := new(big.Int).Lsh(big.NewInt(1), 80) // beyond float64 exact-int range

	token := mustSignVoucherRaw(t, ownerKey, grantee, dealID, deadline, 1)
	got, err := verifyBearerVoucher(token, time.Now().Unix(), voucherTestPin(1))
	if err != nil {
		t.Fatal(err)
	}
	if !sameAddress(got.Owner, owner) || got.DealID.Cmp(dealID) != 0 {
		t.Fatalf("got owner=%s dealId=%s", got.Owner.Hex(), got.DealID)
	}
}

func TestVerifyBearerVoucherExpired(t *testing.T) {
	t.Parallel()
	ownerKey, _ := mustKey(t)
	token := mustSignVoucher(t, ownerKey, voucherFields{
		grantee:  common.HexToAddress("0x1"),
		dealID:   1,
		deadline: time.Now().Add(-time.Minute).Unix(),
		chainID:  1,
	})
	_, err := verifyBearerVoucher(token, time.Now().Unix(), voucherTestPin(1))
	if !errors.Is(err, ErrInvalidVoucher) || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("got %v", err)
	}
}

func TestVerifyBearerVoucherDeadlineEqualsNow(t *testing.T) {
	t.Parallel()
	ownerKey, _ := mustKey(t)
	const now int64 = 1_700_000_000
	token := mustSignVoucher(t, ownerKey, voucherFields{
		grantee:  common.HexToAddress("0x1"),
		dealID:   1,
		deadline: now, // deadline <= now is expired (strictly before deadline)
		chainID:  1,
	})
	_, err := verifyBearerVoucher(token, now, voucherTestPin(1))
	if !errors.Is(err, ErrInvalidVoucher) || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("deadline==now must be expired; got %v", err)
	}
	// Control: one second before deadline still valid.
	if _, err := verifyBearerVoucher(token, now-1, voucherTestPin(1)); err != nil {
		t.Fatalf("deadline=now+1 from verifier clock should accept: %v", err)
	}
}

func TestVerifyBearerVoucherBadSignature(t *testing.T) {
	t.Parallel()
	ownerKey, _ := mustKey(t)
	token := mustSignVoucher(t, ownerKey, voucherFields{
		grantee:  common.HexToAddress("0x1"),
		dealID:   1,
		deadline: time.Now().Add(time.Hour).Unix(),
		chainID:  1,
	})
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}
	var tok voucherToken
	if err := json.Unmarshal(raw, &tok); err != nil {
		t.Fatal(err)
	}
	tok.Signature = "0x" + strings.Repeat("00", 65)
	bad, err := encodeBearerVoucherToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifyBearerVoucher(bad, time.Now().Unix(), voucherTestPin(1))
	if !errors.Is(err, ErrInvalidVoucher) || !strings.Contains(strings.ToLower(err.Error()), "signature") {
		t.Fatalf("got %v", err)
	}
}

func TestParseAndVerifyVouchersMultipleHeaders(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustKey(t)
	otherKey, _ := mustKey(t)
	deadline := time.Now().Add(time.Hour).Unix()

	v1 := mustSignVoucher(t, ownerKey, voucherFields{grantee: common.HexToAddress("0x1"), dealID: 1, deadline: deadline, chainID: 1})
	v2 := mustSignVoucher(t, otherKey, voucherFields{grantee: common.HexToAddress("0x2"), dealID: 2, deadline: deadline, chainID: 1})

	req := httptest.NewRequest(http.MethodGet, "/piece/baga", nil)
	req.Header.Add("Authorization", "Bearer "+v1)
	req.Header.Add("Authorization", "Payment ignored")
	req.Header.Add("Authorization", "Bearer "+v2)

	got, err := parseAndVerifyVouchers(req, voucherTestPin(1))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("len=%d", len(got))
	}
	if !sameAddress(got[0].Owner, owner) {
		t.Fatalf("first owner %s", got[0].Owner.Hex())
	}
}

func TestParseAndVerifyVouchersAnyInvalidFails(t *testing.T) {
	t.Parallel()
	ownerKey, _ := mustKey(t)
	deadline := time.Now().Add(time.Hour).Unix()
	good := mustSignVoucher(t, ownerKey, voucherFields{grantee: common.HexToAddress("0x1"), dealID: 1, deadline: deadline, chainID: 1})

	req := httptest.NewRequest(http.MethodGet, "/piece/baga", nil)
	req.Header.Add("Authorization", "Bearer "+good)
	req.Header.Add("Authorization", "Bearer not-valid-base64!!!")

	_, err := parseAndVerifyVouchers(req, voucherTestPin(1))
	if !errors.Is(err, ErrInvalidVoucher) {
		t.Fatalf("got %v", err)
	}
	var ve *voucherVerifyError
	if !errors.As(err, &ve) || len(ve.details) != 1 || ve.details[0].Index != 1 {
		t.Fatalf("details: %+v", err)
	}
}

func TestBearerAuthorizationHeaderCapitalization(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustKey(t)
	deadline := time.Now().Add(time.Hour).Unix()
	token := mustSignVoucher(t, ownerKey, voucherFields{
		grantee:  common.HexToAddress("0x1"),
		dealID:   7,
		deadline: deadline,
		chainID:  1,
	})

	cases := []struct {
		name       string
		headerName string
		value      string
	}{
		{name: "canonical Authorization + Bearer", headerName: "Authorization", value: "Bearer " + token},
		{name: "lowercase authorization + bearer", headerName: "authorization", value: "bearer " + token},
		{name: "uppercase AUTHORIZATION + BEARER", headerName: "AUTHORIZATION", value: "BEARER " + token},
		{name: "mixed AuThOrIzAtIoN + BeArEr", headerName: "AuThOrIzAtIoN", value: "BeArEr " + token},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/piece/baga", nil)
			// Header.Add canonicalizes the name; also assert Values still finds it.
			req.Header.Add(tc.headerName, tc.value)
			got, err := parseAndVerifyVouchers(req, voucherTestPin(1))
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || !sameAddress(got[0].Owner, owner) {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestBearerAuthorizationRawMapHeaderCapitalization(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustKey(t)
	deadline := time.Now().Add(time.Hour).Unix()
	token := mustSignVoucher(t, ownerKey, voucherFields{
		grantee:  common.HexToAddress("0x1"),
		dealID:   8,
		deadline: deadline,
		chainID:  1,
	})

	// Some stacks leave non-canonical map keys; Values("Authorization") only
	// looks up the canonical key, so copy into canonical form first when needed.
	req := httptest.NewRequest(http.MethodGet, "/piece/baga", nil)
	req.Header = http.Header{
		"AUTHORIZATION": []string{"BEARER " + token},
		"authorization": []string{"bearer " + token},
	}
	// Mimic net/http server canonicalization for lookup compatibility.
	req.Header = canonicalizeHeaderMap(req.Header)

	got, err := parseAndVerifyVouchers(req, voucherTestPin(1))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("len=%d want 2 (both casings after canonicalize)", len(got))
	}
	if !sameAddress(got[0].Owner, owner) || !sameAddress(got[1].Owner, owner) {
		t.Fatalf("owners: %+v", got)
	}
}

func canonicalizeHeaderMap(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vals := range h {
		for _, v := range vals {
			out.Add(k, v)
		}
	}
	return out
}

func TestWriteVoucherErrorJSON(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	writeVoucherError(rec, &voucherVerifyError{details: []voucherErrorDetail{{
		Index: 0, Error: "voucher_expired", Message: "expired",
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

const voucherTestContract = "0x1234567890abcdef1234567890abcdef12345678"

func voucherTestPin(chainID int64) *voucherDomainPin {
	return &voucherDomainPin{
		chainID:  big.NewInt(chainID),
		contract: common.HexToAddress(voucherTestContract),
	}
}

type voucherFields struct {
	grantee  common.Address
	dealID   int64
	deadline int64
	chainID  int64
}

func mustKey(t *testing.T) (*ecdsa.PrivateKey, common.Address) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key, crypto.PubkeyToAddress(key.PublicKey)
}

func mustSignVoucher(t *testing.T, key *ecdsa.PrivateKey, f voucherFields) string {
	t.Helper()
	return mustSignVoucherRaw(t, key, f.grantee, big.NewInt(f.dealID), f.deadline, f.chainID)
}

// mustSignVoucherRaw signs a voucher with an arbitrary uint256 dealId (decimal string in JSON).
func mustSignVoucherRaw(t *testing.T, key *ecdsa.PrivateKey, grantee common.Address, dealID *big.Int, deadline, chainID int64) string {
	t.Helper()
	if dealID == nil {
		t.Fatal("nil dealID")
	}
	payload := map[string]any{
		"domain": map[string]any{
			"name":              voucherDomainName,
			"version":           voucherDomainVer,
			"chainId":           chainID,
			"verifyingContract": voucherTestContract,
		},
		"types": map[string]any{
			voucherPrimaryType: []apitypes.Type{
				{Name: voucherTypeGrantee, Type: "address"},
				{Name: voucherTypeDealID, Type: "uint256"},
				{Name: voucherTypeDeadline, Type: "uint256"},
			},
		},
		"primaryType": voucherPrimaryType,
		"message": map[string]any{
			voucherTypeGrantee:  grantee.Hex(),
			voucherTypeDealID:   dealID.String(),
			voucherTypeDeadline: fmt.Sprintf("%d", deadline),
		},
		"signature": "0x00",
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := decodeVoucherToken(raw)
	if err != nil {
		t.Fatal(err)
	}
	parsedDeal, err := parseVoucherUint256(tok.Message[voucherTypeDealID])
	if err != nil {
		t.Fatal(err)
	}
	deadlineBig, err := parseVoucherUint256(tok.Message[voucherTypeDeadline])
	if err != nil {
		t.Fatal(err)
	}
	tok.Message[voucherTypeDealID] = parsedDeal.String()
	tok.Message[voucherTypeDeadline] = deadlineBig.String()
	ensureEIP712DomainTypes(tok)
	typed := apitypes.TypedData{
		Types:       tok.Types,
		PrimaryType: tok.PrimaryType,
		Domain:      tok.Domain,
		Message:     tok.Message,
	}
	digest, _, err := apitypes.TypedDataAndHash(typed)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypto.Sign(digest, key)
	if err != nil {
		t.Fatal(err)
	}
	sig[64] += 27
	tok.Signature = "0x" + common.Bytes2Hex(sig)
	delete(tok.Types, "EIP712Domain")
	token, err := encodeBearerVoucherToken(*tok)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func encodeBearerVoucherToken(tok voucherToken) (string, error) {
	raw, err := json.Marshal(tok)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
