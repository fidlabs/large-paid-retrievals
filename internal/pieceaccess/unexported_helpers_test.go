// White-box tests for unexported pieceaccess helpers and edge paths
// (voucher parsing/shape, deal authorization helpers, middleware utilities).
//
// This file uses package pieceaccess (not pieceaccess_test) so tests can call
// unexported functions directly. Prefer pieceaccess_test + exported APIs for
// behavior-level middleware/voucher coverage; keep this file for internal
// helper contracts and fail-closed branches that are awkward to hit only
// through the public Authorizer surface.
package pieceaccess

import (
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
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

func TestParseVoucherUint256(t *testing.T) {
	t.Parallel()
	largeOK := new(big.Int).Lsh(big.NewInt(1), 80)
	tooBig := new(big.Int).Lsh(big.NewInt(1), 256) // 2^256, BitLen 257
	cases := []struct {
		name    string
		in      any
		want    *big.Int
		wantErr string
	}{
		{name: "json.Number", in: json.Number("42"), want: big.NewInt(42)},
		{name: "float64", in: float64(42), want: big.NewInt(42)},
		{name: "string", in: "99", want: big.NewInt(99)},
		{name: "string whitespace", in: "  7  ", want: big.NewInt(7)},
		{name: "large string", in: largeOK.String(), want: largeOK},
		{name: "large json.Number", in: json.Number(largeOK.String()), want: largeOK},
		{name: "negative float", in: float64(-1), wantErr: "not an integer"},
		{name: "non-integer float", in: 1.5, wantErr: "not an integer"},
		{name: "float above safe int", in: float64(1 << 53), wantErr: "float64 loses precision"},
		{name: "bad string", in: "nope", wantErr: "not an integer string"},
		{name: "negative string", in: "-1", wantErr: "negative"},
		{name: "out of uint256 range", in: tooBig.String(), wantErr: "out of uint256 range"},
		{name: "unsupported bool", in: true, wantErr: "unsupported type"},
		{name: "nil", in: nil, wantErr: "unsupported type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseVoucherUint256(tc.in)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err=%v want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got.Cmp(tc.want) != 0 {
				t.Fatalf("got %v err=%v want %s", got, err, tc.want)
			}
		})
	}
}

func TestValidateVoucherShape(t *testing.T) {
	t.Parallel()
	valid := validShapeToken()

	t.Run("ok", func(t *testing.T) {
		t.Parallel()
		if err := validateVoucherShape(valid); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		if err := validateVoucherShape(nil); err == nil || !strings.Contains(err.Error(), "nil") {
			t.Fatalf("got %v", err)
		}
	})

	mutate := func(name string, edit func(*voucherToken), wantSub string) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tok := validShapeToken()
			edit(tok)
			err := validateVoucherShape(tok)
			if err == nil || !strings.Contains(err.Error(), wantSub) {
				t.Fatalf("got %v want substring %q", err, wantSub)
			}
		})
	}
	mutate("bad primaryType", func(tok *voucherToken) { tok.PrimaryType = "Other" }, "primaryType")
	mutate("bad domain name", func(tok *voucherToken) { tok.Domain.Name = "Nope" }, "domain.name")
	mutate("bad domain version", func(tok *voucherToken) { tok.Domain.Version = "9" }, "domain.version")
	mutate("missing types", func(tok *voucherToken) { tok.Types = apitypes.Types{} }, "missing types")
	mutate("wrong field count", func(tok *voucherToken) {
		tok.Types[voucherPrimaryType] = tok.Types[voucherPrimaryType][:1]
	}, "field count")
	mutate("wrong field type", func(tok *voucherToken) {
		tok.Types[voucherPrimaryType][0].Type = "bytes32"
	}, "unexpected type field")
	mutate("unknown field name", func(tok *voucherToken) {
		tok.Types[voucherPrimaryType][0].Name = "spender"
	}, "unexpected type field")
	mutate("duplicate type field omits required", func(tok *voucherToken) {
		// Same length as want, but two grantee entries and no deadline — must reject
		// so EIP-712 hashing cannot drop a required field from the signed digest.
		tok.Types[voucherPrimaryType] = []apitypes.Type{
			{Name: voucherTypeGrantee, Type: "address"},
			{Name: voucherTypeGrantee, Type: "address"},
			{Name: voucherTypeDealID, Type: "uint256"},
		}
	}, "duplicate type field")
	mutate("nil message", func(tok *voucherToken) { tok.Message = nil }, "missing message")
	mutate("missing message field", func(tok *voucherToken) { delete(tok.Message, voucherTypeDealID) }, "missing message.dealId")
	mutate("empty signature", func(tok *voucherToken) { tok.Signature = "  " }, "missing signature")
}

func TestVerifyBearerVoucherMalformed(t *testing.T) {
	t.Parallel()
	now := time.Now().Unix()

	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		_, err := verifyBearerVoucher("  ", now, nil)
		if !errors.Is(err, ErrInvalidVoucher) || !strings.Contains(err.Error(), "empty") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("bad base64", func(t *testing.T) {
		t.Parallel()
		_, err := verifyBearerVoucher("!!!", now, nil)
		if !errors.Is(err, ErrInvalidVoucher) || !strings.Contains(err.Error(), "decode") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("bad json", func(t *testing.T) {
		t.Parallel()
		tok := base64.RawURLEncoding.EncodeToString([]byte("{"))
		_, err := verifyBearerVoucher(tok, now, nil)
		if !errors.Is(err, ErrInvalidVoucher) || !strings.Contains(err.Error(), "json") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("shape rejected", func(t *testing.T) {
		t.Parallel()
		tok := validShapeToken()
		tok.PrimaryType = "Wrong"
		raw, _ := encodeBearerVoucherToken(*tok)
		_, err := verifyBearerVoucher(raw, now, nil)
		if !errors.Is(err, ErrInvalidVoucher) || !strings.Contains(err.Error(), "primaryType") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("bad grantee", func(t *testing.T) {
		t.Parallel()
		ownerKey, _ := mustKey(t)
		token := mustSignVoucher(t, ownerKey, voucherFields{
			grantee: common.HexToAddress("0x1"), dealID: 1, deadline: now + 3600, chainID: 1,
		})
		raw, _ := base64.RawURLEncoding.DecodeString(token)
		var tok voucherToken
		_ = json.Unmarshal(raw, &tok)
		tok.Message[voucherTypeGrantee] = "not-an-address"
		bad, _ := encodeBearerVoucherToken(tok)
		_, err := verifyBearerVoucher(bad, now, voucherTestPin(1))
		if !errors.Is(err, ErrInvalidVoucher) || !strings.Contains(err.Error(), "grantee") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("quoted uint strings", func(t *testing.T) {
		t.Parallel()
		ownerKey, owner := mustKey(t)
		deadline := now + 3600
		token := mustSignVoucher(t, ownerKey, voucherFields{
			grantee: common.HexToAddress("0x1"), dealID: 55, deadline: deadline, chainID: 1,
		})
		// Rebuild message with string-encoded ints (still valid JSON map values).
		raw, _ := base64.RawURLEncoding.DecodeString(token)
		var tok voucherToken
		_ = json.Unmarshal(raw, &tok)
		tok.Message[voucherTypeDealID] = "55"
		tok.Message[voucherTypeDeadline] = fmt.Sprintf("%d", deadline)
		// Signature was over numeric fields; string message changes EIP-712 hash → recovery
		// still "succeeds" as some address, but we only care parseVoucherUint256 accepts strings.
		// Re-sign with string fields so verification succeeds end-to-end.
		ensureEIP712DomainTypes(&tok)
		typed := apitypes.TypedData{Types: tok.Types, PrimaryType: tok.PrimaryType, Domain: tok.Domain, Message: tok.Message}
		digest, _, err := apitypes.TypedDataAndHash(typed)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := crypto.Sign(digest, ownerKey)
		if err != nil {
			t.Fatal(err)
		}
		sig[64] += 27
		tok.Signature = "0x" + common.Bytes2Hex(sig)
		delete(tok.Types, "EIP712Domain")
		token, err = encodeBearerVoucherToken(tok)
		if err != nil {
			t.Fatal(err)
		}
		got, err := verifyBearerVoucher(token, now, voucherTestPin(1))
		if err != nil {
			t.Fatal(err)
		}
		if !sameAddress(got.Owner, owner) || got.DealID.Cmp(big.NewInt(55)) != 0 {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("short signature", func(t *testing.T) {
		t.Parallel()
		ownerKey, _ := mustKey(t)
		token := mustSignVoucher(t, ownerKey, voucherFields{
			grantee: common.HexToAddress("0x1"), dealID: 1, deadline: now + 3600, chainID: 1,
		})
		raw, _ := base64.RawURLEncoding.DecodeString(token)
		var tok voucherToken
		_ = json.Unmarshal(raw, &tok)
		tok.Signature = "0xabcd"
		bad, _ := encodeBearerVoucherToken(tok)
		_, err := verifyBearerVoucher(bad, now, voucherTestPin(1))
		if !errors.Is(err, ErrInvalidVoucher) || !strings.Contains(err.Error(), "65 bytes") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("bad recovery id", func(t *testing.T) {
		t.Parallel()
		ownerKey, _ := mustKey(t)
		token := mustSignVoucher(t, ownerKey, voucherFields{
			grantee: common.HexToAddress("0x1"), dealID: 1, deadline: now + 3600, chainID: 1,
		})
		raw, _ := base64.RawURLEncoding.DecodeString(token)
		var tok voucherToken
		_ = json.Unmarshal(raw, &tok)
		sig := common.FromHex(tok.Signature)
		sig[64] = 2 // invalid after 27-normalization path
		tok.Signature = "0x" + common.Bytes2Hex(sig)
		bad, _ := encodeBearerVoucherToken(tok)
		_, err := verifyBearerVoucher(bad, now, voucherTestPin(1))
		if !errors.Is(err, ErrInvalidVoucher) || !strings.Contains(err.Error(), "recovery id") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("bad deadline type", func(t *testing.T) {
		t.Parallel()
		tok := validShapeToken()
		tok.Message[voucherTypeDeadline] = true
		raw, _ := encodeBearerVoucherToken(*tok)
		_, err := verifyBearerVoucher(raw, now, voucherTestPin(1))
		if !errors.Is(err, ErrInvalidVoucher) || !strings.Contains(err.Error(), "deadline") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("bad dealId type", func(t *testing.T) {
		t.Parallel()
		tok := validShapeToken()
		tok.Message[voucherTypeDealID] = true
		tok.Message[voucherTypeDeadline] = float64(now + 3600)
		raw, _ := encodeBearerVoucherToken(*tok)
		_, err := verifyBearerVoucher(raw, now, voucherTestPin(1))
		if !errors.Is(err, ErrInvalidVoucher) || !strings.Contains(err.Error(), "dealId") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("eip712 hash failure", func(t *testing.T) {
		t.Parallel()
		tok := validShapeToken()
		tok.Domain.ChainId = (*math.HexOrDecimal256)(big.NewInt(1))
		tok.Domain.VerifyingContract = voucherTestContract
		tok.Message[voucherTypeDeadline] = float64(now + 3600)
		// Invalid salt makes TypedDataAndHash fail after the domain pin accepts.
		tok.Domain.Salt = "0xnot32bytes"
		raw, _ := encodeBearerVoucherToken(*tok)
		_, err := verifyBearerVoucher(raw, now, voucherTestPin(1))
		if !errors.Is(err, ErrInvalidVoucher) || !strings.Contains(strings.ToLower(err.Error()), "eip-712") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("invalid verifyingContract in domain", func(t *testing.T) {
		t.Parallel()
		tok := validShapeToken()
		tok.Domain.ChainId = (*math.HexOrDecimal256)(big.NewInt(1))
		tok.Domain.VerifyingContract = "not-an-address"
		tok.Message[voucherTypeDeadline] = float64(now + 3600)
		raw, _ := encodeBearerVoucherToken(*tok)
		_, err := verifyBearerVoucher(raw, now, voucherTestPin(1))
		if !errors.Is(err, ErrInvalidVoucher) || !strings.Contains(err.Error(), "verifyingContract") {
			t.Fatalf("got %v", err)
		}
	})
}

func TestEnsureEIP712DomainTypes(t *testing.T) {
	t.Parallel()
	t.Run("nil types and salt", func(t *testing.T) {
		t.Parallel()
		tok := &voucherToken{
			Domain: apitypes.TypedDataDomain{
				Name:              voucherDomainName,
				Version:           voucherDomainVer,
				ChainId:           math.NewHexOrDecimal256(1),
				VerifyingContract: "0x1234567890abcdef1234567890abcdef12345678",
				Salt:              "0x" + strings.Repeat("11", 32),
			},
		}
		ensureEIP712DomainTypes(tok)
		fields := tok.Types["EIP712Domain"]
		var names []string
		for _, f := range fields {
			names = append(names, f.Name)
		}
		want := []string{"name", "version", "chainId", "verifyingContract", "salt"}
		if strings.Join(names, ",") != strings.Join(want, ",") {
			t.Fatalf("fields=%v want %v", names, want)
		}
	})
	t.Run("keeps existing EIP712Domain", func(t *testing.T) {
		t.Parallel()
		existing := []apitypes.Type{{Name: "name", Type: "string"}}
		tok := &voucherToken{
			Types:  apitypes.Types{"EIP712Domain": existing},
			Domain: apitypes.TypedDataDomain{Name: voucherDomainName, Version: voucherDomainVer},
		}
		ensureEIP712DomainTypes(tok)
		if len(tok.Types["EIP712Domain"]) != 1 {
			t.Fatalf("mutated existing domain types: %+v", tok.Types["EIP712Domain"])
		}
	})
}

func TestVoucherAuthorizesDeal(t *testing.T) {
	t.Parallel()
	owner := common.HexToAddress("0xabc0000000000000000000000000000000000abc")
	v := VerifiedVoucher{Owner: owner, DealID: big.NewInt(1001)}
	if voucherAuthorizesDeal(v, nil) {
		t.Fatal("nil deal")
	}
	if voucherAuthorizesDeal(v, &Deal{DealID: "1001", Client: owner, DealType: DealTypePublic}) {
		t.Fatal("public deal")
	}
	if !voucherAuthorizesDeal(v, &Deal{DealID: "1001", Client: owner, DealType: DealTypePrivate}) {
		t.Fatal("private owner+dealId match")
	}
	if voucherAuthorizesDeal(v, &Deal{DealID: "1002", Client: owner, DealType: DealTypePrivate}) {
		t.Fatal("same owner wrong dealId")
	}
	if voucherAuthorizesDeal(VerifiedVoucher{DealID: big.NewInt(1001)}, &Deal{DealID: "1001", Client: owner, DealType: DealTypePrivate}) {
		t.Fatal("zero owner")
	}
	if voucherAuthorizesDeal(VerifiedVoucher{Owner: owner}, &Deal{DealID: "1001", Client: owner, DealType: DealTypePrivate}) {
		t.Fatal("nil voucher dealId")
	}
	if voucherAuthorizesDeal(v, &Deal{DealID: "not-a-number", Client: owner, DealType: DealTypePrivate}) {
		t.Fatal("unparseable deal id")
	}
}

func TestDealAllowsAccess(t *testing.T) {
	t.Parallel()
	owner := common.HexToAddress("0x1")
	if dealAllowsAccess(nil, owner) {
		t.Fatal("nil")
	}
	if !dealAllowsAccess(&Deal{DealType: DealTypePublic}, common.Address{}) {
		t.Fatal("public")
	}
	if dealAllowsAccess(&Deal{DealType: DealTypePrivate, Client: owner}, common.Address{}) {
		t.Fatal("anonymous private")
	}
	if !dealAllowsAccess(&Deal{DealType: DealTypePrivate, Client: owner}, owner) {
		t.Fatal("owner private")
	}
	if dealAllowsAccess(&Deal{DealType: DealTypeUnknown}, owner) {
		t.Fatal("unknown")
	}
}

func TestVoucherErrorHelpers(t *testing.T) {
	t.Parallel()
	if voucherErrorCode(errors.New("expired yesterday")) != "voucher_expired" {
		t.Fatal("expired")
	}
	if voucherErrorCode(errors.New("bad signature")) != "invalid_signature" {
		t.Fatal("signature")
	}
	if voucherErrorCode(errors.New("bearer token base64url decode")) != "malformed_voucher" {
		t.Fatal("malformed")
	}
	if voucherErrorCode(errors.New("something else")) != "invalid_voucher" {
		t.Fatal("default")
	}

	var nilErr *voucherVerifyError
	if nilErr.Error() != ErrInvalidVoucher.Error() {
		t.Fatalf("nil error: %q", nilErr.Error())
	}
	if (&voucherVerifyError{}).Error() != ErrInvalidVoucher.Error() {
		t.Fatal("empty details")
	}

	rec := httptest.NewRecorder()
	writeVoucherError(rec, errors.New("plain failure"))
	var body voucherErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Details) != 1 || body.Details[0].Message != "plain failure" {
		t.Fatalf("body=%+v", body)
	}
}

func TestBearerAuthorizationValuesEdge(t *testing.T) {
	t.Parallel()
	if bearerAuthorizationValues(nil) != nil {
		t.Fatal("nil request")
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Add("Authorization", "   ")
	req.Header.Add("Authorization", "Bearer") // scheme only, no token separator
	req.Header.Add("Authorization", "Payment x")
	if got := bearerAuthorizationValues(req); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestParsePiecePath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path string
		ok   bool
		cid  string
	}{
		{"/piece/baga", true, "baga"},
		{"/healthz", false, ""},
		{"/piece/", false, ""},
		{"/piece/a/b", false, ""},
	}
	for _, tc := range cases {
		cid, ok := parsePiecePath(tc.path)
		if ok != tc.ok || cid != tc.cid {
			t.Fatalf("%q -> (%q,%v) want (%q,%v)", tc.path, cid, ok, tc.cid, tc.ok)
		}
	}
}

func TestHasPaymentAuthorizationNil(t *testing.T) {
	t.Parallel()
	if hasPaymentAuthorization(nil) {
		t.Fatal("nil")
	}
}

func TestSelectRepresentativeDealNilAndVoucher(t *testing.T) {
	t.Parallel()
	owner := common.HexToAddress("0xabc0000000000000000000000000000000000abc")
	other := common.HexToAddress("0x1")
	deals := []*Deal{
		nil,
		{DealID: "1", Client: other, DealType: DealTypePrivate},
		{DealID: "2", Client: owner, DealType: DealTypePrivate},
	}
	got := selectRepresentativeDeal(deals, owner, []VerifiedVoucher{{Owner: owner, Grantee: owner, DealID: big.NewInt(2)}})
	if got == nil || got.DealID != "2" {
		t.Fatalf("got %+v", got)
	}
	// Wrong dealId must not select the same-owner private deal via voucher.
	got = selectRepresentativeDeal(deals, owner, []VerifiedVoucher{{Owner: owner, Grantee: owner, DealID: big.NewInt(99)}})
	if got == nil || got.DealID != "2" {
		// owner matches deal 2 as Client; voucher miss still allows owner match
		t.Fatalf("owner match want deal 2, got %+v", got)
	}
	// Empty requester: vouchers must not authorize; fall back to first non-nil deal.
	got = selectRepresentativeDeal(deals, common.Address{}, []VerifiedVoucher{{Owner: owner, Grantee: owner, DealID: big.NewInt(2)}})
	if got == nil || got.DealID != "1" {
		t.Fatalf("fallback first deal want 1, got %+v", got)
	}
}

func TestPrivateDealAllowedNil(t *testing.T) {
	t.Parallel()
	if privateDealAllowed(nil, common.HexToAddress("0x1"), nil) {
		t.Fatal("nil deal")
	}
	if privateDealAllowed(&Deal{DealType: DealTypePublic}, common.HexToAddress("0x1"), nil) {
		t.Fatal("public")
	}
}

func TestDenyAccessSkipsNilDeals(t *testing.T) {
	t.Parallel()
	a := NewAuthorizer()
	req := httptest.NewRequest(http.MethodGet, "/piece/baga", nil)
	denied, reason := a.denyAccess(req, []*Deal{nil, {DealID: "1", DealType: DealTypePublic}}, nil, nil)
	if denied || reason != "" {
		t.Fatalf("denied=%v reason=%q", denied, reason)
	}
}

func validShapeToken() *voucherToken {
	return &voucherToken{
		Domain: apitypes.TypedDataDomain{
			Name:    voucherDomainName,
			Version: voucherDomainVer,
		},
		Types: apitypes.Types{
			voucherPrimaryType: {
				{Name: voucherTypeGrantee, Type: "address"},
				{Name: voucherTypeDealID, Type: "uint256"},
				{Name: voucherTypeDeadline, Type: "uint256"},
			},
		},
		PrimaryType: voucherPrimaryType,
		Message: map[string]any{
			voucherTypeGrantee:  "0x0000000000000000000000000000000000000001",
			voucherTypeDealID:   float64(1),
			voucherTypeDeadline: float64(time.Now().Add(time.Hour).Unix()),
		},
		Signature: "0x" + strings.Repeat("ab", 65),
	}
}

func TestVerifyBearerVoucherRequiresDomainPin(t *testing.T) {
	t.Parallel()
	ownerKey, _ := mustKey(t)
	token := mustSignVoucher(t, ownerKey, voucherFields{
		grantee: common.HexToAddress("0x1"), dealID: 1, deadline: time.Now().Add(time.Hour).Unix(), chainID: 1,
	})
	_, err := verifyBearerVoucher(token, time.Now().Unix(), nil)
	if !errors.Is(err, ErrInvalidVoucher) || !strings.Contains(err.Error(), "domain pin not configured") {
		t.Fatalf("got %v", err)
	}
}
