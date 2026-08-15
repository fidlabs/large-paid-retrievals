// White-box tests for unexported pieceaccess helpers and edge paths
// (credential parsing/shape, deal authorization helpers, middleware utilities).
package pieceaccess

import (
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
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

func TestParseUint256Field(t *testing.T) {
	t.Parallel()
	largeOK := new(big.Int).Lsh(big.NewInt(1), 80)
	tooBig := new(big.Int).Lsh(big.NewInt(1), 256)
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
			got, err := parseUint256Field(tc.in)
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

func TestValidateProofAndVoucherShape(t *testing.T) {
	t.Parallel()
	t.Run("proof ok", func(t *testing.T) {
		t.Parallel()
		if err := validateProofShape(validProofShape()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("voucher ok", func(t *testing.T) {
		t.Parallel()
		if err := validateVoucherShape(validVoucherShape()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("nil proof", func(t *testing.T) {
		t.Parallel()
		if err := validateProofShape(nil); err == nil || !strings.Contains(err.Error(), "nil") {
			t.Fatalf("got %v", err)
		}
	})

	mutateProof := func(name string, edit func(*eip712TypedDataJSON), wantSub string) {
		t.Run("proof/"+name, func(t *testing.T) {
			t.Parallel()
			obj := validProofShape()
			edit(obj)
			err := validateProofShape(obj)
			if err == nil || !strings.Contains(err.Error(), wantSub) {
				t.Fatalf("got %v want substring %q", err, wantSub)
			}
		})
	}
	mutateProof("bad primaryType", func(o *eip712TypedDataJSON) { o.PrimaryType = "Other" }, "primaryType")
	mutateProof("bad domain name", func(o *eip712TypedDataJSON) { o.Domain.Name = "Nope" }, "domain.name")
	mutateProof("missing types", func(o *eip712TypedDataJSON) { o.Types = apitypes.Types{} }, "missing types")
	mutateProof("wrong field count", func(o *eip712TypedDataJSON) {
		o.Types[primaryTypeProof] = o.Types[primaryTypeProof][:1]
	}, "field count")
	mutateProof("nil message", func(o *eip712TypedDataJSON) { o.Message = nil }, "missing proof.message")
	mutateProof("missing resource", func(o *eip712TypedDataJSON) { delete(o.Message, fieldResource) }, "missing proof.message.resource")

	mutateVoucher := func(name string, edit func(*eip712TypedDataJSON), wantSub string) {
		t.Run("voucher/"+name, func(t *testing.T) {
			t.Parallel()
			obj := validVoucherShape()
			edit(obj)
			err := validateVoucherShape(obj)
			if err == nil || !strings.Contains(err.Error(), wantSub) {
				t.Fatalf("got %v want substring %q", err, wantSub)
			}
		})
	}
	mutateVoucher("duplicate type field", func(o *eip712TypedDataJSON) {
		o.Types[primaryTypeVoucher] = []apitypes.Type{
			{Name: fieldGrantee, Type: "address"},
			{Name: fieldGrantee, Type: "address"},
			{Name: fieldScope, Type: "uint256"},
			{Name: fieldIssuedAt, Type: "uint256"},
		}
	}, "duplicate type field")
	mutateVoucher("missing issuedAt", func(o *eip712TypedDataJSON) { delete(o.Message, fieldIssuedAt) }, "missing voucher.message.issuedAt")
}

func TestDecodeSignedTokenMalformed(t *testing.T) {
	t.Parallel()
	now := time.Now().Unix()
	pin := credentialTestPin(1)

	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		_, _, err := decodeSignedToken("  ")
		if !errors.Is(err, ErrInvalidVoucher) || !strings.Contains(err.Error(), "empty") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("bad base64", func(t *testing.T) {
		t.Parallel()
		_, _, err := decodeSignedToken("!!!")
		if !errors.Is(err, ErrInvalidVoucher) || !strings.Contains(err.Error(), "decode") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("bad json", func(t *testing.T) {
		t.Parallel()
		tok := base64.RawURLEncoding.EncodeToString([]byte("{"))
		_, _, err := decodeSignedToken(tok)
		if !errors.Is(err, ErrInvalidVoucher) || !strings.Contains(err.Error(), "json") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("missing signature", func(t *testing.T) {
		t.Parallel()
		tok := encodeRawToken(t, map[string]any{"primaryType": "RetrievalProof", "message": map[string]any{}})
		_, _, err := decodeSignedToken(tok)
		if !errors.Is(err, ErrInvalidVoucher) || !strings.Contains(err.Error(), "missing signature") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("short signature", func(t *testing.T) {
		t.Parallel()
		ownerKey, _ := mustKey(t)
		domain := NewDomain(big.NewInt(1), common.HexToAddress(testContract))
		td := BuildProofTypedData(domain, big.NewInt(1), testPieceCID, now+3600)
		tok := MustEncodeSignedToken(td, "0xabcd")
		_ = ownerKey
		_, err := verifyProofToken(tok, testPieceCID, now, pin)
		if !errors.Is(err, ErrInvalidVoucher) || !strings.Contains(err.Error(), "65 bytes") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("bad recovery id", func(t *testing.T) {
		t.Parallel()
		ownerKey, _ := mustKey(t)
		domain := NewDomain(big.NewInt(1), common.HexToAddress(testContract))
		td := BuildProofTypedData(domain, big.NewInt(1), testPieceCID, now+3600)
		sig := common.FromHex(MustSignEIP712(ownerKey, td))
		sig[64] = 2
		tok := MustEncodeSignedToken(td, "0x"+common.Bytes2Hex(sig))
		_, err := verifyProofToken(tok, testPieceCID, now, pin)
		if !errors.Is(err, ErrInvalidVoucher) || !strings.Contains(err.Error(), "recovery id") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("eip712 hash failure", func(t *testing.T) {
		t.Parallel()
		obj := validProofShape()
		obj.Domain.ChainId = (*math.HexOrDecimal256)(big.NewInt(1))
		obj.Domain.VerifyingContract = testContract
		obj.Message[fieldDeadline] = float64(now + 3600)
		obj.Domain.Salt = "0xnot32bytes"
		tok := encodeSignedShape(t, obj, "0x"+strings.Repeat("ab", 65))
		_, err := verifyProofToken(tok, testPieceCID, now, pin)
		if !errors.Is(err, ErrInvalidVoucher) || !strings.Contains(strings.ToLower(err.Error()), "eip-712") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("invalid verifyingContract", func(t *testing.T) {
		t.Parallel()
		obj := validProofShape()
		obj.Domain.ChainId = (*math.HexOrDecimal256)(big.NewInt(1))
		obj.Domain.VerifyingContract = "not-an-address"
		obj.Message[fieldDeadline] = float64(now + 3600)
		tok := encodeSignedShape(t, obj, "0x"+strings.Repeat("ab", 65))
		_, err := verifyProofToken(tok, testPieceCID, now, pin)
		if !errors.Is(err, ErrInvalidVoucher) || !strings.Contains(err.Error(), "verifyingContract") {
			t.Fatalf("got %v", err)
		}
	})
}

func TestEnsureEIP712DomainTypes(t *testing.T) {
	t.Parallel()
	t.Run("nil types and salt", func(t *testing.T) {
		t.Parallel()
		obj := &eip712TypedDataJSON{
			Domain: apitypes.TypedDataDomain{
				Name:              eip712DomainName,
				Version:           eip712DomainVer,
				ChainId:           math.NewHexOrDecimal256(1),
				VerifyingContract: testContract,
				Salt:              "0x" + strings.Repeat("11", 32),
			},
		}
		ensureEIP712DomainTypes(obj)
		fields := obj.Types["EIP712Domain"]
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
		obj := &eip712TypedDataJSON{
			Types:  apitypes.Types{"EIP712Domain": existing},
			Domain: apitypes.TypedDataDomain{Name: eip712DomainName, Version: eip712DomainVer},
		}
		ensureEIP712DomainTypes(obj)
		if len(obj.Types["EIP712Domain"]) != 1 {
			t.Fatalf("mutated existing domain types: %+v", obj.Types["EIP712Domain"])
		}
	})
}

func TestAccessAuthorizesDeal(t *testing.T) {
	t.Parallel()
	owner := common.HexToAddress("0xabc0000000000000000000000000000000000abc")
	grantee := common.HexToAddress("0xdef0000000000000000000000000000000000def")

	ownerDirect := &VerifiedAccess{Proof: &VerifiedProof{Requester: owner, Resource: testPieceCID}}
	if accessAuthorizesDeal(ownerDirect, nil) {
		t.Fatal("nil deal")
	}
	if accessAuthorizesDeal(ownerDirect, &Deal{DealID: "1001", Client: owner, DealType: DealTypePublic}) {
		t.Fatal("public deal")
	}
	if !accessAuthorizesDeal(ownerDirect, &Deal{DealID: "1001", Client: owner, DealType: DealTypePrivate}) {
		t.Fatal("owner-direct")
	}
	// Owner-direct ignores scope: owner may retrieve any of their private deals.
	if !accessAuthorizesDeal(ownerDirect, &Deal{DealID: "1002", Client: owner, DealType: DealTypePrivate}) {
		t.Fatal("owner-direct other scope")
	}

	delegated := &VerifiedAccess{
		Proof:    &VerifiedProof{Requester: grantee, Resource: testPieceCID},
		Vouchers: []VerifiedVoucher{{Owner: owner, Grantee: grantee, Scope: big.NewInt(1001)}},
	}
	if !accessAuthorizesDeal(delegated, &Deal{DealID: "1001", Client: owner, DealType: DealTypePrivate}) {
		t.Fatal("delegated")
	}
	if accessAuthorizesDeal(delegated, &Deal{DealID: "1002", Client: owner, DealType: DealTypePrivate}) {
		t.Fatal("voucher scope != deal id")
	}
	wrongIssuer := &VerifiedAccess{
		Proof:    &VerifiedProof{Requester: grantee, Resource: testPieceCID},
		Vouchers: []VerifiedVoucher{{Owner: grantee, Grantee: grantee, Scope: big.NewInt(1001)}},
	}
	if accessAuthorizesDeal(wrongIssuer, &Deal{DealID: "1001", Client: owner, DealType: DealTypePrivate}) {
		t.Fatal("wrong voucher owner")
	}
	noVoucher := &VerifiedAccess{Proof: &VerifiedProof{Requester: grantee}}
	if accessAuthorizesDeal(noVoucher, &Deal{DealID: "1001", Client: owner, DealType: DealTypePrivate}) {
		t.Fatal("grantee without voucher")
	}
	if accessAuthorizesDeal(nil, &Deal{DealID: "1001", Client: owner, DealType: DealTypePrivate}) {
		t.Fatal("nil access")
	}
	if accessAuthorizesDeal(&VerifiedAccess{}, &Deal{DealID: "1001", Client: owner, DealType: DealTypePrivate}) {
		t.Fatal("no proof")
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
	if voucherErrorCode(errors.New("proof expired deadline")) != "proof_expired" {
		t.Fatal("proof expired")
	}
	if voucherErrorCode(errors.New("voucher expired yesterday")) != "voucher_expired" {
		t.Fatal("expired")
	}
	if voucherErrorCode(errors.New("bad signature")) != "invalid_signature" {
		t.Fatal("signature")
	}
	if voucherErrorCode(errors.New("token base64url decode")) != "malformed_voucher" {
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

func TestAuthTokensForSchemeEdge(t *testing.T) {
	t.Parallel()
	if authTokensForScheme(nil, SchemeRetrievalProof) != nil {
		t.Fatal("nil request")
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Add("Authorization", "   ")
	req.Header.Add("Authorization", "RetrievalProof")
	req.Header.Add("Authorization", "Payment x")
	req.Header.Add("Authorization", "RetrievalVoucher v1")
	if got := authTokensForScheme(req, SchemeRetrievalProof); len(got) != 0 {
		t.Fatalf("proof got %v", got)
	}
	if got := authTokensForScheme(req, SchemeRetrievalVoucher); len(got) != 1 || got[0] != "v1" {
		t.Fatalf("voucher got %v", got)
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

func TestSelectRepresentativeDealNilAndAccess(t *testing.T) {
	t.Parallel()
	owner := common.HexToAddress("0xabc0000000000000000000000000000000000abc")
	other := common.HexToAddress("0x1")
	deals := []*Deal{
		nil,
		{DealID: "1", Client: other, DealType: DealTypePrivate},
		{DealID: "2", Client: owner, DealType: DealTypePrivate},
	}
	ownerAccess := &VerifiedAccess{Proof: &VerifiedProof{Requester: owner}}
	got := selectRepresentativeDeal(deals, ownerAccess)
	if got == nil || got.DealID != "2" {
		t.Fatalf("got %+v", got)
	}
	// Access that authorizes no private deal: fall back to first non-nil deal.
	strangerAccess := &VerifiedAccess{Proof: &VerifiedProof{Requester: common.HexToAddress("0x9")}}
	got = selectRepresentativeDeal(deals, strangerAccess)
	if got == nil || got.DealID != "1" {
		t.Fatalf("fallback first deal want 1, got %+v", got)
	}
	// No access: fall back to first non-nil deal.
	got = selectRepresentativeDeal(deals, nil)
	if got == nil || got.DealID != "1" {
		t.Fatalf("fallback first deal want 1, got %+v", got)
	}
}

func TestPrivateDealAllowedNil(t *testing.T) {
	t.Parallel()
	if privateDealAllowed(nil, nil, common.Address{}) {
		t.Fatal("nil deal")
	}
	if privateDealAllowed(&Deal{DealType: DealTypePublic}, nil, common.Address{}) {
		t.Fatal("public")
	}
}

func TestDenyAccessSkipsNilDeals(t *testing.T) {
	t.Parallel()
	a := NewAuthorizer()
	req := httptest.NewRequest(http.MethodGet, "/piece/baga", nil)
	denied, reason, _ := a.denyAccess(req, []*Deal{nil, {DealID: "1", DealType: DealTypePublic}}, nil, nil)
	if denied || reason != "" {
		t.Fatalf("denied=%v reason=%q", denied, reason)
	}
}

// encodeSignedShape serializes an arbitrary typed-data object + signature into a
// signed wire token (for malformed-signature / hash-failure tests).
func encodeSignedShape(t *testing.T, obj *eip712TypedDataJSON, sig string) string {
	t.Helper()
	raw, err := json.Marshal(signedTypedData{
		Domain:      obj.Domain,
		Types:       obj.Types,
		PrimaryType: obj.PrimaryType,
		Message:     obj.Message,
		Signature:   sig,
	})
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func validProofShape() *eip712TypedDataJSON {
	return &eip712TypedDataJSON{
		Domain: apitypes.TypedDataDomain{
			Name:    eip712DomainName,
			Version: eip712DomainVer,
		},
		Types: apitypes.Types{
			primaryTypeProof: {
				{Name: fieldScope, Type: "uint256"},
				{Name: fieldResource, Type: "string"},
				{Name: fieldDeadline, Type: "uint256"},
			},
		},
		PrimaryType: primaryTypeProof,
		Message: map[string]any{
			fieldScope:    float64(1),
			fieldResource: testPieceCID,
			fieldDeadline: float64(time.Now().Add(time.Hour).Unix()),
		},
	}
}

func validVoucherShape() *eip712TypedDataJSON {
	return &eip712TypedDataJSON{
		Domain: apitypes.TypedDataDomain{
			Name:    eip712DomainName,
			Version: eip712DomainVer,
		},
		Types: apitypes.Types{
			primaryTypeVoucher: {
				{Name: fieldGrantee, Type: "address"},
				{Name: fieldScope, Type: "uint256"},
				{Name: fieldIssuedAt, Type: "uint256"},
				{Name: fieldDeadline, Type: "uint256"},
			},
		},
		PrimaryType: primaryTypeVoucher,
		Message: map[string]any{
			fieldGrantee:  "0x0000000000000000000000000000000000000001",
			fieldScope:    float64(1),
			fieldIssuedAt: float64(time.Now().Unix()),
			fieldDeadline: float64(time.Now().Add(time.Hour).Unix()),
		},
	}
}
