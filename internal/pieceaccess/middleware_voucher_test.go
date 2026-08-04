package pieceaccess_test

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/fidlabs/paid-retrievals/internal/pieceaccess"
)

func TestMiddlewarePrivateDealVoucherOwnerAllowed(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustVoucherKey(t)
	grantee := common.HexToAddress("0x0553e4ed281E5a0A0654F6E46a0F80b7153ad506")
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID:   "1001",
		Client:   owner,
		DealType: pieceaccess.DealTypePrivate,
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusPaymentRequired)
	})
	handler := testVoucherAuthorizer(lookup).Middleware(next)

	token := mustBearerVoucher(t, ownerKey, grantee, 1001, time.Now().Add(time.Hour).Unix())
	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc?client="+grantee.Hex(), nil)
	req.Header.Add("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusPaymentRequired {
		t.Fatalf("called=%v code=%d body=%s", called, rec.Code, rec.Body.String())
	}
}

func TestMiddlewarePrivateDealVoucherWrongOwnerDenied(t *testing.T) {
	t.Parallel()
	_, owner := mustVoucherKey(t)
	otherKey, _ := mustVoucherKey(t)
	grantee := common.HexToAddress("0x0553e4ed281E5a0A0654F6E46a0F80b7153ad506")
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID:   "1001",
		Client:   owner,
		DealType: pieceaccess.DealTypePrivate,
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := testVoucherAuthorizer(lookup).Middleware(next)

	token := mustBearerVoucher(t, otherKey, grantee, 1001, time.Now().Add(time.Hour).Unix())
	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc?client="+grantee.Hex(), nil)
	req.Header.Add("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if called {
		t.Fatal("next must not run")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestMiddlewarePrivateDealVoucherWrongDealIDDenied(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustVoucherKey(t)
	grantee := common.HexToAddress("0x0553e4ed281E5a0A0654F6E46a0F80b7153ad506")
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID:   "1001",
		Client:   owner,
		DealType: pieceaccess.DealTypePrivate,
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := testVoucherAuthorizer(lookup).Middleware(next)

	// Same owner signed for a different deal — must not authorize deal 1001.
	token := mustBearerVoucher(t, ownerKey, grantee, 1002, time.Now().Add(time.Hour).Unix())
	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc?client="+grantee.Hex(), nil)
	req.Header.Add("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if called {
		t.Fatal("next must not run")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestMiddlewarePrivateDealVoucherWrongGranteeDenied(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustVoucherKey(t)
	grantee := common.HexToAddress("0x0553e4ed281E5a0A0654F6E46a0F80b7153ad506")
	imposter := common.HexToAddress("0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a")
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID:   "1001",
		Client:   owner,
		DealType: pieceaccess.DealTypePrivate,
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := testVoucherAuthorizer(lookup).Middleware(next)

	token := mustBearerVoucher(t, ownerKey, grantee, 1001, time.Now().Add(time.Hour).Unix())
	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc?client="+imposter.Hex(), nil)
	req.Header.Add("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if called {
		t.Fatal("next must not run when ?client= ≠ grantee")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestMiddlewarePrivateDealVoucherAnonymousBearerIgnored(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustVoucherKey(t)
	grantee := common.HexToAddress("0x0553e4ed281E5a0A0654F6E46a0F80b7153ad506")
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID:   "1001",
		Client:   owner,
		DealType: pieceaccess.DealTypePrivate,
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusPaymentRequired)
	})
	handler := testVoucherAuthorizer(lookup).Middleware(next)

	token := mustBearerVoucher(t, ownerKey, grantee, 1001, time.Now().Add(time.Hour).Unix())
	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc", nil)
	req.Header.Add("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if called {
		t.Fatal("anonymous bearer must be ignored without requester")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestMiddlewarePaymentPreferredOverClientQuery_Voucher(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustVoucherKey(t)
	grantee := common.HexToAddress("0x0553e4ed281E5a0A0654F6E46a0F80b7153ad506")
	other := common.HexToAddress("0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a")
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID:   "1001",
		Client:   owner,
		DealType: pieceaccess.DealTypePrivate,
	}}
	token := mustBearerVoucher(t, ownerKey, grantee, 1001, time.Now().Add(time.Hour).Unix())
	handler := testVoucherAuthorizer(lookup).Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("query_grantee_payment_other_denied", func(t *testing.T) {
		t.Parallel()
		authz, err := paymentAuth(other.Hex())
		if err != nil {
			t.Fatal(err)
		}
		// Prefer Payment over ?client=: spoofed query must not authorize via voucher.
		req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc?client="+grantee.Hex(), nil)
		req.Header.Add("Authorization", "Bearer "+token)
		req.Header.Add("Authorization", authz)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("Payment must beat spoofed ?client=grantee; code=%d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("query_other_payment_grantee_allowed", func(t *testing.T) {
		t.Parallel()
		authz, err := paymentAuth(grantee.Hex())
		if err != nil {
			t.Fatal(err)
		}
		// Prefer Payment over ?client=: authenticated payer is the voucher grantee.
		req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc?client="+other.Hex(), nil)
		req.Header.Add("Authorization", "Bearer "+token)
		req.Header.Add("Authorization", authz)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("Payment grantee must win over spoofed ?client=; code=%d body=%s", rec.Code, rec.Body.String())
		}
	})
}

func TestMiddlewarePaymentPreferredOverClientQuery_Owner(t *testing.T) {
	t.Parallel()
	owner := common.HexToAddress("0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a")
	imposter := common.HexToAddress("0x0553e4ed281E5a0A0654F6E46a0F80b7153ad506")
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID:   "1",
		Client:   owner,
		DealType: pieceaccess.DealTypePrivate,
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := pieceaccess.NewAuthorizer(pieceaccess.WithDealLookup(lookup)).Middleware(next)

	authz, err := paymentAuth(owner.Hex())
	if err != nil {
		t.Fatal(err)
	}
	// Prefer Payment over ?client=: owner pays; spoofed query must not block access.
	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc?client="+imposter.Hex(), nil)
	req.Header.Set("Authorization", authz)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("Payment owner must beat ?client=imposter; called=%v code=%d", called, rec.Code)
	}
}

func TestMiddlewarePrivateDealVoucherSelectsMatchingDealAmongMany(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustVoucherKey(t)
	grantee := common.HexToAddress("0x0553e4ed281E5a0A0654F6E46a0F80b7153ad506")
	lookup := &stubLookup{deals: []*pieceaccess.Deal{
		{DealID: "1001", Client: owner, DealType: pieceaccess.DealTypePrivate},
		{DealID: "1002", Client: owner, DealType: pieceaccess.DealTypePrivate},
	}}
	var gotDeal *pieceaccess.Deal
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d, ok := pieceaccess.DealFromContext(r.Context())
		if ok {
			gotDeal = d
		}
		w.WriteHeader(http.StatusPaymentRequired)
	})
	handler := testVoucherAuthorizer(lookup).Middleware(next)

	token := mustBearerVoucher(t, ownerKey, grantee, 1002, time.Now().Add(time.Hour).Unix())
	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc?client="+grantee.Hex(), nil)
	req.Header.Add("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	if gotDeal == nil || gotDeal.DealID != "1002" {
		t.Fatalf("representative deal=%v want 1002", gotDeal)
	}
}

func TestMiddlewarePrivateDealVoucherPaidWrongGranteeDenied(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustVoucherKey(t)
	grantee := common.HexToAddress("0x0553e4ed281E5a0A0654F6E46a0F80b7153ad506")
	payer := common.HexToAddress("0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a")
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID:   "1001",
		Client:   owner,
		DealType: pieceaccess.DealTypePrivate,
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := testVoucherAuthorizer(lookup).Middleware(next)

	token := mustBearerVoucher(t, ownerKey, grantee, 1001, time.Now().Add(time.Hour).Unix())
	authz, err := paymentAuth(payer.Hex())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc", nil)
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Authorization", authz)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if called {
		t.Fatal("next must not run when Payment client ≠ grantee")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestMiddlewarePrivateDealVoucherDomainPinRejectsWrongChain(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustVoucherKey(t)
	grantee := common.HexToAddress("0x0553e4ed281E5a0A0654F6E46a0F80b7153ad506")
	market := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID:   "1001",
		Client:   owner,
		DealType: pieceaccess.DealTypePrivate,
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := pieceaccess.NewAuthorizer(
		pieceaccess.WithDealLookup(lookup),
		pieceaccess.WithVoucherDomain(big.NewInt(314159), market),
	).Middleware(next)

	// Signed for a different chainId than the SP pin.
	token := mustBearerVoucherOpts(t, ownerKey, voucherSignOpts{
		grantee: grantee, dealID: 1001, deadline: time.Now().Add(time.Hour).Unix(),
		chainID: 1, contract: market.Hex(),
	})
	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc?client="+grantee.Hex(), nil)
	req.Header.Add("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if called {
		t.Fatal("next must not run")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid_voucher") {
		t.Fatalf("want invalid_voucher JSON, body=%s", rec.Body.String())
	}
}

func TestMiddlewarePrivateDealVoucherDomainPinRejectsWrongContract(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustVoucherKey(t)
	grantee := common.HexToAddress("0x0553e4ed281E5a0A0654F6E46a0F80b7153ad506")
	market := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	other := common.HexToAddress("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd")
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID:   "1001",
		Client:   owner,
		DealType: pieceaccess.DealTypePrivate,
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := pieceaccess.NewAuthorizer(
		pieceaccess.WithDealLookup(lookup),
		pieceaccess.WithVoucherDomain(big.NewInt(314159), market),
	).Middleware(next)

	token := mustBearerVoucherOpts(t, ownerKey, voucherSignOpts{
		grantee: grantee, dealID: 1001, deadline: time.Now().Add(time.Hour).Unix(),
		chainID: 314159, contract: other.Hex(),
	})
	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc?client="+grantee.Hex(), nil)
	req.Header.Add("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if called {
		t.Fatal("next must not run")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid_voucher") {
		t.Fatalf("want invalid_voucher JSON, body=%s", rec.Body.String())
	}
}

func TestMiddlewarePrivateDealVoucherDomainPinAcceptsMatch(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustVoucherKey(t)
	grantee := common.HexToAddress("0x0553e4ed281E5a0A0654F6E46a0F80b7153ad506")
	market := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID:   "1001",
		Client:   owner,
		DealType: pieceaccess.DealTypePrivate,
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusPaymentRequired)
	})
	handler := pieceaccess.NewAuthorizer(
		pieceaccess.WithDealLookup(lookup),
		pieceaccess.WithVoucherDomain(big.NewInt(314159), market),
	).Middleware(next)

	token := mustBearerVoucher(t, ownerKey, grantee, 1001, time.Now().Add(time.Hour).Unix())
	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc?client="+grantee.Hex(), nil)
	req.Header.Add("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusPaymentRequired {
		t.Fatalf("called=%v code=%d body=%s", called, rec.Code, rec.Body.String())
	}
}

func TestMiddlewareInvalidVoucherJSONError(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustVoucherKey(t)
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID:   "1",
		Client:   owner,
		DealType: pieceaccess.DealTypePrivate,
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := testVoucherAuthorizer(lookup).Middleware(next)

	expired := mustBearerVoucher(t, ownerKey, common.HexToAddress("0x1"), 1, time.Now().Add(-time.Hour).Unix())
	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc?client=0x0000000000000000000000000000000000000001", nil)
	req.Header.Add("Authorization", "Bearer "+expired)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if called {
		t.Fatal("next must not run")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("content-type=%q body=%s", ct, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "invalid_voucher" {
		t.Fatalf("body=%v", body)
	}
}

func TestMiddlewareBearerDoesNotCountAsPaid(t *testing.T) {
	t.Parallel()
	// Unknown deal + Bearer voucher must not be treated as paid (default-deny).
	lookup := &stubLookup{err: pieceaccess.ErrDealNotFound}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := testVoucherAuthorizer(lookup).Middleware(next)

	ownerKey, _ := mustVoucherKey(t)
	token := mustBearerVoucher(t, ownerKey, common.HexToAddress("0x1"), 1, time.Now().Add(time.Hour).Unix())
	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc?client=0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a", nil)
	req.Header.Add("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("called=%v code=%d body=%s", called, rec.Code, rec.Body.String())
	}
}

func TestMiddlewareVoucherHeaderCapitalization(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustVoucherKey(t)
	grantee := common.HexToAddress("0x0553e4ed281E5a0A0654F6E46a0F80b7153ad506")
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID:   "1001",
		Client:   owner,
		DealType: pieceaccess.DealTypePrivate,
	}}
	token := mustBearerVoucher(t, ownerKey, grantee, 1001, time.Now().Add(time.Hour).Unix())

	cases := []struct {
		headerName string
		value      string
	}{
		{"Authorization", "Bearer " + token},
		{"authorization", "bearer " + token},
		{"AUTHORIZATION", "BEARER " + token},
		{"AuThOrIzAtIoN", "BeArEr " + token},
	}
	for _, tc := range cases {
		t.Run(tc.headerName+"/"+strings.Fields(tc.value)[0], func(t *testing.T) {
			t.Parallel()
			called := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusPaymentRequired)
			})
			handler := testVoucherAuthorizer(lookup).Middleware(next)
			req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc?client="+grantee.Hex(), nil)
			req.Header.Add(tc.headerName, tc.value)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if !called || rec.Code != http.StatusPaymentRequired {
				t.Fatalf("called=%v code=%d body=%s", called, rec.Code, rec.Body.String())
			}
		})
	}
}

func testVoucherAuthorizer(lookup pieceaccess.DealLookup, extra ...pieceaccess.Option) *pieceaccess.Authorizer {
	market := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	opts := []pieceaccess.Option{
		pieceaccess.WithDealLookup(lookup),
		pieceaccess.WithVoucherDomain(big.NewInt(314159), market),
	}
	opts = append(opts, extra...)
	return pieceaccess.NewAuthorizer(opts...)
}

func mustVoucherKey(t *testing.T) (*ecdsa.PrivateKey, common.Address) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key, crypto.PubkeyToAddress(key.PublicKey)
}

type voucherSignOpts struct {
	grantee  common.Address
	dealID   int64
	deadline int64
	chainID  int64
	contract string
}

func mustBearerVoucher(t *testing.T, key *ecdsa.PrivateKey, grantee common.Address, dealID, deadline int64) string {
	t.Helper()
	return mustBearerVoucherOpts(t, key, voucherSignOpts{
		grantee:  grantee,
		dealID:   dealID,
		deadline: deadline,
		chainID:  314159,
		contract: "0x1234567890abcdef1234567890abcdef12345678",
	})
}

func mustBearerVoucherOpts(t *testing.T, key *ecdsa.PrivateKey, opts voucherSignOpts) string {
	t.Helper()
	payload := map[string]any{
		"domain": map[string]any{
			"name":              "PoRepPieceAccess",
			"version":           "1",
			"chainId":           opts.chainID,
			"verifyingContract": opts.contract,
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
			"grantee":  opts.grantee.Hex(),
			"dealId":   opts.dealID,
			"deadline": opts.deadline,
		},
		"signature": "0x00",
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var tok struct {
		Domain      apitypes.TypedDataDomain `json:"domain"`
		Types       apitypes.Types           `json:"types"`
		PrimaryType string                   `json:"primaryType"`
		Message     map[string]any           `json:"message"`
		Signature   string                   `json:"signature"`
	}
	if err := json.Unmarshal(raw, &tok); err != nil {
		t.Fatal(err)
	}
	if tok.Types == nil {
		tok.Types = apitypes.Types{}
	}
	tok.Types["EIP712Domain"] = []apitypes.Type{
		{Name: "name", Type: "string"},
		{Name: "version", Type: "string"},
		{Name: "chainId", Type: "uint256"},
		{Name: "verifyingContract", Type: "address"},
	}
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
	payload["signature"] = "0x" + common.Bytes2Hex(sig)
	raw, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
