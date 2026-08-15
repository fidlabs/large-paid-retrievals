package pieceaccess_test

import (
	"crypto/ecdsa"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/fidlabs/paid-retrievals/internal/pieceaccess"
)

const (
	testPieceCID = "baga6ea4seaqabc"
	testMarket   = "0x1234567890abcdef1234567890abcdef12345678"
)

func TestMiddlewarePrivateDealOwnerProofAllowed(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustCredKey(t)
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID: "1001", Client: owner, DealType: pieceaccess.DealTypePrivate,
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusPaymentRequired)
	})
	handler := testCredentialAuthorizer(lookup).Middleware(next)

	proof := mustOwnerCredential(t, ownerKey, 1001, testPieceCID, time.Now().Add(time.Hour).Unix(), 314159)
	req := httptest.NewRequest(http.MethodGet, "/piece/"+testPieceCID, nil)
	addRetrievalProof(req, proof)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusPaymentRequired {
		t.Fatalf("called=%v code=%d body=%s", called, rec.Code, rec.Body.String())
	}
}

func TestMiddlewarePrivateDealDelegatedCredentialAllowed(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustCredKey(t)
	granteeKey, grantee := mustCredKey(t)
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID: "1001", Client: owner, DealType: pieceaccess.DealTypePrivate,
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusPaymentRequired)
	})
	handler := testCredentialAuthorizer(lookup).Middleware(next)

	now := time.Now().Unix()
	proof, voucher := mustDelegatedCredential(t, ownerKey, granteeKey, 1001, testPieceCID, now, now+3600, now+86400, 314159)
	req := httptest.NewRequest(http.MethodGet, "/piece/"+testPieceCID+"?client="+grantee.Hex(), nil)
	addRetrievalProof(req, proof)
	addRetrievalVoucher(req, voucher)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusPaymentRequired {
		t.Fatalf("called=%v code=%d body=%s", called, rec.Code, rec.Body.String())
	}
}

func TestMiddlewarePrivateDealWrongVoucherOwnerDenied(t *testing.T) {
	t.Parallel()
	_, owner := mustCredKey(t)
	otherKey, _ := mustCredKey(t)
	granteeKey, grantee := mustCredKey(t)
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID: "1001", Client: owner, DealType: pieceaccess.DealTypePrivate,
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := testCredentialAuthorizer(lookup).Middleware(next)

	now := time.Now().Unix()
	// Voucher signed by otherKey (not the deal owner).
	proof, voucher := mustDelegatedCredential(t, otherKey, granteeKey, 1001, testPieceCID, now, now+3600, now+86400, 314159)
	req := httptest.NewRequest(http.MethodGet, "/piece/"+testPieceCID+"?client="+grantee.Hex(), nil)
	addRetrievalProof(req, proof)
	addRetrievalVoucher(req, voucher)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if called {
		t.Fatal("next must not run")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestMiddlewarePrivateDealWrongScopeDenied(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustCredKey(t)
	granteeKey, grantee := mustCredKey(t)
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID: "1001", Client: owner, DealType: pieceaccess.DealTypePrivate,
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := testCredentialAuthorizer(lookup).Middleware(next)

	now := time.Now().Unix()
	// Voucher scope 1002 does not match deal 1001.
	proof, voucher := mustDelegatedCredential(t, ownerKey, granteeKey, 1002, testPieceCID, now, now+3600, now+86400, 314159)
	req := httptest.NewRequest(http.MethodGet, "/piece/"+testPieceCID+"?client="+grantee.Hex(), nil)
	addRetrievalProof(req, proof)
	addRetrievalVoucher(req, voucher)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if called {
		t.Fatal("next must not run")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestMiddlewarePaymentPreferredOverClientQuery_Credential(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustCredKey(t)
	granteeKey, grantee := mustCredKey(t)
	other := common.HexToAddress("0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a")
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID: "1001", Client: owner, DealType: pieceaccess.DealTypePrivate,
	}}
	now := time.Now().Unix()
	proof, voucher := mustDelegatedCredential(t, ownerKey, granteeKey, 1001, testPieceCID, now, now+3600, now+86400, 314159)
	handler := testCredentialAuthorizer(lookup).Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("query_grantee_payment_other_denied", func(t *testing.T) {
		t.Parallel()
		authz, err := paymentAuth(other.Hex())
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/piece/"+testPieceCID+"?client="+grantee.Hex(), nil)
		addRetrievalProof(req, proof)
		addRetrievalVoucher(req, voucher)
		req.Header.Add("Authorization", authz)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("Payment must match proof requester; code=%d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("query_other_payment_grantee_allowed", func(t *testing.T) {
		t.Parallel()
		authz, err := paymentAuth(grantee.Hex())
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/piece/"+testPieceCID+"?client="+other.Hex(), nil)
		addRetrievalProof(req, proof)
		addRetrievalVoucher(req, voucher)
		req.Header.Add("Authorization", authz)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("Payment matching proof requester must allow; code=%d body=%s", rec.Code, rec.Body.String())
		}
	})
}

func TestMiddlewarePaymentPreferredOverClientQuery_OwnerProof(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustCredKey(t)
	imposter := common.HexToAddress("0x0553e4ed281E5a0A0654F6E46a0F80b7153ad506")
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID: "1", Client: owner, DealType: pieceaccess.DealTypePrivate,
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := testCredentialAuthorizer(lookup).Middleware(next)

	proof := mustOwnerCredential(t, ownerKey, 1, testPieceCID, time.Now().Add(time.Hour).Unix(), 314159)
	authz, err := paymentAuth(owner.Hex())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/piece/"+testPieceCID+"?client="+imposter.Hex(), nil)
	addRetrievalProof(req, proof)
	req.Header.Add("Authorization", authz)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("Payment owner + proof must beat ?client=imposter; called=%v code=%d", called, rec.Code)
	}
}

func TestMiddlewarePrivateDealCredentialSelectsMatchingDealAmongMany(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustCredKey(t)
	granteeKey, grantee := mustCredKey(t)
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
	handler := testCredentialAuthorizer(lookup).Middleware(next)

	now := time.Now().Unix()
	proof, voucher := mustDelegatedCredential(t, ownerKey, granteeKey, 1002, testPieceCID, now, now+3600, now+86400, 314159)
	req := httptest.NewRequest(http.MethodGet, "/piece/"+testPieceCID+"?client="+grantee.Hex(), nil)
	addRetrievalProof(req, proof)
	addRetrievalVoucher(req, voucher)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	if gotDeal == nil || gotDeal.DealID != "1002" {
		t.Fatalf("representative deal=%v want 1002", gotDeal)
	}
}

func TestMiddlewarePrivateDealPaidWrongPaymentClientDenied(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustCredKey(t)
	granteeKey, _ := mustCredKey(t)
	payer := common.HexToAddress("0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a")
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID: "1001", Client: owner, DealType: pieceaccess.DealTypePrivate,
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := testCredentialAuthorizer(lookup).Middleware(next)

	now := time.Now().Unix()
	proof, voucher := mustDelegatedCredential(t, ownerKey, granteeKey, 1001, testPieceCID, now, now+3600, now+86400, 314159)
	authz, err := paymentAuth(payer.Hex())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/piece/"+testPieceCID, nil)
	addRetrievalProof(req, proof)
	addRetrievalVoucher(req, voucher)
	req.Header.Add("Authorization", authz)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if called {
		t.Fatal("next must not run when Payment client ≠ proof requester")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestMiddlewarePrivateDealDomainPinRejectsWrongChain(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustCredKey(t)
	market := common.HexToAddress(testMarket)
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID: "1001", Client: owner, DealType: pieceaccess.DealTypePrivate,
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

	proof := mustOwnerCredential(t, ownerKey, 1001, testPieceCID, time.Now().Add(time.Hour).Unix(), 1)
	req := httptest.NewRequest(http.MethodGet, "/piece/"+testPieceCID, nil)
	addRetrievalProof(req, proof)
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

func TestMiddlewarePrivateDealDomainPinRejectsWrongContract(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustCredKey(t)
	market := common.HexToAddress(testMarket)
	other := common.HexToAddress("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd")
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID: "1001", Client: owner, DealType: pieceaccess.DealTypePrivate,
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

	domain := pieceaccess.NewDomain(big.NewInt(314159), other)
	proofTD := pieceaccess.BuildProofTypedData(domain, big.NewInt(1001), testPieceCID, time.Now().Add(time.Hour).Unix())
	proof := pieceaccess.MustEncodeSignedToken(proofTD, pieceaccess.MustSignEIP712(ownerKey, proofTD))
	req := httptest.NewRequest(http.MethodGet, "/piece/"+testPieceCID, nil)
	addRetrievalProof(req, proof)
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

func TestMiddlewarePrivateDealDomainPinAcceptsMatch(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustCredKey(t)
	granteeKey, grantee := mustCredKey(t)
	market := common.HexToAddress(testMarket)
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID: "1001", Client: owner, DealType: pieceaccess.DealTypePrivate,
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

	now := time.Now().Unix()
	proof, voucher := mustDelegatedCredential(t, ownerKey, granteeKey, 1001, testPieceCID, now, now+3600, now+86400, 314159)
	req := httptest.NewRequest(http.MethodGet, "/piece/"+testPieceCID+"?client="+grantee.Hex(), nil)
	addRetrievalProof(req, proof)
	addRetrievalVoucher(req, voucher)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusPaymentRequired {
		t.Fatalf("called=%v code=%d body=%s", called, rec.Code, rec.Body.String())
	}
}

func TestMiddlewareInvalidCredentialJSONError(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustCredKey(t)
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID: "1", Client: owner, DealType: pieceaccess.DealTypePrivate,
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := testCredentialAuthorizer(lookup).Middleware(next)

	expired := mustOwnerCredential(t, ownerKey, 1, testPieceCID, time.Now().Add(-time.Hour).Unix(), 314159)
	req := httptest.NewRequest(http.MethodGet, "/piece/"+testPieceCID, nil)
	addRetrievalProof(req, expired)
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

func TestMiddlewareRetrievalDoesNotCountAsPaid(t *testing.T) {
	t.Parallel()
	lookup := &stubLookup{err: pieceaccess.ErrDealNotFound}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := testCredentialAuthorizer(lookup).Middleware(next)

	ownerKey, _ := mustCredKey(t)
	proof := mustOwnerCredential(t, ownerKey, 1, testPieceCID, time.Now().Add(time.Hour).Unix(), 314159)
	req := httptest.NewRequest(http.MethodGet, "/piece/"+testPieceCID+"?client=0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a", nil)
	addRetrievalProof(req, proof)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("called=%v code=%d body=%s", called, rec.Code, rec.Body.String())
	}
}

func TestMiddlewareCredentialHeaderCapitalization(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustCredKey(t)
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID: "1001", Client: owner, DealType: pieceaccess.DealTypePrivate,
	}}
	proof := mustOwnerCredential(t, ownerKey, 1001, testPieceCID, time.Now().Add(time.Hour).Unix(), 314159)

	cases := []struct {
		headerName string
		value      string
	}{
		{"Authorization", "RetrievalProof " + proof},
		{"authorization", "retrievalproof " + proof},
		{"AUTHORIZATION", "RETRIEVALPROOF " + proof},
		{"AuThOrIzAtIoN", "ReTrIeVaLpRoOf " + proof},
	}
	for _, tc := range cases {
		t.Run(tc.headerName+"/"+strings.Fields(tc.value)[0], func(t *testing.T) {
			t.Parallel()
			called := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusPaymentRequired)
			})
			handler := testCredentialAuthorizer(lookup).Middleware(next)
			req := httptest.NewRequest(http.MethodGet, "/piece/"+testPieceCID, nil)
			req.Header.Add(tc.headerName, tc.value)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if !called || rec.Code != http.StatusPaymentRequired {
				t.Fatalf("called=%v code=%d body=%s", called, rec.Code, rec.Body.String())
			}
		})
	}
}

func testCredentialAuthorizer(lookup pieceaccess.DealLookup, extra ...pieceaccess.Option) *pieceaccess.Authorizer {
	market := common.HexToAddress(testMarket)
	opts := []pieceaccess.Option{
		pieceaccess.WithDealLookup(lookup),
		pieceaccess.WithVoucherDomain(big.NewInt(314159), market),
	}
	opts = append(opts, extra...)
	return pieceaccess.NewAuthorizer(opts...)
}

func mustCredKey(t *testing.T) (*ecdsa.PrivateKey, common.Address) {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key, crypto.PubkeyToAddress(key.PublicKey)
}

// mustOwnerCredential returns a bare base64url RetrievalProof token signed by
// ownerKey (owner-direct). Attach it with addRetrievalProof.
func mustOwnerCredential(t *testing.T, ownerKey *ecdsa.PrivateKey, scope int64, resource string, proofDeadline, chainID int64) string {
	t.Helper()
	domain := pieceaccess.NewDomain(big.NewInt(chainID), common.HexToAddress(testMarket))
	td := pieceaccess.BuildProofTypedData(domain, big.NewInt(scope), resource, proofDeadline)
	return pieceaccess.MustEncodeSignedToken(td, pieceaccess.MustSignEIP712(ownerKey, td))
}

// mustDelegatedCredential returns (proofToken, voucherToken): the proof is signed
// by granteeKey (the requester), the voucher by ownerKey (the deal owner).
func mustDelegatedCredential(t *testing.T, ownerKey, granteeKey *ecdsa.PrivateKey, scope int64, resource string, issuedAt, proofDeadline, voucherDeadline, chainID int64) (string, string) {
	t.Helper()
	domain := pieceaccess.NewDomain(big.NewInt(chainID), common.HexToAddress(testMarket))
	grantee := crypto.PubkeyToAddress(granteeKey.PublicKey)
	proofTD := pieceaccess.BuildProofTypedData(domain, big.NewInt(scope), resource, proofDeadline)
	voucherTD := pieceaccess.BuildVoucherTypedData(domain, grantee, big.NewInt(scope), issuedAt, voucherDeadline)
	proof := pieceaccess.MustEncodeSignedToken(proofTD, pieceaccess.MustSignEIP712(granteeKey, proofTD))
	voucher := pieceaccess.MustEncodeSignedToken(voucherTD, pieceaccess.MustSignEIP712(ownerKey, voucherTD))
	return proof, voucher
}

func addRetrievalProof(req *http.Request, proofToken string) {
	req.Header.Add("Authorization", "RetrievalProof "+proofToken)
}

func addRetrievalVoucher(req *http.Request, voucherToken string) {
	req.Header.Add("Authorization", "RetrievalVoucher "+voucherToken)
}
