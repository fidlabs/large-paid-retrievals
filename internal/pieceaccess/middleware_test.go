package pieceaccess_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/fidlabs/paid-retrievals/internal/mpp"
	"github.com/fidlabs/paid-retrievals/internal/pieceaccess"
)

type stubLookup struct {
	deal  *pieceaccess.Deal
	deals []*pieceaccess.Deal
	err   error
	cid   string
}

func (s *stubLookup) LookupByPieceCID(_ context.Context, pieceCID string, _ common.Address) ([]*pieceaccess.Deal, error) {
	s.cid = pieceCID
	if s.err != nil {
		return nil, s.err
	}
	if len(s.deals) > 0 {
		return s.deals, nil
	}
	if s.deal != nil {
		return []*pieceaccess.Deal{s.deal}, nil
	}
	return nil, nil
}

func TestMiddlewarePassthrough(t *testing.T) {
	t.Parallel()

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("ok"))
	})

	lookup := &stubLookup{deal: &pieceaccess.Deal{DealID: "1", DealType: pieceaccess.DealTypePublic}}
	handler := pieceaccess.NewAuthorizer(pieceaccess.WithDealLookup(lookup)).Middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("next handler was not called")
	}
	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTeapot)
	}
	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q, want %q", body, "ok")
	}
}

func TestMiddlewareSetsAccessContext(t *testing.T) {
	t.Parallel()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !pieceaccess.AccessChecked(r.Context()) {
			t.Error("pieceaccess context missing in next handler")
		}
		w.WriteHeader(http.StatusOK)
	})

	lookup := &stubLookup{deal: &pieceaccess.Deal{DealID: "1", DealType: pieceaccess.DealTypePublic}}
	handler := pieceaccess.NewAuthorizer(pieceaccess.WithDealLookup(lookup)).Middleware(next)
	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestMiddlewareRunsBeforePayment(t *testing.T) {
	t.Parallel()

	var order []string
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "upstream")
		if !pieceaccess.AccessChecked(r.Context()) {
			t.Error("pieceaccess did not run before upstream")
		}
		w.WriteHeader(http.StatusOK)
	})

	payment := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "payment")
		if !pieceaccess.AccessChecked(r.Context()) {
			t.Fatal("pieceaccess did not run before payment middleware")
		}
		upstream.ServeHTTP(w, r)
	})

	lookup := &stubLookup{deal: &pieceaccess.Deal{DealID: "1", DealType: pieceaccess.DealTypePublic}}
	handler := pieceaccess.NewAuthorizer(pieceaccess.WithDealLookup(lookup)).Middleware(payment)

	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	wantOrder := []string{"payment", "upstream"}
	if len(order) != len(wantOrder) {
		t.Fatalf("call order = %v, want %v", order, wantOrder)
	}
	for i := range wantOrder {
		if order[i] != wantOrder[i] {
			t.Fatalf("call order = %v, want %v", order, wantOrder)
		}
	}
}

func TestPaymentBeforeAccessLeavesContextUnset(t *testing.T) {
	t.Parallel()

	lookup := &stubLookup{deal: &pieceaccess.Deal{DealID: "1", DealType: pieceaccess.DealTypePublic}}
	access := pieceaccess.NewAuthorizer(pieceaccess.WithDealLookup(lookup))
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	payment := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if pieceaccess.AccessChecked(r.Context()) {
			t.Fatal("access context set before payment middleware ran")
		}
		access.Middleware(upstream).ServeHTTP(w, r)
	})

	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc", nil)
	rec := httptest.NewRecorder()
	payment.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestMiddlewareLookupLogsDeal(t *testing.T) {
	t.Parallel()

	deal := &pieceaccess.Deal{
		DealID:     "7",
		Client:     common.HexToAddress("0x1111111111111111111111111111111111111111"),
		ProviderID: 1000,
		DealType:   pieceaccess.DealTypePrivate,
		State:      "COMPLETED",
	}
	lookup := &stubLookup{deal: deal}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var gotDeal *pieceaccess.Deal
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d, ok := pieceaccess.DealFromContext(r.Context())
		if !ok {
			t.Fatal("expected deal in context")
		}
		gotDeal = d
		w.WriteHeader(http.StatusOK)
	})

	handler := pieceaccess.NewAuthorizer(
		pieceaccess.WithDealLookup(lookup),
		pieceaccess.WithLogger(logger),
	).Middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc?client="+deal.Client.Hex(), nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if lookup.cid != "baga6ea4seaqabc" {
		t.Fatalf("lookup cid = %q", lookup.cid)
	}
	if gotDeal == nil || gotDeal.DealID != "7" {
		t.Fatalf("context deal = %+v", gotDeal)
	}
	logs := logBuf.String()
	if !strings.Contains(logs, "porep deal for piece") {
		t.Fatalf("expected deal log, got %q", logs)
	}
	if !strings.Contains(logs, "deal_id") || !strings.Contains(logs, "COMPLETED") {
		t.Fatalf("expected deal JSON fields in log, got %q", logs)
	}
}

func TestMiddlewareLookupNotFoundContinues(t *testing.T) {
	t.Parallel()

	lookup := &stubLookup{err: pieceaccess.ErrDealNotFound}
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if _, ok := pieceaccess.DealFromContext(r.Context()); ok {
			t.Fatal("did not expect deal in context")
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := pieceaccess.NewAuthorizer(
		pieceaccess.WithDealLookup(lookup),
		pieceaccess.WithLogger(logger),
	).Middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("next should still run")
	}
	if !strings.Contains(logBuf.String(), "porep deal not found") {
		t.Fatalf("expected not-found log, got %q", logBuf.String())
	}
}

func TestMiddlewareLookupErrorDenied(t *testing.T) {
	t.Parallel()

	lookup := &stubLookup{err: errors.New("rpc down")}
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := pieceaccess.NewAuthorizer(
		pieceaccess.WithDealLookup(lookup),
		pieceaccess.WithLogger(logger),
	).Middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if called {
		t.Fatal("next must not run when deal lookup fails")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	logs := logBuf.String()
	if !strings.Contains(logs, "deal lookup failed") {
		t.Fatalf("expected warn log, got %q", logs)
	}
	if !strings.Contains(logs, "porep piece access denied") {
		t.Fatalf("expected access denied log, got %q", logs)
	}
}

func TestMiddlewareLookupErrorHEADAllowed(t *testing.T) {
	t.Parallel()

	lookup := &stubLookup{err: errors.New("rpc down")}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := pieceaccess.NewAuthorizer(pieceaccess.WithDealLookup(lookup)).Middleware(next)
	req := httptest.NewRequest(http.MethodHead, "/piece/baga6ea4seaqabc", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("called=%v code=%d", called, rec.Code)
	}
}

func TestDealJSON(t *testing.T) {
	t.Parallel()

	deal := pieceaccess.Deal{
		DealID:     "1",
		ProviderID: 1000,
		DealType:   pieceaccess.DealTypePublic,
		State:      "COMPLETED",
	}
	b, err := json.Marshal(deal)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["deal_id"] != "1" || m["state"] != "COMPLETED" || m["deal_type"] != "public" {
		t.Fatalf("unexpected JSON: %s", b)
	}
}

func TestMiddlewarePrivateDealOwnerAllowed(t *testing.T) {
	t.Parallel()
	owner := common.HexToAddress("0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a")
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID:   "1",
		Client:   owner,
		DealType: pieceaccess.DealTypePrivate,
		State:    "ACCEPTED",
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := pieceaccess.NewAuthorizer(pieceaccess.WithDealLookup(lookup)).Middleware(next)
	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc?client="+owner.Hex(), nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("called=%v code=%d", called, rec.Code)
	}
}

func TestMiddlewareMultiplePrivateDealsMatchingOwnerAllowed(t *testing.T) {
	t.Parallel()
	ownerA := common.HexToAddress("0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a")
	ownerB := common.HexToAddress("0x0553e4ed281E5a0A0654F6E46a0F80b7153ad506")
	lookup := &stubLookup{deals: []*pieceaccess.Deal{
		{DealID: "1", Client: ownerA, DealType: pieceaccess.DealTypePrivate},
		{DealID: "2", Client: ownerB, DealType: pieceaccess.DealTypePrivate},
	}}
	called := false
	var gotDealID string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if d, ok := pieceaccess.DealFromContext(r.Context()); ok {
			gotDealID = d.DealID
		}
		w.WriteHeader(http.StatusOK)
	})
	handler := pieceaccess.NewAuthorizer(pieceaccess.WithDealLookup(lookup)).Middleware(next)

	// Owner B must be allowed even when listed second (not the "picked" first deal).
	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc?client="+ownerB.Hex(), nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("called=%v code=%d", called, rec.Code)
	}
	if gotDealID != "2" {
		t.Fatalf("representative deal: got %q want 2", gotDealID)
	}
}

func TestMiddlewareMultiplePrivateDealsPrefersPublic(t *testing.T) {
	t.Parallel()
	owner := common.HexToAddress("0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a")
	lookup := &stubLookup{deals: []*pieceaccess.Deal{
		{DealID: "1", Client: owner, DealType: pieceaccess.DealTypePrivate},
		{DealID: "2", Client: common.HexToAddress("0x1"), DealType: pieceaccess.DealTypePublic},
	}}
	var gotType pieceaccess.DealType
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if d, ok := pieceaccess.DealFromContext(r.Context()); ok {
			gotType = d.DealType
		}
		w.WriteHeader(http.StatusOK)
	})
	handler := pieceaccess.NewAuthorizer(pieceaccess.WithDealLookup(lookup)).Middleware(next)
	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d", rec.Code)
	}
	if gotType != pieceaccess.DealTypePublic {
		t.Fatalf("representative type: got %v", gotType)
	}
}

func TestMiddlewarePrivateDealOtherDenied(t *testing.T) {
	t.Parallel()
	owner := common.HexToAddress("0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a")
	other := "0x0553e4ed281E5a0A0654F6E46a0F80b7153ad506"
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID:   "1",
		Client:   owner,
		DealType: pieceaccess.DealTypePrivate,
		State:    "ACCEPTED",
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := pieceaccess.NewAuthorizer(pieceaccess.WithDealLookup(lookup)).Middleware(next)
	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc?client="+other, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if called {
		t.Fatal("next must not run")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestMiddlewarePrivateDealHEADAllowedWithoutClient(t *testing.T) {
	t.Parallel()
	owner := common.HexToAddress("0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a")
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID:   "1",
		Client:   owner,
		DealType: pieceaccess.DealTypePrivate,
		State:    "ACCEPTED",
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := pieceaccess.NewAuthorizer(pieceaccess.WithDealLookup(lookup)).Middleware(next)
	req := httptest.NewRequest(http.MethodHead, "/piece/baga6ea4seaqabc", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("called=%v code=%d", called, rec.Code)
	}
}

func TestMiddlewarePrivateDealHEADAllowedWithBearerOrPayment(t *testing.T) {
	t.Parallel()
	ownerKey, owner := mustVoucherKey(t)
	grantee := common.HexToAddress("0x0553e4ed281E5a0A0654F6E46a0F80b7153ad506")
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID:   "1001",
		Client:   owner,
		DealType: pieceaccess.DealTypePrivate,
	}}
	token := mustBearerVoucher(t, ownerKey, grantee, 1001, time.Now().Add(time.Hour).Unix())
	handler := testVoucherAuthorizer(lookup).Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("payment", func(t *testing.T) {
		t.Parallel()
		authz, err := paymentAuth(grantee.Hex())
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodHead, "/piece/baga6ea4seaqabc", nil)
		req.Header.Set("Authorization", authz)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("HEAD with Payment must stay unrestricted; code=%d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("bearer_and_client", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodHead, "/piece/baga6ea4seaqabc?client="+grantee.Hex(), nil)
		req.Header.Add("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("HEAD with Bearer+?client= must stay unrestricted; code=%d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("bearer_without_client", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodHead, "/piece/baga6ea4seaqabc", nil)
		req.Header.Add("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("HEAD with Bearer and no requester must stay unrestricted; code=%d body=%s", rec.Code, rec.Body.String())
		}
	})
}

func TestMiddlewarePrivateDealAnonymousGETDenied(t *testing.T) {
	t.Parallel()
	owner := common.HexToAddress("0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a")
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID:   "1",
		Client:   owner,
		DealType: pieceaccess.DealTypePrivate,
		State:    "ACCEPTED",
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusPaymentRequired)
	})
	handler := pieceaccess.NewAuthorizer(pieceaccess.WithDealLookup(lookup)).Middleware(next)
	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if called {
		t.Fatal("next must not run for anonymous private probe")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d", rec.Code)
	}
}

func TestMiddlewarePrivateDealOwnerQueryAllowed(t *testing.T) {
	t.Parallel()
	owner := common.HexToAddress("0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a")
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID:   "1",
		Client:   owner,
		DealType: pieceaccess.DealTypePrivate,
		State:    "ACCEPTED",
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusPaymentRequired)
	})
	handler := pieceaccess.NewAuthorizer(pieceaccess.WithDealLookup(lookup)).Middleware(next)
	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc?client="+owner.Hex(), nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusPaymentRequired {
		t.Fatalf("called=%v code=%d", called, rec.Code)
	}
}

func TestMiddlewarePublicDealOtherAllowed(t *testing.T) {
	t.Parallel()
	owner := common.HexToAddress("0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a")
	other := "0x0553e4ed281E5a0A0654F6E46a0F80b7153ad506"
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID:   "2",
		Client:   owner,
		DealType: pieceaccess.DealTypePublic,
		State:    "ACCEPTED",
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusPaymentRequired)
	})
	handler := pieceaccess.NewAuthorizer(pieceaccess.WithDealLookup(lookup)).Middleware(next)
	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc?client="+other, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusPaymentRequired {
		t.Fatalf("called=%v code=%d", called, rec.Code)
	}
}

func TestMiddlewarePaidGETPublicAllowed(t *testing.T) {
	t.Parallel()
	owner := common.HexToAddress("0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a")
	other := "0x0553e4ed281E5a0A0654F6E46a0F80b7153ad506"
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID:   "2",
		Client:   owner,
		DealType: pieceaccess.DealTypePublic,
		State:    "ACCEPTED",
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := pieceaccess.NewAuthorizer(pieceaccess.WithDealLookup(lookup)).Middleware(next)
	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc?client="+other, nil)
	req.Header.Set("Authorization", "Payment unused")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("called=%v code=%d", called, rec.Code)
	}
}

func TestMiddlewarePaidGETPrivateOwnerAllowed(t *testing.T) {
	t.Parallel()
	owner := common.HexToAddress("0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a")
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID:   "1",
		Client:   owner,
		DealType: pieceaccess.DealTypePrivate,
		State:    "ACCEPTED",
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := pieceaccess.NewAuthorizer(pieceaccess.WithDealLookup(lookup)).Middleware(next)
	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc?client="+owner.Hex(), nil)
	req.Header.Set("Authorization", "Payment unused")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("called=%v code=%d", called, rec.Code)
	}
}

func TestMiddlewarePaidGETPrivateOtherDenied(t *testing.T) {
	t.Parallel()
	owner := common.HexToAddress("0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a")
	other := "0x0553e4ed281E5a0A0654F6E46a0F80b7153ad506"
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID:   "1",
		Client:   owner,
		DealType: pieceaccess.DealTypePrivate,
		State:    "ACCEPTED",
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := pieceaccess.NewAuthorizer(pieceaccess.WithDealLookup(lookup)).Middleware(next)
	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc?client="+other, nil)
	req.Header.Set("Authorization", "Payment unused")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if called {
		t.Fatal("next must not run")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d", rec.Code)
	}
}

func TestMiddlewarePaidGETNoDealDenied(t *testing.T) {
	t.Parallel()
	lookup := &stubLookup{err: pieceaccess.ErrDealNotFound}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := pieceaccess.NewAuthorizer(pieceaccess.WithDealLookup(lookup)).Middleware(next)
	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc?client=0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a", nil)
	req.Header.Set("Authorization", "Payment unused")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if called {
		t.Fatal("next must not run")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d", rec.Code)
	}
}

func TestMiddlewarePaidGETLookupErrorDenied(t *testing.T) {
	t.Parallel()
	lookup := &stubLookup{err: errors.New("cdp down")}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := pieceaccess.NewAuthorizer(pieceaccess.WithDealLookup(lookup)).Middleware(next)
	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc?client=0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a", nil)
	req.Header.Set("Authorization", "Payment unused")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if called || rec.Code != http.StatusForbidden {
		t.Fatalf("called=%v code=%d", called, rec.Code)
	}
}

func TestMiddlewareUnknownDealType(t *testing.T) {
	t.Parallel()
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID:   "9",
		DealType: pieceaccess.DealTypeUnknown,
	}}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := pieceaccess.NewAuthorizer(pieceaccess.WithDealLookup(lookup)).Middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unpaid unknown type should pass, code=%d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc?client=0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a", nil)
	req.Header.Set("Authorization", "Payment unused")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("paid unknown type should deny, code=%d", rec.Code)
	}
}

func TestMiddlewareWithClientIdentityHeader(t *testing.T) {
	t.Parallel()
	owner := common.HexToAddress("0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a")
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
	handler := pieceaccess.NewAuthorizer(
		pieceaccess.WithDealLookup(lookup),
		pieceaccess.WithClientIdentity("wallet", "X-Wallet"),
	).Middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc", nil)
	req.Header.Set("X-Wallet", owner.Hex())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("called=%v code=%d", called, rec.Code)
	}
}

func TestMiddlewareRequesterFromAuthorization(t *testing.T) {
	t.Parallel()
	owner := common.HexToAddress("0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a")
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
	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc", nil)
	req.Header.Set("Authorization", authz)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("called=%v code=%d body=%s", called, rec.Code, rec.Body.String())
	}
}

func TestMiddlewareAuthorizationDecodeFailures(t *testing.T) {
	t.Parallel()
	owner := common.HexToAddress("0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a")
	lookup := &stubLookup{deal: &pieceaccess.Deal{
		DealID:   "1",
		Client:   owner,
		DealType: pieceaccess.DealTypePrivate,
	}}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := pieceaccess.NewAuthorizer(pieceaccess.WithDealLookup(lookup)).Middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc", nil)
	req.Header.Set("Authorization", "Payment !!!")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("invalid auth should not identify client; code=%d", rec.Code)
	}

	badClient, err := paymentAuth("not-an-address")
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, "/piece/baga6ea4seaqabc", nil)
	req.Header.Set("Authorization", badClient)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-hex client in auth; code=%d", rec.Code)
	}
}

func TestMiddlewareSkipsNonPiecePaths(t *testing.T) {
	t.Parallel()
	lookup := &stubLookup{deal: &pieceaccess.Deal{DealID: "1", DealType: pieceaccess.DealTypePrivate}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := pieceaccess.NewAuthorizer(pieceaccess.WithDealLookup(lookup)).Middleware(next)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called || lookup.cid != "" {
		t.Fatalf("called=%v lookupCid=%q", called, lookup.cid)
	}
}

func TestMiddlewareNilPanics(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected nil authorizer panic")
			}
		}()
		var a *pieceaccess.Authorizer
		_ = a.Middleware(next)
	}()
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected nil next panic")
			}
		}()
		_ = pieceaccess.NewAuthorizer(pieceaccess.WithDealLookup(&stubLookup{})).Middleware(nil)
	}()
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected missing DealLookup panic")
			}
		}()
		_ = pieceaccess.NewAuthorizer().Middleware(next)
	}()
}

func TestDealFromContextNil(t *testing.T) {
	t.Parallel()
	if _, ok := pieceaccess.DealFromContext(context.Background()); ok {
		t.Fatal("expected no deal")
	}
}

func paymentAuth(client string) (string, error) {
	cred := mpp.Credential{
		Payload: mpp.ProofPayload{
			Version:       mpp.VersionV1,
			ChallengeID:   "11111111-2222-3333-4444-555555555555",
			DealUUID:      "11111111-2222-3333-4444-555555555555",
			ClientAddress: client,
			CID:           "bafkreic3gqso3booyry4fwc5wfnhaio574lami3am6nv4k6q6u2legzzdm",
			Method:        http.MethodGet,
			Path:          "/piece/baga6ea4seaqabc",
			Host:          "127.0.0.1:8787",
			Nonce:         "n1",
			SigType:       mpp.SigTypeEVM,
			Signature:     "00",
			ExpiresUnix:   4102444800, // 2100-01-01
		},
	}
	return cred.EncodeAuthorization()
}
