package pieceaccess_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fidlabs/paid-retrievals/internal/pieceaccess"
)

func TestMiddlewarePassthrough(t *testing.T) {
	t.Parallel()

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("ok"))
	})

	handler := pieceaccess.NewAuthorizer().Middleware(next)

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

	handler := pieceaccess.NewAuthorizer().Middleware(next)
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

	handler := pieceaccess.NewAuthorizer().Middleware(payment)

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

	access := pieceaccess.NewAuthorizer()
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Wrong stack: payment wraps access instead of access wrapping payment.
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
