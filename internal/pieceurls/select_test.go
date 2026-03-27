package pieceurls

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSelectBestPieceSource_Cheapest402(t *testing.T) {
	const cid = "baga6ea4seaq"

	mk402 := func(price string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/piece/"+cid {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusPaymentRequired)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"x402": map[string]string{
					"deal_uuid": "11111111-1111-1111-1111-111111111111",
					"cid":       cid,
					"price_fil": price,
					"payee_0x":  "0x2222222222222222222222222222222222222222",
				},
			})
		}
	}

	sHigh := httptest.NewServer(mk402("5.0"))
	defer sHigh.Close()
	sLow := httptest.NewServer(mk402("0.01"))
	defer sLow.Close()

	uHigh, err := url.Parse(sHigh.URL)
	if err != nil {
		t.Fatal(err)
	}
	uLow, err := url.Parse(sLow.URL)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	cli := &http.Client{Timeout: 30 * time.Second}
	sel, err := SelectBestPieceSource(context.Background(), cli, cid, "0x3333333333333333333333333333333333333333", dir, []*url.URL{uHigh, uLow}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sel.Free {
		t.Fatalf("expected paid selection, got free")
	}
	if sel.PriceFIL != "0.01" {
		t.Fatalf("expected cheapest price 0.01, got %q", sel.PriceFIL)
	}
	if sel.Base.Host != uLow.Host {
		t.Fatalf("expected base %s, got %s", uLow.Host, sel.Base.Host)
	}
}

func TestSelectBestPieceSource_FreeBeatsPaid(t *testing.T) {
	const cid = "bagaFree"

	sPaid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/piece/"+cid {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusPaymentRequired)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"x402": map[string]string{
				"deal_uuid": "22222222-2222-2222-2222-222222222222",
				"cid":       cid,
				"price_fil": "0.001",
				"payee_0x":  "0x4444444444444444444444444444444444444444",
			},
		})
	}))
	defer sPaid.Close()

	sFree := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/piece/"+cid {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fake-car-bytes"))
	}))
	defer sFree.Close()

	uPaid, _ := url.Parse(sPaid.URL)
	uFree, _ := url.Parse(sFree.URL)

	dir := t.TempDir()
	cli := &http.Client{Timeout: 30 * time.Second}
	sel, err := SelectBestPieceSource(context.Background(), cli, cid, "0x5555555555555555555555555555555555555555", dir, []*url.URL{uPaid, uFree}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !sel.Free {
		t.Fatalf("expected free selection")
	}
	b, err := os.ReadFile(filepath.Join(dir, sanitizeFilename(cid)+".car"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "fake-car-bytes" {
		t.Fatalf("unexpected CAR body %q", string(b))
	}
}
