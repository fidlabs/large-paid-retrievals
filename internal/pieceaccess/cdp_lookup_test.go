package pieceaccess

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCDPLookupByPieceCID(t *testing.T) {
	const piece = "baga6ea4seaqnhyk3yemnz3mhbfuvqe6jaknhhwtqc633pobzs5adasnwnfgyuli"
	var sawQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/po-rep/deals" {
			http.NotFound(w, r)
			return
		}
		sawQuery = r.URL.RawQuery
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{
					"dealId":        "7",
					"providerId":    "f01004",
					"clientAddress": "0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a",
					"dealState":     "ACCEPTED",
					"dealType":      "PRIVATE",
					"active":        false,
				},
			},
			"pagination": map[string]any{"page": 1, "pagesCount": 1, "totalCount": 1},
		})
	}))
	t.Cleanup(srv.Close)

	lookup, err := NewCDPLookup(CDPLookupConfig{
		BaseURL:    srv.URL,
		ProviderID: 1004,
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	deal, err := lookup.LookupByPieceCID(context.Background(), piece)
	if err != nil {
		t.Fatal(err)
	}
	if deal.DealID != "7" {
		t.Fatalf("deal id: got %s", deal.DealID)
	}
	if deal.DealType != DealTypePrivate {
		t.Fatalf("deal type: got %v", deal.DealType)
	}
	if deal.ProviderID != 1004 {
		t.Fatalf("provider: got %d", deal.ProviderID)
	}
	wantClient := "0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a"
	if !strings.EqualFold(deal.Client.Hex(), wantClient) {
		t.Fatalf("client: got %s want %s", deal.Client.Hex(), wantClient)
	}
	if !strings.Contains(sawQuery, "pieceCID="+piece) {
		t.Fatalf("query missing pieceCID: %s", sawQuery)
	}
	if !strings.Contains(sawQuery, "providerId=f01004") {
		t.Fatalf("query missing providerId: %s", sawQuery)
	}
}

func TestCDPLookupPrefersActive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"dealId": "1", "providerId": "f01", "clientAddress": "0x1", "dealState": "ACCEPTED", "dealType": "PRIVATE", "active": false},
				{"dealId": "2", "providerId": "f01", "clientAddress": "0x2", "dealState": "COMPLETED", "dealType": "PRIVATE", "active": true},
			},
		})
	}))
	t.Cleanup(srv.Close)

	lookup, err := NewCDPLookup(CDPLookupConfig{BaseURL: srv.URL, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	deal, err := lookup.LookupByPieceCID(context.Background(), "baga6ea4seaqaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	if deal.DealID != "2" {
		t.Fatalf("expected active deal 2, got %s", deal.DealID)
	}
}

func TestCDPLookupPrefersPublicOverPrivate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"dealId": "1", "providerId": "f01", "clientAddress": "0x1", "dealState": "ACCEPTED", "dealType": "PRIVATE", "active": true},
				{"dealId": "2", "providerId": "f01", "clientAddress": "0x2", "dealState": "ACCEPTED", "dealType": "PUBLIC", "active": false},
			},
		})
	}))
	t.Cleanup(srv.Close)

	lookup, err := NewCDPLookup(CDPLookupConfig{BaseURL: srv.URL, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	deal, err := lookup.LookupByPieceCID(context.Background(), "baga6ea4seaqaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	if deal.DealID != "2" || deal.DealType != DealTypePublic {
		t.Fatalf("expected public deal 2, got id=%s type=%v", deal.DealID, deal.DealType)
	}
}

func TestCDPLookupNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{}})
	}))
	t.Cleanup(srv.Close)

	lookup, err := NewCDPLookup(CDPLookupConfig{BaseURL: srv.URL, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = lookup.LookupByPieceCID(context.Background(), "baga6ea4seaqaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if !errors.Is(err, ErrDealNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestParseF0ActorID(t *testing.T) {
	cases := []struct {
		in   string
		want uint64
	}{
		{"f01004", 1004},
		{"t01003", 1003},
		{"1004", 1004},
	}
	for _, tc := range cases {
		got, err := parseF0ActorID(tc.in)
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("%s: got %d want %d", tc.in, got, tc.want)
		}
	}
	if _, err := parseF0ActorID(""); err == nil {
		t.Fatal("expected empty error")
	}
	if _, err := parseF0ActorID("f0abc"); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestNewCDPLookupValidation(t *testing.T) {
	t.Parallel()
	if _, err := NewCDPLookup(CDPLookupConfig{}); err == nil {
		t.Fatal("expected empty base URL error")
	}
	if _, err := NewCDPLookup(CDPLookupConfig{BaseURL: "://bad"}); err == nil {
		t.Fatal("expected invalid URL error")
	}
	lookup, err := NewCDPLookup(CDPLookupConfig{BaseURL: "http://127.0.0.1:9"})
	if err != nil {
		t.Fatal(err)
	}
	if lookup.client == nil {
		t.Fatal("expected default HTTP client")
	}
}

func TestCDPLookupEmptyPieceCID(t *testing.T) {
	t.Parallel()
	lookup, err := NewCDPLookup(CDPLookupConfig{BaseURL: "http://example.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lookup.LookupByPieceCID(context.Background(), "  "); err == nil {
		t.Fatal("expected empty piece CID error")
	}
	var nilLookup *CDPLookup
	if _, err := nilLookup.LookupByPieceCID(context.Background(), "baga"); err == nil {
		t.Fatal("expected nil receiver error")
	}
}

func TestCDPLookupHTTPErrors(t *testing.T) {
	t.Parallel()
	t.Run("status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, strings.Repeat("x", 250), http.StatusBadGateway)
		}))
		t.Cleanup(srv.Close)
		lookup, err := NewCDPLookup(CDPLookupConfig{BaseURL: srv.URL, HTTPClient: srv.Client()})
		if err != nil {
			t.Fatal(err)
		}
		_, err = lookup.LookupByPieceCID(context.Background(), "baga6ea4seaqaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		if err == nil || !strings.Contains(err.Error(), "HTTP 502") {
			t.Fatalf("got %v", err)
		}
		if !strings.Contains(err.Error(), "…") {
			t.Fatalf("expected truncated body marker in %v", err)
		}
	})
	t.Run("bad_json", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("{"))
		}))
		t.Cleanup(srv.Close)
		lookup, err := NewCDPLookup(CDPLookupConfig{BaseURL: srv.URL, HTTPClient: srv.Client()})
		if err != nil {
			t.Fatal(err)
		}
		_, err = lookup.LookupByPieceCID(context.Background(), "baga6ea4seaqaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		if err == nil || !strings.Contains(err.Error(), "decode") {
			t.Fatalf("got %v", err)
		}
	})
}

func TestCDPLookupDealIDFormsAndBadProvider(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{
					"dealId":        42,
					"providerId":    "f01004",
					"clientAddress": "0xAF6C83b9D33DdEAD8810011abb5cA1Cfc2d8754a",
					"dealState":     "ACCEPTED",
					"dealType":      "PUBLIC",
					"active":        true,
				},
			},
		})
	}))
	t.Cleanup(srv.Close)

	lookup, err := NewCDPLookup(CDPLookupConfig{BaseURL: srv.URL, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	deal, err := lookup.LookupByPieceCID(context.Background(), "baga6ea4seaqaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	if deal.DealID != "42" {
		t.Fatalf("numeric dealId: got %q", deal.DealID)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"dealId": "1", "providerId": "not-an-id", "clientAddress": "0x1", "dealType": "PUBLIC", "active": true},
			},
		})
	}))
	t.Cleanup(bad.Close)
	lookup, err = NewCDPLookup(CDPLookupConfig{BaseURL: bad.URL, HTTPClient: bad.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = lookup.LookupByPieceCID(context.Background(), "baga6ea4seaqaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err == nil || !strings.Contains(err.Error(), "providerId") {
		t.Fatalf("got %v", err)
	}
}

func TestDecodeJSONStringish(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw  string
		want string
	}{
		{``, ""},
		{`null`, ""},
		{`"abc"`, "abc"},
		{`99`, "99"},
		{`true`, "true"},
	}
	for _, tc := range cases {
		got := decodeJSONStringish(json.RawMessage(tc.raw))
		if got != tc.want {
			t.Fatalf("raw %s: got %q want %q", tc.raw, got, tc.want)
		}
	}
}

func TestToDealNil(t *testing.T) {
	t.Parallel()
	var d *cdpDeal
	if _, err := d.toDeal(); err == nil {
		t.Fatal("expected nil deal error")
	}
}
