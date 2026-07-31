package pieceaccess

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
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
	deals, err := lookup.LookupByPieceCID(context.Background(), piece)
	if err != nil {
		t.Fatal(err)
	}
	if len(deals) != 1 {
		t.Fatalf("deals: got %d", len(deals))
	}
	deal := deals[0]
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

func TestCDPLookupReturnsAllDeals(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"dealId": "1", "providerId": "f01", "clientAddress": "0x1", "dealState": "ACCEPTED", "dealType": "PRIVATE", "active": false},
				{"dealId": "2", "providerId": "f01", "clientAddress": "0x2", "dealState": "COMPLETED", "dealType": "PRIVATE", "active": true},
				{"dealId": "3", "providerId": "f01", "clientAddress": "0x3", "dealState": "ACCEPTED", "dealType": "PUBLIC", "active": false},
			},
			"pagination": map[string]any{"page": 1, "pagesCount": 1, "totalCount": 3},
		})
	}))
	t.Cleanup(srv.Close)

	lookup, err := NewCDPLookup(CDPLookupConfig{BaseURL: srv.URL, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	deals, err := lookup.LookupByPieceCID(context.Background(), "baga6ea4seaqaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	if len(deals) != 3 {
		t.Fatalf("expected 3 deals, got %d", len(deals))
	}
	ids := map[string]bool{}
	for _, d := range deals {
		ids[d.DealID] = true
	}
	for _, id := range []string{"1", "2", "3"} {
		if !ids[id] {
			t.Fatalf("missing deal %s", id)
		}
	}
}

func TestCDPLookupPaginatesAllPages(t *testing.T) {
	var pages []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		limit := r.URL.Query().Get("limit")
		if limit != "100" {
			t.Errorf("limit=%s want 100", limit)
		}
		pages = append(pages, atoi(t, page))
		switch page {
		case "1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{
					{"dealId": "1", "providerId": "f01", "clientAddress": "0x1", "dealType": "PRIVATE", "active": true},
					{"dealId": "2", "providerId": "f01", "clientAddress": "0x2", "dealType": "PRIVATE", "active": true},
				},
				"pagination": map[string]any{"page": 1, "pagesCount": 2, "totalCount": 3},
			})
		case "2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{
					{"dealId": "3", "providerId": "f01", "clientAddress": "0x3", "dealType": "PUBLIC", "active": true},
				},
				"pagination": map[string]any{"page": 2, "pagesCount": 2, "totalCount": 3},
			})
		default:
			t.Errorf("unexpected page %s", page)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{}})
		}
	}))
	t.Cleanup(srv.Close)

	lookup, err := NewCDPLookup(CDPLookupConfig{BaseURL: srv.URL, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	deals, err := lookup.LookupByPieceCID(context.Background(), "baga6ea4seaqaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	if len(deals) != 3 {
		t.Fatalf("expected 3 deals across pages, got %d", len(deals))
	}
	if len(pages) != 2 || pages[0] != 1 || pages[1] != 2 {
		t.Fatalf("pages fetched: %v", pages)
	}
	if deals[2].DealID != "3" || deals[2].DealType != DealTypePublic {
		t.Fatalf("page-2 deal: %+v", deals[2])
	}
}

func TestCDPLookupPaginatesWithoutPagesCount(t *testing.T) {
	// When pagination metadata is missing, keep fetching while pages are full.
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		page := r.URL.Query().Get("page")
		if page == "1" {
			data := make([]map[string]any, cdpDealsPageLimit)
			for i := range data {
				data[i] = map[string]any{
					"dealId": strconv.Itoa(i + 1), "providerId": "f01",
					"clientAddress": "0x1", "dealType": "PRIVATE", "active": true,
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"dealId": "101", "providerId": "f01", "clientAddress": "0x2", "dealType": "PUBLIC", "active": true},
			},
		})
	}))
	t.Cleanup(srv.Close)

	lookup, err := NewCDPLookup(CDPLookupConfig{BaseURL: srv.URL, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	deals, err := lookup.LookupByPieceCID(context.Background(), "baga6ea4seaqaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	if len(deals) != cdpDealsPageLimit+1 {
		t.Fatalf("got %d deals want %d", len(deals), cdpDealsPageLimit+1)
	}
	if n != 2 {
		t.Fatalf("expected 2 HTTP fetches, got %d", n)
	}
	if deals[len(deals)-1].DealID != "101" {
		t.Fatalf("last deal: %+v", deals[len(deals)-1])
	}
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestCDPLookupFiltersProviderClientSide(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"dealId": "1", "providerId": "f01", "clientAddress": "0x1", "dealType": "PRIVATE", "active": true},
				{"dealId": "2", "providerId": "f02", "clientAddress": "0x2", "dealType": "PUBLIC", "active": true},
			},
		})
	}))
	t.Cleanup(srv.Close)

	lookup, err := NewCDPLookup(CDPLookupConfig{BaseURL: srv.URL, ProviderID: 1, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	deals, err := lookup.LookupByPieceCID(context.Background(), "baga6ea4seaqaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	if len(deals) != 1 || deals[0].DealID != "1" {
		t.Fatalf("got %+v", deals)
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
	deals, err := lookup.LookupByPieceCID(context.Background(), "baga6ea4seaqaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	if len(deals) != 1 || deals[0].DealID != "42" {
		t.Fatalf("numeric dealId: got %+v", deals)
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
