package pieceurls

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fidlabs/paid-retrievals/internal/mpp"
)

func mpp402Handler(cid, dealUUID, price, payee string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/piece/"+cid {
			http.NotFound(w, r)
			return
		}
		ch := mpp.Challenge{
			ID:          dealUUID,
			Realm:       mpp.RealmPrefix + r.Host,
			Method:      mpp.MethodID,
			Intent:      mpp.IntentID,
			Description: "test",
			Request: mpp.PaymentRequest{
				DealUUID:   dealUUID,
				CID:        cid,
				PriceUSDFC: price,
				Payee0x:    payee,
				Method:     http.MethodGet,
				Path:       "/piece/" + cid,
				Host:       r.Host,
			},
			Expires: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		}
		v, err := ch.WWWAuthenticateValue()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("WWW-Authenticate", v)
		w.WriteHeader(http.StatusPaymentRequired)
	}
}

func TestSelectBestPieceSource_Cheapest402(t *testing.T) {
	const cid = "bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e"
	const payee = "0x2222222222222222222222222222222222222222"

	sHigh := httptest.NewServer(mpp402Handler(cid, "11111111-1111-1111-1111-111111111111", "5.0", payee))
	defer sHigh.Close()
	sLow := httptest.NewServer(mpp402Handler(cid, "22222222-2222-2222-2222-222222222222", "0.01", payee))
	defer sLow.Close()

	uHigh, err := url.Parse(sHigh.URL)
	if err != nil {
		t.Fatal(err)
	}
	uLow, err := url.Parse(sLow.URL)
	if err != nil {
		t.Fatal(err)
	}

	c := NewClient(&http.Client{Timeout: 30 * time.Second})
	sel, err := c.SelectBestPieceSource(context.Background(), cid, []*url.URL{uHigh, uLow}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sel.Free {
		t.Fatalf("expected paid selection, got free")
	}
	if sel.PriceUSDFC != "0.01" {
		t.Fatalf("expected cheapest price 0.01, got %q", sel.PriceUSDFC)
	}
	if sel.Base.Host != uLow.Host {
		t.Fatalf("expected base %s, got %s", uLow.Host, sel.Base.Host)
	}
}

func TestSelectBestPieceSource_FreeBeatsPaid(t *testing.T) {
	const cid = "bafkreieuudnwcbsdc4aknumlx2hkj3c5ipq5ixhb2gbi4n35phf4cara6i"
	const payee = "0x4444444444444444444444444444444444444444"

	sPaid := httptest.NewServer(mpp402Handler(cid, "33333333-3333-3333-3333-333333333333", "0.001", payee))
	defer sPaid.Close()

	body := []byte("fake-car-bytes")
	sFree := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/piece/"+cid {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodHead:
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	defer sFree.Close()

	uPaid, _ := url.Parse(sPaid.URL)
	uFree, _ := url.Parse(sFree.URL)

	dir := t.TempDir()
	c := NewClient(&http.Client{Timeout: 30 * time.Second})
	sel, err := c.SelectBestPieceSource(context.Background(), cid, []*url.URL{uPaid, uFree}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !sel.Free {
		t.Fatalf("expected free selection")
	}
	if sel.TotalBytes != int64(len(body)) {
		t.Fatalf("TotalBytes=%d want %d", sel.TotalBytes, len(body))
	}
	if _, err := os.Stat(filepath.Join(dir, sanitizeFilename(cid)+".car")); !os.IsNotExist(err) {
		t.Fatalf("probe must not create CAR on disk: %v", err)
	}
}

func TestSelectBestPieceSource_NoBases(t *testing.T) {
	c := NewClient(&http.Client{})
	_, err := c.SelectBestPieceSource(context.Background(), "bafy", nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "no candidate bases") {
		t.Fatalf("got %v", err)
	}
}

func TestSelectBestPieceSource_NoUsableEndpoint(t *testing.T) {
	const cid = "bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	c := NewClient(srv.Client())
	_, err := c.SelectBestPieceSource(context.Background(), cid, []*url.URL{u}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "no usable endpoint") {
		t.Fatalf("got %v", err)
	}
}

func TestSelectBestPieceSource_Bad402Header(t *testing.T) {
	const cid = "bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", "Bearer junk")
		w.WriteHeader(http.StatusPaymentRequired)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	var logs []string
	logFn := func(format string, args ...any) { logs = append(logs, format) }
	c := NewClient(srv.Client())
	_, err := c.SelectBestPieceSource(context.Background(), cid, []*url.URL{u}, logFn, nil)
	if err == nil || !strings.Contains(err.Error(), "no usable endpoint") {
		t.Fatalf("got %v", err)
	}
	if len(logs) == 0 {
		t.Fatal("expected probe logs")
	}
}

func TestSelectBestPieceSource_InvalidChallengePayload(t *testing.T) {
	const cid = "bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Payment realm="x", method="filecoinpay", intent="retrieval", id="d", request="e30"`)
		w.WriteHeader(http.StatusPaymentRequired)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	c := NewClient(srv.Client())
	_, err := c.SelectBestPieceSource(context.Background(), cid, []*url.URL{u}, nil, nil)
	if err == nil {
		t.Fatal("expected no usable endpoint")
	}
}

func TestSelectBestPieceSource_BareGETProbe(t *testing.T) {
	const cid = "bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e"
	const payee = "0x2222222222222222222222222222222222222222"

	gotQueryCh := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gotQueryCh <- r.URL.RawQuery
		}
		mpp402Handler(cid, "11111111-1111-1111-1111-111111111111", "0.01", payee)(w, r)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(srv.Client())
	if _, err := c.SelectBestPieceSource(context.Background(), cid, []*url.URL{u}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if gotQuery := <-gotQueryCh; gotQuery != "" {
		t.Fatalf("probe GET query = %q, want bare path", gotQuery)
	}
}

func TestSelectBestPieceSource_RetryClientOnForbidden(t *testing.T) {
	t.Parallel()
	const cid = "bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e"
	const payee = "0x2222222222222222222222222222222222222222"
	const client = "0x1111111111111111111111111111111111111111"

	var queries []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusOK)
			return
		}
		mu.Lock()
		queries = append(queries, r.URL.RawQuery)
		mu.Unlock()
		if r.URL.Query().Get("client") == "" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		mpp402Handler(cid, "11111111-1111-1111-1111-111111111111", "0.01", payee)(w, r)
	}))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(srv.Client())
	c.ProbeClient = client
	sel, err := c.SelectBestPieceSource(context.Background(), cid, []*url.URL{u}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sel == nil || sel.PriceUSDFC != "0.01" {
		t.Fatalf("selection: %+v", sel)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(queries) != 2 || queries[0] != "" || queries[1] != "client="+client {
		t.Fatalf("queries=%v", queries)
	}
}

func TestSelectBestPieceSource_SendsBearerVouchersOnlyWithClient(t *testing.T) {
	t.Parallel()
	const cid = "bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e"
	const voucher = "v.payload.sig"
	const client = "0x1111111111111111111111111111111111111111"
	const payee = "0x2222222222222222222222222222222222222222"

	type probeHit struct {
		query string
		auth  []string
	}
	hitsCh := make(chan probeHit, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusOK)
			return
		}
		hitsCh <- probeHit{query: r.URL.RawQuery, auth: r.Header.Values("Authorization")}
		if r.URL.Query().Get("client") == "" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		mpp402Handler(cid, "11111111-1111-1111-1111-111111111111", "0.01", payee)(w, r)
	}))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(srv.Client())
	c.ProbeClient = client
	c.ProbeVouchers = []string{voucher, " second "}
	sel, err := c.SelectBestPieceSource(context.Background(), cid, []*url.URL{u}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sel == nil || sel.PriceUSDFC != "0.01" {
		t.Fatalf("selection: %+v", sel)
	}

	anon := <-hitsCh
	if anon.query != "" || len(anon.auth) != 0 {
		t.Fatalf("anonymous probe: query=%q auth=%v, want bare path and no Bearer", anon.query, anon.auth)
	}
	withClient := <-hitsCh
	wantAuth := []string{"Bearer " + voucher, "Bearer second"}
	if withClient.query != "client="+client || len(withClient.auth) != len(wantAuth) ||
		withClient.auth[0] != wantAuth[0] || withClient.auth[1] != wantAuth[1] {
		t.Fatalf("client probe: query=%q auth=%v, want client=%s auth=%v", withClient.query, withClient.auth, client, wantAuth)
	}
}

func TestSelectBestPieceSource_NilClient(t *testing.T) {
	var c *Client
	_, err := c.SelectBestPieceSource(context.Background(), "bafy", []*url.URL{{Scheme: "http", Host: "h"}}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "nil") {
		t.Fatalf("got %v", err)
	}
}

func TestSanitizeFilename(t *testing.T) {
	if sanitizeFilename("") != "piece" {
		t.Fatal("empty")
	}
	if sanitizeFilename("ok-CID.123") != "ok-CID.123" {
		t.Fatal("alnum")
	}
	if sanitizeFilename("a/b:c") != "a_b_c" {
		t.Fatalf("got %q", sanitizeFilename("a/b:c"))
	}
}

func TestTruncateForLog(t *testing.T) {
	if truncateForLog("  hi  ", 10) != "hi" {
		t.Fatal("trim")
	}
	long := strings.Repeat("x", 20)
	got := truncateForLog(long, 5)
	if got != "xxxxx…" {
		t.Fatalf("got %q", got)
	}
}

func TestCloneURLBase(t *testing.T) {
	if cloneURLBase(nil) != nil {
		t.Fatal("nil")
	}
	u, _ := url.Parse("http://h/p?q=1#frag")
	cp := cloneURLBase(u)
	if cp.Path != "" || cp.RawQuery != "" || cp.Fragment != "" {
		t.Fatalf("got %+v", cp)
	}
}
