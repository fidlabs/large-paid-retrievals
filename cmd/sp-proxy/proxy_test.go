package main

import (
	"context"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/fidlabs/paid-retrievals/internal/filpay"
	"github.com/fidlabs/paid-retrievals/internal/mpp"
	"github.com/fidlabs/paid-retrievals/internal/paymentheader"
	"github.com/fidlabs/paid-retrievals/internal/pieceaccess"
	piecepayment "github.com/fidlabs/paid-retrievals/internal/piecepayment"
	"github.com/fidlabs/paid-retrievals/internal/sqlitestore"
)

const testQuotePayee0x = "0x2222222222222222222222222222222222222222"

type stubFilpay struct {
	signer   common.Address
	payments common.Address
	credit   func(ctx context.Context, payer, payee common.Address) (string, *big.Int, error)
	closed   bool
}

func (s *stubFilpay) CreditRailPayment(ctx context.Context, payer, payee common.Address, paymentTxHash string) (string, *big.Int, error) {
	if s.credit != nil {
		return s.credit(ctx, payer, payee)
	}
	if strings.TrimSpace(paymentTxHash) == "" {
		paymentTxHash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	}
	return paymentTxHash, new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil), nil
}

func (s *stubFilpay) WithdrawPayeeProceeds(context.Context, common.Address) (string, *big.Int, error) {
	return "", big.NewInt(0), nil
}

func (s *stubFilpay) SignerAddress() common.Address   { return s.signer }
func (s *stubFilpay) PaymentsAddress() common.Address { return s.payments }
func (s *stubFilpay) Close()                          { s.closed = true }

func stubFilpayFactory() newFilpayClientFunc {
	return func(context.Context, string, string, string, string, string, ...filpay.Option) (proxyFilpay, error) {
		return defaultStubFilpay(), nil
	}
}

func defaultStubFilpay() *stubFilpay {
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	return &stubFilpay{
		signer:   addr,
		payments: common.HexToAddress("0x3333333333333333333333333333333333333333"),
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func openTestStore(t *testing.T) *sqlitestore.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sp.db")
	s, err := sqlitestore.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func upstreamPieceServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Method", r.Method)
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", "13")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.ipld.car")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("DUMMY-CAR"))
	}))
}

func upstreamChunkedPieceServer(t *testing.T) *httptest.Server {
	t.Helper()
	const body = "CHUNKED-CAR-BODY"
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Method", r.Method)
		w.Header().Set("X-Upstream-Chunked", "1")
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.ipld.car")
		// No Content-Length: net/http uses chunked framing on the wire.
		_, _ = w.Write([]byte(body))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
}

func upstreamHostPort(t *testing.T, raw string) (string, int) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

func TestPreserveUpstreamContentLength(t *testing.T) {
	t.Run("chunked passthrough", func(t *testing.T) {
		resp := &http.Response{
			Header:        http.Header{"Transfer-Encoding": {"chunked"}},
			ContentLength: -1,
		}
		if err := preserveUpstreamContentLength(resp); err != nil {
			t.Fatal(err)
		}
		if resp.Header.Get("Transfer-Encoding") != "chunked" {
			t.Fatal("Transfer-Encoding should remain for chunked upstream")
		}
		if resp.ContentLength != -1 {
			t.Fatalf("ContentLength=%d", resp.ContentLength)
		}
	})
	t.Run("content length without chunked", func(t *testing.T) {
		resp := &http.Response{
			Header:        http.Header{"Content-Length": {"99"}},
			ContentLength: -1,
		}
		if err := preserveUpstreamContentLength(resp); err != nil {
			t.Fatal(err)
		}
		if resp.ContentLength != 99 {
			t.Fatalf("ContentLength=%d", resp.ContentLength)
		}
	})
	t.Run("content length plus chunked prefers chunked", func(t *testing.T) {
		resp := &http.Response{
			Header: http.Header{
				"Content-Length":    {"99"},
				"Transfer-Encoding": {"chunked"},
			},
			ContentLength: -1,
		}
		if err := preserveUpstreamContentLength(resp); err != nil {
			t.Fatal(err)
		}
		if resp.Header.Get("Transfer-Encoding") != "chunked" {
			t.Fatal("should not strip chunked encoding")
		}
		if resp.ContentLength != -1 {
			t.Fatalf("ContentLength=%d", resp.ContentLength)
		}
	})
}

func TestReverseProxyPreservesChunkedUpstream(t *testing.T) {
	upstream := upstreamChunkedPieceServer(t)
	defer upstream.Close()
	upURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(upURL)
	proxy.ModifyResponse = preserveUpstreamContentLength
	ts := httptest.NewServer(proxy)
	defer ts.Close()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
	if res.Header.Get("X-Upstream-Chunked") != "1" {
		t.Fatal("expected upstream chunked marker header")
	}
	if cl := res.Header.Get("Content-Length"); cl != "" {
		t.Fatalf("chunked upstream should not get a synthetic Content-Length header, got %q", cl)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "CHUNKED-CAR-BODY" {
		t.Fatalf("body %q", body)
	}
}

func TestValidateUpstream(t *testing.T) {
	if _, err := validateUpstream("", 8788); err == nil {
		t.Fatal("expected empty host error")
	}
	if _, err := validateUpstream("127.0.0.1", 0); err == nil {
		t.Fatal("expected invalid port")
	}
	if _, err := validateUpstream("127.0.0.1", 70000); err == nil {
		t.Fatal("expected port too large")
	}
	u, err := validateUpstream("127.0.0.1", 8788)
	if err != nil || u.Host != "127.0.0.1:8788" {
		t.Fatalf("got %v %v", u, err)
	}
}

func TestResolvePayee(t *testing.T) {
	stub := defaultStubFilpay()
	got, err := resolvePayee("", stub)
	if err != nil {
		t.Fatal(err)
	}
	if got != stub.SignerAddress().Hex() {
		t.Fatalf("default payee: got %s", got)
	}
	if _, err := resolvePayee("not-an-address", stub); err == nil {
		t.Fatal("expected invalid payee")
	}
	custom := "0x4444444444444444444444444444444444444444"
	got, err = resolvePayee(custom, stub)
	if err != nil || got != custom {
		t.Fatalf("custom payee: %v %s", err, got)
	}
}

func TestBuildProxyHandlerAccessBeforePayment(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !pieceaccess.AccessChecked(r.Context()) {
			t.Errorf("pieceaccess middleware did not run before upstream %s %s", r.Method, r.URL.Path)
		}
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", "13")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.ipld.car")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("DUMMY-CAR"))
	})

	store := openTestStore(t)
	config := piecepayment.Config{
		PriceUSDFCPerGB: "0.01",
		ClientQuery:     "client",
		ClientHeader:    "X-Client-Address",
		MaxClockSkew:    30 * time.Second,
		QuotePayee0x:    testQuotePayee0x,
		FilecoinPay:     defaultStubFilpay(),
		Store:           store,
	}
	svc := piecepayment.NewRetrievalService(config)
	handler := buildPieceHandler(pieceaccess.NewAuthorizer(), svc, upstream)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/piece/") {
			handler.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	const testCID = "bafkreidde4sfyosf2pm6u4vxb65wogjg464a6y6tcg75opo6q5wv34bley"

	t.Run("GET quote probe", func(t *testing.T) {
		res, err := http.Get(ts.URL + "/piece/" + testCID)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusPaymentRequired {
			t.Fatalf("expected 402 got %d", res.StatusCode)
		}
	})

	t.Run("HEAD passthrough", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodHead, ts.URL+"/piece/bafytestpiece", nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 got %d", res.StatusCode)
		}
	})
}

func TestBuildProxyHandlerRoutes(t *testing.T) {
	upstream := upstreamPieceServer(t)
	defer upstream.Close()

	upURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, port := upstreamHostPort(t, upstream.URL)
	store := openTestStore(t)
	stub := defaultStubFilpay()
	settings := proxyAppSettings{
		PriceUSDFCPerGB: "0.01",
		ClientQuery:     "client",
		ClientHeader:    "X-Client-Address",
		MaxSkewSec:      30,
	}
	h := buildProxyHandler(upURL, host, port, store, stub, testQuotePayee0x, settings, testLogger(), nil)
	ts := httptest.NewServer(h)
	defer ts.Close()

	t.Run("health", func(t *testing.T) {
		res, err := http.Get(ts.URL + "/health")
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("status %d", res.StatusCode)
		}
		body, _ := io.ReadAll(res.Body)
		if string(body) != "ok" {
			t.Fatalf("body %q", body)
		}
	})

	t.Run("not found", func(t *testing.T) {
		res, err := http.Get(ts.URL + "/other")
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Fatalf("status %d", res.StatusCode)
		}
	})

	t.Run("method not allowed", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/health", nil)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("status %d", res.StatusCode)
		}
	})

	t.Run("piece issues payment challenge", func(t *testing.T) {
		client := "0x5555555555555555555555555555555555555555"
		const testCID = "bafkreidde4sfyosf2pm6u4vxb65wogjg464a6y6tcg75opo6q5wv34bley"
		res, err := http.Get(ts.URL + "/piece/" + testCID + "?client=" + client)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusPaymentRequired {
			t.Fatalf("expected 402 got %d", res.StatusCode)
		}
		if !strings.Contains(res.Header.Get("WWW-Authenticate"), "Payment") {
			t.Fatal("missing payment challenge header")
		}
		ch, err := mpp.ParseWWWAuthenticate(res.Header.Get("WWW-Authenticate"))
		if err != nil {
			t.Fatal(err)
		}
		wantPrice, err := paymentheader.PriceUSDFCForBytes("0.01", 13)
		if err != nil {
			t.Fatal(err)
		}
		if ch.Request.PriceUSDFC != wantPrice {
			t.Fatalf("price_usdfc=%q want %q (13 bytes bills 1 GiB at 0.01 USDFC/GiB)", ch.Request.PriceUSDFC, wantPrice)
		}
	})

	t.Run("raw GET issues payment challenge", func(t *testing.T) {
		const testCID = "bafkreidde4sfyosf2pm6u4vxb65wogjg464a6y6tcg75opo6q5wv34bley"
		res, err := http.Get(ts.URL + "/piece/" + testCID)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusPaymentRequired {
			t.Fatalf("expected 402 got %d", res.StatusCode)
		}
		if _, err := mpp.ParseWWWAuthenticate(res.Header.Get("WWW-Authenticate")); err != nil {
			t.Fatalf("WWW-Authenticate: %v", err)
		}
	})

	t.Run("piece HEAD proxied to upstream", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodHead, ts.URL+"/piece/bafytestpiece", nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 got %d", res.StatusCode)
		}
		if res.Header.Get("X-Upstream-Method") != http.MethodHead {
			t.Fatalf("upstream method %q", res.Header.Get("X-Upstream-Method"))
		}
		if res.ContentLength != 13 {
			t.Fatalf("Content-Length=%d", res.ContentLength)
		}
		body, _ := io.ReadAll(res.Body)
		if len(body) != 0 {
			t.Fatalf("HEAD body len=%d", len(body))
		}
	})

	t.Run("health HEAD", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodHead, ts.URL+"/health", nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("status %d", res.StatusCode)
		}
		if n, _ := io.ReadAll(res.Body); len(n) != 0 {
			t.Fatalf("HEAD body len=%d", len(n))
		}
	})
}

func TestRunProxyAppValidation(t *testing.T) {
	defer restoreProxyHooks(t)()

	proxyNewFilpayClient = stubFilpayFactory()
	proxyListenAndServe = func(string, http.Handler) error { return nil }

	settings := proxyAppSettings{
		DBPath:       filepath.Join(t.TempDir(), "sp.db"),
		UpstreamHost: "",
		UpstreamPort: 8788,
	}
	if err := runProxyApp(settings); err == nil {
		t.Fatal("expected upstream host error")
	}

	settings.UpstreamHost = "127.0.0.1"
	settings.UpstreamPort = 0
	if err := runProxyApp(settings); err == nil {
		t.Fatal("expected invalid port")
	}

	settings.UpstreamPort = 8788
	settings.DBRetention = 6 * time.Hour
	if err := runProxyApp(settings); err == nil {
		t.Fatal("expected db retention shorter than paid-access TTL error")
	}
}

func TestNewPorepDealLookupRequiresProviderID(t *testing.T) {
	t.Parallel()
	_, _, err := newPorepDealLookup(context.Background(), proxyAppSettings{
		PorepCDPURL:     "http://127.0.0.1:23300",
		PorepProviderID: 0,
	}, testLogger())
	if err == nil || !strings.Contains(err.Error(), "--porep-provider-id") {
		t.Fatalf("got %v", err)
	}

	lookup, closeFn, err := newPorepDealLookup(context.Background(), proxyAppSettings{}, testLogger())
	if err != nil || lookup != nil {
		t.Fatalf("empty CDP URL should disable lookup: lookup=%v err=%v", lookup, err)
	}
	closeFn()

	lookup, closeFn, err = newPorepDealLookup(context.Background(), proxyAppSettings{
		PorepCDPURL:     "http://127.0.0.1:23300",
		PorepProviderID: 1004,
	}, testLogger())
	if err != nil || lookup == nil {
		t.Fatalf("got lookup=%v err=%v", lookup, err)
	}
	closeFn()
}

func TestRunProxyAppCDPRequiresProviderID(t *testing.T) {
	defer restoreProxyHooks(t)()

	upstream := upstreamPieceServer(t)
	defer upstream.Close()
	host, port := upstreamHostPort(t, upstream.URL)

	proxyOpenStore = sqlitestore.OpenStore
	proxyNewFilpayClient = stubFilpayFactory()
	proxyListenAndServe = func(string, http.Handler) error { return nil }

	settings := proxyAppSettings{
		DBPath:          filepath.Join(t.TempDir(), "sp.db"),
		UpstreamHost:    host,
		UpstreamPort:    port,
		PayPayeeAddress: testQuotePayee0x,
		PorepCDPURL:     "http://127.0.0.1:23300",
		PorepProviderID: 0,
	}
	err := runProxyApp(settings)
	if err == nil || !strings.Contains(err.Error(), "porep deal lookup") {
		t.Fatalf("got %v", err)
	}
}

func TestRunProxyAppInvalidPayee(t *testing.T) {
	defer restoreProxyHooks(t)()

	upstream := upstreamPieceServer(t)
	defer upstream.Close()
	host, port := upstreamHostPort(t, upstream.URL)

	proxyOpenStore = sqlitestore.OpenStore
	proxyNewFilpayClient = stubFilpayFactory()
	proxyListenAndServe = func(string, http.Handler) error { return nil }

	settings := proxyAppSettings{
		DBPath:          filepath.Join(t.TempDir(), "sp.db"),
		UpstreamHost:    host,
		UpstreamPort:    port,
		PayPayeeAddress: "not-an-address",
	}
	if err := runProxyApp(settings); err == nil {
		t.Fatal("expected invalid payee")
	}
}

func TestCobraExecuteStartsProxy(t *testing.T) {
	defer restoreProxyHooks(t)()

	// Flag defaults read SP_PROXY_POREP_* at registration; clear so ambient
	// devnet env cannot enable CDP without a provider ID.
	t.Setenv("SP_PROXY_POREP_CDP_URL", "")
	t.Setenv("SP_PROXY_POREP_PROVIDER_ID", "0")

	upstream := upstreamPieceServer(t)
	defer upstream.Close()
	host, port := upstreamHostPort(t, upstream.URL)

	var captured http.Handler
	proxyOpenStore = sqlitestore.OpenStore
	proxyNewFilpayClient = stubFilpayFactory()
	proxyListenAndServe = func(addr string, h http.Handler) error {
		captured = h
		return nil
	}

	db := filepath.Join(t.TempDir(), "sp.db")
	cmd := root()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"--db", db,
		"--upstream-host", host,
		"--upstream-port", strconv.Itoa(port),
		"--pay-payee-address", testQuotePayee0x,
		"--porep-cdp-url", "", // disable CDP for this routing smoke test
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if captured == nil {
		t.Fatal("handler not captured")
	}

	ts := httptest.NewServer(captured)
	defer ts.Close()
	res, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
}

func TestCobraInvalidUpstreamPort(t *testing.T) {
	defer restoreProxyHooks(t)()
	proxyNewFilpayClient = stubFilpayFactory()
	proxyListenAndServe = func(string, http.Handler) error { return nil }

	cmd := root()
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--upstream-port", "0"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error")
	}
}
