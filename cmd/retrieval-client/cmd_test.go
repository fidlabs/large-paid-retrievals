package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/data-preservation-programs/go-synapse/constants"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/fidlabs/paid-retrievals/internal/filpay"
	"github.com/fidlabs/paid-retrievals/internal/mpp"
)

// Valid IPFS CIDs required for MPP WWW-Authenticate parsing (see internal/mpp validateIPFSCID).
const (
	testPieceCID  = "bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e"
	testPieceCID2 = "bafkreieuudnwcbsdc4aknumlx2hkj3c5ipq5ixhb2gbi4n35phf4cara6i"
)

type stubPieceDiscovery struct {
	bases []*url.URL
	err   error
}

func (s stubPieceDiscovery) DiscoverPieceHTTPBases(context.Context, string) ([]*url.URL, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.bases, nil
}

func setDiscoverStub(s pieceDiscoveryClient) {
	newPieceDiscoveryClient = func(*http.Client, string) pieceDiscoveryClient { return s }
}

func restoreHooks(t *testing.T) func() {
	t.Helper()
	origNew, origDisc, origPrompt := filpayNewClient, newPieceDiscoveryClient, promptReader
	return func() {
		filpayNewClient = origNew
		newPieceDiscoveryClient = origDisc
		promptReader = origPrompt
	}
}

func stubFilpaySigner(signer common.Address) {
	filpayNewClient = func(ctx context.Context, rpcURL, privateKeyHex, privateKeyFile, privateKeyEnv, paymentsAddress string, opts ...filpay.Option) (filpayOperations, error) {
		return &mockFilpayOps{signer: signer, railID: big.NewInt(1)}, nil
	}
}

func stubDiscoverURL(t *testing.T, raw string) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	nu := *u
	setDiscoverStub(stubPieceDiscovery{bases: []*url.URL{&nu}})
}

func freeCarHandler(cid string, body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/piece/"+cid {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodHead, http.MethodGet:
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusOK)
			if r.Method == http.MethodGet {
				_, _ = w.Write(body)
			}
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func mpp402BadPayeeHandler(cid, dealUUID, price string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/piece/"+cid {
			http.NotFound(w, r)
			return
		}
		ch := mpp.Challenge{
			ID: dealUUID, Realm: mpp.RealmPrefix + r.Host, Method: mpp.MethodID, Intent: mpp.IntentID,
			Request: mpp.PaymentRequest{
				DealUUID: dealUUID, CID: cid, PriceUSDFC: price, Payee0x: "not-a-valid-address",
				Method: http.MethodGet, Path: "/piece/" + cid, Host: r.Host,
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

func testKeyHex(t *testing.T) (hexKey string, addr common.Address) {
	t.Helper()
	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(crypto.FromECDSA(pk)), crypto.PubkeyToAddress(pk.PublicKey)
}

func mpp402Handler(cid, dealUUID, price, payee string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/piece/"+cid {
			http.NotFound(w, r)
			return
		}
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Payment ") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("paid-car"))
			return
		}
		ch := mpp.Challenge{
			ID:     dealUUID,
			Realm:  mpp.RealmPrefix + r.Host,
			Method: mpp.MethodID,
			Intent: mpp.IntentID,
			Request: mpp.PaymentRequest{
				DealUUID: dealUUID, CID: cid, PriceUSDFC: price, Payee0x: payee,
				Method: http.MethodGet, Path: "/piece/" + cid, Host: r.Host,
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

func TestRootHelp(t *testing.T) {
	cmd := root()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "fetch") || !strings.Contains(buf.String(), "rail-check") {
		t.Fatalf("help: %s", buf.String())
	}
}

func TestCmdFetchMissingPrivateKey(t *testing.T) {
	cmd := root()
	var errBuf bytes.Buffer
	cmd.SetErr(&errBuf)
	cmd.SetOut(io.Discard)
	cmd.SetArgs([]string{"fetch"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "private key") {
		t.Fatalf("got %v stderr=%s", err, errBuf.String())
	}
	if strings.Contains(errBuf.String(), "Usage:") {
		t.Fatalf("runtime error should not print usage, stderr=%s", errBuf.String())
	}
}

func TestCmdFetchUnknownFlagShowsUsage(t *testing.T) {
	keyHex, _ := testKeyHex(t)
	cmd := root()
	var errBuf, outBuf bytes.Buffer
	cmd.SetErr(&errBuf)
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"fetch", "--filpay-private-key", keyHex, "--not-a-real-flag"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error")
	}
	combined := errBuf.String() + outBuf.String()
	if !strings.Contains(combined, "Usage:") || !strings.Contains(combined, "unknown flag") {
		t.Fatalf("expected usage after unknown flag, got stderr=%q stdout=%q err=%v", errBuf.String(), outBuf.String(), err)
	}
}

func TestCmdFetchNoCIDsNoUsage(t *testing.T) {
	keyHex, _ := testKeyHex(t)
	var errBuf bytes.Buffer
	cmd := root()
	cmd.SetErr(&errBuf)
	cmd.SetOut(io.Discard)
	cmd.SetArgs([]string{"fetch", "--filpay-private-key", keyHex})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "at least one CID") {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(errBuf.String(), "Usage:") {
		t.Fatalf("validation error should not print usage, stderr=%s", errBuf.String())
	}
}

func TestCmdFetchManifestExclusive(t *testing.T) {
	keyHex, _ := testKeyHex(t)
	dir := t.TempDir()
	manifest := filepath.Join(dir, "m.json")
	if err := os.WriteFile(manifest, []byte(`{"pieces":[{"piece_cid":"baga1"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := root()
	cmd.SetErr(io.Discard)
	cmd.SetOut(io.Discard)
	cmd.SetArgs([]string{
		"fetch", "--filpay-private-key", keyHex,
		"--manifest", manifest, "--cid", "bafy1",
	})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("got %v", err)
	}
}

func TestCmdFetchEmptyManifest(t *testing.T) {
	keyHex, _ := testKeyHex(t)
	dir := t.TempDir()
	manifest := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(manifest, []byte(`{"pieces":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := root()
	cmd.SetErr(io.Discard)
	cmd.SetOut(io.Discard)
	cmd.SetArgs([]string{"fetch", "--filpay-private-key", keyHex, "--manifest", manifest})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "no pieces") {
		t.Fatalf("got %v", err)
	}
}

func TestCmdFetchPaidPieceWithMockFilpay(t *testing.T) {
	const (
		cid      = testPieceCID
		dealUUID = "11111111-2222-3333-4444-555555555555"
		payee    = "0x2222222222222222222222222222222222222222"
	)
	keyHex, clientAddr := testKeyHex(t)

	ts := httptest.NewServer(mpp402Handler(cid, dealUUID, "0.01", payee))
	defer ts.Close()

	origNew := filpayNewClient
	defer func() { filpayNewClient = origNew }()
	filpayNewClient = func(ctx context.Context, rpcURL, privateKeyHex, privateKeyFile, privateKeyEnv, paymentsAddress string, opts ...filpay.Option) (filpayOperations, error) {
		return &mockFilpayOps{
			signer: clientAddr,
			railID: big.NewInt(1),
		}, nil
	}

	outDir := t.TempDir()
	cmd := root()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"fetch",
		"--filpay-private-key", keyHex,
		"--yes",
		"--sp-base-url", ts.URL,
		"--cid", cid,
		"--out-dir", outDir,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	carPath := filepath.Join(outDir, sanitizeFilename(cid)+".car")
	b, err := os.ReadFile(carPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "paid-car" {
		t.Fatalf("car %q", b)
	}
}

func TestCmdRailCheckWithPayeeFlag(t *testing.T) {
	keyHex, clientAddr := testKeyHex(t)
	payee := "0x2222222222222222222222222222222222222222"

	origNew := filpayNewClient
	defer func() { filpayNewClient = origNew }()
	filpayNewClient = func(ctx context.Context, rpcURL, privateKeyHex, privateKeyFile, privateKeyEnv, paymentsAddress string, opts ...filpay.Option) (filpayOperations, error) {
		return &mockFilpayOps{
			signer: clientAddr,
			railID: big.NewInt(42),
			avail:  big.NewInt(1000),
			approval: &filpay.OperatorApprovalStatus{
				Approved: true, RateAllowance: big.NewInt(1), LockupAllowance: big.NewInt(1), MaxLockupPeriod: big.NewInt(1),
				RateUsed: big.NewInt(0), LockupUsed: big.NewInt(0),
			},
			rails: []filpay.TokenRailDetail{{
				RailID: big.NewInt(42), From: clientAddr, To: common.HexToAddress(payee),
				Token: constants.USDFCAddressesByChainID[constants.ChainIDCalibration],
			}},
		}, nil
	}

	cmd := root()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"rail-check",
		"--filpay-private-key", keyHex,
		"--payee", payee,
		"--required-usdfc", "0.01",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
}

func TestCmdRailCheckNoPayees(t *testing.T) {
	keyHex, clientAddr := testKeyHex(t)
	origNew := filpayNewClient
	defer func() { filpayNewClient = origNew }()
	filpayNewClient = func(ctx context.Context, rpcURL, privateKeyHex, privateKeyFile, privateKeyEnv, paymentsAddress string, opts ...filpay.Option) (filpayOperations, error) {
		return &mockFilpayOps{signer: clientAddr}, nil
	}

	cmd := root()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"rail-check", "--filpay-private-key", keyHex})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "no payees discovered") {
		t.Fatalf("got %v", err)
	}
}

func TestCmdFetchInvalidSPBaseURL(t *testing.T) {
	keyHex, _ := testKeyHex(t)
	origNew := filpayNewClient
	defer func() { filpayNewClient = origNew }()
	filpayNewClient = func(ctx context.Context, rpcURL, privateKeyHex, privateKeyFile, privateKeyEnv, paymentsAddress string, opts ...filpay.Option) (filpayOperations, error) {
		return &mockFilpayOps{signer: common.HexToAddress("0x1")}, nil
	}

	cmd := root()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"fetch", "--filpay-private-key", keyHex,
		"--sp-base-url", "://bad", "--cid", "bafy1",
	})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "sp-base-url") {
		t.Fatalf("got %v", err)
	}
}

func TestCmdFetchFreeCAR(t *testing.T) {
	const cid = testPieceCID
	keyHex, clientAddr := testKeyHex(t)
	restore := restoreHooks(t)
	defer restore()

	ts := httptest.NewServer(freeCarHandler(cid, []byte("free-bytes")))
	defer ts.Close()
	stubDiscoverURL(t, ts.URL)
	stubFilpaySigner(clientAddr)

	outDir := t.TempDir()
	cmd := root()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"fetch", "--filpay-private-key", keyHex, "--yes",
		"--cid", cid, "--out-dir", outDir,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(outDir, sanitizeFilename(cid)+".car"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "free-bytes" {
		t.Fatalf("got %q", b)
	}
}

func TestCmdFetchFreeCARParallelFlag(t *testing.T) {
	const cid = testPieceCID
	keyHex, clientAddr := testKeyHex(t)
	restore := restoreHooks(t)
	defer restore()

	ts := httptest.NewServer(freeCarHandler(cid, []byte("free-bytes-parallel")))
	defer ts.Close()
	stubDiscoverURL(t, ts.URL)
	stubFilpaySigner(clientAddr)

	outDir := t.TempDir()
	cmd := root()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"fetch", "--filpay-private-key", keyHex, "--yes",
		"--cid", cid, "--out-dir", outDir, "--parallel", "2",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(outDir, sanitizeFilename(cid)+".car"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "free-bytes-parallel" {
		t.Fatalf("got %q", b)
	}
}

func TestCmdFetchUsesDiscoverInjection(t *testing.T) {
	const (
		cid      = testPieceCID
		dealUUID = "11111111-2222-3333-4444-555555555555"
		payee    = "0x2222222222222222222222222222222222222222"
	)
	keyHex, clientAddr := testKeyHex(t)
	restore := restoreHooks(t)
	defer restore()

	ts := httptest.NewServer(mpp402Handler(cid, dealUUID, "0.01", payee))
	defer ts.Close()
	stubDiscoverURL(t, ts.URL)
	stubFilpaySigner(clientAddr)

	outDir := t.TempDir()
	cmd := root()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"fetch", "--filpay-private-key", keyHex, "--yes",
		"--cid", cid, "--out-dir", outDir, "--verbose", "--pay-debug",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
}

func TestCmdFetchDiscoverError(t *testing.T) {
	keyHex, _ := testKeyHex(t)
	restore := restoreHooks(t)
	defer restore()
	setDiscoverStub(stubPieceDiscovery{err: errors.New("discovery unavailable")})

	cmd := root()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"fetch", "--filpay-private-key", keyHex, "--cid", "bafy1"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "discover endpoints") {
		t.Fatalf("got %v", err)
	}
}

func TestCmdFetchDiscoverNoEndpoints(t *testing.T) {
	keyHex, _ := testKeyHex(t)
	restore := restoreHooks(t)
	defer restore()
	setDiscoverStub(stubPieceDiscovery{})

	cmd := root()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"fetch", "--filpay-private-key", keyHex, "--cid", "bafy1"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "no HTTP endpoints") {
		t.Fatalf("got %v", err)
	}
}

func TestCmdFetchDryRunNoFilpay(t *testing.T) {
	const (
		cid      = testPieceCID
		dealUUID = "11111111-2222-3333-4444-555555555555"
		payee    = "0x2222222222222222222222222222222222222222"
	)
	keyHex, clientAddr := testKeyHex(t)
	restore := restoreHooks(t)
	defer restore()

	ts := httptest.NewServer(mpp402Handler(cid, dealUUID, "0.01", payee))
	defer ts.Close()
	stubDiscoverURL(t, ts.URL)
	var filpayCalls int
	filpayNewClient = func(context.Context, string, string, string, string, string, ...filpay.Option) (filpayOperations, error) {
		filpayCalls++
		return &mockFilpayOps{signer: clientAddr}, nil
	}

	var buf bytes.Buffer
	cmd := root()
	cmd.SetOut(&buf)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"fetch", "--filpay-private-key", keyHex, "--dry-run",
		"--sp-base-url", ts.URL, "--cid", cid, "--out-dir", t.TempDir(),
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if filpayCalls != 0 {
		t.Fatalf("filpay client created %d times, want 0 for --dry-run", filpayCalls)
	}
	if !strings.Contains(buf.String(), "Quote only") {
		t.Fatalf("output %q", buf.String())
	}
}

func TestCmdFetchAbortedAtPromptNoPrepare(t *testing.T) {
	const (
		cid      = testPieceCID
		dealUUID = "11111111-2222-3333-4444-555555555555"
		payee    = "0x2222222222222222222222222222222222222222"
	)
	keyHex, clientAddr := testKeyHex(t)
	restore := restoreHooks(t)
	defer restore()

	ts := httptest.NewServer(mpp402Handler(cid, dealUUID, "0.01", payee))
	defer ts.Close()
	stubDiscoverURL(t, ts.URL)
	mock := &mockFilpayOps{signer: clientAddr}
	filpayNewClient = func(context.Context, string, string, string, string, string, ...filpay.Option) (filpayOperations, error) {
		return mock, nil
	}
	promptReader = strings.NewReader("no\n")

	cmd := root()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"fetch", "--filpay-private-key", keyHex,
		"--sp-base-url", ts.URL, "--cid", cid, "--out-dir", t.TempDir(),
	})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "aborted") {
		t.Fatalf("got %v", err)
	}
	if mock.prepareCalls != 0 || mock.chargeCalls != 0 {
		t.Fatalf("prepare=%d charge=%d, want 0 before confirm", mock.prepareCalls, mock.chargeCalls)
	}
}

func TestCmdFetchAbortedAtPrompt(t *testing.T) {
	const (
		cid      = testPieceCID
		dealUUID = "11111111-2222-3333-4444-555555555555"
		payee    = "0x2222222222222222222222222222222222222222"
	)
	keyHex, clientAddr := testKeyHex(t)
	restore := restoreHooks(t)
	defer restore()

	ts := httptest.NewServer(mpp402Handler(cid, dealUUID, "0.01", payee))
	defer ts.Close()
	stubDiscoverURL(t, ts.URL)
	stubFilpaySigner(clientAddr)
	promptReader = strings.NewReader("no\n")

	cmd := root()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"fetch", "--filpay-private-key", keyHex,
		"--sp-base-url", ts.URL, "--cid", cid, "--out-dir", t.TempDir(),
	})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "aborted") {
		t.Fatalf("got %v", err)
	}
}

func TestCmdFetchSignerMismatch(t *testing.T) {
	const (
		cid      = testPieceCID
		dealUUID = "11111111-2222-3333-4444-555555555555"
		payee    = "0x2222222222222222222222222222222222222222"
	)
	keyHex, clientAddr := testKeyHex(t)
	restore := restoreHooks(t)
	defer restore()

	ts := httptest.NewServer(mpp402Handler(cid, dealUUID, "0.01", payee))
	defer ts.Close()
	stubDiscoverURL(t, ts.URL)
	other := common.HexToAddress("0x9999999999999999999999999999999999999999")
	stubFilpaySigner(other)

	cmd := root()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"fetch", "--filpay-private-key", keyHex, "--yes",
		"--cid", cid, "--out-dir", t.TempDir(),
	})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "does not match filpay signer") {
		t.Fatalf("got %v", err)
	}
	_ = clientAddr
}

func TestCmdFetchFilpayInitError(t *testing.T) {
	const (
		cid      = testPieceCID
		dealUUID = "11111111-2222-3333-4444-555555555555"
		payee    = "0x2222222222222222222222222222222222222222"
	)
	keyHex, clientAddr := testKeyHex(t)
	restore := restoreHooks(t)
	defer restore()

	ts := httptest.NewServer(mpp402Handler(cid, dealUUID, "0.01", payee))
	defer ts.Close()
	stubDiscoverURL(t, ts.URL)
	filpayNewClient = func(ctx context.Context, rpcURL, privateKeyHex, privateKeyFile, privateKeyEnv, paymentsAddress string, opts ...filpay.Option) (filpayOperations, error) {
		return nil, errors.New("rpc down")
	}
	_ = clientAddr

	cmd := root()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"fetch", "--filpay-private-key", keyHex, "--yes",
		"--cid", cid, "--out-dir", t.TempDir(),
	})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "init filpay") {
		t.Fatalf("got %v", err)
	}
}

func TestCmdFetchManifestE2E(t *testing.T) {
	const (
		cid      = testPieceCID
		dealUUID = "11111111-2222-3333-4444-555555555555"
		payee    = "0x2222222222222222222222222222222222222222"
	)
	keyHex, clientAddr := testKeyHex(t)
	restore := restoreHooks(t)
	defer restore()

	ts := httptest.NewServer(mpp402Handler(cid, dealUUID, "0.01", payee))
	defer ts.Close()
	stubDiscoverURL(t, ts.URL)
	stubFilpaySigner(clientAddr)

	manifest := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(manifest, []byte(`{"pieces":[{"piece_cid":"`+cid+`"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	cmd := root()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"fetch", "--filpay-private-key", keyHex, "--yes",
		"--manifest", manifest, "--out-dir", outDir,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
}

func TestCmdFetchTwoPaidCIDs(t *testing.T) {
	const payee = "0x2222222222222222222222222222222222222222"
	cid1, cid2 := testPieceCID, testPieceCID2
	keyHex, clientAddr := testKeyHex(t)
	restore := restoreHooks(t)
	defer restore()

	mux := http.NewServeMux()
	mux.HandleFunc("/piece/"+cid1, mpp402Handler(cid1, "11111111-1111-1111-1111-111111111111", "0.01", payee))
	mux.HandleFunc("/piece/"+cid2, mpp402Handler(cid2, "22222222-2222-2222-2222-222222222222", "0.02", payee))
	ts := httptest.NewServer(mux)
	defer ts.Close()
	stubDiscoverURL(t, ts.URL)
	stubFilpaySigner(clientAddr)

	outDir := t.TempDir()
	cmd := root()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"fetch", "--filpay-private-key", keyHex, "--yes",
		"--cid", cid1, "--cid", cid2, "--out-dir", outDir,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, cid := range []string{cid1, cid2} {
		if _, err := os.Stat(filepath.Join(outDir, sanitizeFilename(cid)+".car")); err != nil {
			t.Fatalf("cid %s: %v", cid, err)
		}
	}
}

func TestCmdRailCheckDiscoverProbe(t *testing.T) {
	const (
		cid      = testPieceCID
		dealUUID = "11111111-2222-3333-4444-555555555555"
		payee    = "0x2222222222222222222222222222222222222222"
	)
	keyHex, clientAddr := testKeyHex(t)
	restore := restoreHooks(t)
	defer restore()

	ts := httptest.NewServer(mpp402Handler(cid, dealUUID, "0.01", payee))
	defer ts.Close()
	stubDiscoverURL(t, ts.URL)
	stubFilpaySigner(clientAddr)

	cmd := root()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"rail-check", "--filpay-private-key", keyHex, "--cid", cid,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
}

func TestCmdRailCheckInvalidPayeeFlag(t *testing.T) {
	keyHex, clientAddr := testKeyHex(t)
	restore := restoreHooks(t)
	defer restore()
	stubFilpaySigner(clientAddr)

	cmd := root()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"rail-check", "--filpay-private-key", keyHex,
		"--payee", "not-an-address", "--required-usdfc", "0.01",
	})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "invalid --payee") {
		t.Fatalf("got %v", err)
	}
}

func TestCmdRailCheckInvalidRequiredUSDFC(t *testing.T) {
	keyHex, clientAddr := testKeyHex(t)
	restore := restoreHooks(t)
	defer restore()
	stubFilpaySigner(clientAddr)

	cmd := root()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"rail-check", "--filpay-private-key", keyHex,
		"--payee", "0x2222222222222222222222222222222222222222",
		"--required-usdfc", "not-a-number",
	})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "invalid --required-usdfc") {
		t.Fatalf("got %v", err)
	}
}

func TestCmdRailCheckInvalidChallengePayee(t *testing.T) {
	const cid = testPieceCID
	keyHex, clientAddr := testKeyHex(t)
	restore := restoreHooks(t)
	defer restore()

	ts := httptest.NewServer(mpp402BadPayeeHandler(cid, "11111111-2222-3333-4444-555555555555", "0.01"))
	defer ts.Close()
	stubDiscoverURL(t, ts.URL)
	stubFilpaySigner(clientAddr)

	cmd := root()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"rail-check", "--filpay-private-key", keyHex, "--cid", cid})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "invalid payee_0x") {
		t.Fatalf("got %v", err)
	}
}

func TestCmdRailCheckOperatorApprovalError(t *testing.T) {
	keyHex, clientAddr := testKeyHex(t)
	payee := "0x2222222222222222222222222222222222222222"
	restore := restoreHooks(t)
	defer restore()
	filpayNewClient = func(ctx context.Context, rpcURL, privateKeyHex, privateKeyFile, privateKeyEnv, paymentsAddress string, opts ...filpay.Option) (filpayOperations, error) {
		return &mockFilpayOps{
			signer: clientAddr, railID: big.NewInt(1), avail: big.NewInt(1000),
			approvalErr: errors.New("approval rpc failed"),
		}, nil
	}

	cmd := root()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"rail-check", "--filpay-private-key", keyHex,
		"--payee", payee, "--required-usdfc", "0.01",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
}

func TestCmdRailCheckNoActiveRail(t *testing.T) {
	keyHex, clientAddr := testKeyHex(t)
	payee := "0x2222222222222222222222222222222222222222"
	restore := restoreHooks(t)
	defer restore()
	filpayNewClient = func(ctx context.Context, rpcURL, privateKeyHex, privateKeyFile, privateKeyEnv, paymentsAddress string, opts ...filpay.Option) (filpayOperations, error) {
		return &mockFilpayOps{
			signer: clientAddr, avail: big.NewInt(1000),
			approval: &filpay.OperatorApprovalStatus{
				Approved: true, RateAllowance: big.NewInt(1), LockupAllowance: big.NewInt(1),
				MaxLockupPeriod: big.NewInt(1), RateUsed: big.NewInt(0), LockupUsed: big.NewInt(0),
			},
			railErr: errors.New("no rail"),
		}, nil
	}

	cmd := root()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"rail-check", "--filpay-private-key", keyHex,
		"--payee", payee, "--required-usdfc", "0.01",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
}

func TestCmdRailCheckSignerMismatch(t *testing.T) {
	keyHex, clientAddr := testKeyHex(t)
	restore := restoreHooks(t)
	defer restore()
	other := common.HexToAddress("0x9999999999999999999999999999999999999999")
	stubFilpaySigner(other)

	cmd := root()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"rail-check", "--filpay-private-key", keyHex,
		"--payee", "0x2222222222222222222222222222222222222222",
	})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "does not match filpay signer") {
		t.Fatalf("got %v", err)
	}
	_ = clientAddr
}

func TestCmdRailCheckSufficientFunds(t *testing.T) {
	keyHex, clientAddr := testKeyHex(t)
	payee := "0x2222222222222222222222222222222222222222"
	restore := restoreHooks(t)
	defer restore()
	filpayNewClient = func(ctx context.Context, rpcURL, privateKeyHex, privateKeyFile, privateKeyEnv, paymentsAddress string, opts ...filpay.Option) (filpayOperations, error) {
		return &mockFilpayOps{
			signer: clientAddr, railID: big.NewInt(5),
			avail: big.NewInt(1_000_000_000_000_000_000), // large avail
			approval: &filpay.OperatorApprovalStatus{
				Approved: true, RateAllowance: big.NewInt(1), LockupAllowance: big.NewInt(1),
				MaxLockupPeriod: big.NewInt(1), RateUsed: big.NewInt(0), LockupUsed: big.NewInt(0),
			},
		}, nil
	}

	cmd := root()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"rail-check", "--filpay-private-key", keyHex,
		"--payee", payee, "--required-usdfc", "0.01",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
}

// Ensure mockFilpayOps satisfies filpayOperations at compile time.
var _ filpayOperations = (*mockFilpayOps)(nil)
