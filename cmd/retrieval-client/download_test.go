package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type captureDownloadProgress struct {
	noopProgress
	headersTotal int64
}

func (captureDownloadProgress) Enabled() bool { return true }

func (c *captureDownloadProgress) DownloadHeaders(_ string, totalBytes int64) {
	c.headersTotal = totalBytes
}

func withDownloadRetryConfig(t *testing.T, attempts int, delay time.Duration) {
	t.Helper()
	prevAttempts := downloadMaxAttempts
	prevDelay := downloadRetryDelay
	downloadMaxAttempts = attempts
	downloadRetryDelay = delay
	t.Cleanup(func() {
		downloadMaxAttempts = prevAttempts
		downloadRetryDelay = prevDelay
	})
}

func TestDownloadCARSuccess(t *testing.T) {
	const cid = "bafyDownloadOk"
	body := []byte("CAR-DATA-HERE")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") != "identity" {
			http.Error(w, "expected identity encoding", http.StatusBadRequest)
			return
		}
		if r.Header.Get("Authorization") != "Payment test" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Length", "13")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	base, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	err = downloadCAR(http.DefaultClient, base, cid, "/piece/"+cid, "", "Payment test", outDir, -1, noopProgress{}, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	carPath := filepath.Join(outDir, sanitizeFilename(cid)+".car")
	got, err := os.ReadFile(carPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("body %q", got)
	}
	if filepath.Base(carPath) != sanitizeFilename(cid)+".car" {
		t.Fatalf("path %s", carPath)
	}
}

func TestDownloadCARPaymentAndRetrievalVouchers(t *testing.T) {
	const cid = "bafyVoucherOk"
	const client = "0x1111111111111111111111111111111111111111"
	body := []byte("CAR-WITH-VOUCHER")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("client") != client {
			http.Error(w, "missing client", http.StatusBadRequest)
			return
		}
		auths := r.Header.Values("Authorization")
		want := []string{"Payment test", "RetrievalProof tok-a", "RetrievalVoucher tok-b"}
		if len(auths) != len(want) {
			http.Error(w, fmt.Sprintf("Authorization=%v", auths), http.StatusUnauthorized)
			return
		}
		for i := range want {
			if auths[i] != want[i] {
				http.Error(w, fmt.Sprintf("Authorization=%v", auths), http.StatusUnauthorized)
				return
			}
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	base, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	err = downloadCAR(http.DefaultClient, base, cid, "/piece/"+cid, client, "Payment test", outDir, int64(len(body)), noopProgress{}, false, []string{"RetrievalProof tok-a", "RetrievalVoucher tok-b"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDownloadCARSendsAuthHeadersWithoutClient(t *testing.T) {
	// Free private pieces may probe with credentials then download without Payment;
	// RetrievalProof/Voucher headers must still be sent (proof is the identity).
	const cid = "bafyFreePrivateAuth"
	body := []byte("CAR-FREE-AUTH")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			http.Error(w, "expected no ?client=", http.StatusBadRequest)
			return
		}
		auths := r.Header.Values("Authorization")
		want := []string{"RetrievalProof tok-a", "RetrievalVoucher tok-b"}
		if len(auths) != len(want) {
			http.Error(w, fmt.Sprintf("Authorization=%v", auths), http.StatusUnauthorized)
			return
		}
		for i := range want {
			if auths[i] != want[i] {
				http.Error(w, fmt.Sprintf("Authorization=%v", auths), http.StatusUnauthorized)
				return
			}
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	base, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	err = downloadFreeCAR(http.DefaultClient, base, cid, "", t.TempDir(), int64(len(body)), noopProgress{}, false,
		[]string{"RetrievalProof tok-a", "RetrievalVoucher tok-b"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDownloadCARAnonymousOmitsAuthWhenNoHeaders(t *testing.T) {
	const cid = "bafyNoClientVoucher"
	body := []byte("CAR-ANON")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			http.Error(w, "expected anonymous", http.StatusBadRequest)
			return
		}
		if len(r.Header.Values("Authorization")) != 0 {
			http.Error(w, fmt.Sprintf("unexpected Authorization=%v", r.Header.Values("Authorization")), http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	base, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	err = downloadCAR(http.DefaultClient, base, cid, "/piece/"+cid, "", "", t.TempDir(), int64(len(body)), noopProgress{}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDownloadCARUsesProbeTotalWhenResponseHasNoLength(t *testing.T) {
	const cid = "bafyProbeTotal"
	body := []byte("car-chunk-data")
	probeTotal := int64(len(body))
	base, err := url.Parse("http://piece.test")
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: roundTripNoContentLength(body)}
	prog := &captureDownloadProgress{}
	err = downloadCAR(cli, base, cid, "/piece/"+cid, "", "", t.TempDir(), probeTotal, prog, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if prog.headersTotal != probeTotal {
		t.Fatalf("headersTotal=%d want probe %d", prog.headersTotal, probeTotal)
	}
}

type roundTripNoContentLength []byte

func (b roundTripNoContentLength) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode:    http.StatusOK,
		Body:          io.NopCloser(bytes.NewReader(b)),
		Header:        make(http.Header),
		ContentLength: -1,
		Request:       req,
	}, nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestDownloadCARReportsContentLengthHeader(t *testing.T) {
	const cid = "bafyDownloadLen"
	const wantLen = int64(1 << 20)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1048576")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, wantLen))
	}))
	defer ts.Close()

	base, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	prog := &captureDownloadProgress{}
	err = downloadCAR(http.DefaultClient, base, cid, "/piece/"+cid, "", "", t.TempDir(), 99, prog, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if prog.headersTotal != wantLen {
		t.Fatalf("headersTotal=%d want GET Content-Length %d", prog.headersTotal, wantLen)
	}
}

func TestContentRangeStart(t *testing.T) {
	t.Parallel()
	tests := []struct {
		header string
		want   int64
		ok     bool
	}{
		{"bytes 3-12/13", 3, true},
		{"bytes 0-0/1", 0, true},
		{"", 0, false},
		{"bytes -", 0, false},
		{"text 0-1/2", 0, false},
	}
	for _, tc := range tests {
		got, ok := contentRangeStart(tc.header)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("contentRangeStart(%q) = (%d, %v), want (%d, %v)", tc.header, got, ok, tc.want, tc.ok)
		}
	}
}

func TestPartialFileSize(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "piece.car.partial")
	if _, err := partialFileSize(path); err == nil {
		t.Fatal("missing partial should error")
	}
	if err := os.WriteFile(path, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := partialFileSize(path)
	if err != nil || got != 3 {
		t.Fatalf("partialFileSize() = (%d, %v), want (3, nil)", got, err)
	}
}

func TestGetShortOfExpectedSize(t *testing.T) {
	if getShortOfExpectedSize(100, -1) {
		t.Fatal("unknown probe HEAD size should not count as short GET")
	}
	if getShortOfExpectedSize(100, 100) {
		t.Fatal("full GET should not be short")
	}
	if !getShortOfExpectedSize(10, 100) {
		t.Fatal("expected short GET vs probe HEAD")
	}
}

func TestDownloadCARRetriesWhenGETShortOfProbeHEAD(t *testing.T) {
	withDownloadRetryConfig(t, 3, 1*time.Millisecond)

	const cid = "bafyIncomplete"
	const probeTotal = int64(1024)
	body := []byte("short")
	base, err := url.Parse("http://piece.test")
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{Transport: roundTripNoContentLength(body)}
	outDir := t.TempDir()
	err = downloadCAR(cli, base, cid, "/piece/"+cid, "", "", outDir, probeTotal, noopProgress{}, false, nil)
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("got %v, want incomplete error", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, sanitizeFilename(cid)+".car")); err == nil {
		t.Fatal("incomplete file should not be committed")
	}
	if _, err := os.Stat(filepath.Join(outDir, sanitizeFilename(cid)+".car.partial")); !os.IsNotExist(err) {
		t.Fatal("partial path should be removed")
	}
}

func TestDownloadCARRetriesIncompleteThenSucceeds(t *testing.T) {
	withDownloadRetryConfig(t, 100, time.Millisecond)

	const cid = "bafyRetryShort"
	full := []byte("CAR-DATA-HERE")
	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Length", "13")
		w.WriteHeader(http.StatusOK)
		if n < 3 {
			_, _ = w.Write(full[:3])
			return
		}
		_, _ = w.Write(full)
	}))
	defer ts.Close()

	base, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	if err := downloadCAR(http.DefaultClient, base, cid, "/piece/"+cid, "", "", outDir, int64(len(full)), noopProgress{}, false, nil); err != nil {
		t.Fatalf("download failed: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Fatalf("hits=%d want 3", got)
	}
}

func TestDownloadCARRetriesWithRangeResume(t *testing.T) {
	withDownloadRetryConfig(t, 100, time.Millisecond)

	const cid = "bafyRangeResume"
	full := []byte("CAR-DATA-HERE")
	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		switch n {
		case 1:
			if got := r.Header.Get("Range"); got != "" {
				t.Fatalf("first attempt should not send Range, got %q", got)
			}
			w.Header().Set("Content-Length", "13")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(full[:3])
		case 2:
			if got := r.Header.Get("Range"); got != "bytes=3-" {
				t.Fatalf("second attempt should resume with range bytes=3-, got %q", got)
			}
			remain := full[3:]
			w.Header().Set("Content-Length", "10")
			w.Header().Set("Content-Range", "bytes 3-12/13")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(remain)
		default:
			t.Fatalf("unexpected extra attempt %d", n)
		}
	}))
	defer ts.Close()

	base, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	if err := downloadCAR(http.DefaultClient, base, cid, "/piece/"+cid, "", "", outDir, int64(len(full)), noopProgress{}, false, nil); err != nil {
		t.Fatalf("download failed: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("hits=%d want 2", got)
	}
	got, err := os.ReadFile(filepath.Join(outDir, sanitizeFilename(cid)+".car"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(full) {
		t.Fatalf("resumed body %q", got)
	}
}

func TestDownloadCARContentRangeMismatchRestartsFromZero(t *testing.T) {
	withDownloadRetryConfig(t, 100, time.Millisecond)

	const cid = "bafyRangeMismatch"
	full := []byte("CAR-DATA-HERE")
	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		switch n {
		case 1:
			w.Header().Set("Content-Length", "13")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(full[:3])
		case 2:
			if got := r.Header.Get("Range"); got != "bytes=3-" {
				t.Fatalf("second attempt range=%q", got)
			}
			// Mismatched Content-Range: reject body and retry from scratch.
			w.Header().Set("Content-Length", "13")
			w.Header().Set("Content-Range", "bytes 0-12/13")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(full)
		case 3:
			if got := r.Header.Get("Range"); got != "" {
				t.Fatalf("third attempt should not send Range, got %q", got)
			}
			w.Header().Set("Content-Length", "13")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(full)
		default:
			t.Fatalf("unexpected extra attempt %d", n)
		}
	}))
	defer ts.Close()

	base, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	if err := downloadCAR(http.DefaultClient, base, cid, "/piece/"+cid, "", "", outDir, int64(len(full)), noopProgress{}, false, nil); err != nil {
		t.Fatalf("download failed: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Fatalf("hits=%d want 3", got)
	}
	got, err := os.ReadFile(filepath.Join(outDir, sanitizeFilename(cid)+".car"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(full) {
		t.Fatalf("body %q", got)
	}
}

func TestDownloadCARPartialFileSizeMismatchRestartsFromZero(t *testing.T) {
	withDownloadRetryConfig(t, 100, time.Millisecond)

	const cid = "bafyPartialMismatch"
	full := []byte("CAR-DATA-HERE")
	outDir := t.TempDir()
	partialPath := filepath.Join(outDir, sanitizeFilename(cid)+".car.partial")
	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		switch n {
		case 1:
			w.Header().Set("Content-Length", "13")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(full[:3])
		case 2:
			if got := r.Header.Get("Range"); got != "bytes=3-" {
				t.Fatalf("second attempt range=%q", got)
			}
			if err := os.WriteFile(partialPath, []byte("XX"), 0o644); err != nil {
				t.Fatal(err)
			}
			remain := full[3:]
			w.Header().Set("Content-Length", "10")
			w.Header().Set("Content-Range", "bytes 3-12/13")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(remain)
		case 3:
			if got := r.Header.Get("Range"); got != "" {
				t.Fatalf("third attempt should not send Range, got %q", got)
			}
			w.Header().Set("Content-Length", "13")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(full)
		default:
			t.Fatalf("unexpected extra attempt %d", n)
		}
	}))
	defer ts.Close()

	base, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := downloadCAR(http.DefaultClient, base, cid, "/piece/"+cid, "", "", outDir, int64(len(full)), noopProgress{}, false, nil); err != nil {
		t.Fatalf("download failed: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Fatalf("hits=%d want 3", got)
	}
	got, err := os.ReadFile(filepath.Join(outDir, sanitizeFilename(cid)+".car"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(full) {
		t.Fatalf("body %q", got)
	}
}

func TestDownloadCARExhaustsMaxAttemptsWithConstantDelay(t *testing.T) {
	withDownloadRetryConfig(t, 5, time.Millisecond)

	const cid = "bafyMaxAttempts"
	const probeTotal = int64(13)
	body := []byte("short")
	var hits int32
	cli := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		atomic.AddInt32(&hits, 1)
		return &http.Response{
			StatusCode:    http.StatusOK,
			Body:          io.NopCloser(bytes.NewReader(body)),
			Header:        make(http.Header),
			ContentLength: -1,
			Request:       &http.Request{Method: http.MethodGet},
		}, nil
	})}
	base, err := url.Parse("http://piece.test")
	if err != nil {
		t.Fatal(err)
	}
	err = downloadCAR(cli, base, cid, "/piece/"+cid, "", "", t.TempDir(), probeTotal, noopProgress{}, false, nil)
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("got %v, want incomplete error", err)
	}
	if got := atomic.LoadInt32(&hits); got != 5 {
		t.Fatalf("hits=%d want 5 (constant delay should not stop retries early)", got)
	}
}

func TestDownloadCARPlainErrorBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	}))
	defer ts.Close()
	base, _ := url.Parse(ts.URL)
	err := downloadCAR(http.DefaultClient, base, "bafy1", "/piece/bafy1", "", "", t.TempDir(), -1, noopProgress{}, false, nil)
	if err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("got %v", err)
	}
}
