package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLineProgressTxLifecycle(t *testing.T) {
	var buf bytes.Buffer
	ui := &lineProgress{out: &buf, dl: downloadProgressState{total: -1}}
	ui.TxSubmitted("createRail", "0xabcdef1234567890abcdef1234567890abcdef12")
	time.Sleep(120 * time.Millisecond)
	ui.TxConfirmed("createRail", "0xabcdef1234567890abcdef1234567890abcdef12", 28*time.Second, "12345")
	out := buf.String()
	for _, sub := range []string{"createRail", "submitted", "waiting for", "confirmed", "block 12345"} {
		if !strings.Contains(out, sub) {
			t.Fatalf("missing %q in:\n%s", sub, out)
		}
	}
}

// lastSpinnerRedraw returns the most recent download spinner payload from terminal output.
func lastSpinnerRedraw(out string) string {
	parts := strings.Split(out, "\033[2K")
	for i := len(parts) - 1; i >= 0; i-- {
		p := parts[i]
		if strings.Contains(p, "waiting for SP") ||
			strings.Contains(p, " received") ||
			(strings.Contains(p, " / ") && strings.Contains(p, "%")) {
			return p
		}
	}
	if len(parts) == 0 {
		return out
	}
	return parts[len(parts)-1]
}

func TestDownloadHeadersReplacesWaitingSpinner(t *testing.T) {
	var buf bytes.Buffer
	ui := &lineProgress{out: &buf, dl: downloadProgressState{total: -1}}
	const cid = "bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e"
	ui.DownloadStart(cid, "http://127.0.0.1/piece", -1, true, 0)
	time.Sleep(50 * time.Millisecond)
	ui.DownloadHeaders(cid, 32<<30)
	time.Sleep(150 * time.Millisecond)

	last := lastSpinnerRedraw(buf.String())
	if strings.Contains(last, "waiting for SP") {
		t.Fatalf("spinner still shows waiting after headers: %q", last)
	}
	if !strings.Contains(last, "32.0 GiB") || !strings.Contains(last, "%") {
		t.Fatalf("expected progress with total in last spinner line: %q", last)
	}
	if !strings.Contains(buf.String(), "\033[2K") {
		t.Fatal("expected full-line clear escape in spinner output")
	}
}

func TestLineProgressPaidDownloadUnknownTotal(t *testing.T) {
	var buf bytes.Buffer
	ui := &lineProgress{out: &buf, dl: downloadProgressState{total: -1}}
	const cid = "bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e"
	ui.DownloadStart(cid, "http://127.0.0.1/piece", -1, true, 0)
	ui.DownloadHeaders(cid, -1)
	ui.DownloadProgress(cid, 4096, -1)
	time.Sleep(80 * time.Millisecond)

	last := lastSpinnerRedraw(buf.String())
	if strings.Contains(last, "waiting for SP") {
		t.Fatalf("still waiting: %q", last)
	}
	if !strings.Contains(last, "received") {
		t.Fatalf("expected indeterminate progress: %q", last)
	}
}

func TestLineProgressDownloadFailed(t *testing.T) {
	var buf bytes.Buffer
	ui := &lineProgress{out: &buf, dl: downloadProgressState{total: -1}}
	const cid = "bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e"
	ui.DownloadStart(cid, "http://127.0.0.1/piece", -1, true, 0)
	ui.DownloadFailed(cid)
	if strings.Contains(buf.String(), "waiting for SP") && !strings.Contains(buf.String(), "\033[2K") {
		t.Fatalf("failed download should clear spinner line: %q", buf.String())
	}
}

func TestLineProgressDownloadSpinner(t *testing.T) {
	var buf bytes.Buffer
	ui := &lineProgress{out: &buf, dl: downloadProgressState{total: -1}}
	ui.DownloadStart("bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e", "http://127.0.0.1/piece", -1, true, 0)
	ui.DownloadHeaders("bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e", 32<<30)
	ui.DownloadProgress("bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e", 1<<30, 32<<30)
	time.Sleep(120 * time.Millisecond)
	ui.DownloadDone("bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e", "/out/piece.car")
	out := buf.String()
	for _, sub := range []string{"downloading", "32.0 GiB", "1.0 GiB / 32.0 GiB", "stored"} {
		if !strings.Contains(out, sub) {
			t.Fatalf("missing %q in:\n%s", sub, out)
		}
	}
	if strings.Contains(out, "total size") {
		t.Fatalf("should not print total size line, got:\n%s", out)
	}
}

func TestLineProgressProbeSpinner(t *testing.T) {
	var buf bytes.Buffer
	ui := &lineProgress{out: &buf, dl: downloadProgressState{total: -1}}
	ui.ProbeEndpointsStart(1, 2, "bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e", 4)
	ui.ProbeEndpointsProgress(1, 2, "bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e", 2, 4)
	time.Sleep(120 * time.Millisecond)
	ui.ProbeEndpointsEnd(1, 2, "bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e", "paid 0.01 USDFC from http://127.0.0.1:8787")
	out := buf.String()
	for _, sub := range []string{"probing 4 endpoint", "probing endpoints 2/4", "paid 0.01 USDFC"} {
		if !strings.Contains(out, sub) {
			t.Fatalf("missing %q in:\n%s", sub, out)
		}
	}
}

func TestFormatProbeProgress(t *testing.T) {
	got := formatProbeProgress(2, 5, "bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e", 3, 7)
	if !strings.Contains(got, "piece 2/5") || !strings.Contains(got, "3/7") {
		t.Fatalf("got %q", got)
	}
	got = formatProbeProgress(1, 1, "bafy", 0, 0)
	if !strings.Contains(got, "probing endpoints") || strings.Contains(got, "endpoints 0/") {
		t.Fatalf("expected indeterminate probe line, got %q", got)
	}
}

func TestFormatDownloadProgress(t *testing.T) {
	const cid = "bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e"
	got := formatDownloadProgress(cid, 5<<20, 32<<30, false, true, 0)
	if !strings.Contains(got, "5.0 MiB") || !strings.Contains(got, "32.0 GiB") || !strings.Contains(got, "%") {
		t.Fatalf("got %q", got)
	}
	got = formatDownloadProgress(cid, 0, 32<<30, false, true, 0)
	if !strings.Contains(got, "0 B") || !strings.Contains(got, "32.0 GiB") {
		t.Fatalf("got %q", got)
	}
	got = formatDownloadProgress(cid, 1024, -1, false, true, 0)
	if !strings.Contains(got, "1.0 KiB received") {
		t.Fatalf("got %q", got)
	}
	got = formatDownloadProgress(cid, 0, 0, false, true, 0)
	if !strings.Contains(got, "0 B / 0 B") {
		t.Fatalf("got %q", got)
	}
	got = formatDownloadProgress(cid, 0, -1, true, true, 0)
	if !strings.Contains(got, "waiting for SP") {
		t.Fatalf("got %q", got)
	}
	got = formatDownloadProgress(cid, 0, 32<<30, true, true, 0)
	if !strings.Contains(got, "0 B") || !strings.Contains(got, "32.0 GiB") || !strings.Contains(got, "waiting for SP") {
		t.Fatalf("probe total while waiting: %q", got)
	}
	got = formatDownloadProgress(cid, 0, 32<<30, true, false, 0)
	if strings.Contains(got, "waiting for SP") {
		t.Fatalf("free downloads should not show settlement wait text: %q", got)
	}
	got = formatDownloadProgress(cid, 0, -1, true, false, 0)
	if strings.Contains(got, "waiting for SP") || !strings.Contains(got, "waiting for response") {
		t.Fatalf("free unknown total should show generic response wait: %q", got)
	}
}

func TestDownloadStartShowsProbeTotalWhileWaiting(t *testing.T) {
	var buf bytes.Buffer
	ui := &lineProgress{out: &buf, dl: downloadProgressState{total: -1}}
	const cid = "bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e"
	const probeTotal = 8 << 30
	ui.DownloadStart(cid, "http://127.0.0.1/piece", probeTotal, true, 0)
	time.Sleep(120 * time.Millisecond)

	last := lastSpinnerRedraw(buf.String())
	if !strings.Contains(last, "8.0 GiB") || !strings.Contains(last, "waiting for SP") {
		t.Fatalf("expected probe total before GET: %q", last)
	}
	if strings.Contains(last, "received") {
		t.Fatalf("should not show indeterminate progress: %q", last)
	}
}

func TestFormatDownloadProgressIncludesRetryCount(t *testing.T) {
	const cid = "bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e"
	got := formatDownloadProgress(cid, 0, 32<<30, true, true, 2)
	if !strings.Contains(got, "[retry 2]") {
		t.Fatalf("missing retry count: %q", got)
	}
}

func TestDownloadProgressStateOnAttemptMidDownload(t *testing.T) {
	var s downloadProgressState
	s.onStart(32<<30, true, 0)
	s.onHeaders(32 << 30)
	s.onProgress(1<<30, 32<<30)
	s.onAttempt(32<<30, 2)

	if s.awaitingHTTP {
		t.Fatal("mid-download retry should not revert to HTTP wait")
	}
	got := formatDownloadStatus(s.written, s.total, s.awaitingHTTP, s.paid, s.retries)
	if strings.Contains(got, "waiting for SP") {
		t.Fatalf("should keep byte progress visible: %q", got)
	}
	if !strings.Contains(got, "1.0 GiB / 32.0 GiB") || !strings.Contains(got, "[retry 2]") {
		t.Fatalf("expected progress with retry suffix: %q", got)
	}
}

func TestDownloadProgressStateOnAttemptBeforeBytes(t *testing.T) {
	var s downloadProgressState
	s.onStart(-1, true, 0)
	s.onAttempt(-1, 1)
	if !s.awaitingHTTP {
		t.Fatal("pre-body retry should show HTTP wait")
	}
	got := formatDownloadStatus(s.written, s.total, s.awaitingHTTP, s.paid, s.retries)
	if !strings.Contains(got, "waiting for SP") || !strings.Contains(got, "[retry 1]") {
		t.Fatalf("expected wait line with retry: %q", got)
	}
}

func TestDownloadAttemptUpdatesSpinnerWithoutNewDownloadLine(t *testing.T) {
	var buf bytes.Buffer
	ui := &lineProgress{out: &buf, dl: downloadProgressState{total: -1}}
	const cid = "bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e"
	ui.DownloadStart(cid, "http://127.0.0.1/piece", 8<<30, true, 0)
	time.Sleep(80 * time.Millisecond)
	ui.DownloadAttempt(8<<30, 2)
	time.Sleep(80 * time.Millisecond)
	ui.DownloadDone(cid, "/out/piece.car")

	out := buf.String()
	if strings.Count(out, "→ downloading ") != 1 {
		t.Fatalf("expected one download banner, got:\n%s", out)
	}
	if !strings.Contains(out, "[retry 2]") {
		t.Fatalf("expected retry count in spinner output, got:\n%s", out)
	}
	if !strings.Contains(out, "stored /out/piece.car (after 2 retries)") {
		t.Fatalf("expected retry count in stored line, got:\n%s", out)
	}
}

func TestNoopProgressDisabled(t *testing.T) {
	if newProgressUI(nil, false).Enabled() {
		t.Fatal("nil writer should disable progress")
	}
	if newProgressUI(&bytes.Buffer{}, false).Enabled() {
		t.Fatal("non-terminal writer should disable progress")
	}
	if newProgressUI(os.Stderr, true).Enabled() {
		t.Fatal("--no-progress should disable progress")
	}
}

func TestFormatBytes(t *testing.T) {
	if formatBytes(512) != "512 B" {
		t.Fatal(formatBytes(512))
	}
	if formatBytes(2048) != "2.0 KiB" {
		t.Fatal(formatBytes(2048))
	}
}
