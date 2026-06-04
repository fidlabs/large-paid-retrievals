package main

import (
	"bytes"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/fidlabs/paid-retrievals/internal/pieceurls"
)

func TestMakeProbeLogVerbose(t *testing.T) {
	var buf bytes.Buffer
	log := makeProbeLog(&buf, true)
	if log == nil {
		t.Fatal("expected logger")
	}
	log("probing endpoint %s", "http://127.0.0.1:8787/piece/bafy1")
	if !strings.Contains(buf.String(), "http://127.0.0.1:8787/piece/bafy1") {
		t.Fatalf("got %q", buf.String())
	}
}

func TestMakeProbeLogVerboseSkipsChallengeBody(t *testing.T) {
	var buf bytes.Buffer
	log := makeProbeLog(&buf, true)
	log("challenge response body (truncated): %s", "secret")
	if strings.Contains(buf.String(), "secret") {
		t.Fatalf("verbose stdout should not include challenge body: %q", buf.String())
	}
}

func TestMakeProbeLogDisabled(t *testing.T) {
	if makeProbeLog(&bytes.Buffer{}, false) != nil {
		t.Fatal("expected nil logger")
	}
}

func TestProbeLogToStdout(t *testing.T) {
	if probeLogToStdout("challenge response headers: x") {
		t.Fatal("headers should stay off stdout")
	}
	if !probeLogToStdout("probing endpoint %s") {
		t.Fatal("probe lines should go to stdout when verbose")
	}
}

func TestProbeSelectionSummary(t *testing.T) {
	if probeSelectionSummary(nil) != "" {
		t.Fatal("nil selection")
	}
	if probeSelectionSummary(&pieceurls.Selection{}) != "" {
		t.Fatal("missing base")
	}
	u, err := url.Parse("http://sp.example:9000")
	if err != nil {
		t.Fatal(err)
	}
	free := probeSelectionSummary(&pieceurls.Selection{Base: u, Free: true})
	if !strings.Contains(free, "free direct from http://sp.example:9000") {
		t.Fatalf("got %q", free)
	}
	paid := probeSelectionSummary(&pieceurls.Selection{
		Base: u, Free: false, PriceUSDFC: "0.01", Payee0x: "0x2222222222222222222222222222222222222222",
	})
	if !strings.Contains(paid, "paid 0.01 USDFC") || !strings.Contains(paid, "payee=0x2222") {
		t.Fatalf("got %q", paid)
	}
}

func TestProbeCallbackFor(t *testing.T) {
	if probeCallbackFor(noopProgress{}, 1, 2) != nil {
		t.Fatal("disabled UI should not install probe callback")
	}
	var buf bytes.Buffer
	ui := &lineProgress{out: &buf, dl: downloadProgressState{total: -1}}
	cb := probeCallbackFor(ui, 2, 5)
	if cb == nil {
		t.Fatal("expected callback")
	}
	cb.ProbeStart("bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e", 3)
	cb.ProbeFinished("bafkreidcbkgxoddug6vawnjrzb4aaublfn46sd2rvxnykbxkkarke7y76e", 2, 3)
	time.Sleep(80 * time.Millisecond)
	out := buf.String()
	if !strings.Contains(out, "piece 2/5") || !strings.Contains(out, "probing 3 endpoint") {
		t.Fatalf("got %q", out)
	}
}
