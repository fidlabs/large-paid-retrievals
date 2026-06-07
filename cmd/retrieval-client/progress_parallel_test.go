package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestParallelDownloadFailedNoOp(t *testing.T) {
	const cid = "baga6ea4seaqchqdzwxltukzwbtajfugthjhikv2ezg46qjvsevzbe7nghsxtmbj"
	pui := newParallelDownloadProgress(&bytes.Buffer{}, []string{cid})
	ui := pui.bind(cid, true)
	ui.DownloadStart(cid, "http://127.0.0.1/piece", 32<<30, true, 0)
	ui.DownloadFailed(cid)

	pui.mu.Lock()
	ps := pui.pieces[0]
	pui.mu.Unlock()
	if ps.done || ps.failed {
		t.Fatalf("DownloadFailed should not mark terminal state: done=%v failed=%v", ps.done, ps.failed)
	}
}

func TestParallelProgressFailureLinesStayShort(t *testing.T) {
	const (
		cid0 = "baga6ea4seaqchqdzwxltukzwbtajfugthjhikv2ezg46qjvsevzbe7nghsxtmbj"
		cid1 = "baga6ea4seaqchqdzwxltukzwbtajfugthjhikv2ezg46qjvsevzbe7nghsxtmbk"
	)
	var buf bytes.Buffer
	pui := newParallelDownloadProgress(&buf, []string{cid0, cid1})
	stop := make(chan struct{})
	done := make(chan struct{})
	go pui.renderLoop(stop, done)

	ui0 := pui.bind(cid0, true)
	ui0.DownloadStart(cid0, "http://127.0.0.1/piece", 32<<30, true, 0)
	ui1 := pui.bind(cid1, true)
	ui1.DownloadStart(cid1, "http://127.0.0.1/piece", 32<<30, true, 0)
	time.Sleep(spinnerInterval)

	longErr := fmt.Errorf(`download %s failed: 402 Payment Required {"type":"https://paymentauth.org/problems/verification-failed","detail":"Credential payload failed validation"}`, cid0)
	ui0.DownloadAttempt(32<<30, 5)
	pui.setFailed(cid0, longErr)
	pui.setFailed(cid1, longErr)
	time.Sleep(2 * spinnerInterval)

	close(stop)
	<-done

	out := buf.String()
	if strings.Contains(out, "402 Payment") || strings.Contains(out, "verification-failed") {
		t.Fatalf("parallel UI should not print inline error bodies:\n%s", out)
	}
	if strings.Count(out, "✗") < 2 {
		t.Fatalf("expected failure markers:\n%s", out)
	}
	final := extractLastParallelBlock(out, 2)
	if strings.Count(final, "piece 1/2") != 1 || strings.Count(final, "piece 2/2") != 1 {
		t.Fatalf("expected one line per piece in final snapshot, got:\n%s", final)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "failed:") {
			t.Fatalf("unexpected inline failure detail: %q", line)
		}
	}
	if !strings.Contains(final, "failed [retry 5]") {
		t.Fatalf("expected retry count on failed terminal line, got:\n%s", final)
	}
}

func TestParallelProgressStaggeredFailuresNoDuplicateBlock(t *testing.T) {
	const (
		cid0 = "baga6ea4seaqchqdzwxltukzwbtajfugthjhikv2ezg46qjvsevzbe7nghsxtmbj"
		cid1 = "baga6ea4seaqchqdzwxltukzwbtajfugthjhikv2ezg46qjvsevzbe7nghsxtmbk"
		cid2 = "baga6ea4seaqchqdzwxltukzwbtajfugthjhikv2ezg46qjvsevzbe7nghsxtmbm"
		cid3 = "baga6ea4seaqchqdzwxltukzwbtajfugthjhikv2ezg46qjvsevzbe7nghsxtmbn"
	)
	var buf bytes.Buffer
	pui := newParallelDownloadProgress(&buf, []string{cid0, cid1, cid2, cid3})
	stop := make(chan struct{})
	done := make(chan struct{})
	go pui.renderLoop(stop, done)

	for _, cid := range []string{cid0, cid1, cid2, cid3} {
		ui := pui.bind(cid, true)
		ui.DownloadStart(cid, "http://127.0.0.1/piece", 32<<30, true, 0)
	}
	time.Sleep(spinnerInterval)

	pui.setFailed(cid0, fmt.Errorf("failed"))
	pui.setFailed(cid2, fmt.Errorf("failed"))
	pui.setFailed(cid3, fmt.Errorf("failed"))
	time.Sleep(spinnerInterval)
	pui.setFailed(cid1, fmt.Errorf("failed"))
	time.Sleep(3 * spinnerInterval)

	close(stop)
	<-done

	final := extractLastParallelBlock(buf.String(), 4)
	for i := 1; i <= 4; i++ {
		marker := fmt.Sprintf("piece %d/4", i)
		if strings.Count(final, marker) != 1 {
			t.Fatalf("expected exactly one %q line in final snapshot, got:\n%s", marker, final)
		}
	}
}

// extractLastParallelBlock returns the most recent N-line render snapshot (after the last cursor-up).
func extractLastParallelBlock(out string, pieceCount int) string {
	marker := fmt.Sprintf("\033[%dA", pieceCount)
	if idx := strings.LastIndex(out, marker); idx >= 0 {
		return out[idx+len(marker):]
	}
	return out
}

func TestParallelProgressFreezesWhenAllTerminal(t *testing.T) {
	const cid = "baga6ea4seaqchqdzwxltukzwbtajfugthjhikv2ezg46qjvsevzbe7nghsxtmbj"
	var buf bytes.Buffer
	pui := newParallelDownloadProgress(&buf, []string{cid})
	stop := make(chan struct{})
	done := make(chan struct{})
	go pui.renderLoop(stop, done)

	ui := pui.bind(cid, true)
	ui.DownloadStart(cid, "http://127.0.0.1/piece", 32<<30, true, 0)
	pui.setFailed(cid, fmt.Errorf("download failed"))
	time.Sleep(2 * spinnerInterval)

	before := buf.String()
	time.Sleep(3 * spinnerInterval)
	after := buf.String()
	if before != after {
		t.Fatalf("expected frozen output after terminal state; before len=%d after len=%d", len(before), len(after))
	}

	close(stop)
	<-done
}
