package main

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/fidlabs/paid-retrievals/internal/filpay"
	"golang.org/x/term"
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

type spinnerKind int

const (
	spinnerNone spinnerKind = iota
	spinnerTx
	spinnerProbe
	spinnerDownload
)

const (
	spinnerInterval       = 80 * time.Millisecond
	waitingForSPMessage   = "waiting for SP (payment settlement)"
	waitingForRespMessage = "waiting for response"
)

// ProgressUI reports fetch phases, chain waits, and download progress to the user.
type ProgressUI interface {
	filpay.TxProgress
	Enabled() bool
	Phase(msg string)
	PieceProbe(index, total int, cid, detail string)
	ProbeEndpointsStart(pieceIndex, pieceTotal int, cid string, endpointCount int)
	ProbeEndpointsProgress(pieceIndex, pieceTotal int, cid string, completed, total int)
	ProbeEndpointsEnd(pieceIndex, pieceTotal int, cid string, summary string)
	DownloadStart(cid, url string, expectedTotal int64, paid bool, retries int) // expectedTotal from probe HEAD; < 0 if unknown
	DownloadAttempt(expectedTotal int64, retries int)
	DownloadHeaders(cid string, totalBytes int64)
	DownloadProgress(cid string, written, total int64)
	DownloadFailed(cid string)
	DownloadDone(cid, path string)
}

type noopProgress struct{}

func (noopProgress) Enabled() bool                                     { return false }
func (noopProgress) Phase(string)                                      {}
func (noopProgress) PieceProbe(int, int, string, string)               {}
func (noopProgress) ProbeEndpointsStart(int, int, string, int)         {}
func (noopProgress) ProbeEndpointsProgress(int, int, string, int, int) {}
func (noopProgress) ProbeEndpointsEnd(int, int, string, string)        {}
func (noopProgress) TxSubmitted(string, string)                        {}
func (noopProgress) TxWaiting(string, string, time.Duration)           {}
func (noopProgress) TxConfirmed(string, string, time.Duration, string) {}
func (noopProgress) DownloadStart(string, string, int64, bool, int)    {}
func (noopProgress) DownloadAttempt(int64, int)                        {}
func (noopProgress) DownloadHeaders(string, int64)                     {}
func (noopProgress) DownloadProgress(string, int64, int64)             {}
func (noopProgress) DownloadFailed(string)                             {}
func (noopProgress) DownloadDone(string, string)                       {}

type lineProgress struct {
	out io.Writer

	spinMu    sync.Mutex
	spinDone  chan struct{}
	spinKind  spinnerKind
	spinFrame int

	// Tx wait spinner
	spinOp    string
	spinHash  string
	spinStart time.Time

	// Endpoint probe spinner
	probePieceIdx    int
	probePieceTotal  int
	probeCID         string
	probeDone        int
	probeEndpointCnt int

	// Download spinner (written/total updated from copy loop)
	dlCID string
	dl    downloadProgressState
}

func newProgressUI(out io.Writer, noProgress bool) ProgressUI {
	if noProgress || out == nil {
		return noopProgress{}
	}
	f, ok := out.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return noopProgress{}
	}
	return &lineProgress{out: out, dl: downloadProgressState{total: -1}}
}

func (p *lineProgress) Enabled() bool { return true }

func (p *lineProgress) Phase(msg string) {
	p.stopSpinner()
	fmt.Fprintf(p.out, "→ %s\n", msg)
}

func (p *lineProgress) PieceProbe(index, total int, cid, detail string) {
	if detail == "" {
		fmt.Fprintf(p.out, "→ piece %d/%d: %s\n", index, total, shortCID(cid))
		return
	}
	fmt.Fprintf(p.out, "→ piece %d/%d: %s — %s\n", index, total, shortCID(cid), detail)
}

func (p *lineProgress) TxSubmitted(op, txHash string) {
	p.stopSpinner()
	fmt.Fprintf(p.out, "→ %s submitted %s\n", op, shortTxHash(txHash))
	p.startSpinner(spinnerTx, func() {
		p.spinOp = op
		p.spinHash = txHash
		p.spinStart = time.Now()
	})
}

func (p *lineProgress) TxWaiting(string, string, time.Duration) {}

func (p *lineProgress) ProbeEndpointsStart(pieceIndex, pieceTotal int, cid string, endpointCount int) {
	p.stopSpinner()
	fmt.Fprintf(p.out, "→ piece %d/%d: %s — probing %d endpoint(s)\n", pieceIndex, pieceTotal, shortCID(cid), endpointCount)
	p.startSpinner(spinnerProbe, func() {
		p.probePieceIdx = pieceIndex
		p.probePieceTotal = pieceTotal
		p.probeCID = cid
		p.probeDone = 0
		p.probeEndpointCnt = endpointCount
	})
}

func (p *lineProgress) ProbeEndpointsProgress(pieceIndex, pieceTotal int, cid string, completed, total int) {
	p.spinMu.Lock()
	p.probePieceIdx = pieceIndex
	p.probePieceTotal = pieceTotal
	p.probeCID = cid
	p.probeDone = completed
	p.probeEndpointCnt = total
	p.spinMu.Unlock()
}

func (p *lineProgress) ProbeEndpointsEnd(pieceIndex, pieceTotal int, cid, summary string) {
	p.stopSpinner()
	if summary == "" {
		return
	}
	fmt.Fprintf(p.out, "→ piece %d/%d: %s — %s\n", pieceIndex, pieceTotal, shortCID(cid), summary)
}

func (p *lineProgress) TxConfirmed(op, txHash string, elapsed time.Duration, block string) {
	p.stopSpinner()
	fmt.Fprintf(p.out, "→ %s confirmed %s in %s (block %s)\n", op, shortTxHash(txHash), elapsed.Round(time.Second), block)
}

func (p *lineProgress) DownloadStart(cid, url string, expectedTotal int64, paid bool, retries int) {
	p.stopSpinner()
	fmt.Fprintf(p.out, "→ downloading %s from %s\n", shortCID(cid), url)
	p.startSpinner(spinnerDownload, func() {
		p.initDownloadAttemptLocked(cid, expectedTotal, paid, retries)
	})
}

func (p *lineProgress) DownloadAttempt(expectedTotal int64, retries int) {
	p.spinMu.Lock()
	p.updateDownloadAttemptLocked(expectedTotal, retries)
	p.spinMu.Unlock()
	p.redrawSpinnerLine()
}

func (p *lineProgress) DownloadHeaders(cid string, totalBytes int64) {
	p.spinMu.Lock()
	p.dlCID = cid
	p.dl.onHeaders(totalBytes)
	p.spinMu.Unlock()
	p.redrawSpinnerLine()
}

func (p *lineProgress) DownloadProgress(_ string, written, total int64) {
	p.spinMu.Lock()
	p.dl.onProgress(written, total)
	p.spinMu.Unlock()
}

func (p *lineProgress) DownloadFailed(string) {
	p.stopSpinner()
}

func (p *lineProgress) DownloadDone(cid, path string) {
	p.spinMu.Lock()
	retries := p.dl.retries
	p.spinMu.Unlock()
	p.stopSpinner()
	if retries > 0 {
		fmt.Fprintf(p.out, "→ stored %s (after %d retries)\n", path, retries)
		return
	}
	fmt.Fprintf(p.out, "→ stored %s\n", path)
}

func (p *lineProgress) initDownloadAttemptLocked(cid string, expectedTotal int64, paid bool, retries int) {
	p.dlCID = cid
	p.dl.onStart(expectedTotal, paid, retries)
}

func (p *lineProgress) updateDownloadAttemptLocked(expectedTotal int64, retries int) {
	p.dl.onAttempt(expectedTotal, retries)
}

func (p *lineProgress) startSpinner(kind spinnerKind, init func()) {
	p.spinMu.Lock()
	defer p.spinMu.Unlock()
	if p.spinDone != nil {
		return
	}
	p.spinKind = kind
	p.spinFrame = 0
	init()
	done := make(chan struct{})
	p.spinDone = done
	go p.runSpinner(done)
}

func (p *lineProgress) runSpinner(done <-chan struct{}) {
	ticker := time.NewTicker(spinnerInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			p.spinMu.Lock()
			kind := p.spinKind
			frame := p.spinFrame
			p.spinFrame++
			line := p.spinnerLineLocked(kind)
			if line != "" {
				f := spinnerFrames[frame%len(spinnerFrames)]
				p.writeSpinnerLine(f, line)
			}
			p.spinMu.Unlock()
		}
	}
}

func (p *lineProgress) spinnerLineLocked(kind spinnerKind) string {
	switch kind {
	case spinnerTx:
		elapsed := time.Since(p.spinStart).Round(time.Second)
		return fmt.Sprintf("waiting for %s %s (%s)", p.spinOp, shortTxHash(p.spinHash), elapsed)
	case spinnerProbe:
		return formatProbeProgress(p.probePieceIdx, p.probePieceTotal, p.probeCID, p.probeDone, p.probeEndpointCnt)
	case spinnerDownload:
		return formatDownloadProgress(p.dlCID, p.dl.written, p.dl.total, p.dl.awaitingHTTP, p.dl.paid, p.dl.retries)
	default:
		return ""
	}
}

func formatProbeProgress(pieceIndex, pieceTotal int, cid string, completed, total int) string {
	if total <= 0 {
		return fmt.Sprintf("piece %d/%d %s probing endpoints", pieceIndex, pieceTotal, shortCID(cid))
	}
	return fmt.Sprintf("piece %d/%d %s probing endpoints %d/%d", pieceIndex, pieceTotal, shortCID(cid), completed, total)
}

func formatDownloadProgress(cid string, written, total int64, awaitingHTTP, paid bool, retries int) string {
	status := formatDownloadStatus(written, total, awaitingHTTP, paid, retries)
	if status == "" {
		return ""
	}
	return fmt.Sprintf("%s %s", shortCID(cid), status)
}

func (p *lineProgress) redrawSpinnerLine() {
	p.spinMu.Lock()
	defer p.spinMu.Unlock()
	if p.spinDone == nil || p.spinKind != spinnerDownload {
		return
	}
	line := formatDownloadProgress(p.dlCID, p.dl.written, p.dl.total, p.dl.awaitingHTTP, p.dl.paid, p.dl.retries)
	if line == "" {
		return
	}
	f := spinnerFrames[p.spinFrame%len(spinnerFrames)]
	p.writeSpinnerLine(f, line)
}

// writeSpinnerLine clears the full terminal row and redraws the spinner (caller holds spinMu).
func (p *lineProgress) writeSpinnerLine(frame, line string) {
	fmt.Fprintf(p.out, "\r\033[2K  %s %s", frame, line)
}

func (p *lineProgress) stopSpinner() {
	p.spinMu.Lock()
	defer p.spinMu.Unlock()
	if p.spinDone == nil {
		return
	}
	close(p.spinDone)
	p.spinDone = nil
	p.spinKind = spinnerNone
	fmt.Fprint(p.out, "\r\033[2K")
}

func shortCID(cid string) string {
	if len(cid) <= 16 {
		return cid
	}
	return cid[:10] + "…" + cid[len(cid)-6:]
}

func shortTxHash(h string) string {
	h = trim0x(h)
	if len(h) <= 14 {
		return "0x" + h
	}
	return "0x" + h[:8] + "…" + h[len(h)-4:]
}

func trim0x(s string) string {
	if len(s) >= 2 && (s[0:2] == "0x" || s[0:2] == "0X") {
		return s[2:]
	}
	return s
}

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

type downloadProgressState struct {
	written      int64
	total        int64 // < 0 when Content-Length unknown
	awaitingHTTP bool
	paid         bool
	retries      int
}

func (s *downloadProgressState) onStart(expectedTotal int64, paid bool, retries int) {
	s.written = 0
	s.total = -1
	if expectedTotal >= 0 {
		s.total = expectedTotal
	}
	s.awaitingHTTP = true
	s.paid = paid
	s.retries = retries
}

func (s *downloadProgressState) onAttempt(expectedTotal int64, retries int) {
	s.retries = retries
	// Only show HTTP-wait text when no bytes received yet; mid-download retries keep progress visible.
	if s.written == 0 {
		s.awaitingHTTP = true
	}
	// Keep existing written/total to avoid spinner regressions between retries.
	// Only backfill total from probe when unknown.
	if s.total < 0 && expectedTotal >= 0 {
		s.total = expectedTotal
	}
}

func (s *downloadProgressState) onHeaders(total int64) {
	s.awaitingHTTP = false
	if total >= 0 {
		s.total = total
	}
}

func (s *downloadProgressState) onProgress(written, total int64) {
	s.written = written
	if total >= 0 {
		s.total = total
	}
}

func formatDownloadStatus(written, total int64, awaitingHTTP, paid bool, retries int) string {
	if total >= 0 {
		line := formatByteProgress(written, total)
		if awaitingHTTP && paid {
			line += " — " + waitingForSPMessage
		}
		return withRetrySuffix(line, retries)
	}
	if awaitingHTTP {
		status := waitingForRespMessage
		if paid {
			status = waitingForSPMessage
		}
		return withRetrySuffix(status, retries)
	}
	return withRetrySuffix(fmt.Sprintf("%s received", formatBytes(written)), retries)
}

func formatByteProgress(written, total int64) string {
	if total == 0 {
		return fmt.Sprintf("%s / %s (100%%)", formatBytes(written), formatBytes(total))
	}
	pct := float64(written) / float64(total) * 100
	return fmt.Sprintf("%s / %s (%.1f%%)", formatBytes(written), formatBytes(total), pct)
}

func withRetrySuffix(line string, retries int) string {
	if retries <= 0 {
		return line
	}
	return fmt.Sprintf("%s [retry %d]", line, retries)
}
