package main

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

type parallelPieceState struct {
	cid       string
	dl        downloadProgressState
	started   bool
	done      bool
	failed    bool
	lastError string
}

type parallelDownloadProgress struct {
	out      io.Writer
	piecePos map[string]int

	mu     sync.Mutex
	pieces []parallelPieceState
	frame  int
}

func newParallelDownloadProgress(out io.Writer, cids []string) *parallelDownloadProgress {
	pieces := make([]parallelPieceState, 0, len(cids))
	pos := make(map[string]int, len(cids))
	for i, cid := range cids {
		pos[cid] = i
		pieces = append(pieces, parallelPieceState{
			cid: cid,
			dl:  downloadProgressState{total: -1, awaitingHTTP: true},
		})
	}
	return &parallelDownloadProgress{
		out:      out,
		piecePos: pos,
		pieces:   pieces,
	}
}

func (p *parallelDownloadProgress) bind(cid string, paid bool) ProgressUI {
	return &boundParallelPieceProgress{
		parent: p,
		cid:    cid,
		paid:   paid,
	}
}

func (p *parallelDownloadProgress) renderLoop(stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(spinnerInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			p.render(true)
			return
		case <-ticker.C:
			p.render(false)
		}
	}
}

func (p *parallelDownloadProgress) render(final bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.frame++

	// Move up before redraw (all rows except first draw).
	if p.frame > 1 {
		fmt.Fprintf(p.out, "\033[%dA", len(p.pieces))
	}
	for i := range p.pieces {
		line := p.formatPieceLine(i, final)
		fmt.Fprintf(p.out, "\r\033[2K%s\n", line)
	}
}

func (p *parallelDownloadProgress) formatPieceLine(i int, final bool) string {
	ps := p.pieces[i]
	prefix := fmt.Sprintf("piece %d/%d %s", i+1, len(p.pieces), shortCID(ps.cid))
	if ps.done {
		if ps.failed {
			if ps.lastError != "" {
				return fmt.Sprintf("✗ %s failed: %s", prefix, ps.lastError)
			}
			return fmt.Sprintf("✗ %s failed", prefix)
		}
		if ps.dl.retries > 0 {
			return fmt.Sprintf("✓ %s done [retry %d]", prefix, ps.dl.retries)
		}
		return fmt.Sprintf("✓ %s done", prefix)
	}
	if !ps.started {
		return fmt.Sprintf("  %s queued", prefix)
	}
	frame := spinnerFrames[p.frame%len(spinnerFrames)]
	if final {
		frame = "·"
	}
	status := formatDownloadStatus(ps.dl.written, ps.dl.total, ps.dl.awaitingHTTP, ps.dl.paid, ps.dl.retries)
	return fmt.Sprintf("%s %s %s", frame, prefix, status)
}

func (p *parallelDownloadProgress) withPiece(cid string, fn func(ps *parallelPieceState)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	i, ok := p.piecePos[cid]
	if !ok {
		return
	}
	fn(&p.pieces[i])
}

func (p *parallelDownloadProgress) setStarted(cid string, paid bool, total int64, retries int) {
	p.withPiece(cid, func(ps *parallelPieceState) {
		ps.started = true
		ps.dl.onStart(total, paid, retries)
	})
}

func (p *parallelDownloadProgress) setAttempt(cid string, retries int, expectedTotal int64) {
	p.withPiece(cid, func(ps *parallelPieceState) {
		ps.dl.onAttempt(expectedTotal, retries)
	})
}

func (p *parallelDownloadProgress) setHeaders(cid string, total int64) {
	p.withPiece(cid, func(ps *parallelPieceState) {
		ps.dl.onHeaders(total)
	})
}

func (p *parallelDownloadProgress) setProgress(cid string, written, total int64) {
	p.withPiece(cid, func(ps *parallelPieceState) {
		ps.dl.onProgress(written, total)
		ps.dl.awaitingHTTP = false
	})
}

func (p *parallelDownloadProgress) setDone(cid string) {
	p.withPiece(cid, func(ps *parallelPieceState) {
		ps.done = true
		ps.failed = false
		ps.lastError = ""
	})
}

func (p *parallelDownloadProgress) setFailed(cid string, err error) {
	p.withPiece(cid, func(ps *parallelPieceState) {
		ps.done = true
		ps.failed = true
		if err == nil {
			return
		}
		msg := strings.TrimSpace(err.Error())
		if len(msg) > 96 {
			msg = msg[:96] + "..."
		}
		ps.lastError = msg
	})
}

type boundParallelPieceProgress struct {
	parent *parallelDownloadProgress
	cid    string
	paid   bool
}

func (b *boundParallelPieceProgress) Enabled() bool                                     { return true }
func (b *boundParallelPieceProgress) Phase(string)                                      {}
func (b *boundParallelPieceProgress) PieceProbe(int, int, string, string)               {}
func (b *boundParallelPieceProgress) ProbeEndpointsStart(int, int, string, int)         {}
func (b *boundParallelPieceProgress) ProbeEndpointsProgress(int, int, string, int, int) {}
func (b *boundParallelPieceProgress) ProbeEndpointsEnd(int, int, string, string)        {}
func (b *boundParallelPieceProgress) TxSubmitted(string, string)                        {}
func (b *boundParallelPieceProgress) TxWaiting(string, string, time.Duration)           {}
func (b *boundParallelPieceProgress) TxConfirmed(string, string, time.Duration, string) {}
func (b *boundParallelPieceProgress) DownloadStart(_ string, _ string, expectedTotal int64, _ bool, retries int) {
	b.parent.setStarted(b.cid, b.paid, expectedTotal, retries)
}
func (b *boundParallelPieceProgress) DownloadAttempt(expectedTotal int64, retries int) {
	b.parent.setAttempt(b.cid, retries, expectedTotal)
}
func (b *boundParallelPieceProgress) DownloadHeaders(_ string, total int64) {
	b.parent.setHeaders(b.cid, total)
}
func (b *boundParallelPieceProgress) DownloadProgress(_ string, written, total int64) {
	b.parent.setProgress(b.cid, written, total)
}
func (b *boundParallelPieceProgress) DownloadFailed(_ string) {
	b.parent.setFailed(b.cid, nil)
}
func (b *boundParallelPieceProgress) DownloadDone(_, _ string) {
	b.parent.setDone(b.cid)
}
