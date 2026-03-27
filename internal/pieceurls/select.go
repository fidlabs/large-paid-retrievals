package pieceurls

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/fidlabs/paid-retrievals/internal/paymentheader"
	"github.com/fidlabs/paid-retrievals/internal/x402"
)

const probeParallel = 16

// Selection is the winning source for one piece after probing candidate HTTP bases.
type Selection struct {
	Base      *url.URL
	CID       string
	Free      bool
	SavedPath string

	DealUUID string
	PriceFIL string
	Payee0x  string
}

// SelectBestPieceSource probes GET {base}/piece/{cid}?client=… for each base (concurrently).
// Any 200 response is treated as a free direct CAR download (saved under outDir).
// Among 402 responses, the lowest price_fil (parsed as wei) wins.
// Other status codes and failures are ignored.
func SelectBestPieceSource(ctx context.Context, cli *http.Client, pieceCID, client0x, outDir string, bases []*url.URL, log func(string, ...any)) (*Selection, error) {
	if len(bases) == 0 {
		return nil, errors.New("no candidate bases to probe")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var freeClaimed atomic.Bool
	var freeResult atomic.Pointer[Selection]

	sem := make(chan struct{}, probeParallel)
	var wg sync.WaitGroup

	var mu sync.Mutex
	var bestPaid *Selection
	var bestWei *big.Int

	for _, b := range bases {
		b := cloneURLBase(b)
		if b == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			sel, err := probePieceEndpoint(ctx, cli, b, pieceCID, client0x, outDir, log, &freeClaimed, &freeResult, cancel)
			if err != nil || sel == nil {
				return
			}

			mu.Lock()
			defer mu.Unlock()
			w, err := paymentheader.ParseFILToWei(sel.PriceFIL)
			if err != nil {
				return
			}
			if bestWei == nil || w.Cmp(bestWei) < 0 {
				bestWei = w
				cp := *sel
				bestPaid = &cp
			}
		}()
	}

	wg.Wait()

	if p := freeResult.Load(); p != nil {
		return p, nil
	}
	if bestPaid != nil {
		return bestPaid, nil
	}
	return nil, fmt.Errorf("no usable endpoint for piece %s (no 200 CAR and no valid 402 quote)", pieceCID)
}

func cloneURLBase(b *url.URL) *url.URL {
	if b == nil {
		return nil
	}
	u := *b
	u.Path = ""
	u.RawQuery = ""
	u.Fragment = ""
	return &u
}

func probePieceEndpoint(ctx context.Context, cli *http.Client, base *url.URL, cid, client0x, outDir string, log func(string, ...any), freeClaimed *atomic.Bool, freeResult *atomic.Pointer[Selection], cancel context.CancelFunc) (*Selection, error) {
	u := *base
	u.Path = "/piece/" + cid
	q := u.Query()
	q.Set("client", client0x)
	u.RawQuery = q.Encode()
	full := u.String()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return nil, err
	}
	res, err := cli.Do(req)
	if err != nil {
		if log != nil {
			log("probe GET %s failed: %v", full, err)
		}
		return nil, err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		if !freeClaimed.CompareAndSwap(false, true) {
			_, _ = io.Copy(io.Discard, res.Body)
			return nil, nil
		}
		writeOK := false
		defer func() {
			if !writeOK {
				freeClaimed.Store(false)
			}
		}()
		outPath := filepath.Join(outDir, sanitizeFilename(cid)+".car")
		f, err := os.Create(outPath)
		if err != nil {
			return nil, err
		}
		if _, err := io.Copy(f, res.Body); err != nil {
			f.Close()
			_ = os.Remove(outPath)
			return nil, err
		}
		if err := f.Close(); err != nil {
			_ = os.Remove(outPath)
			return nil, err
		}
		writeOK = true
		sel := &Selection{
			Base:      cloneURLBase(base),
			CID:       cid,
			Free:      true,
			SavedPath: outPath,
		}
		freeResult.Store(sel)
		if log != nil {
			log("probe free CAR cid=%s base=%s -> %s", cid, base.String(), outPath)
		}
		cancel()
		return nil, nil

	case http.StatusPaymentRequired:
		body, err := io.ReadAll(io.LimitReader(res.Body, 1<<21))
		if err != nil {
			return nil, err
		}
		var payload struct {
			X402 x402.QuoteResponse `json:"x402"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			if log != nil {
				log("probe 402 cid=%s base=%s: bad json: %v", cid, base.String(), err)
			}
			return nil, err
		}
		if payload.X402.DealUUID == "" || payload.X402.PriceFIL == "" {
			if log != nil {
				log("probe 402 cid=%s base=%s: invalid quote body", cid, base.String())
			}
			return nil, errors.New("invalid quote payload")
		}
		if log != nil {
			log("probe paid quote cid=%s base=%s deal=%s price_fil=%s payee=%s", cid, base.String(), payload.X402.DealUUID, payload.X402.PriceFIL, payload.X402.Payee0x)
		}
		return &Selection{
			Base:     cloneURLBase(base),
			CID:      cid,
			Free:     false,
			DealUUID: payload.X402.DealUUID,
			PriceFIL: payload.X402.PriceFIL,
			Payee0x:  strings.TrimSpace(payload.X402.Payee0x),
		}, nil

	default:
		if log != nil {
			log("probe skip cid=%s base=%s status=%d", cid, base.String(), res.StatusCode)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<16))
		return nil, nil
	}
}

func sanitizeFilename(v string) string {
	if v == "" {
		return "piece"
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-', r == '_', r == '.':
			return r
		default:
			return '_'
		}
	}, v)
}
