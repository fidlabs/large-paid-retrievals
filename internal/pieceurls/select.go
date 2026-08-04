package pieceurls

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/fidlabs/paid-retrievals/internal/mpp"
	"github.com/fidlabs/paid-retrievals/internal/paymentheader"
)

// Selection is the winning source for one piece after probing candidate HTTP bases.
type Selection struct {
	Base *url.URL
	CID  string
	Free bool

	DealUUID   string
	PriceUSDFC string
	Payee0x    string
	// Challenge is set for paid (402) selections; parsed from WWW-Authenticate (MPP).
	Challenge mpp.Challenge

	// TotalBytes is the CAR size when known from a probe HEAD 200 (-1 otherwise).
	TotalBytes int64
}

// SelectBestPieceSource probes each base with HEAD (size) and GET {base}/piece/{cid}
// (concurrently). The first GET is anonymous (no vouchers). On 403 (private deal)
// it retries with ?client=ProbeClient when set, attaching ProbeVouchers as Bearer
// headers. Any GET 200 marks the piece as free (response body is not downloaded
// during probe). Among 402 responses with a valid MPP WWW-Authenticate challenge,
// the lowest price_usdfc (parsed as base units) wins. Other status codes and
// failures are ignored.
func (c *Client) SelectBestPieceSource(ctx context.Context, pieceCID string, bases []*url.URL, log func(string, ...any), probe ProbeCallback) (*Selection, error) {
	if c == nil || c.HTTP == nil {
		return nil, fmt.Errorf("pieceurls: client or HTTP client is nil")
	}
	if len(bases) == 0 {
		return nil, errors.New("no candidate bases to probe")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var freeClaimed atomic.Bool
	var freeResult atomic.Pointer[Selection]

	parallel := c.ProbeParallelism
	if parallel <= 0 {
		parallel = defaultProbeParallel
	}
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup

	var mu sync.Mutex
	var bestPaid *Selection
	var bestBaseUnits *big.Int

	probeTotal := 0
	for _, b := range bases {
		if cloneURLBase(b) != nil {
			probeTotal++
		}
	}
	if probe != nil && probeTotal > 0 {
		probe.ProbeStart(pieceCID, probeTotal)
	}
	var probeDone atomic.Int32

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
			defer func() {
				if probe != nil {
					done := int(probeDone.Add(1))
					probe.ProbeFinished(pieceCID, done, probeTotal)
				}
			}()

			sel, err := c.probePieceEndpoint(ctx, b, pieceCID, log, &freeClaimed, &freeResult, cancel)
			if err != nil || sel == nil {
				return
			}

			mu.Lock()
			defer mu.Unlock()
			w, err := paymentheader.ParseTokenToBaseUnits(sel.PriceUSDFC)
			if err != nil {
				return
			}
			if bestBaseUnits == nil || w.Cmp(bestBaseUnits) < 0 {
				bestBaseUnits = w
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
	return nil, fmt.Errorf("no usable endpoint for piece %s (no free 200 endpoint and no valid 402 MPP challenge)", pieceCID)
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

func pieceProbeURL(base *url.URL, cid, client0x string) string {
	u := *base
	u.Path = "/piece/" + cid
	u.RawQuery = ""
	u.Fragment = ""
	if c := strings.TrimSpace(client0x); c != "" {
		q := u.Query()
		q.Set("client", c)
		u.RawQuery = q.Encode()
	}
	return u.String()
}

func (c *Client) probePieceEndpoint(ctx context.Context, base *url.URL, cid string, log func(string, ...any), freeClaimed *atomic.Bool, freeResult *atomic.Pointer[Selection], cancel context.CancelFunc) (*Selection, error) {
	// HEAD is anonymous (size/existence are public).
	totalBytes := c.probeHEAD(ctx, pieceProbeURL(base, cid, ""), log)

	// First try without client — public deals return 200/402; private return 403.
	sel, forbidden, err := c.probeGET(ctx, base, cid, "", totalBytes, log, freeClaimed, freeResult, cancel)
	if err != nil {
		return nil, err
	}
	if sel != nil || !forbidden {
		return sel, nil
	}

	client0x := ""
	if c != nil {
		client0x = strings.TrimSpace(c.ProbeClient)
	}
	if client0x == "" {
		if log != nil {
			log("probe forbidden cid=%s base=%s (private deal; no ProbeClient to retry)", cid, base.String())
		}
		return nil, nil
	}
	if log != nil {
		log("probe forbidden without client; retrying with client=%s cid=%s base=%s", client0x, cid, base.String())
	}
	sel, _, err = c.probeGET(ctx, base, cid, client0x, totalBytes, log, freeClaimed, freeResult, cancel)
	return sel, err
}

// probeGET performs one GET probe. forbidden is true when the SP returned 403.
func (c *Client) probeGET(ctx context.Context, base *url.URL, cid, client0x string, totalBytes int64, log func(string, ...any), freeClaimed *atomic.Bool, freeResult *atomic.Pointer[Selection], cancel context.CancelFunc) (sel *Selection, forbidden bool, err error) {
	full := pieceProbeURL(base, cid, client0x)
	if log != nil {
		log("probing endpoint %s", full)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return nil, false, err
	}
	// Vouchers are only meaningful with a requester identity; skip on anonymous probes.
	if strings.TrimSpace(client0x) != "" {
		AddBearerVoucherHeaders(req.Header, c.ProbeVouchers)
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		if log != nil {
			log("probe GET %s failed: %v", full, err)
		}
		return nil, false, err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		// Do not drain the full CAR during probe (only checking availability).
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 8192))
		if !freeClaimed.CompareAndSwap(false, true) {
			return nil, false, nil
		}
		out := &Selection{
			Base:       cloneURLBase(base),
			CID:        cid,
			Free:       true,
			TotalBytes: totalBytes,
		}
		freeResult.Store(out)
		if log != nil {
			log("probe free endpoint cid=%s base=%s (HTTP 200, download deferred)", cid, base.String())
		}
		cancel()
		return nil, false, nil

	case http.StatusPaymentRequired:
		body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		if log != nil {
			log("challenge response status=%d cid=%s", res.StatusCode, cid)
			log("challenge response headers: content-type=%q cache-control=%q", res.Header.Get("Content-Type"), res.Header.Get("Cache-Control"))
			log("challenge response body (truncated): %s", truncateForLog(string(body), 2048))
		}
		wa := strings.TrimSpace(res.Header.Get("WWW-Authenticate"))
		ch, err := mpp.ParseWWWAuthenticate(wa)
		if err != nil {
			if log != nil {
				log("probe 402 cid=%s base=%s: bad WWW-Authenticate: %v", cid, base.String(), err)
			}
			return nil, false, err
		}
		if ch.Request.DealUUID == "" || ch.Request.PriceUSDFC == "" {
			if log != nil {
				log("probe 402 challenge OK cid=%s base=%s: invalid MPP challenge request", cid, base.String())
			}
			return nil, false, errors.New("invalid MPP challenge payload")
		}
		if log != nil {
			log("challenge OK payment={id:%s deal_uuid:%s cid:%s price_usdfc:%s payee_0x:%q}", ch.ID, ch.Request.DealUUID, ch.Request.CID, ch.Request.PriceUSDFC, ch.Request.Payee0x)
		}
		return &Selection{
			Base:       cloneURLBase(base),
			CID:        cid,
			Free:       false,
			TotalBytes: totalBytes,
			DealUUID:   ch.Request.DealUUID,
			PriceUSDFC: ch.Request.PriceUSDFC,
			Payee0x:    strings.TrimSpace(ch.Request.Payee0x),
			Challenge:  *ch,
		}, false, nil

	case http.StatusForbidden:
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<16))
		if log != nil {
			log("probe forbidden cid=%s base=%s status=403", cid, base.String())
		}
		return nil, true, nil

	default:
		if log != nil {
			log("probe skip cid=%s base=%s status=%d", cid, base.String(), res.StatusCode)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<16))
		return nil, false, nil
	}
}

func (c *Client) probeHEAD(ctx context.Context, full string, log func(string, ...any)) int64 {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, full, nil)
	if err != nil {
		return -1
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		if log != nil {
			log("probe HEAD %s failed: %v", full, err)
		}
		return -1
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		if log != nil {
			log("probe HEAD %s status=%d", full, res.StatusCode)
		}
		return -1
	}
	return ResponseTotalBytes(res)
}

func truncateForLog(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// AddBearerVoucherHeaders appends Authorization: Bearer <token> for each voucher.
// Tokens may be raw base64url or already prefixed with "Bearer ". Callers should
// only invoke this when a client identity is present (not on anonymous probes).
func AddBearerVoucherHeaders(h http.Header, vouchers []string) {
	if h == nil {
		return
	}
	for _, raw := range vouchers {
		tok := strings.TrimSpace(raw)
		if tok == "" {
			continue
		}
		if scheme, rest, ok := strings.Cut(tok, " "); ok && strings.EqualFold(scheme, "Bearer") {
			tok = strings.TrimSpace(rest)
		}
		if tok == "" {
			continue
		}
		h.Add("Authorization", "Bearer "+tok)
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
