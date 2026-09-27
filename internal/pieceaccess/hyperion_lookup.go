package pieceaccess

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

const (
	// DefaultHyperionBaseURL is the public Hyperion PoRep deals API (mainnet).
	DefaultHyperionBaseURL = "https://hyperion.allocator.tech"
	hyperionDealsPageLimit = 100
	hyperionDealsMaxPages  = 1000 // safety cap against broken pagination
)

// HyperionLookupConfig configures HTTP lookup against Hyperion GET /po-rep/deals.
type HyperionLookupConfig struct {
	BaseURL    string // e.g. https://hyperion.allocator.tech or http://127.0.0.1:23300
	ProviderID uint64 // required; passed as providerId=f0… and enforced client-side
	HTTPClient *http.Client
}

// HyperionLookup resolves PoRep deals via Hyperion pieceCid query, scoped to one provider.
type HyperionLookup struct {
	baseURL    string
	providerID uint64
	client     *http.Client
}

// NewHyperionLookup prepares an HTTP DealLookup against Hyperion.
func NewHyperionLookup(cfg HyperionLookupConfig) (*HyperionLookup, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		return nil, fmt.Errorf("pieceaccess: Hyperion base URL is required")
	}
	if _, err := url.ParseRequestURI(base); err != nil {
		return nil, fmt.Errorf("pieceaccess: invalid Hyperion base URL %q: %w", base, err)
	}
	if cfg.ProviderID == 0 {
		return nil, fmt.Errorf("pieceaccess: Hyperion ProviderID is required")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &HyperionLookup{
		baseURL:    base,
		providerID: cfg.ProviderID,
		client:     hc,
	}, nil
}

// LookupByPieceCID implements DealLookup. It pages Hyperion deals for the piece
// filtered to ProviderID and stops early once a public deal is found (public is
// more permissive than private, and a later page may still reveal one). Private
// deals are always collected through the full result set so denyAccess can
// evaluate credentials against every candidate.
//
// Residual risk (eyes open): access decisions trust Hyperion's pieceCid filter,
// and deal rows do not echo pieceCid for client-side re-check. That is fragile
// against filter bugs, but fits the Filecoin SP threat model: an SP can bypass
// this whole logical stack and serve bytes straight from disk. Client-side
// encryption is the robust control against an untrustworthy SP; this gate is a
// baseline for cooperative operators, not a hard secrecy boundary.
func (c *HyperionLookup) LookupByPieceCID(ctx context.Context, pieceCID string, requester common.Address) ([]*Deal, error) {
	if c == nil {
		return nil, fmt.Errorf("pieceaccess: HyperionLookup is nil")
	}
	pieceCID = strings.TrimSpace(pieceCID)
	if pieceCID == "" {
		return nil, fmt.Errorf("pieceaccess: empty piece CID")
	}

	out := make([]*Deal, 0)
	for pageNum := 1; pageNum <= hyperionDealsMaxPages; pageNum++ {
		q := url.Values{}
		q.Set("pieceCid", pieceCID)
		q.Set("limit", strconv.Itoa(hyperionDealsPageLimit))
		q.Set("page", strconv.Itoa(pageNum))
		q.Set("providerId", fmt.Sprintf("f0%d", c.providerID))

		rawURL := c.baseURL + "/po-rep/deals?" + q.Encode()
		var page hyperionDealsPage
		if err := c.getJSON(ctx, rawURL, &page); err != nil {
			return nil, err
		}
		if len(page.Data) == 0 {
			break
		}

		for i := range page.Data {
			d, err := page.Data[i].toDeal()
			if err != nil {
				return nil, err
			}
			if d.ProviderID != c.providerID {
				continue
			}
			// Public-wins: a public deal is enough; keep scanning only while every
			// hit so far is private/unknown in case a public deal appears later.
			if d.DealType == DealTypePublic {
				return []*Deal{d}, nil
			}
			out = append(out, d)
		}

		if !page.hasMore(pageNum, hyperionDealsPageLimit) {
			break
		}
		if pageNum == hyperionDealsMaxPages {
			return nil, fmt.Errorf("pieceaccess: Hyperion pagination exceeded %d pages for pieceCid", hyperionDealsMaxPages)
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("%w: Hyperion returned no deals for pieceCid", ErrDealNotFound)
	}
	return out, nil
}

func (c *HyperionLookup) getJSON(ctx context.Context, rawURL string, dest any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("pieceaccess: Hyperion request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	res, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("pieceaccess: Hyperion GET %s: %w", rawURL, err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("pieceaccess: Hyperion read: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 200 {
			msg = msg[:200] + "…"
		}
		return fmt.Errorf("pieceaccess: Hyperion GET %s: HTTP %d: %s", rawURL, res.StatusCode, msg)
	}
	if err := json.Unmarshal(body, dest); err != nil {
		return fmt.Errorf("pieceaccess: Hyperion decode: %w", err)
	}
	return nil
}

type hyperionDealsPage struct {
	Data       []hyperionDeal     `json:"data"`
	Pagination hyperionPagination `json:"pagination"`
}

type hyperionPagination struct {
	Page       int `json:"page"`
	PagesCount int `json:"pagesCount"`
	TotalCount int `json:"totalCount"`
}

// hasMore reports whether another page should be fetched after pageNum.
// Prefer pagination.pagesCount when present; otherwise continue while this
// page was full (len == limit).
func (p hyperionDealsPage) hasMore(pageNum, limit int) bool {
	if p.Pagination.PagesCount > 0 {
		return pageNum < p.Pagination.PagesCount
	}
	return len(p.Data) >= limit
}

type hyperionDeal struct {
	DealID        json.RawMessage `json:"dealId"`
	ProviderID    string          `json:"providerId"`
	ClientAddress string          `json:"clientAddress"`
	DealState     string          `json:"dealState"`
	DealType      string          `json:"dealType"`
	Active        bool            `json:"active"`
}

func (d *hyperionDeal) toDeal() (*Deal, error) {
	if d == nil {
		return nil, fmt.Errorf("pieceaccess: nil Hyperion deal")
	}
	providerID, err := parseF0ActorID(d.ProviderID)
	if err != nil {
		return nil, fmt.Errorf("pieceaccess: Hyperion providerId %q: %w", d.ProviderID, err)
	}
	return &Deal{
		DealID:     decodeJSONStringish(d.DealID),
		Client:     common.HexToAddress(d.ClientAddress),
		ProviderID: providerID,
		DealType:   ParseDealType(d.DealType),
		State:      strings.TrimSpace(d.DealState),
	}, nil
}

func decodeJSONStringish(raw json.RawMessage) string {
	raw = json.RawMessage(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		return n.String()
	}
	return strings.Trim(string(raw), `"`)
}

func parseF0ActorID(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "f0") || strings.HasPrefix(lower, "t0") {
		s = s[2:]
	}
	id, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, err
	}
	return id, nil
}

var _ DealLookup = (*HyperionLookup)(nil)
