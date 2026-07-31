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
	// DefaultCDPBaseURL is the public Compliance Data Platform API.
	DefaultCDPBaseURL = "https://cdp.allocator.tech"
)

// CDPLookupConfig configures HTTP lookup against CDP GET /po-rep/deals.
type CDPLookupConfig struct {
	BaseURL    string // e.g. https://cdp.allocator.tech or http://127.0.0.1:23300
	ProviderID uint64 // optional; when set, passed as providerId=f0… filter
	HTTPClient *http.Client
}

// CDPLookup resolves a PoRep deal via CDP pieceCID query.
type CDPLookup struct {
	baseURL    string
	providerID uint64
	client     *http.Client
}

// NewCDPLookup prepares an HTTP DealLookup against CDP.
func NewCDPLookup(cfg CDPLookupConfig) (*CDPLookup, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		return nil, fmt.Errorf("pieceaccess: CDP base URL is required")
	}
	if _, err := url.ParseRequestURI(base); err != nil {
		return nil, fmt.Errorf("pieceaccess: invalid CDP base URL %q: %w", base, err)
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &CDPLookup{
		baseURL:    base,
		providerID: cfg.ProviderID,
		client:     hc,
	}, nil
}

// LookupByPieceCID implements DealLookup.
func (c *CDPLookup) LookupByPieceCID(ctx context.Context, pieceCID string) (*Deal, error) {
	if c == nil {
		return nil, fmt.Errorf("pieceaccess: CDPLookup is nil")
	}
	pieceCID = strings.TrimSpace(pieceCID)
	if pieceCID == "" {
		return nil, fmt.Errorf("pieceaccess: empty piece CID")
	}

	q := url.Values{}
	q.Set("pieceCID", pieceCID)
	q.Set("limit", "10")
	q.Set("page", "1")
	if c.providerID != 0 {
		q.Set("providerId", fmt.Sprintf("f0%d", c.providerID))
	}

	rawURL := c.baseURL + "/po-rep/deals?" + q.Encode()
	var page cdpDealsPage
	if err := c.getJSON(ctx, rawURL, &page); err != nil {
		return nil, err
	}
	if len(page.Data) == 0 {
		return nil, fmt.Errorf("%w: CDP returned no deals for pieceCID", ErrDealNotFound)
	}

	return pickBestCDPDeal(page.Data).toDeal()
}

// pickBestCDPDeal prefers a PUBLIC deal (any client may retrieve), then an active
// deal, then the first result.
func pickBestCDPDeal(deals []cdpDeal) *cdpDeal {
	var firstPublic, firstActive, first *cdpDeal
	for i := range deals {
		d := &deals[i]
		if first == nil {
			first = d
		}
		if firstPublic == nil && ParseDealType(d.DealType) == DealTypePublic {
			firstPublic = d
		}
		if firstActive == nil && d.Active {
			firstActive = d
		}
	}
	if firstPublic != nil {
		return firstPublic
	}
	if firstActive != nil {
		return firstActive
	}
	return first
}

func (c *CDPLookup) getJSON(ctx context.Context, rawURL string, dest any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("pieceaccess: CDP request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	res, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("pieceaccess: CDP GET %s: %w", rawURL, err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("pieceaccess: CDP read: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 200 {
			msg = msg[:200] + "…"
		}
		return fmt.Errorf("pieceaccess: CDP GET %s: HTTP %d: %s", rawURL, res.StatusCode, msg)
	}
	if err := json.Unmarshal(body, dest); err != nil {
		return fmt.Errorf("pieceaccess: CDP decode: %w", err)
	}
	return nil
}

type cdpDealsPage struct {
	Data []cdpDeal `json:"data"`
}

type cdpDeal struct {
	DealID        json.RawMessage `json:"dealId"`
	ProviderID    string          `json:"providerId"`
	ClientAddress string          `json:"clientAddress"`
	DealState     string          `json:"dealState"`
	DealType      string          `json:"dealType"`
	Active        bool            `json:"active"`
}

func (d *cdpDeal) toDeal() (*Deal, error) {
	if d == nil {
		return nil, fmt.Errorf("pieceaccess: nil CDP deal")
	}
	providerID, err := parseF0ActorID(d.ProviderID)
	if err != nil {
		return nil, fmt.Errorf("pieceaccess: CDP providerId %q: %w", d.ProviderID, err)
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

var _ DealLookup = (*CDPLookup)(nil)
