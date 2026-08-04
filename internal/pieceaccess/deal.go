package pieceaccess

import (
	"context"
	"errors"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// ErrDealNotFound is returned when no PoRep market deal maps to the piece CID.
var ErrDealNotFound = errors.New("pieceaccess: porep deal not found for piece CID")

// DealLookup resolves PoRep deals from a piece CID for access checks.
// requester may be the zero address (anonymous); implementations may stop early
// once a public deal or a private deal owned by requester is found.
type DealLookup interface {
	LookupByPieceCID(ctx context.Context, pieceCID string, requester common.Address) ([]*Deal, error)
}

// DealType mirrors PoRepMarket dealType (public=10, private=20).
// Private means only the deal client (or a wallet with a valid owner-signed
// voucher) may download the CAR; metadata remains public.
type DealType uint8

const (
	DealTypeUnknown DealType = 0
	DealTypePublic  DealType = 10
	DealTypePrivate DealType = 20
)

func (t DealType) String() string {
	switch t {
	case DealTypePublic:
		return "public"
	case DealTypePrivate:
		return "private"
	default:
		return "unknown"
	}
}

// MarshalJSON encodes DealType as a lowercase label.
func (t DealType) MarshalJSON() ([]byte, error) {
	return []byte(`"` + t.String() + `"`), nil
}

// ParseDealType accepts CDP/on-chain labels ("PUBLIC"/"PRIVATE") or decimal codes.
func ParseDealType(s string) DealType {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "public", "10":
		return DealTypePublic
	case "private", "20":
		return DealTypePrivate
	default:
		return DealTypeUnknown
	}
}

// Deal is the piece-access view of a PoRep deal (from CDP).
type Deal struct {
	DealID     string         `json:"deal_id"`
	Client     common.Address `json:"client"`
	ProviderID uint64         `json:"provider_id"`
	DealType   DealType       `json:"deal_type"`
	State      string         `json:"state,omitempty"`
}
