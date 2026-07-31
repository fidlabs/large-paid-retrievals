// Package pieceaccess gates piece CAR retrieval for private PoRep deals.
//
// Private deals (and their piece CIDs / sizes) are recorded on the public chain
// and indexed by CDP — there is no secrecy about existence or size. HEAD is
// always allowed. GET without a client only succeeds for public deals; private
// pieces return 403 so probes can retry with ?client=. Paid GET (client +
// Payment Authorization) is default-deny unless the piece is on a public deal
// or a private deal owned by the requester.
package pieceaccess

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/fidlabs/paid-retrievals/internal/mpp"
)

type accessContextKey struct{}
type dealContextKey struct{}

// AccessChecked reports whether pieceaccess middleware ran for this request.
func AccessChecked(ctx context.Context) bool {
	_, ok := ctx.Value(accessContextKey{}).(struct{})
	return ok
}

// DealFromContext returns the PoRep deal resolved for this request, if any.
func DealFromContext(ctx context.Context) (*Deal, bool) {
	d, ok := ctx.Value(dealContextKey{}).(*Deal)
	return d, ok && d != nil
}

// Authorizer evaluates whether a client may access a piece before payment.
type Authorizer struct {
	lookup       DealLookup
	logger       *slog.Logger
	clientQuery  string
	clientHeader string
}

// Option configures Authorizer.
type Option func(*Authorizer)

// WithDealLookup enables PoRep deal resolution from piece CID (CDP).
func WithDealLookup(lookup DealLookup) Option {
	return func(a *Authorizer) {
		a.lookup = lookup
	}
}

// WithLogger sets the structured logger used for deal resolution messages.
func WithLogger(logger *slog.Logger) Option {
	return func(a *Authorizer) {
		a.logger = logger
	}
}

// WithClientIdentity sets how the retrieving wallet is identified (same keys as piecepayment).
func WithClientIdentity(queryKey, headerKey string) Option {
	return func(a *Authorizer) {
		a.clientQuery = strings.TrimSpace(queryKey)
		a.clientHeader = strings.TrimSpace(headerKey)
	}
}

// NewAuthorizer returns an authorizer. Without a DealLookup it remains a passthrough.
func NewAuthorizer(opts ...Option) *Authorizer {
	a := &Authorizer{
		clientQuery:  "client",
		clientHeader: "X-Client-Address",
	}
	for _, opt := range opts {
		opt(a)
	}
	if a.logger == nil {
		a.logger = slog.Default()
	}
	return a
}

// Middleware wraps next so access is checked before payment and upstream proxying.
func (a *Authorizer) Middleware(next http.Handler) http.Handler {
	if a == nil {
		panic("pieceaccess: Authorizer is required")
	}
	if next == nil {
		panic("pieceaccess: next handler is required")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), accessContextKey{}, struct{}{})
		if a.lookup != nil {
			if cid, ok := parsePiecePath(r.URL.Path); ok {
				deal, err := a.lookup.LookupByPieceCID(ctx, cid)
				if err == nil && deal != nil {
					ctx = context.WithValue(ctx, dealContextKey{}, deal)
					a.logDeal(cid, deal)
				} else if errors.Is(err, ErrDealNotFound) {
					a.logger.Info("porep deal not found for piece", "piece_cid", cid)
				} else if err != nil {
					a.logger.Warn("porep deal lookup failed", "piece_cid", cid, "error", err)
				}
				if denied, reason := a.denyAccess(r, deal, err); denied {
					a.logger.Info("porep piece access denied",
						"piece_cid", cid,
						"deal_id", dealID(deal),
						"reason", reason,
					)
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func dealID(deal *Deal) string {
	if deal == nil {
		return ""
	}
	return deal.DealID
}

// denyAccess implements piece access policy for probes and paid retrieval.
//
// HEAD is never denied (size/existence are public).
// Unauthenticated GET: only public deals may proceed (402/200); private → 403.
// GET with ?client=: public OK; private OK only when client is the deal owner.
// Paid GET (Authorization + client): default-deny; same public/private rules.
func (a *Authorizer) denyAccess(r *http.Request, deal *Deal, lookupErr error) (bool, string) {
	if r.Method == http.MethodHead {
		return false, ""
	}

	requester := a.requesterAddress(r)
	paid := a.isPaidRetrieval(r)

	if paid {
		if lookupErr != nil && !errors.Is(lookupErr, ErrDealNotFound) {
			return true, "deal lookup failed"
		}
		if deal == nil || errors.Is(lookupErr, ErrDealNotFound) {
			return true, "no porep deal for piece"
		}
	}

	if deal == nil {
		// Unknown deal: allow quote/probe through (no private metadata to enforce).
		return false, ""
	}

	switch deal.DealType {
	case DealTypePublic:
		return false, ""
	case DealTypePrivate:
		if requester == (common.Address{}) {
			return true, "private deal requires client identity"
		}
		if !sameAddress(requester, deal.Client) {
			return true, "client is not the private deal owner"
		}
		return false, ""
	default:
		if paid {
			return true, "unknown deal type"
		}
		return false, ""
	}
}

// isPaidRetrieval is true when the request carries Payment Authorization and a
// resolvable client (query, header, or Authorization payload).
func (a *Authorizer) isPaidRetrieval(r *http.Request) bool {
	if strings.TrimSpace(r.Header.Get("Authorization")) == "" {
		return false
	}
	return a.requesterAddress(r) != (common.Address{})
}

func (a *Authorizer) requesterAddress(r *http.Request) common.Address {
	if a.clientQuery != "" {
		if v := strings.TrimSpace(r.URL.Query().Get(a.clientQuery)); v != "" && common.IsHexAddress(v) {
			return common.HexToAddress(v)
		}
	}
	if a.clientHeader != "" {
		if v := strings.TrimSpace(r.Header.Get(a.clientHeader)); v != "" && common.IsHexAddress(v) {
			return common.HexToAddress(v)
		}
	}
	raw := strings.TrimSpace(r.Header.Get("Authorization"))
	if raw == "" {
		return common.Address{}
	}
	cred, err := mpp.DecodeAuthorization(raw)
	if err != nil {
		return common.Address{}
	}
	v := strings.TrimSpace(cred.Payload.ClientAddress)
	if !common.IsHexAddress(v) {
		return common.Address{}
	}
	return common.HexToAddress(v)
}

func sameAddress(a, b common.Address) bool {
	return strings.EqualFold(a.Hex(), b.Hex())
}

func (a *Authorizer) logDeal(pieceCID string, deal *Deal) {
	payload, err := json.Marshal(deal)
	if err != nil {
		a.logger.Debug("porep deal for piece",
			"piece_cid", pieceCID,
			"deal_id", deal.DealID,
			"deal_type", deal.DealType.String(),
			"state", deal.State,
		)
		return
	}
	a.logger.Debug("porep deal for piece", "piece_cid", pieceCID, "deal", string(payload))
}

func parsePiecePath(path string) (string, bool) {
	if !strings.HasPrefix(path, "/piece/") {
		return "", false
	}
	cid := strings.TrimPrefix(path, "/piece/")
	if cid == "" || strings.Contains(cid, "/") {
		return "", false
	}
	return cid, true
}
