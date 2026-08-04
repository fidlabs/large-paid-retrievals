// Package pieceaccess gates piece CAR retrieval for private PoRep deals.
//
// Private deals (and their piece CIDs / sizes) are recorded on the public chain
// and indexed by CDP — there is no secrecy about existence or size. HEAD is
// always allowed. GET without a client only succeeds for public deals; private
// pieces return 403 so probes can retry with ?client= and Bearer access vouchers.
// Paid GET (Payment Authorization + client) is default-deny unless the piece is
// on a public deal, a private deal owned by the requester, or a private deal
// authorized by a valid owner-signed voucher (matching dealId; requester must
// be the signed grantee). Bearer vouchers are ignored when no requester identity
// is present. When Authorization: Payment is present, its ClientAddress is the
// requester (preferred over ?client= / client header) so access cannot be
// confused by a spoofed query parameter.
package pieceaccess

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
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

// DealFromContext returns a representative PoRep deal for this request, if any.
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
	voucherPin   *voucherDomainPin
}

// Option configures Authorizer.
type Option func(*Authorizer)

// WithDealLookup sets PoRep deal resolution from piece CID (CDP). Required for Middleware.
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

// WithVoucherDomain pins EIP-712 voucher domain chainId and verifyingContract
// (PoRep market). Required whenever Bearer vouchers are accepted: verification
// fails closed if the pin is missing. Both arguments must be set (chainID > 0,
// non-zero contract); otherwise this is a no-op (and vouchers will be rejected).
func WithVoucherDomain(chainID *big.Int, verifyingContract common.Address) Option {
	return func(a *Authorizer) {
		if chainID == nil || chainID.Sign() <= 0 || verifyingContract == (common.Address{}) {
			return
		}
		a.voucherPin = &voucherDomainPin{
			chainID:  new(big.Int).Set(chainID),
			contract: verifyingContract,
		}
	}
}

// NewAuthorizer returns an authorizer. Middleware requires WithDealLookup (privacy is always enforced).
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
	if a.lookup == nil {
		panic("pieceaccess: DealLookup is required (WithDealLookup)")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), accessContextKey{}, struct{}{})
		if cid, ok := parsePiecePath(r.URL.Path); ok {
			requester := a.requesterAddress(r)
			// Vouchers require a requester. Without identity, Bearers are ignored
			// (not parsed). Requester resolution prefers Payment over ?client= —
			// see requesterAddress.
			var vouchers []VerifiedVoucher
			if requester != (common.Address{}) {
				var verr error
				vouchers, verr = parseAndVerifyVouchers(r, a.voucherPin)
				if verr != nil {
					a.logger.Info("porep voucher verification failed", "piece_cid", cid, "error", verr)
					writeVoucherError(w, verr)
					return
				}
			}

			deals, err := a.lookup.LookupByPieceCID(ctx, cid, requester)
			var deal *Deal
			if err == nil && len(deals) > 0 {
				deal = selectRepresentativeDeal(deals, requester, vouchers)
				ctx = context.WithValue(ctx, dealContextKey{}, deal)
				a.logDeal(cid, deal)
			} else if errors.Is(err, ErrDealNotFound) {
				a.logger.Info("porep deal not found for piece", "piece_cid", cid)
			} else if err != nil {
				a.logger.Warn("porep deal lookup failed", "piece_cid", cid, "error", err)
			}
			if denied, reason := a.denyAccess(r, deals, err, vouchers); denied {
				a.logger.Info("porep piece access denied",
					"piece_cid", cid,
					"deal_id", dealID(deal),
					"reason", reason,
				)
				http.Error(w, "forbidden", http.StatusForbidden)
				return
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

// selectRepresentativeDeal picks one deal for logging/context: public first,
// then a private deal owned by requester or authorized by voucher, then the first deal.
func selectRepresentativeDeal(deals []*Deal, requester common.Address, vouchers []VerifiedVoucher) *Deal {
	var firstPublic, matchingPrivate, first *Deal
	for _, d := range deals {
		if d == nil {
			continue
		}
		if first == nil {
			first = d
		}
		switch d.DealType {
		case DealTypePublic:
			if firstPublic == nil {
				firstPublic = d
			}
		case DealTypePrivate:
			if matchingPrivate == nil && privateDealAllowed(d, requester, vouchers) {
				matchingPrivate = d
			}
		}
	}
	if firstPublic != nil {
		return firstPublic
	}
	if matchingPrivate != nil {
		return matchingPrivate
	}
	return first
}

// denyAccess implements piece access policy for probes and paid retrieval.
//
// HEAD is never denied (size/existence are public).
// Lookup transport/decode errors fail closed on GET (paid or probe) so private
// pieces cannot appear probeable during a CDP outage. ErrDealNotFound still
// allows unpaid probes (no private metadata to enforce).
// Access is allowed if any matching deal is public, any private deal is owned
// by the requester, or any private deal is authorized by a verified voucher
// whose recovered owner matches the deal client, signed dealId matches the CDP
// deal, and the requester is the signed grantee. Bearer vouchers are not used
// when there is no requester. Anonymous GET without identity on private-only
// pieces returns 403. Paid GET (Payment Authorization + client): default-deny
// when no usable deal.
func (a *Authorizer) denyAccess(r *http.Request, deals []*Deal, lookupErr error, vouchers []VerifiedVoucher) (bool, string) {
	if r.Method == http.MethodHead {
		return false, ""
	}

	requester := a.requesterAddress(r)
	paid := a.isPaidRetrieval(r)

	if lookupErr != nil && !errors.Is(lookupErr, ErrDealNotFound) {
		return true, "deal lookup failed"
	}

	if paid {
		if len(deals) == 0 || errors.Is(lookupErr, ErrDealNotFound) {
			return true, "no porep deal for piece"
		}
	}

	if len(deals) == 0 {
		// Unknown deal: allow quote/probe through (no private metadata to enforce).
		return false, ""
	}

	var sawPrivate, sawUnknown bool
	for _, d := range deals {
		if d == nil {
			continue
		}
		switch d.DealType {
		case DealTypePublic:
			return false, ""
		case DealTypePrivate:
			sawPrivate = true
			if privateDealAllowed(d, requester, vouchers) {
				return false, ""
			}
		default:
			sawUnknown = true
		}
	}

	if sawPrivate {
		if requester == (common.Address{}) {
			return true, "private deal requires client identity"
		}
		return true, "client is not the private deal owner and no matching voucher"
	}
	if sawUnknown && paid {
		return true, "unknown deal type"
	}
	return false, ""
}

func privateDealAllowed(d *Deal, requester common.Address, vouchers []VerifiedVoucher) bool {
	if d == nil || d.DealType != DealTypePrivate {
		return false
	}
	if requester == (common.Address{}) {
		return false
	}
	if sameAddress(requester, d.Client) {
		return true
	}
	for _, v := range vouchers {
		if voucherAuthorizesDeal(v, d) && sameAddress(requester, v.Grantee) {
			return true
		}
	}
	return false
}

// isPaidRetrieval is true when the request carries Payment Authorization and a
// resolvable client (Payment payload preferred, else query/header).
func (a *Authorizer) isPaidRetrieval(r *http.Request) bool {
	if !hasPaymentAuthorization(r) {
		return false
	}
	return a.requesterAddress(r) != (common.Address{})
}

func hasPaymentAuthorization(r *http.Request) bool {
	if r == nil {
		return false
	}
	prefix := strings.ToLower(mpp.AuthScheme) + " "
	for _, raw := range r.Header.Values("Authorization") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(raw)), prefix) {
			return true
		}
	}
	return false
}

// requesterAddress resolves the retrieving wallet used for owner and voucher
// grantee checks.
//
// Prefer Payment over ?client= (enforced here):
//  1. Authorization: Payment → ClientAddress from the signed MPP credential
//  2. else ?client= query (a.clientQuery)
//  3. else client header (a.clientHeader)
//
// Why Payment must win: access runs before piecepayment settle. ?client= is
// unauthenticated claim-only (fine for probes). On a paid GET, trusting query
// first would let an attacker pass ?client=<voucher-grantee> with a stolen
// Bearer while Authorization: Payment is a different payer, so access could
// authorize the grantee while settlement charges/serves the payer. Preferring
// Payment binds owner/voucher checks to the authenticated payer identity.
func (a *Authorizer) requesterAddress(r *http.Request) common.Address {
	// Step 1: signed Payment credential (must beat spoofable query/header).
	if addr := paymentClientAddress(r); addr != (common.Address{}) {
		return addr
	}
	// Steps 2–3: probe identity only when no usable Payment client is present.
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
	return common.Address{}
}

// paymentClientAddress returns ClientAddress from the first decodable
// Authorization: Payment header, or the zero address if none. Used only via
// requesterAddress so Payment stays preferred over ?client=.
func paymentClientAddress(r *http.Request) common.Address {
	if r == nil {
		return common.Address{}
	}
	prefix := strings.ToLower(mpp.AuthScheme) + " "
	for _, raw := range r.Header.Values("Authorization") {
		raw = strings.TrimSpace(raw)
		if !strings.HasPrefix(strings.ToLower(raw), prefix) {
			continue
		}
		cred, err := mpp.DecodeAuthorization(raw)
		if err != nil {
			continue
		}
		v := strings.TrimSpace(cred.Payload.ClientAddress)
		if !common.IsHexAddress(v) {
			continue
		}
		return common.HexToAddress(v)
	}
	return common.Address{}
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
