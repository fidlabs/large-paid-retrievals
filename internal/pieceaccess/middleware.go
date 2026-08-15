// Package pieceaccess gates piece CAR retrieval for private PoRep deals.
//
// Private deals (and their piece CIDs / sizes) are recorded on the public chain
// and indexed by CDP — there is no secrecy about existence or size. HEAD is
// always allowed. GET without a Retrieval credential only succeeds for public
// deals; private pieces return 403 so probes can retry with a proof (+ voucher
// when delegated). Owner ?client= / Payment alone is not enough for private
// deals — the requester signs a RetrievalProof (optionally with a
// RetrievalVoucher). Paid GET still uses Authorization: Payment; when both are
// present, Payment ClientAddress MUST equal the proof signer.
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

// WithClientIdentity sets how the retrieving wallet is identified for logging
// and paid-probe heuristics (same keys as piecepayment). Access decisions for
// private deals use Retrieval credentials, not query/header alone.
func WithClientIdentity(queryKey, headerKey string) Option {
	return func(a *Authorizer) {
		a.clientQuery = strings.TrimSpace(queryKey)
		a.clientHeader = strings.TrimSpace(headerKey)
	}
}

// WithVoucherDomain pins EIP-712 credential domain chainId and verifyingContract
// (PoRep market). Required whenever Retrieval credentials are accepted:
// verification fails closed if the pin is missing. Both arguments must be set
// (chainID > 0, non-zero contract); otherwise this is a no-op (and credentials
// will be rejected).
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
			// Always parse Retrieval credentials when present — the proof provides
			// requester identity. Do not require ?client= / Payment before parse.
			// A present-but-invalid proof is fatal; invalid vouchers are best-effort.
			access, cerr := parseAndVerifyAccess(r, cid, a.voucherPin)
			if cerr != nil {
				a.logger.Info("porep credential verification failed", "piece_cid", cid, "error", cerr)
				writeVoucherError(w, cerr)
				return
			}

			requester := a.requesterAddress(r)
			if requester == (common.Address{}) && access != nil && access.Proof != nil {
				requester = access.Proof.Requester
			}
			deals, err := a.lookup.LookupByPieceCID(ctx, cid, requester)
			var deal *Deal
			if err == nil && len(deals) > 0 {
				deal = selectRepresentativeDeal(deals, access)
				ctx = context.WithValue(ctx, dealContextKey{}, deal)
				a.logDeal(cid, deal)
			} else if errors.Is(err, ErrDealNotFound) {
				a.logger.Info("porep deal not found for piece", "piece_cid", cid)
			} else if err != nil {
				a.logger.Warn("porep deal lookup failed", "piece_cid", cid, "error", err)
			}
			if denied, reason, credentialDenial := a.denyAccess(r, deals, err, access); denied {
				a.logger.Info("porep piece access denied",
					"piece_cid", cid,
					"deal_id", dealID(deal),
					"reason", reason,
				)
				// Emit a JSON diagnostic only when the client actually presented a
				// credential set that failed to authorize a private piece.
				if credentialDenial && access != nil {
					if de := access.denialError(); de != nil {
						writeVoucherError(w, de)
						return
					}
				}
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
// then a private deal authorized by the access credentials, then the first deal.
func selectRepresentativeDeal(deals []*Deal, access *VerifiedAccess) *Deal {
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
			if matchingPrivate == nil && privateDealAllowed(d, access, common.Address{}) {
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
// Access is allowed if any matching deal is public, or any private deal is
// authorized by a verified Retrieval credential (owner-direct proof or
// proof+voucher). Owner ?client= / Payment alone is not sufficient.
// When credentials and a decodable Payment ClientAddress are both present,
// Payment must equal the proof requester.
//
// The third return value is true when the denial is a private-deal credential
// failure, so the caller can emit a JSON diagnostic (vs a plain 403).
func (a *Authorizer) denyAccess(r *http.Request, deals []*Deal, lookupErr error, access *VerifiedAccess) (bool, string, bool) {
	if r.Method == http.MethodHead {
		return false, "", false
	}

	paid := a.isPaidRetrieval(r)
	paymentClient := paymentClientAddress(r)

	if lookupErr != nil && !errors.Is(lookupErr, ErrDealNotFound) {
		return true, "deal lookup failed", false
	}

	if paid {
		if len(deals) == 0 || errors.Is(lookupErr, ErrDealNotFound) {
			return true, "no porep deal for piece", false
		}
	}

	if len(deals) == 0 {
		// Unknown deal: allow quote/probe through (no private metadata to enforce).
		return false, "", false
	}

	var sawPrivate, sawUnknown bool
	for _, d := range deals {
		if d == nil {
			continue
		}
		switch d.DealType {
		case DealTypePublic:
			return false, "", false
		case DealTypePrivate:
			sawPrivate = true
			if privateDealAllowed(d, access, paymentClient) {
				return false, "", false
			}
		default:
			sawUnknown = true
		}
	}

	if sawPrivate {
		if access == nil || access.Proof == nil {
			return true, "private deal requires retrieval proof", true
		}
		if paymentClient != (common.Address{}) && !sameAddress(paymentClient, access.Proof.Requester) {
			return true, "payment client does not match proof requester", true
		}
		return true, "no authorizing voucher for private deal", true
	}
	if sawUnknown && paid {
		return true, "unknown deal type", false
	}
	return false, "", false
}

// privateDealAllowed reports whether the access credentials authorize the
// private deal. When paymentClient is non-zero (decodable Payment header), it
// must equal the proof requester.
func privateDealAllowed(d *Deal, access *VerifiedAccess, paymentClient common.Address) bool {
	if d == nil || d.DealType != DealTypePrivate {
		return false
	}
	if !accessAuthorizesDeal(access, d) {
		return false
	}
	if paymentClient != (common.Address{}) && (access.Proof == nil || !sameAddress(paymentClient, access.Proof.Requester)) {
		return false
	}
	return true
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

// requesterAddress resolves a wallet identity for CDP lookup hints and paid
// heuristics. Prefer Payment over ?client= / header. Private-deal access
// decisions use verified credentials, not this address alone.
func (a *Authorizer) requesterAddress(r *http.Request) common.Address {
	if addr := paymentClientAddress(r); addr != (common.Address{}) {
		return addr
	}
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
// Authorization: Payment header, or the zero address if none.
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
