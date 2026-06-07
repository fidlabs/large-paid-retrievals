package piecepayment

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/fidlabs/paid-retrievals/internal/mpp"
	"github.com/fidlabs/paid-retrievals/internal/paymentheader"
	"github.com/google/uuid"
)

const (
	// We have a "human scale" of 10 minutes for the challenge TTL to allow wallet funding and retry.
	challengeTTL  = 10 * time.Minute
	paidAccessTTL = 12 * time.Hour
)

var ErrDealNotFound = errors.New("deal not found")
var ErrReplayNonce = errors.New("nonce already used")
var ErrPieceSizeUnknown = errors.New("piece size unknown for pricing")

type Deal struct {
	DealUUID       string
	Client         string
	CID            string
	PriceUSDFC     string
	Payee0x        string
	LastPaidTxHash string
}

type DealStore interface {
	InsertQuote(ctx context.Context, dealUUID, client, cid, priceUSDFC, payee0x string) error
	GetDeal(ctx context.Context, dealUUID string) (*Deal, error)
	IsDealPaidSince(ctx context.Context, dealUUID, client, cid string, sinceUnix int64) (bool, error)
	ConsumeNonce(ctx context.Context, dealUUID, nonce string, expiresUnix int64) error
	MarkPaid(ctx context.Context, dealUUID, txHash string) error
}

type FilecoinPaySettler interface {
	SettleIfFunded(ctx context.Context, payer, payee common.Address, priceBaseUnits *big.Int) (txHash string, err error)
}

type QuoteOutcome struct {
	Challenge mpp.Challenge
}

type PaidOutcome struct {
	Deal   *Deal
	CID    string
	TxHash string
}

type PaymentRequiredError struct {
	Deal   *Deal
	Code   string
	Detail string
}

func (e *PaymentRequiredError) Error() string {
	return fmt.Sprintf("payment required (%s): %s", e.Code, e.Detail)
}

type BadRequestError struct {
	Message string
}

func (e *BadRequestError) Error() string {
	return e.Message
}

type Config struct {
	PriceUSDFCPerGB string
	ClientQuery     string
	ClientHeader    string
	MaxClockSkew    time.Duration
	QuotePayee0x    string
	PayDebug        bool
	FilecoinPay     FilecoinPaySettler
	Logger          *slog.Logger
	Store           DealStore
}

type settlementLockEntry struct {
	mu   sync.Mutex
	refs int
}

type RetrievalService struct {
	cfg    Config
	logger *slog.Logger

	settleMu    sync.Mutex
	settleLocks map[string]*settlementLockEntry
}

func NewRetrievalService(cfg Config) *RetrievalService {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Store == nil {
		panic("middleware: ServiceConfig.Store is required")
	}
	return &RetrievalService{
		cfg:         cfg,
		logger:      logger,
		settleLocks: make(map[string]*settlementLockEntry),
	}
}

func (s *RetrievalService) IssueQuote(r *http.Request, cid string, pieceBytes int64) (*QuoteOutcome, error) {
	client := identifyClient(r, s.cfg.ClientQuery, s.cfg.ClientHeader)
	if !common.IsHexAddress(strings.TrimSpace(client)) {
		s.logger.Warn("bad request: client must be 0x FVM address", "client", client)
		return nil, &BadRequestError{Message: "bad request: client must be a 0x FVM address"}
	}
	if pieceBytes < 0 {
		return nil, ErrPieceSizeUnknown
	}
	priceUSDFC, err := paymentheader.PriceUSDFCForBytes(s.cfg.PriceUSDFCPerGB, pieceBytes)
	if err != nil {
		return nil, fmt.Errorf("compute piece price: %w", err)
	}
	dealID := uuid.NewString()
	payee := strings.TrimSpace(s.cfg.QuotePayee0x)
	if err := s.cfg.Store.InsertQuote(r.Context(), dealID, client, cid, priceUSDFC, payee); err != nil {
		s.logger.Error("failed to insert quote", "error", err, "deal_uuid", dealID, "client", client, "cid", cid, "piece_bytes", pieceBytes, "price_usdfc", priceUSDFC)
		return nil, fmt.Errorf("insert quote: %w", err)
	}
	s.logger.Info("issued piece quote", "deal_uuid", dealID, "cid", cid, "piece_bytes", pieceBytes, "price_usdfc", priceUSDFC)
	return &QuoteOutcome{Challenge: buildChallenge(r.Host, dealID, cid, priceUSDFC, payee)}, nil
}

func (s *RetrievalService) AuthorizeAndSettle(r *http.Request, cid, rawHdr string) (*PaidOutcome, error) {
	cred, err := mpp.DecodeAuthorization(rawHdr)
	if err != nil {
		s.logCredentialValidationFailure("decode_authorization",
			"error", err.Error(),
			"auth_len", len(strings.TrimSpace(rawHdr)),
		)
		return nil, &PaymentRequiredError{Code: "malformed-credential", Detail: "Invalid Payment authorization credential format"}
	}
	hdr := cred.Payload
	if cred.Challenge.ID != hdr.ChallengeID || hdr.ChallengeID != hdr.DealUUID {
		s.logCredentialValidationFailure("challenge_id_mismatch",
			"challenge_id", cred.Challenge.ID,
			"payload_challenge_id", hdr.ChallengeID,
			"payload_deal_uuid", hdr.DealUUID,
		)
		return nil, &PaymentRequiredError{Code: "invalid-challenge", Detail: "Challenge id does not match deal id"}
	}
	now := time.Now()
	if err := hdr.Validate(); err != nil {
		s.logCredentialValidationFailure("payload_validate",
			"error", err.Error(),
			"deal_uuid", hdr.DealUUID,
			"cid", hdr.CID,
		)
		return nil, &PaymentRequiredError{Code: "verification-failed", Detail: "Credential payload failed validation"}
	}
	if err := hdr.ValidateExpiresWithinFutureBound(now, challengeTTL, s.cfg.MaxClockSkew); err != nil {
		s.logCredentialValidationFailure("payload_expiry_too_far",
			"error", err.Error(),
			"deal_uuid", hdr.DealUUID,
			"cid", hdr.CID,
			"expires_unix", hdr.ExpiresUnix,
			"now_unix", now.Unix(),
			"max_clock_skew_sec", int64(s.cfg.MaxClockSkew.Seconds()),
		)
		return nil, &PaymentRequiredError{Code: "payment-expired", Detail: "Credential expiry is too far in the future"}
	}
	if r.Method != http.MethodGet || strings.ToUpper(hdr.Method) != http.MethodGet || hdr.Path != r.URL.Path || !hostMatches(hdr.Host, r.Host) {
		s.logCredentialValidationFailure("request_fields_mismatch",
			"deal_uuid", hdr.DealUUID,
			"cid", hdr.CID,
			"cred_method", hdr.Method,
			"req_method", r.Method,
			"cred_path", hdr.Path,
			"req_path", r.URL.Path,
			"cred_host", hdr.Host,
			"req_host", r.Host,
		)
		return nil, &PaymentRequiredError{Code: "verification-failed", Detail: "Credential request fields do not match"}
	}
	deal, err := s.cfg.Store.GetDeal(r.Context(), hdr.DealUUID)
	if err != nil {
		s.logCredentialValidationFailure("unknown_deal",
			"deal_uuid", hdr.DealUUID,
			"cid", hdr.CID,
			"error", err.Error(),
		)
		return nil, &PaymentRequiredError{Code: "invalid-challenge", Detail: "Challenge is unknown or expired"}
	}
	expectedReqB64, err := mpp.CanonicalRequestB64(mpp.PaymentRequest{
		DealUUID:   deal.DealUUID,
		CID:        deal.CID,
		PriceUSDFC: deal.PriceUSDFC,
		Payee0x:    deal.Payee0x,
		Method:     http.MethodGet,
		Path:       "/piece/" + deal.CID,
		Host:       r.Host,
	})
	if err != nil {
		return nil, fmt.Errorf("canonical request: %w", err)
	}
	if !strings.EqualFold(cred.Challenge.Method, mpp.MethodID) ||
		!strings.EqualFold(cred.Challenge.Intent, mpp.IntentID) ||
		cred.Challenge.Request != expectedReqB64 {
		s.logCredentialValidationFailure("challenge_params_mismatch",
			"deal_uuid", deal.DealUUID,
			"cid", cid,
			"cred_method", cred.Challenge.Method,
			"cred_intent", cred.Challenge.Intent,
			"expected_method", mpp.MethodID,
			"expected_intent", mpp.IntentID,
			"cred_request", cred.Challenge.Request,
			"expected_request", expectedReqB64,
		)
		return nil, &PaymentRequiredError{Deal: deal, Code: "invalid-challenge", Detail: "Credential challenge parameters do not match issued challenge"}
	}
	if !sameHexAddress(hdr.ClientAddress, deal.Client) || deal.CID != cid || (hdr.CID != "" && hdr.CID != cid) {
		s.logCredentialValidationFailure("deal_binding_mismatch",
			"deal_uuid", deal.DealUUID,
			"cred_client", hdr.ClientAddress,
			"deal_client", deal.Client,
			"req_cid", cid,
			"deal_cid", deal.CID,
			"cred_cid", hdr.CID,
		)
		return nil, &PaymentRequiredError{Deal: deal, Code: "verification-failed", Detail: "Credential does not match quoted deal"}
	}
	if !strings.EqualFold(strings.TrimSpace(hdr.SigType), mpp.SigTypeEVM) {
		s.logCredentialValidationFailure("unsupported_sig_type",
			"deal_uuid", deal.DealUUID,
			"cid", cid,
			"sig_type", hdr.SigType,
		)
		return nil, &PaymentRequiredError{Deal: deal, Code: "method-unsupported", Detail: "Only evm signature type is supported"}
	}
	verifier := mpp.EVMVerifier{}
	if err := verifier.Verify(hdr.ClientAddress, hdr.CanonicalMessage(), hdr.Signature); err != nil {
		s.logCredentialValidationFailure("signature_verification",
			"deal_uuid", deal.DealUUID,
			"cid", cid,
			"client", hdr.ClientAddress,
			"error", err.Error(),
		)
		return nil, &PaymentRequiredError{Deal: deal, Code: "verification-failed", Detail: "Credential signature verification failed"}
	}
	// If this deal was already settled recently, skip nonce consumption and on-chain
	// settlement and serve the piece immediately — supports resumable downloads and
	// parallel/range retries without charging the client again.
	since := now.Add(-paidAccessTTL).Unix()
	if paid, err := s.cfg.Store.IsDealPaidSince(r.Context(), deal.DealUUID, deal.Client, deal.CID, since); err == nil && paid {
		s.logger.Info("paid retrieval reused", "deal_uuid", deal.DealUUID, "client", deal.Client, "cid", cid)
		return &PaidOutcome{Deal: deal, CID: cid, TxHash: deal.LastPaidTxHash}, nil
	} else if err != nil {
		return nil, fmt.Errorf("check paid window: %w", err)
	}
	// Past-expiry is checked only on the first-settlement path. After a successful payment,
	// clients may retry large downloads with the same (possibly expired) credential while
	// paidAccessTTL covers the deal; settlement already happened and must not be re-required.
	if err := hdr.ValidateExpiresNotPast(now); err != nil {
		s.logCredentialValidationFailure("payload_expired",
			"error", err.Error(),
			"deal_uuid", hdr.DealUUID,
			"cid", hdr.CID,
			"expires_unix", hdr.ExpiresUnix,
			"now_unix", now.Unix(),
		)
		return nil, &PaymentRequiredError{Code: "verification-failed", Detail: "Credential payload failed validation"}
	}
	priceBaseUnits, err := paymentheader.ParseTokenToBaseUnits(deal.PriceUSDFC)
	if err != nil {
		return nil, fmt.Errorf("parse price usdfc: %w", err)
	}
	if err := s.cfg.Store.ConsumeNonce(r.Context(), deal.DealUUID, hdr.Nonce, hdr.ExpiresUnix); err != nil {
		if err == ErrReplayNonce {
			s.logCredentialValidationFailure("nonce_replay",
				"deal_uuid", deal.DealUUID,
				"cid", cid,
				"nonce", hdr.Nonce,
				"expires_unix", hdr.ExpiresUnix,
			)
			return nil, &PaymentRequiredError{Deal: deal, Code: "invalid-challenge", Detail: "Credential nonce has already been used"}
		}
		return nil, fmt.Errorf("consume nonce: %w", err)
	}
	payer := common.HexToAddress(strings.TrimSpace(deal.Client))
	payeeAddr := common.HexToAddress(strings.TrimSpace(deal.Payee0x))
	unlock := s.lockSettlementPair(payer, payeeAddr)
	defer unlock()
	txHash, err := s.cfg.FilecoinPay.SettleIfFunded(r.Context(), payer, payeeAddr, priceBaseUnits)
	if err != nil {
		return nil, settlementPaymentRequiredError(deal, err)
	}
	s.logger.Info("filecoin pay rail settled", "deal_uuid", deal.DealUUID, "settle_tx", txHash, "payer", payer.Hex(), "payee", payeeAddr.Hex())

	if err := s.cfg.Store.MarkPaid(r.Context(), deal.DealUUID, txHash); err != nil {
		// We don't return an error here because we want to continue serving the piece even if marking paid fails as payment has been settled.
		s.logger.Error("failed to mark deal paid", "error", err, "deal_uuid", deal.DealUUID)
	}
	s.logger.Info("paid retrieval authorized", "deal_uuid", deal.DealUUID, "client", deal.Client, "cid", cid)
	return &PaidOutcome{Deal: deal, CID: cid, TxHash: txHash}, nil
}

func issueChallengeForDeal(w http.ResponseWriter, r *http.Request, deal *Deal, logger *slog.Logger) {
	if deal == nil {
		return
	}
	challenge := buildChallenge(r.Host, deal.DealUUID, deal.CID, deal.PriceUSDFC, deal.Payee0x)
	if err := mpp.SetPaymentRequired(w, challenge); err != nil {
		logger.Error("failed to write payment challenge", "deal_uuid", challenge.ID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func buildChallenge(host, dealID, cid, priceUSDFC, payee string) mpp.Challenge {
	return mpp.Challenge{
		ID:          dealID,
		Realm:       mpp.RealmPrefix + host,
		Method:      mpp.MethodID,
		Intent:      mpp.IntentID,
		Description: "Filecoin piece retrieval charge",
		Opaque: map[string]string{
			"deal_uuid": dealID,
			"cid":       cid,
		},
		Request: mpp.PaymentRequest{
			DealUUID:   dealID,
			CID:        cid,
			PriceUSDFC: priceUSDFC,
			Payee0x:    payee,
			Method:     http.MethodGet,
			Path:       "/piece/" + cid,
			Host:       host,
		},
		Expires: time.Now().Add(challengeTTL).UTC().Format(time.RFC3339),
	}
}

func identifyClient(r *http.Request, clientQuery, clientHeader string) string {
	if v := strings.TrimSpace(r.URL.Query().Get(clientQuery)); v != "" {
		return sanitizeClient(v)
	}
	if v := strings.TrimSpace(r.Header.Get(clientHeader)); v != "" {
		return sanitizeClient(v)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return sanitizeClient(r.RemoteAddr)
	}
	return sanitizeClient(host)
}

func sanitizeClient(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "unknown"
	}
	if len(v) > 256 {
		v = v[:256]
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-', r == '_', r == '.', r == ':', r == '@':
			return r
		default:
			return -1
		}
	}, v)
}

func (s *RetrievalService) logCredentialValidationFailure(reason string, attrs ...any) {
	if s == nil || s.logger == nil {
		return
	}
	args := make([]any, 0, len(attrs)+2)
	args = append(args, "reason", reason)
	args = append(args, attrs...)
	s.logger.Debug("credential validation failed", args...)
}

func hostMatches(hdrHost, reqHost string) bool {
	return strings.EqualFold(strings.TrimSpace(hdrHost), strings.TrimSpace(reqHost))
}

func sameHexAddress(a, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if !common.IsHexAddress(a) || !common.IsHexAddress(b) {
		return false
	}
	return common.HexToAddress(a) == common.HexToAddress(b)
}

func (s *RetrievalService) lockSettlementPair(payer, payee common.Address) func() {
	key := payer.Hex() + "|" + payee.Hex()
	s.settleMu.Lock()
	entry, ok := s.settleLocks[key]
	if !ok {
		entry = &settlementLockEntry{}
		s.settleLocks[key] = entry
	}
	entry.refs++
	s.settleMu.Unlock()

	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		s.settleMu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(s.settleLocks, key)
		}
		s.settleMu.Unlock()
	}
}

func settlementPaymentRequiredError(deal *Deal, err error) *PaymentRequiredError {
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "insufficient") || strings.Contains(msg, "no active token rail") || strings.Contains(msg, "no funds") {
		return &PaymentRequiredError{
			Deal:   deal,
			Code:   "payment-insufficient",
			Detail: "Filecoin Pay rail or available balance is insufficient for settlement",
		}
	}
	return &PaymentRequiredError{
		Deal:   deal,
		Code:   "payment-unavailable",
		Detail: "Payment settlement is temporarily unavailable; please retry",
	}
}
