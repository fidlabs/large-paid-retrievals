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
	PriceUSDFC   string
	ClientQuery  string
	ClientHeader string
	MaxClockSkew time.Duration
	QuotePayee0x string
	PayDebug     bool
	FilecoinPay  FilecoinPaySettler
	Logger       *slog.Logger
	Store        DealStore
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

func (s *RetrievalService) IssueQuote(r *http.Request, cid string) (*QuoteOutcome, error) {
	client := identifyClient(r, s.cfg.ClientQuery, s.cfg.ClientHeader)
	if !common.IsHexAddress(strings.TrimSpace(client)) {
		s.logger.Warn("bad request: client must be 0x FVM address", "client", client)
		return nil, &BadRequestError{Message: "bad request: client must be a 0x FVM address"}
	}
	dealID := uuid.NewString()
	payee := strings.TrimSpace(s.cfg.QuotePayee0x)
	if err := s.cfg.Store.InsertQuote(r.Context(), dealID, client, cid, s.cfg.PriceUSDFC, payee); err != nil {
		s.logger.Error("failed to insert quote", "error", err, "deal_uuid", dealID, "client", client, "cid", cid)
		return nil, fmt.Errorf("insert quote: %w", err)
	}
	return &QuoteOutcome{Challenge: buildChallenge(r.Host, dealID, cid, s.cfg.PriceUSDFC, payee)}, nil
}

func (s *RetrievalService) AuthorizeAndSettle(r *http.Request, cid, rawHdr string) (*PaidOutcome, error) {
	cred, err := mpp.DecodeAuthorization(rawHdr)
	if err != nil {
		return nil, &PaymentRequiredError{Code: "malformed-credential", Detail: "Invalid Payment authorization credential format"}
	}
	hdr := cred.Payload
	if cred.Challenge.ID != hdr.ChallengeID || hdr.ChallengeID != hdr.DealUUID {
		return nil, &PaymentRequiredError{Code: "invalid-challenge", Detail: "Challenge id does not match deal id"}
	}
	now := time.Now()
	if err := hdr.ValidateAt(now); err != nil {
		return nil, &PaymentRequiredError{Code: "verification-failed", Detail: "Credential payload failed validation"}
	}
	if hdr.ExpiresUnix > now.Add(10*time.Minute).Unix()+int64(s.cfg.MaxClockSkew.Seconds()) {
		return nil, &PaymentRequiredError{Code: "payment-expired", Detail: "Credential expiry is too far in the future"}
	}
	if strings.ToUpper(hdr.Method) != http.MethodGet || hdr.Path != r.URL.Path || !hostMatches(hdr.Host, r.Host) {
		return nil, &PaymentRequiredError{Code: "verification-failed", Detail: "Credential request fields do not match"}
	}
	deal, err := s.cfg.Store.GetDeal(r.Context(), hdr.DealUUID)
	if err != nil {
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
		return nil, &PaymentRequiredError{Deal: deal, Code: "invalid-challenge", Detail: "Credential challenge parameters do not match issued challenge"}
	}
	if !sameHexAddress(hdr.ClientAddress, deal.Client) || deal.CID != cid || (hdr.CID != "" && hdr.CID != cid) {
		return nil, &PaymentRequiredError{Deal: deal, Code: "verification-failed", Detail: "Credential does not match quoted deal"}
	}
	if !strings.EqualFold(strings.TrimSpace(hdr.SigType), mpp.SigTypeEVM) {
		return nil, &PaymentRequiredError{Deal: deal, Code: "method-unsupported", Detail: "Only evm signature type is supported"}
	}
	verifier := mpp.EVMVerifier{}
	if err := verifier.Verify(hdr.ClientAddress, hdr.CanonicalMessage(), hdr.Signature); err != nil {
		return nil, &PaymentRequiredError{Deal: deal, Code: "verification-failed", Detail: "Credential signature verification failed"}
	}
	since := time.Now().Add(-paidAccessTTL).Unix()
	if paid, err := s.cfg.Store.IsDealPaidSince(r.Context(), deal.DealUUID, deal.Client, deal.CID, since); err == nil && paid {
		s.logger.Info("paid retrieval reused", "deal_uuid", deal.DealUUID, "client", deal.Client, "cid", cid)
		return &PaidOutcome{Deal: deal, CID: cid, TxHash: deal.LastPaidTxHash}, nil
	} else if err != nil {
		return nil, fmt.Errorf("check paid window: %w", err)
	}
	priceBaseUnits, err := paymentheader.ParseTokenToBaseUnits(deal.PriceUSDFC)
	if err != nil {
		return nil, fmt.Errorf("parse price usdfc: %w", err)
	}
	if err := s.cfg.Store.ConsumeNonce(r.Context(), deal.DealUUID, hdr.Nonce, hdr.ExpiresUnix); err != nil {
		if err == ErrReplayNonce {
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
	if err := mpp.WritePaymentRequired(w, challenge); err != nil {
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
