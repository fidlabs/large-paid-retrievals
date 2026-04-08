package spproxy

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fidlabs/paid-retrievals/internal/mpp"
	"github.com/fidlabs/paid-retrievals/internal/paymentheader"
	"github.com/ethereum/go-ethereum/common"
)

var cidPattern = regexp.MustCompile(`^[a-zA-Z0-9._:-]{8,256}$`)
const problemBase = "https://paymentauth.org/problems/"

type problemDetail struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type Config struct {
	PriceFIL      string
	ClientQuery   string
	ClientHeader  string
	MaxHeaderSize int
	MaxClockSkew  time.Duration
	Logger        *slog.Logger

	// FilecoinPay (native FIL) is required: quotes include payee_0x; paid downloads require EVM-signed MPP proof + on-chain settleRail.
	FilecoinPay  FilecoinPaySettler
	QuotePayee0x string
	// PayDebug emits extra Info-level logs for Filecoin Pay (HTTP + use with filpay --pay-debug on settler).
	PayDebug bool
}

func NewHandler(cfg Config, store *Store) http.Handler {
	if cfg.PriceFIL == "" {
		cfg.PriceFIL = "0.01"
	}
	if cfg.ClientQuery == "" {
		cfg.ClientQuery = "client"
	}
	if cfg.ClientHeader == "" {
		cfg.ClientHeader = "X-Client-Address"
	}
	if cfg.MaxHeaderSize <= 0 {
		cfg.MaxHeaderSize = 4096
	}
	if cfg.MaxClockSkew <= 0 {
		cfg.MaxClockSkew = 30 * time.Second
	}
	if cfg.FilecoinPay == nil {
		panic("spproxy: Config.FilecoinPay is required")
	}
	payee := strings.TrimSpace(cfg.QuotePayee0x)
	if payee == "" || !common.IsHexAddress(payee) {
		panic("spproxy: Config.QuotePayee0x must be a non-empty 0x FVM address")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("incoming request", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
		if r.Method != http.MethodGet {
			logger.Warn("method not allowed", "method", r.Method, "path", r.URL.Path)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == "/health" {
			logger.Debug("health check")
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("ok"))
			return
		}
		cid, ok := parsePiecePath(r.URL.Path)
		if !ok {
			logger.Warn("invalid piece path", "path", r.URL.Path)
			http.NotFound(w, r)
			return
		}

		rawHdr := strings.TrimSpace(r.Header.Get("Authorization"))
		if rawHdr == "" {
			handleQuote(w, r, store, cfg, cid, logger)
			return
		}
		if len(rawHdr) > cfg.MaxHeaderSize {
			logger.Warn("payment header too large", "path", r.URL.Path, "size", len(rawHdr), "max", cfg.MaxHeaderSize)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		handlePaid(w, r, store, cfg, cid, rawHdr, logger)
	})
}

func parsePiecePath(path string) (string, bool) {
	if !strings.HasPrefix(path, "/piece/") {
		return "", false
	}
	cid := strings.TrimPrefix(path, "/piece/")
	if cid == "" || strings.Contains(cid, "/") || !cidPattern.MatchString(cid) {
		return "", false
	}
	return cid, true
}

func handleQuote(w http.ResponseWriter, r *http.Request, store *Store, cfg Config, cid string, logger *slog.Logger) {
	client := identifyClient(r, cfg)
	if !common.IsHexAddress(strings.TrimSpace(client)) {
		logger.Warn("bad request: client must be 0x FVM address", "client", client)
		http.Error(w, "bad request: client must be a 0x FVM address", http.StatusBadRequest)
		return
	}
	dealID := uuid.NewString()
	payee := strings.TrimSpace(cfg.QuotePayee0x)
	if err := store.InsertQuote(r.Context(), dealID, client, cid, cfg.PriceFIL, payee); err != nil {
		logger.Error("failed to insert quote", "error", err, "deal_uuid", dealID, "client", client, "cid", cid)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	logger.Info("mpp challenge created", "deal_uuid", dealID, "client", client, "cid", cid, "price_fil", cfg.PriceFIL)
	if cfg.PayDebug {
		logger.Info("filecoin pay challenge", "scope", "filpay-http", "deal_uuid", dealID, "client_0x", client,
			"cid", cid, "price_fil", cfg.PriceFIL, "payee_0x", payee, "filecoin_pay", true)
	}
	challenge := mpp.Challenge{
		ID:     dealID,
		Realm:  mpp.RealmPrefix + r.Host,
		Method: mpp.MethodID,
		Intent: mpp.IntentID,
		Description: "Filecoin piece retrieval charge",
		Opaque: map[string]string{
			"deal_uuid": dealID,
			"cid":       cid,
		},
		Request: mpp.PaymentRequest{
			DealUUID: dealID,
			CID:      cid,
			PriceFIL: cfg.PriceFIL,
			Payee0x:  payee,
			Method:   http.MethodGet,
			Path:     "/piece/" + cid,
			Host:     r.Host,
		},
		Expires: time.Now().Add(2 * time.Minute).UTC().Format(time.RFC3339),
	}
	if err := mpp.WritePaymentRequired(w, challenge); err != nil {
		logger.Error("failed to write payment challenge", "deal_uuid", dealID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
}

func issueChallengeForDeal(w http.ResponseWriter, r *http.Request, deal *Deal, logger *slog.Logger) {
	if deal == nil {
		return
	}
	challenge := mpp.Challenge{
		ID:     deal.DealUUID,
		Realm:  mpp.RealmPrefix + r.Host,
		Method: mpp.MethodID,
		Intent: mpp.IntentID,
		Description: "Filecoin piece retrieval charge",
		Opaque: map[string]string{
			"deal_uuid": deal.DealUUID,
			"cid":       deal.CID,
		},
		Request: mpp.PaymentRequest{
			DealUUID: deal.DealUUID,
			CID:      deal.CID,
			PriceFIL: deal.PriceFIL,
			Payee0x:  deal.Payee0x,
			Method:   http.MethodGet,
			Path:     "/piece/" + deal.CID,
			Host:     r.Host,
		},
		Expires: time.Now().Add(2 * time.Minute).UTC().Format(time.RFC3339),
	}
	wa, err := challenge.WWWAuthenticateValue()
	if err != nil {
		logger.Warn("failed to write fresh challenge", "deal_uuid", deal.DealUUID, "error", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("WWW-Authenticate", wa)
}

func writeProblem(w http.ResponseWriter, status int, code, detail string) {
	title := "Payment Error"
	switch code {
	case "payment-required":
		title = "Payment Required"
	case "payment-insufficient":
		title = "Payment Insufficient"
	case "payment-expired":
		title = "Payment Expired"
	case "verification-failed":
		title = "Payment Verification Failed"
	case "method-unsupported":
		title = "Payment Method Unsupported"
	case "malformed-credential":
		title = "Malformed Payment Credential"
	case "invalid-challenge":
		title = "Invalid Payment Challenge"
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problemDetail{
		Type:   problemBase + code,
		Title:  title,
		Status: status,
		Detail: detail,
	})
}

func failPaymentRequired(w http.ResponseWriter, r *http.Request, deal *Deal, logger *slog.Logger, code, detail string) {
	if deal != nil {
		issueChallengeForDeal(w, r, deal, logger)
	} else {
		w.Header().Set("WWW-Authenticate", mpp.AuthScheme+` realm="`+mpp.RealmPrefix+r.Host+`", method="`+mpp.MethodID+`", intent="`+mpp.IntentID+`"`)
	}
	writeProblem(w, http.StatusPaymentRequired, code, detail)
}

func handlePaid(w http.ResponseWriter, r *http.Request, store *Store, cfg Config, cid, rawHdr string, logger *slog.Logger) {
	cred, err := mpp.DecodeAuthorization(rawHdr)
	if err != nil {
		logger.Warn("payment required: decode authorization credential", "error", err, "cid", cid, "path", r.URL.Path)
		failPaymentRequired(w, r, nil, logger, "malformed-credential", "Invalid Payment authorization credential format")
		return
	}
	hdr := cred.Payload
	if cred.Challenge.ID != hdr.ChallengeID {
		logger.Warn("payment required: challenge id mismatch", "challenge_id", cred.Challenge.ID, "payload_challenge_id", hdr.ChallengeID)
		failPaymentRequired(w, r, nil, logger, "invalid-challenge", "Credential challenge id does not match payload challenge id")
		return
	}
	if hdr.ChallengeID != hdr.DealUUID {
		logger.Warn("payment required: challenge/deal mismatch", "challenge_id", hdr.ChallengeID, "deal_uuid", hdr.DealUUID)
		failPaymentRequired(w, r, nil, logger, "invalid-challenge", "Challenge id does not match deal id")
		return
	}
	now := time.Now()
	if err := hdr.ValidateAt(now); err != nil {
		logger.Warn("payment required: invalid payload", "error", err, "deal_uuid", hdr.DealUUID, "cid", cid)
		failPaymentRequired(w, r, nil, logger, "verification-failed", "Credential payload failed validation")
		return
	}
	if hdr.ExpiresUnix > now.Add(10*time.Minute).Unix()+int64(cfg.MaxClockSkew.Seconds()) {
		logger.Warn("payment required: expiry too far in future", "deal_uuid", hdr.DealUUID, "cid", cid, "expires_unix", hdr.ExpiresUnix)
		failPaymentRequired(w, r, nil, logger, "payment-expired", "Credential expiry is too far in the future")
		return
	}
	if strings.ToUpper(hdr.Method) != http.MethodGet {
		logger.Warn("payment required: bad method in payload", "deal_uuid", hdr.DealUUID, "payload_method", hdr.Method, "expected", http.MethodGet)
		failPaymentRequired(w, r, nil, logger, "verification-failed", "Credential method does not match request method")
		return
	}
	if hdr.Path != r.URL.Path {
		logger.Warn("payment required: path mismatch", "deal_uuid", hdr.DealUUID, "payload_path", hdr.Path, "request_path", r.URL.Path)
		failPaymentRequired(w, r, nil, logger, "verification-failed", "Credential path does not match request path")
		return
	}
	if !hostMatches(hdr.Host, r.Host) {
		logger.Warn("payment required: host mismatch", "deal_uuid", hdr.DealUUID, "payload_host", hdr.Host, "request_host", r.Host)
		failPaymentRequired(w, r, nil, logger, "verification-failed", "Credential host does not match request host")
		return
	}
	deal, err := store.GetDeal(r.Context(), hdr.DealUUID)
	if err != nil {
		logger.Warn("payment required: unknown deal", "deal_uuid", hdr.DealUUID, "error", err)
		failPaymentRequired(w, r, nil, logger, "invalid-challenge", "Challenge is unknown or expired")
		return
	}
	expectedReqB64, err := mpp.CanonicalRequestB64(mpp.PaymentRequest{
		DealUUID: deal.DealUUID,
		CID:      deal.CID,
		PriceFIL: deal.PriceFIL,
		Payee0x:  deal.Payee0x,
		Method:   http.MethodGet,
		Path:     "/piece/" + deal.CID,
		Host:     r.Host,
	})
	if err != nil {
		logger.Error("internal: request encoding failed", "deal_uuid", deal.DealUUID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !strings.EqualFold(cred.Challenge.Method, mpp.MethodID) ||
		!strings.EqualFold(cred.Challenge.Intent, mpp.IntentID) ||
		cred.Challenge.Request != expectedReqB64 {
		logger.Warn("payment required: challenge echo mismatch", "deal_uuid", deal.DealUUID)
		failPaymentRequired(w, r, deal, logger, "invalid-challenge", "Credential challenge parameters do not match issued challenge")
		return
	}
	if !sameHexAddress(hdr.ClientAddress, deal.Client) {
		logger.Warn("payment required: client mismatch", "deal_uuid", hdr.DealUUID, "payload_client", hdr.ClientAddress, "deal_client", deal.Client)
		failPaymentRequired(w, r, deal, logger, "verification-failed", "Credential client address does not match quoted client")
		return
	}
	if deal.CID != cid {
		logger.Warn("payment required: cid mismatch", "deal_uuid", hdr.DealUUID, "request_cid", cid, "deal_cid", deal.CID)
		failPaymentRequired(w, r, deal, logger, "verification-failed", "Deal CID does not match requested CID")
		return
	}
	if hdr.CID != "" && hdr.CID != cid {
		logger.Warn("payment required: explicit payload cid mismatch", "deal_uuid", hdr.DealUUID, "payload_cid", hdr.CID, "request_cid", cid)
		failPaymentRequired(w, r, deal, logger, "verification-failed", "Credential CID does not match requested CID")
		return
	}
	if !strings.EqualFold(strings.TrimSpace(hdr.SigType), mpp.SigTypeEVM) {
		logger.Warn("payment required: mpp signatures must be evm", "deal_uuid", hdr.DealUUID, "sig_type", hdr.SigType)
		failPaymentRequired(w, r, deal, logger, "method-unsupported", "Only evm signature type is supported")
		return
	}
	verifier := mpp.EVMVerifier{}
	if err := verifier.Verify(hdr.ClientAddress, hdr.CanonicalMessage(), hdr.Signature); err != nil {
		logger.Warn("payment required: signature verify failed", "deal_uuid", hdr.DealUUID, "client", hdr.ClientAddress, "error", err)
		failPaymentRequired(w, r, deal, logger, "verification-failed", "Credential signature verification failed")
		return
	}
	if cfg.PayDebug {
		logger.Info("filecoin pay mpp signature ok", "scope", "filpay-http", "deal_uuid", hdr.DealUUID,
			"sig_type", hdr.SigType, "client_0x", hdr.ClientAddress, "cid", cid)
	}
	if strings.TrimSpace(deal.Payee0x) == "" || !common.IsHexAddress(strings.TrimSpace(deal.Payee0x)) {
		logger.Error("internal: deal missing payee_0x", "deal_uuid", deal.DealUUID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	priceWei, err := paymentheader.ParseFILToWei(deal.PriceFIL)
	if err != nil {
		logger.Error("internal: bad price_fil on deal", "deal_uuid", deal.DealUUID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	payer := common.HexToAddress(strings.TrimSpace(deal.Client))
	payeeAddr := common.HexToAddress(strings.TrimSpace(deal.Payee0x))
	if cfg.PayDebug {
		logger.Info("filecoin pay calling SettleIfFunded", "scope", "filpay-http", "deal_uuid", hdr.DealUUID,
			"payer", payer.Hex(), "payee", payeeAddr.Hex(), "price_wei", priceWei.String(), "price_fil", deal.PriceFIL)
	}
	txHash, err := cfg.FilecoinPay.SettleIfFunded(r.Context(), payer, payeeAddr, priceWei)
	if err != nil {
		logger.Warn("payment required: filecoin pay settle failed", "deal_uuid", hdr.DealUUID, "error", err)
		failPaymentRequired(w, r, deal, logger, "payment-insufficient", "Filecoin Pay rail or available balance is insufficient for settlement")
		return
	}
	logger.Info("filecoin pay rail settled", "deal_uuid", deal.DealUUID, "settle_tx", txHash, "payer", payer.Hex(), "payee", payeeAddr.Hex())
	if err := store.ConsumeNonce(r.Context(), deal.DealUUID, hdr.Nonce, hdr.ExpiresUnix); err != nil {
		if err == ErrReplayNonce {
			logger.Warn("payment required: replay nonce", "deal_uuid", deal.DealUUID, "nonce", hdr.Nonce)
			failPaymentRequired(w, r, deal, logger, "invalid-challenge", "Credential nonce has already been used")
			return
		}
		logger.Error("failed to consume nonce", "deal_uuid", deal.DealUUID, "nonce", hdr.Nonce, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := store.MarkPaid(r.Context(), deal.DealUUID); err != nil {
		logger.Error("failed to mark paid", "deal_uuid", deal.DealUUID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	logger.Info("paid retrieval authorized", "deal_uuid", deal.DealUUID, "client", deal.Client, "cid", cid)

	body := dummyCAR(cid, deal.DealUUID)
	_ = mpp.WritePaymentReceipt(w.Header(), mpp.MethodID, txHash, time.Now())
	w.Header().Set("Content-Type", "application/vnd.ipld.car")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.car\"", cid))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func identifyClient(r *http.Request, cfg Config) string {
	if v := strings.TrimSpace(r.URL.Query().Get(cfg.ClientQuery)); v != "" {
		return sanitizeClient(v)
	}
	if v := strings.TrimSpace(r.Header.Get(cfg.ClientHeader)); v != "" {
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

func dummyCAR(cid, deal string) []byte {
	// Placeholder payload for first-commit integration testing.
	return []byte("DUMMY-CAR\nCID=" + cid + "\nDEAL=" + deal + "\n")
}
