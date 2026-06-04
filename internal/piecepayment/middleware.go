package piecepayment

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/fidlabs/paid-retrievals/internal/mpp"
)

type pieceAuthContextKey struct{}

type PieceAuthContext struct {
	DealUUID string
	CID      string
	TxHash   string
}

func PieceAuthFromContext(ctx context.Context) (PieceAuthContext, bool) {
	v, ok := ctx.Value(pieceAuthContextKey{}).(PieceAuthContext)
	return v, ok
}

func (svc *RetrievalService) PiecePaymentMiddleware(MaxHeaderSize int) func(http.Handler) http.Handler {
	if svc == nil {
		panic("piecepayment: RetrievalService is required")
	}
	logger := svc.logger
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cid, ok := parsePiecePath(r.URL.Path)
			if !ok {
				http.NotFound(w, r)
				return
			}

			// HEAD is proxied for size probes; payment applies on GET only.
			if r.Method == http.MethodHead {
				next.ServeHTTP(w, r)
				return
			}

			rawHdr := strings.TrimSpace(r.Header.Get("Authorization"))
			if svc.cfg.PayDebug {
				logger.Info("piece request auth",
					"method", r.Method,
					"path", r.URL.Path,
					"auth_present", rawHdr != "",
					"auth_len", len(rawHdr),
				)
			}
			if rawHdr == "" {
				// Probe upstream with HEAD for existence and piece size before quoting.
				exists, status, pieceBytes := upstreamProbe(next, r)
				if !exists {
					logger.Debug("upstream HEAD probe cannot quote", "path", r.URL.Path, "upstream_status", status)
					writeProblem(w, http.StatusServiceUnavailable, "payment-unavailable", "Cannot determine piece size for pricing; upstream HEAD must return 200 with Content-Length")
					return
				}
				outcome, err := svc.IssueQuote(r, cid, pieceBytes)
				if err != nil {
					if badReq, ok := errors.AsType[*BadRequestError](err); ok {
						writeProblem(w, http.StatusBadRequest, "bad-request", badReq.Message)
						return
					}
					if errors.Is(err, ErrPieceSizeUnknown) {
						writeProblem(w, http.StatusServiceUnavailable, "payment-unavailable", "Cannot determine piece size for pricing; upstream must advertise Content-Length on HEAD")
						return
					}
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}
				if err := mpp.WritePaymentRequired(w, outcome.Challenge); err != nil {
					logger.Error("failed to write payment challenge", "deal_uuid", outcome.Challenge.ID, "error", err)
					http.Error(w, "internal error", http.StatusInternalServerError)
				}
				return
			}
			// We assume that the upstream exists if there is an authorization header as we must have issued a payment challenge already
			if len(rawHdr) > MaxHeaderSize {
				logger.Warn("payment header too large", "path", r.URL.Path, "size", len(rawHdr), "max", MaxHeaderSize)
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			outcome, err := svc.AuthorizeAndSettle(r, cid, rawHdr)
			if err != nil {
				var payErr *PaymentRequiredError
				if errors.As(err, &payErr) {
					failPaymentRequired(w, r, payErr.Deal, logger, payErr.Code, payErr.Detail)
					return
				}
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}

			ctx := context.WithValue(r.Context(), pieceAuthContextKey{}, PieceAuthContext{
				DealUUID: outcome.Deal.DealUUID,
				CID:      outcome.CID,
				TxHash:   outcome.TxHash,
			})
			next.ServeHTTP(newReceiptResponseWriter(w, logger, outcome.Deal.DealUUID, outcome.TxHash), r.WithContext(ctx))
		})
	}
}

type receiptResponseWriter struct {
	w           http.ResponseWriter
	logger      *slog.Logger
	dealUUID    string
	txHash      string
	wroteHeader bool
}

func newReceiptResponseWriter(w http.ResponseWriter, logger *slog.Logger, dealUUID, txHash string) *receiptResponseWriter {
	return &receiptResponseWriter{w: w, logger: logger, dealUUID: dealUUID, txHash: txHash}
}

func (w *receiptResponseWriter) Header() http.Header {
	return w.w.Header()
}

func (w *receiptResponseWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.w.Write(p)
}

func (w *receiptResponseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.logger.Debug("writing payment receipt", "deal_uuid", w.dealUUID, "tx_hash", w.txHash)

	if statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices {
		if err := mpp.WritePaymentReceipt(w.w.Header(), mpp.MethodID, w.txHash, time.Now()); err != nil {
			w.logger.Error("failed to write payment receipt", "deal_uuid", w.dealUUID, "error", err)
		}
	}

	w.w.WriteHeader(statusCode)
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

func upstreamProbe(next http.Handler, r *http.Request) (exists bool, status int, pieceBytes int64) {
	probeReq := r.Clone(r.Context())
	probeReq.Method = http.MethodHead
	probeReq.Header = pricingProbeRequestHeaders(r.Header)
	probeReq.ContentLength = 0
	probeReq.Body = http.NoBody
	probeReq.GetBody = nil

	rec := newProbeResponseWriter()
	next.ServeHTTP(rec, probeReq)
	status = rec.statusCode
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return false, status, -1
	}
	return true, status, pricingProbePieceBytes(status, rec.header)
}

type probeResponseWriter struct {
	header     http.Header
	body       bytes.Buffer
	statusCode int
}

func newProbeResponseWriter() *probeResponseWriter {
	return &probeResponseWriter{
		header:     make(http.Header),
		statusCode: http.StatusOK,
	}
}

func (w *probeResponseWriter) Header() http.Header {
	return w.header
}

func (w *probeResponseWriter) Write(p []byte) (int, error) {
	return w.body.Write(p)
}

func (w *probeResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}
