package piecepayment

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"

	"github.com/fidlabs/paid-retrievals/internal/mpp"
)

var cidPattern = regexp.MustCompile(`^[a-zA-Z0-9._:-]{8,256}$`)

const (
	problemBase = "https://paymentauth.org/problems/"
)

type problemDetail struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func writeProblem(w http.ResponseWriter, status int, code, detail string) {
	title := "Payment Error"
	switch code {
	case "bad-request":
		title = "Bad Request"
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
	case "payment-unavailable":
		title = "Payment Temporarily Unavailable"
	case "rate-limited":
		title = "Too Many Requests"
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
	status := http.StatusPaymentRequired
	if code == "payment-unavailable" {
		status = http.StatusServiceUnavailable
	}
	writeProblem(w, status, code, detail)
}
