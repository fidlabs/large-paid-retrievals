package piecepayment

import (
	"net/http"
	"strconv"
	"strings"
)

// pricingProbeStrippedHeaders are removed from the upstream HEAD used for quoting so
// clients cannot influence Content-Length via Range, conditional requests, or encoding negotiation.
var pricingProbeStrippedHeaders = []string{
	"Range",
	"If-Range",
	"If-Match",
	"If-None-Match",
	"If-Modified-Since",
	"If-Unmodified-Since",
	"Accept-Encoding",
	"Accept",
	"TE",
	"Transfer-Encoding",
	"Content-Encoding",
	"A-IM",
}

func pricingProbeRequestHeaders(client http.Header) http.Header {
	h := client.Clone()
	h.Del("Authorization")
	for _, name := range pricingProbeStrippedHeaders {
		h.Del(name)
	}
	for key := range h {
		if strings.HasPrefix(strings.ToLower(key), "if-") {
			h.Del(key)
		}
	}
	// Request the full identity-encoded resource size.
	h.Set("Accept-Encoding", "identity")
	return h
}

func pricingProbePieceBytes(status int, header http.Header) int64 {
	switch status {
	case http.StatusOK:
		return probeResponseTotalBytes(header)
	case http.StatusNoContent:
		return 0
	case http.StatusPartialContent:
		// Defensive: partial HEAD must not set the quoted full-piece price.
		return -1
	default:
		return -1
	}
}

func probeResponseTotalBytes(header http.Header) int64 {
	cl := strings.TrimSpace(header.Get("Content-Length"))
	if cl == "" {
		return -1
	}
	n, err := strconv.ParseInt(cl, 10, 64)
	if err != nil || n < 0 {
		return -1
	}
	return n
}
