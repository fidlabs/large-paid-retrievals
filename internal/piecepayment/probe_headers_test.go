package piecepayment

import (
	"net/http"
	"strconv"
	"testing"
)

func TestPricingProbeRequestHeadersStripsRangeAndConditionals(t *testing.T) {
	in := http.Header{
		"Range":            []string{"bytes=0-99"},
		"If-Range":         []string{`"etag"`},
		"If-None-Match":    []string{`"etag"`},
		"Accept-Encoding":  []string{"gzip, br"},
		"Authorization":    []string{"Payment x"},
		"X-Client-Address": []string{"0xabc"},
	}
	out := pricingProbeRequestHeaders(in)
	for _, name := range []string{"Range", "If-Range", "If-None-Match", "Authorization"} {
		if out.Get(name) != "" {
			t.Fatalf("expected %s stripped, got %q", name, out.Get(name))
		}
	}
	if got := out.Get("Accept-Encoding"); got != "identity" {
		t.Fatalf("Accept-Encoding=%q want identity", got)
	}
	if out.Get("X-Client-Address") != "0xabc" {
		t.Fatal("expected harmless client header preserved")
	}
}

func TestPricingProbePieceBytesRejectsPartialContent(t *testing.T) {
	h := http.Header{"Content-Length": []string{"99"}}
	if got := pricingProbePieceBytes(http.StatusPartialContent, h); got != -1 {
		t.Fatalf("got %d want -1 for 206", got)
	}
}

func TestPricingProbePieceBytesRejectsNoContent(t *testing.T) {
	if got := pricingProbePieceBytes(http.StatusNoContent, http.Header{}); got != -1 {
		t.Fatalf("got %d want -1 for 204", got)
	}
}

func TestPricingProbePieceBytesOK(t *testing.T) {
	const want = 1 << 30
	h := http.Header{"Content-Length": []string{strconv.FormatInt(want, 10)}}
	if got := pricingProbePieceBytes(http.StatusOK, h); got != want {
		t.Fatalf("got %d want %d", got, want)
	}
}
