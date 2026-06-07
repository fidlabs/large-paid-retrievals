package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestDownloadCARFormatsProblemDetails(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = w.Write([]byte(`{"type":"https://paymentauth.org/problems/payment-insufficient","title":"Payment Insufficient","status":402,"detail":"Amount too low"}`))
	}))
	defer ts.Close()

	base, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	cli := &http.Client{}
	err = downloadCAR(cli, base, "bafytstproblem1", "/piece/bafytstproblem1", "", "Payment abc", t.TempDir(), -1, noopProgress{}, false)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "Payment Insufficient") {
		t.Fatalf("expected title in error, got %q", msg)
	}
	if !strings.Contains(msg, "Amount too low") {
		t.Fatalf("expected detail in error, got %q", msg)
	}
	if strings.Contains(msg, "{") {
		t.Fatalf("raw problem JSON should not appear in error, got %q", msg)
	}
}
