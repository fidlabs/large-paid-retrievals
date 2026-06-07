package main

import (
	"errors"
	"strings"
	"testing"
)

func TestFormatDownloadErrorLinesProblemJSON(t *testing.T) {
	const cid = "baga6ea4seaqchqdzwxltukzwbtajfugthjhikv2ezg46qjvsevzbe7nghsxtmbj"
	raw := `download ` + cid + ` failed: 402 Payment Required {"type":"https://paymentauth.org/problems/verification-failed","title":"Payment Verification Failed","status":402,"detail":"Credential payload failed validation"}`
	lines := formatDownloadErrorLines(cid, errors.New(raw))
	if len(lines) != 2 {
		t.Fatalf("lines = %v", lines)
	}
	if !strings.Contains(lines[0], "402 Payment Required") || !strings.Contains(lines[0], "Payment Verification Failed") {
		t.Fatalf("head = %q", lines[0])
	}
	if lines[1] != "Credential payload failed validation" {
		t.Fatalf("detail = %q", lines[1])
	}
}

func TestNewDownloadFailuresErrorMultiLine(t *testing.T) {
	const (
		cid0 = "baga6ea4seaqchqdzwxltukzwbtajfugthjhikv2ezg46qjvsevzbe7nghsxtmbj"
		cid1 = "baga6ea4seaqchqdzwxltukzwbtajfugthjhikv2ezg46qjvsevzbe7nghsxtmbk"
	)
	items := []challengeItem{{CID: cid0}, {CID: cid1}}
	failures := []pieceDownloadFailure{
		{idx: 1, cid: cid1, err: errors.New("download " + cid1 + " failed: 402 Payment Required {\"title\":\"Payment Verification Failed\",\"type\":\"https://paymentauth.org/problems/verification-failed\",\"detail\":\"bad sig\"}")},
		{idx: 0, cid: cid0, err: errors.New("download " + cid0 + " failed: connection reset")},
	}
	msg := newDownloadFailuresError(items, failures).Error()
	if !strings.Contains(msg, "download failed for 2 piece(s):") {
		t.Fatalf("header missing: %q", msg)
	}
	if strings.Contains(msg, ";") {
		t.Fatalf("should not use semicolon-separated errors: %q", msg)
	}
	if !strings.Contains(msg, "1. "+shortCID(cid0)) || !strings.Contains(msg, "2. "+shortCID(cid1)) {
		t.Fatalf("expected ordered numbered pieces: %q", msg)
	}
	if !strings.Contains(msg, "connection reset") {
		t.Fatalf("expected plain error preserved: %q", msg)
	}
	if !strings.Contains(msg, "bad sig") {
		t.Fatalf("expected parsed detail: %q", msg)
	}
}

func TestFormatHTTPDownloadProblem(t *testing.T) {
	const cid = "bafytest"
	body := []byte(`{"type":"https://paymentauth.org/problems/payment-insufficient","title":"Payment Insufficient","status":402,"detail":"Amount too low"}`)
	err := formatHTTPDownloadProblem(cid, "402 Payment Required", body)
	msg := err.Error()
	if strings.Contains(msg, "{") {
		t.Fatalf("raw JSON should not appear: %q", msg)
	}
	if !strings.Contains(msg, "Payment Insufficient") || !strings.Contains(msg, "Amount too low") {
		t.Fatalf("formatted problem missing fields: %q", msg)
	}
}
