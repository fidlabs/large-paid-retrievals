package mpp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

const testPieceCID = "bafkreic3gqso3booyry4fwc5wfnhaio574lami3am6nv4k6q6u2legzzdm"

func testChallenge() Challenge {
	return Challenge{
		ID:     "11111111-2222-3333-4444-555555555555",
		Realm:  RealmPrefix + "127.0.0.1:8787",
		Method: MethodID,
		Intent: IntentID,
		Request: PaymentRequest{
			DealUUID:   "11111111-2222-3333-4444-555555555555",
			CID:        testPieceCID,
			PriceUSDFC: "0.01",
			Payee0x:    "0x2222222222222222222222222222222222222222",
			Method:     http.MethodGet,
			Path:       "/piece/" + testPieceCID,
			Host:       "127.0.0.1:8787",
		},
		Expires:     time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
		Description: "Filecoin piece retrieval charge",
		Opaque: map[string]string{
			"deal_uuid": "11111111-2222-3333-4444-555555555555",
			"cid":       testPieceCID,
		},
		Digest: "sha256-deadbeef",
	}
}

func signedProofPayload(t *testing.T, ch Challenge) ProofPayload {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	client := crypto.PubkeyToAddress(key.PublicKey).Hex()
	p := ProofPayload{
		Version:       VersionV1,
		ChallengeID:   ch.ID,
		DealUUID:      ch.Request.DealUUID,
		ClientAddress: client,
		CID:           ch.Request.CID,
		Method:        ch.Request.Method,
		Path:          ch.Request.Path,
		Host:          ch.Request.Host,
		Nonce:         "nonce-abc",
		ExpiresUnix:   time.Now().Add(time.Hour).Unix(),
	}
	sigType, sig, err := SignEVM(key, p.CanonicalMessage())
	if err != nil {
		t.Fatal(err)
	}
	p.SigType = sigType
	p.Signature = sig
	return p
}

func TestProofPayloadValidateAndCanonicalMessage(t *testing.T) {
	ch := testChallenge()
	p := signedProofPayload(t, ch)

	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := p.ValidateAt(time.Now()); err != nil {
		t.Fatal(err)
	}

	msg := string(p.CanonicalMessage())
	for _, want := range []string{
		"mpp-v1\n",
		"challenge_id=" + p.ChallengeID,
		"client=" + strings.ToLower(p.ClientAddress),
		"method=GET",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("canonical message missing %q:\n%s", want, msg)
		}
	}

	expired := p
	expired.ExpiresUnix = time.Now().Add(-time.Minute).Unix()
	if err := expired.ValidateAt(time.Now()); err == nil {
		t.Fatal("expected expiry error")
	} else if !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader, got %v", err)
	}
}

func TestProofPayloadValidateErrors(t *testing.T) {
	valid := signedProofPayload(t, testChallenge())

	tests := []struct {
		name   string
		mutate func(*ProofPayload)
	}{
		{"bad version", func(p *ProofPayload) { p.Version = "mpp-v2" }},
		{"missing challenge id", func(p *ProofPayload) { p.ChallengeID = "" }},
		{"missing client", func(p *ProofPayload) { p.ClientAddress = "" }},
		{"missing signature", func(p *ProofPayload) { p.Signature = "" }},
		{"zero expiry", func(p *ProofPayload) { p.ExpiresUnix = 0 }},
		{"invalid cid", func(p *ProofPayload) { p.CID = "not-a-cid" }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := valid
			tc.mutate(&p)
			if err := p.Validate(); !errors.Is(err, ErrInvalidHeader) {
				t.Fatalf("Validate() = %v, want ErrInvalidHeader", err)
			}
		})
	}
}

func TestValidateIPFSCID(t *testing.T) {
	if err := validateIPFSCID(testPieceCID); err != nil {
		t.Fatalf("valid cid: %v", err)
	}

	tests := []struct {
		name string
		cid  string
	}{
		{"empty", ""},
		{"fake baga", "baga6ea4seaqtest"},
		{"plain text", "not-a-cid"},
		{"too short", "12345"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateIPFSCID(tc.cid); !errors.Is(err, ErrInvalidHeader) {
				t.Fatalf("validateIPFSCID(%q) = %v, want ErrInvalidHeader", tc.cid, err)
			}
		})
	}
}

func TestParseWWWAuthenticateInvalidCID(t *testing.T) {
	ch := testChallenge()
	ch.Request.CID = "baga6ea4seaqtest"
	wa, err := ch.WWWAuthenticateValue()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseWWWAuthenticate(wa); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("ParseWWWAuthenticate() = %v, want ErrInvalidHeader", err)
	}
}

func TestDecodeAuthorizationInvalidCID(t *testing.T) {
	payload := signedProofPayload(t, testChallenge())
	payload.CID = "baga6ea4seaqtest"
	raw, err := json.Marshal(Credential{Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	authz := AuthScheme + " " + base64.RawURLEncoding.EncodeToString(raw)
	if _, err := DecodeAuthorization(authz); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("DecodeAuthorization() = %v, want ErrInvalidHeader", err)
	}
}

func TestProofPayloadDefaultVersion(t *testing.T) {
	p := signedProofPayload(t, testChallenge())
	p.Version = ""
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if p.Version != VersionV1 {
		t.Fatalf("Version = %q, want %q", p.Version, VersionV1)
	}
}

func TestChallengeWWWAuthenticateRoundTrip(t *testing.T) {
	ch := testChallenge()

	wa, err := ch.WWWAuthenticateValue()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(wa, AuthScheme+" ") {
		t.Fatalf("header = %q", wa)
	}

	parsed, err := ParseWWWAuthenticate(wa)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ID != ch.ID || parsed.Realm != ch.Realm {
		t.Fatalf("parsed challenge mismatch: %+v", parsed)
	}
	if parsed.Request.DealUUID != ch.Request.DealUUID || parsed.Request.CID != ch.Request.CID {
		t.Fatalf("parsed request mismatch: %+v", parsed.Request)
	}
	if parsed.Opaque["cid"] != ch.Opaque["cid"] {
		t.Fatalf("opaque = %#v", parsed.Opaque)
	}
}

func TestParseWWWAuthenticateErrors(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"empty", ""},
		{"wrong scheme", "Bearer token"},
		{"missing request", AuthScheme + ` id="x", realm="r", method="m", intent="i"`},
		{"bad request b64", AuthScheme + ` id="x", realm="r", method="m", intent="i", request="!!!"`},
		{"bad opaque b64", AuthScheme + ` id="x", realm="r", method="m", intent="i", request="e30", opaque="!!!"`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseWWWAuthenticate(tc.value); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestSplitAuthParamsQuotedComma(t *testing.T) {
	raw := `description="hello, world", id="abc", realm="piece:host"`
	params, err := parseAuthParams(raw)
	if err != nil {
		t.Fatal(err)
	}
	if params["description"] != "hello, world" {
		t.Fatalf("description = %q", params["description"])
	}
	if params["id"] != "abc" {
		t.Fatalf("id = %q", params["id"])
	}
}

func TestCredentialAuthorizationRoundTrip(t *testing.T) {
	ch := testChallenge()
	payload := signedProofPayload(t, ch)

	cred, err := BuildCredential(ch, payload, payload.ClientAddress)
	if err != nil {
		t.Fatal(err)
	}

	authz, err := cred.EncodeAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(authz, AuthScheme+" ") {
		t.Fatalf("authorization = %q", authz)
	}

	decoded, err := DecodeAuthorization(authz)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Payload.DealUUID != payload.DealUUID {
		t.Fatalf("payload deal uuid = %q", decoded.Payload.DealUUID)
	}
	if decoded.Challenge.ID != ch.ID {
		t.Fatalf("challenge id = %q", decoded.Challenge.ID)
	}
}

func TestDecodeAuthorizationErrors(t *testing.T) {
	validPayload := signedProofPayload(t, testChallenge())
	validPayload.Nonce = ""
	validRaw, err := json.Marshal(Credential{Payload: validPayload})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"wrong scheme", "Bearer x"},
		{"bad b64", AuthScheme + " !!!"},
		{"bad json", AuthScheme + " " + base64.RawURLEncoding.EncodeToString([]byte("{"))},
		{"invalid payload", AuthScheme + " " + base64.RawURLEncoding.EncodeToString(validRaw)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeAuthorization(tc.raw); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestProofPayloadHTTPEncodeDecode(t *testing.T) {
	p := signedProofPayload(t, testChallenge())

	enc, err := p.EncodeHTTP()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeHTTP(enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec.DealUUID != p.DealUUID || dec.Signature != p.Signature {
		t.Fatalf("decoded = %+v", dec)
	}

	if _, err := DecodeHTTP(""); err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestSetPaymentRequiredDoesNotWriteStatus(t *testing.T) {
	ch := testChallenge()
	rec := httptest.NewRecorder()
	var wroteStatus bool
	w := &statusTrackingWriter{
		ResponseWriter: rec,
		onWriteHeader:  func() { wroteStatus = true },
	}
	if err := SetPaymentRequired(w, ch); err != nil {
		t.Fatal(err)
	}
	if wroteStatus {
		t.Fatal("SetPaymentRequired must not call WriteHeader")
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("expected WWW-Authenticate")
	}
}

type statusTrackingWriter struct {
	http.ResponseWriter
	onWriteHeader func()
}

func (w *statusTrackingWriter) WriteHeader(code int) {
	w.onWriteHeader()
	w.ResponseWriter.WriteHeader(code)
}

func TestWritePaymentRequired(t *testing.T) {
	ch := testChallenge()
	rec := httptest.NewRecorder()

	if err := WritePaymentRequired(rec, ch); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("expected no-store cache control")
	}
	if _, err := ParseWWWAuthenticate(rec.Header().Get("WWW-Authenticate")); err != nil {
		t.Fatal(err)
	}
}

func TestWritePaymentReceipt(t *testing.T) {
	h := http.Header{}
	ts := time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC)
	if err := WritePaymentReceipt(h, MethodID, "0xabc", ts); err != nil {
		t.Fatal(err)
	}
	raw := h.Get("Payment-Receipt")
	if raw == "" {
		t.Fatal("missing receipt header")
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]string
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatal(err)
	}
	if body["reference"] != "0xabc" || body["method"] != MethodID {
		t.Fatalf("receipt = %#v", body)
	}
}

func TestCanonicalRequestB64AndChallengeParams(t *testing.T) {
	req := testChallenge().Request
	b64, err := CanonicalRequestB64(req)
	if err != nil {
		t.Fatal(err)
	}
	if b64 == "" {
		t.Fatal("expected non-empty b64")
	}

	fields := ChallengeFields{
		ID:          "id-1",
		Realm:       "piece:host",
		Method:      MethodID,
		Intent:      IntentID,
		Request:     b64,
		Expires:     "2026-05-20T12:00:00Z",
		Description: "desc",
		Opaque:      "b64opaque",
		Digest:      "digest-val",
	}
	canonical := CanonicalChallengeParams(fields)
	for _, part := range []string{"id=id-1", "method=" + MethodID, "digest=digest-val"} {
		if !strings.Contains(canonical, part) {
			t.Fatalf("canonical params missing %q: %s", part, canonical)
		}
	}
}

func TestRequestB64URL(t *testing.T) {
	ch := testChallenge()
	b64, err := ch.RequestB64URL()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	var req PaymentRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		t.Fatal(err)
	}
	if req.CID != ch.Request.CID {
		t.Fatalf("cid = %q", req.CID)
	}
}
