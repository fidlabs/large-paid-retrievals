package piecepayment

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/fidlabs/paid-retrievals/internal/mpp"
)

const testPieceCID = "bafkreidde4sfyosf2pm6u4vxb65wogjg464a6y6tcg75opo6q5wv34bley"

type mockDealStore struct {
	deals          map[string]*Deal
	lastPaidAt     map[string]int64
	lastPaidTxHash map[string]string
	insertErr      error
	getErr         error
	consumeErr     error
	markPaidErr    error
}

func (m *mockDealStore) InsertQuote(_ context.Context, dealUUID, client, cid, priceUSDFC, payee0x string) error {
	if m.insertErr != nil {
		return m.insertErr
	}
	if m.deals == nil {
		m.deals = make(map[string]*Deal)
	}
	m.deals[dealUUID] = &Deal{
		DealUUID: dealUUID, Client: client, CID: cid, PriceUSDFC: priceUSDFC, Payee0x: payee0x,
	}
	return nil
}

func (m *mockDealStore) GetDeal(_ context.Context, dealUUID string) (*Deal, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	d, ok := m.deals[dealUUID]
	if !ok {
		return nil, ErrDealNotFound
	}
	return d, nil
}

func (m *mockDealStore) ConsumeNonce(_ context.Context, dealUUID, nonce string, _ int64) error {
	if m.consumeErr != nil {
		return m.consumeErr
	}
	key := dealUUID + ":" + nonce
	if m.deals == nil {
		m.deals = make(map[string]*Deal)
	}
	if _, used := m.deals[key]; used {
		return ErrReplayNonce
	}
	m.deals[key] = &Deal{}
	return nil
}

func (m *mockDealStore) MarkPaid(_ context.Context, dealUUID, txHash string) error {
	if m.markPaidErr == nil {
		if m.lastPaidAt == nil {
			m.lastPaidAt = map[string]int64{}
		}
		if m.lastPaidTxHash == nil {
			m.lastPaidTxHash = map[string]string{}
		}
		m.lastPaidAt[dealUUID] = time.Now().Unix()
		m.lastPaidTxHash[dealUUID] = txHash
		if d, ok := m.deals[dealUUID]; ok {
			d.LastPaidTxHash = txHash
		}
	}
	return m.markPaidErr
}

func (m *mockDealStore) IsDealPaidSince(_ context.Context, dealUUID, client, cid string, sinceUnix int64) (bool, error) {
	if m.lastPaidAt == nil {
		return false, nil
	}
	d, ok := m.deals[dealUUID]
	if !ok {
		return false, nil
	}
	if d.Client != client || d.CID != cid {
		return false, nil
	}
	if strings.TrimSpace(d.LastPaidTxHash) == "" {
		return false, nil
	}
	return m.lastPaidAt[dealUUID] >= sinceUnix, nil
}

type stubSettler struct {
	txHash string
	err    error
}

func (s stubSettler) SettleIfFunded(context.Context, common.Address, common.Address, *big.Int) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	if s.txHash == "" {
		return "0xabc", nil
	}
	return s.txHash, nil
}

func testService(t *testing.T, store DealStore, settler FilecoinPaySettler) (*RetrievalService, *ecdsa.PrivateKey, string) {
	t.Helper()
	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	client := crypto.PubkeyToAddress(pk.PublicKey).Hex()
	svc := NewRetrievalService(Config{
		PriceUSDFC:   "0.1",
		ClientQuery:  "client",
		ClientHeader: "X-Client-Address",
		MaxClockSkew: 30 * time.Second,
		QuotePayee0x: "0x2222222222222222222222222222222222222222",
		FilecoinPay:  settler,
		Store:        store,
	})
	return svc, pk, client
}

func issueQuoteRequest(t *testing.T, host, cid, client string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://"+host+"/piece/"+cid+"?client="+client, nil)
	req.Host = host
	return req
}

func paidRequest(t *testing.T, host, cid, authz string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://"+host+"/piece/"+cid, nil)
	req.Host = host
	req.Header.Set("Authorization", authz)
	return req
}

func buildProof(t *testing.T, pk *ecdsa.PrivateKey, ch mpp.Challenge, client, cid, host, nonce string, expiresUnix int64) string {
	t.Helper()
	hdr := &mpp.ProofPayload{
		Version:       mpp.VersionV1,
		ChallengeID:   ch.ID,
		DealUUID:      ch.ID,
		ClientAddress: client,
		CID:           cid,
		Method:        http.MethodGet,
		Path:          "/piece/" + cid,
		Host:          host,
		Nonce:         nonce,
		ExpiresUnix:   expiresUnix,
	}
	st, sig, err := mpp.SignEVM(pk, hdr.CanonicalMessage())
	if err != nil {
		t.Fatal(err)
	}
	hdr.SigType = st
	hdr.Signature = sig
	cred, err := mpp.BuildCredential(ch, *hdr, client)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := cred.EncodeAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPaymentRequiredError_Error(t *testing.T) {
	e := &PaymentRequiredError{Code: "payment-required", Detail: "need funds"}
	if !strings.Contains(e.Error(), "payment-required") || !strings.Contains(e.Error(), "need funds") {
		t.Fatal(e.Error())
	}
}

func TestBadRequestError_Error(t *testing.T) {
	e := &BadRequestError{Message: "bad client"}
	if e.Error() != "bad client" {
		t.Fatal(e.Error())
	}
}

func TestNewRetrievalServiceRequiresStore(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic without store")
		}
	}()
	_ = NewRetrievalService(Config{Store: nil})
}

func TestIdentifyClientAndSanitize(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example/piece/x?client=0xAbCd", nil)
	if got := identifyClient(req, "client", "X-Client"); got != "0xAbCd" {
		t.Fatalf("query: %q", got)
	}
	req = httptest.NewRequest(http.MethodGet, "http://example/piece/x", nil)
	req.Header.Set("X-Client", "0x1111111111111111111111111111111111111111")
	if got := identifyClient(req, "client", "X-Client"); got != "0x1111111111111111111111111111111111111111" {
		t.Fatalf("header: %q", got)
	}
	req = httptest.NewRequest(http.MethodGet, "http://example/piece/x", nil)
	req.RemoteAddr = "203.0.113.5:12345"
	if got := identifyClient(req, "client", "X-Client"); got != "203.0.113.5" {
		t.Fatalf("remote: %q", got)
	}
	req.RemoteAddr = "badaddr"
	if got := identifyClient(req, "client", "X-Client"); got != "badaddr" {
		t.Fatalf("remote no port: %q", got)
	}
	if sanitizeClient("  ") != "unknown" {
		t.Fatal("empty sanitize")
	}
	long := strings.Repeat("a", 300)
	if len(sanitizeClient(long)) != 256 {
		t.Fatal("truncate")
	}
	if sanitizeClient("ok@host:1.2") != "ok@host:1.2" {
		t.Fatal("allowed chars")
	}
	if sanitizeClient("bad space") != "badspace" {
		t.Fatalf("strip invalid: %q", sanitizeClient("bad space"))
	}
}

func TestParsePiecePathAndHostHelpers(t *testing.T) {
	cases := []struct {
		path string
		ok   bool
	}{
		{"/piece/" + testPieceCID, true},
		{"/piece/", false},
		{"/piece/a/b", false},
		{"/piece/short", false},
		{"/other/" + testPieceCID, false},
	}
	for _, tc := range cases {
		_, ok := parsePiecePath(tc.path)
		if ok != tc.ok {
			t.Fatalf("%s ok=%v", tc.path, ok)
		}
	}
	if !hostMatches(" Host ", "host") {
		t.Fatal("hostMatches")
	}
	a := "0xAbCdEf1234567890123456789012345678901234"
	b := "0xabcdef1234567890123456789012345678901234"
	if !sameHexAddress(a, b) {
		t.Fatal("same hex")
	}
	if sameHexAddress("not", "0x1111111111111111111111111111111111111111") || sameHexAddress("0x1111111111111111111111111111111111111111", "bad") {
		t.Fatal("invalid hex")
	}
}

func TestPieceAuthFromContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), pieceAuthContextKey{}, PieceAuthContext{
		DealUUID: "d1", CID: testPieceCID, TxHash: "0x1",
	})
	got, ok := PieceAuthFromContext(ctx)
	if !ok || got.DealUUID != "d1" {
		t.Fatalf("got %+v ok=%v", got, ok)
	}
	if _, ok := PieceAuthFromContext(context.Background()); ok {
		t.Fatal("expected missing")
	}
}

func TestLockSettlementPairSerializesSamePair(t *testing.T) {
	svc := NewRetrievalService(Config{
		Store:       &mockDealStore{},
		FilecoinPay: stubSettler{},
	})
	payer := common.HexToAddress("0x1111111111111111111111111111111111111111")
	payee := common.HexToAddress("0x2222222222222222222222222222222222222222")

	unlock1 := svc.lockSettlementPair(payer, payee)

	acquired := make(chan struct{})
	release := make(chan struct{})
	go func() {
		unlock2 := svc.lockSettlementPair(payer, payee)
		close(acquired)
		<-release
		unlock2()
	}()

	select {
	case <-acquired:
		t.Fatal("second lock should block while first is held")
	case <-time.After(50 * time.Millisecond):
		// expected blocked
	}

	unlock1()
	select {
	case <-acquired:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("second lock did not acquire after first released")
	}
	close(release)
}

func TestIssueQuoteBadClient(t *testing.T) {
	svc, _, _ := testService(t, &mockDealStore{}, stubSettler{})
	req := httptest.NewRequest(http.MethodGet, "http://h/piece/"+testPieceCID+"?client=not-an-address", nil)
	req.Host = "h"
	_, err := svc.IssueQuote(req, testPieceCID)
	if err == nil {
		t.Fatal("expected error")
	}
	var bad *BadRequestError
	if !errors.As(err, &bad) {
		t.Fatalf("got %T %v", err, err)
	}
}

func TestAuthorizeAndSettleErrors(t *testing.T) {
	store := &mockDealStore{}
	svc, pk, client := testService(t, store, stubSettler{})
	host := "127.0.0.1:1"

	q, err := svc.IssueQuote(issueQuoteRequest(t, host, testPieceCID, client), testPieceCID)
	if err != nil {
		t.Fatal(err)
	}
	ch := q.Challenge

	t.Run("malformed credential", func(t *testing.T) {
		_, err := svc.AuthorizeAndSettle(paidRequest(t, host, testPieceCID, "Payment ???"), testPieceCID, "Payment ???")
		var pe *PaymentRequiredError
		if !errors.As(err, &pe) || pe.Code != "malformed-credential" {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("unknown deal", func(t *testing.T) {
		raw := buildProof(t, pk, ch, client, testPieceCID, host, "n-unknown", time.Now().Add(time.Minute).Unix())
		store.deals = map[string]*Deal{} // drop quoted deal
		_, err := svc.AuthorizeAndSettle(paidRequest(t, host, testPieceCID, raw), testPieceCID, raw)
		var pe *PaymentRequiredError
		if !errors.As(err, &pe) || pe.Code != "invalid-challenge" {
			t.Fatalf("got %v", err)
		}
		store.deals = map[string]*Deal{ch.ID: {DealUUID: ch.ID, Client: client, CID: testPieceCID, PriceUSDFC: "0.1", Payee0x: "0x2222222222222222222222222222222222222222"}}
	})

	t.Run("expired credential", func(t *testing.T) {
		raw := buildProof(t, pk, ch, client, testPieceCID, host, "n-exp", time.Now().Add(-time.Hour).Unix())
		_, err := svc.AuthorizeAndSettle(paidRequest(t, host, testPieceCID, raw), testPieceCID, raw)
		var pe *PaymentRequiredError
		if !errors.As(err, &pe) || pe.Code != "verification-failed" {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("expiry too far", func(t *testing.T) {
		raw := buildProof(t, pk, ch, client, testPieceCID, host, "n-far", time.Now().Add(48*time.Hour).Unix())
		_, err := svc.AuthorizeAndSettle(paidRequest(t, host, testPieceCID, raw), testPieceCID, raw)
		var pe *PaymentRequiredError
		if !errors.As(err, &pe) || pe.Code != "payment-expired" {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("wrong request fields", func(t *testing.T) {
		hdr := &mpp.ProofPayload{
			Version: mpp.VersionV1, ChallengeID: ch.ID, DealUUID: ch.ID,
			ClientAddress: client, CID: testPieceCID, Method: http.MethodPost,
			Path: "/piece/" + testPieceCID, Host: host, Nonce: "n-wrong",
			ExpiresUnix: time.Now().Add(time.Minute).Unix(),
		}
		st, sig, _ := mpp.SignEVM(pk, hdr.CanonicalMessage())
		hdr.SigType, hdr.Signature = st, sig
		cred, _ := mpp.BuildCredential(ch, *hdr, client)
		raw, _ := cred.EncodeAuthorization()
		_, err := svc.AuthorizeAndSettle(paidRequest(t, host, testPieceCID, raw), testPieceCID, raw)
		var pe *PaymentRequiredError
		if !errors.As(err, &pe) || pe.Code != "verification-failed" {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("unsupported sig type", func(t *testing.T) {
		raw := buildProof(t, pk, ch, client, testPieceCID, host, "n-sig", time.Now().Add(time.Minute).Unix())
		cred, _ := mpp.DecodeAuthorization(raw)
		cred.Payload.SigType = "rsa"
		raw2, _ := cred.EncodeAuthorization()
		_, err := svc.AuthorizeAndSettle(paidRequest(t, host, testPieceCID, raw2), testPieceCID, raw2)
		var pe *PaymentRequiredError
		if !errors.As(err, &pe) || pe.Code != "method-unsupported" {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("bad signature", func(t *testing.T) {
		raw := buildProof(t, pk, ch, client, testPieceCID, host, "n-bad", time.Now().Add(time.Minute).Unix())
		cred, _ := mpp.DecodeAuthorization(raw)
		cred.Payload.Signature = "0x" + strings.Repeat("00", 32)
		raw2, _ := cred.EncodeAuthorization()
		_, err := svc.AuthorizeAndSettle(paidRequest(t, host, testPieceCID, raw2), testPieceCID, raw2)
		var pe *PaymentRequiredError
		if !errors.As(err, &pe) || pe.Code != "verification-failed" {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("settlement failure", func(t *testing.T) {
		svc2, pk2, client2 := testService(t, store, stubSettler{err: errors.New("no funds")})
		q2, _ := svc2.IssueQuote(issueQuoteRequest(t, host, testPieceCID, client2), testPieceCID)
		raw := buildProof(t, pk2, q2.Challenge, client2, testPieceCID, host, "n-pay", time.Now().Add(time.Minute).Unix())
		_, err := svc2.AuthorizeAndSettle(paidRequest(t, host, testPieceCID, raw), testPieceCID, raw)
		var pe *PaymentRequiredError
		if !errors.As(err, &pe) || pe.Code != "payment-insufficient" {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("settlement transient failure", func(t *testing.T) {
		svc2, pk2, client2 := testService(t, store, stubSettler{err: errors.New("nonce too low")})
		q2, _ := svc2.IssueQuote(issueQuoteRequest(t, host, testPieceCID, client2), testPieceCID)
		raw := buildProof(t, pk2, q2.Challenge, client2, testPieceCID, host, "n-pay-2", time.Now().Add(time.Minute).Unix())
		_, err := svc2.AuthorizeAndSettle(paidRequest(t, host, testPieceCID, raw), testPieceCID, raw)
		var pe *PaymentRequiredError
		if !errors.As(err, &pe) || pe.Code != "payment-unavailable" {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("replay nonce", func(t *testing.T) {
		svc3, pk3, client3 := testService(t, &mockDealStore{}, stubSettler{})
		q3, _ := svc3.IssueQuote(issueQuoteRequest(t, host, testPieceCID, client3), testPieceCID)
		raw := buildProof(t, pk3, q3.Challenge, client3, testPieceCID, host, "replay-n", time.Now().Add(time.Minute).Unix())
		first, err := svc3.AuthorizeAndSettle(paidRequest(t, host, testPieceCID, raw), testPieceCID, raw)
		if err != nil {
			t.Fatal(err)
		}
		replay, err := svc3.AuthorizeAndSettle(paidRequest(t, host, testPieceCID, raw), testPieceCID, raw)
		if err != nil {
			t.Fatalf("expected replay accepted in paid window, got %v", err)
		}
		if first.TxHash == "" || replay.TxHash != first.TxHash {
			t.Fatalf("expected replay tx hash reuse, first=%q replay=%q", first.TxHash, replay.TxHash)
		}
	})

	t.Run("mark paid failure still succeeds", func(t *testing.T) {
		svc4, pk4, client4 := testService(t, &mockDealStore{markPaidErr: errors.New("db down")}, stubSettler{})
		q4, _ := svc4.IssueQuote(issueQuoteRequest(t, host, testPieceCID, client4), testPieceCID)
		raw := buildProof(t, pk4, q4.Challenge, client4, testPieceCID, host, "n-mark", time.Now().Add(time.Minute).Unix())
		out, err := svc4.AuthorizeAndSettle(paidRequest(t, host, testPieceCID, raw), testPieceCID, raw)
		if err != nil || out.TxHash == "" {
			t.Fatalf("out=%+v err=%v", out, err)
		}
	})
}

func TestFailPaymentRequiredWithoutDeal(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/piece/"+testPieceCID, nil)
	req.Host = "example.com"
	failPaymentRequired(rec, req, nil, nil, "malformed-credential", "bad format")
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("status %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("WWW-Authenticate"), mpp.AuthScheme) {
		t.Fatal("expected authenticate header")
	}
}
