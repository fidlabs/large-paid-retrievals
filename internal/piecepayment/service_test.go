package piecepayment

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"log/slog"
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

const (
	testPieceCID      = "bafkreidde4sfyosf2pm6u4vxb65wogjg464a6y6tcg75opo6q5wv34bley"
	testQuotePieceGiB = int64(1 << 30)
	testPaymentTxHash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func testService(t *testing.T, store DealStore, settler FilecoinPaySettler) (*RetrievalService, *ecdsa.PrivateKey, string) {
	t.Helper()
	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	client := crypto.PubkeyToAddress(pk.PublicKey).Hex()
	svc := NewRetrievalService(Config{
		PriceUSDFCPerGB: "0.1",
		ClientQuery:     "client",
		ClientHeader:    "X-Client-Address",
		MaxClockSkew:    30 * time.Second,
		QuotePayee0x:    "0x2222222222222222222222222222222222222222",
		FilecoinPay:     settler,
		Store:           store,
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
		PaymentTxHash: testPaymentTxHash,
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

func TestQuoteClientAndSanitize(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example/piece/x?client=0x1111111111111111111111111111111111111111", nil)
	client, err := quoteClient(req, "client", "X-Client")
	if err != nil || client != "0x1111111111111111111111111111111111111111" {
		t.Fatalf("query: client=%q err=%v", client, err)
	}
	req = httptest.NewRequest(http.MethodGet, "http://example/piece/x", nil)
	req.Header.Set("X-Client", "0x1111111111111111111111111111111111111111")
	client, err = quoteClient(req, "client", "X-Client")
	if err != nil || client != "0x1111111111111111111111111111111111111111" {
		t.Fatalf("header: client=%q err=%v", client, err)
	}
	req = httptest.NewRequest(http.MethodGet, "http://example/piece/x", nil)
	req.RemoteAddr = "203.0.113.5:12345"
	client, err = quoteClient(req, "client", "X-Client")
	if err != nil || client != "" {
		t.Fatalf("anonymous: client=%q err=%v", client, err)
	}
	req = httptest.NewRequest(http.MethodGet, "http://example/piece/x?client=not-valid", nil)
	_, err = quoteClient(req, "client", "X-Client")
	if err == nil {
		t.Fatal("expected bad client error")
	}
	var bad *BadRequestError
	if !errors.As(err, &bad) {
		t.Fatalf("got %T %v", err, err)
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
	case <-time.After(200 * time.Millisecond):
		// expected blocked
	}

	unlock1()
	select {
	case <-acquired:
	case <-time.After(1 * time.Second):
		t.Fatal("second lock did not acquire after first released")
	}
	close(release)
}

func TestLockSettlementPairRemovesIdleEntry(t *testing.T) {
	svc := NewRetrievalService(Config{
		Store:       &mockDealStore{},
		FilecoinPay: stubSettler{},
	})
	payer := common.HexToAddress("0x1111111111111111111111111111111111111111")
	payee := common.HexToAddress("0x2222222222222222222222222222222222222222")

	unlock := svc.lockSettlementPair(payer, payee)
	svc.settleMu.Lock()
	if len(svc.settleLocks) != 1 {
		t.Fatalf("expected one lock entry while held, got %d", len(svc.settleLocks))
	}
	svc.settleMu.Unlock()

	unlock()
	svc.settleMu.Lock()
	defer svc.settleMu.Unlock()
	if len(svc.settleLocks) != 0 {
		t.Fatalf("expected lock table empty after unlock, got %d entries", len(svc.settleLocks))
	}
}

func TestIssueQuoteBadClient(t *testing.T) {
	svc, _, _ := testService(t, &mockDealStore{}, stubSettler{})
	req := httptest.NewRequest(http.MethodGet, "http://h/piece/"+testPieceCID+"?client=not-an-address", nil)
	req.Host = "h"
	_, err := svc.IssueQuote(req, testPieceCID, testQuotePieceGiB)
	if err == nil {
		t.Fatal("expected error")
	}
	var bad *BadRequestError
	if !errors.As(err, &bad) {
		t.Fatalf("got %T %v", err, err)
	}
}

func TestIssueQuoteWithoutClient(t *testing.T) {
	store := &mockDealStore{deals: map[string]*Deal{}}
	svc, _, _ := testService(t, store, stubSettler{})
	req := httptest.NewRequest(http.MethodGet, "http://h/piece/"+testPieceCID, nil)
	req.Host = "h"
	out, err := svc.IssueQuote(req, testPieceCID, testQuotePieceGiB)
	if err != nil {
		t.Fatal(err)
	}
	if out.Challenge.ID == "" || out.Challenge.Request.CID != testPieceCID {
		t.Fatalf("challenge: %+v", out.Challenge)
	}
	deal := store.deals[out.Challenge.ID]
	if deal == nil || deal.Client != "" {
		t.Fatalf("anonymous quote stored client=%q", deal.Client)
	}
}

func TestAuthorizeAndSettleErrors(t *testing.T) {
	store := &mockDealStore{}
	svc, pk, client := testService(t, store, stubSettler{})
	host := "127.0.0.1:1"

	q, err := svc.IssueQuote(issueQuoteRequest(t, host, testPieceCID, client), testPieceCID, testQuotePieceGiB)
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
		store.deals = map[string]*Deal{ch.ID: {
			DealUUID: ch.ID, Client: client, CID: testPieceCID,
			PriceUSDFC: ch.Request.PriceUSDFC, Payee0x: "0x2222222222222222222222222222222222222222",
		}}
	})

	t.Run("expired credential", func(t *testing.T) {
		raw := buildProof(t, pk, ch, client, testPieceCID, host, "n-exp", time.Now().Add(-time.Hour).Unix())
		_, err := svc.AuthorizeAndSettle(paidRequest(t, host, testPieceCID, raw), testPieceCID, raw)
		var pe *PaymentRequiredError
		if !errors.As(err, &pe) || pe.Code != "verification-failed" {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("expired credential allowed when already paid", func(t *testing.T) {
		paidStore := &mockDealStore{}
		svcPaid, pkPaid, clientPaid := testService(t, paidStore, stubSettler{})
		qPaid, err := svcPaid.IssueQuote(issueQuoteRequest(t, host, testPieceCID, clientPaid), testPieceCID, testQuotePieceGiB)
		if err != nil {
			t.Fatal(err)
		}
		chPaid := qPaid.Challenge
		const paidTx = "0xpaidreuse"
		now := time.Now().Unix()
		paidStore.allocations = map[string]*DealAllocation{
			chPaid.ID: {
				DealUUID: chPaid.ID, Client: clientPaid, CID: testPieceCID,
				SettleTxHash: paidTx, AllocatedAt: now, AccessExpiresAt: now + int64(paidAccessTTL.Seconds()),
			},
		}
		raw := buildProof(t, pkPaid, chPaid, clientPaid, testPieceCID, host, "n-exp-paid", time.Now().Add(-time.Hour).Unix())
		out, err := svcPaid.AuthorizeAndSettle(paidRequest(t, host, testPieceCID, raw), testPieceCID, raw)
		if err != nil {
			t.Fatalf("expected paid reuse with expired credential, got %v", err)
		}
		if out.TxHash != paidTx {
			t.Fatalf("tx hash %q want %q", out.TxHash, paidTx)
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

	t.Run("non-GET request", func(t *testing.T) {
		raw := buildProof(t, pk, ch, client, testPieceCID, host, "n-post-req", time.Now().Add(time.Minute).Unix())
		req := httptest.NewRequest(http.MethodPost, "http://"+host+"/piece/"+testPieceCID, nil)
		req.Host = host
		req.Header.Set("Authorization", raw)
		_, err := svc.AuthorizeAndSettle(req, testPieceCID, raw)
		var pe *PaymentRequiredError
		if !errors.As(err, &pe) || pe.Code != "verification-failed" {
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
		q2, _ := svc2.IssueQuote(issueQuoteRequest(t, host, testPieceCID, client2), testPieceCID, testQuotePieceGiB)
		raw := buildProof(t, pk2, q2.Challenge, client2, testPieceCID, host, "n-pay", time.Now().Add(time.Minute).Unix())
		_, err := svc2.AuthorizeAndSettle(paidRequest(t, host, testPieceCID, raw), testPieceCID, raw)
		var pe *PaymentRequiredError
		if !errors.As(err, &pe) || pe.Code != "payment-insufficient" {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("settlement transient failure", func(t *testing.T) {
		svc2, pk2, client2 := testService(t, store, stubSettler{err: errors.New("nonce too low")})
		q2, _ := svc2.IssueQuote(issueQuoteRequest(t, host, testPieceCID, client2), testPieceCID, testQuotePieceGiB)
		raw := buildProof(t, pk2, q2.Challenge, client2, testPieceCID, host, "n-pay-2", time.Now().Add(time.Minute).Unix())
		_, err := svc2.AuthorizeAndSettle(paidRequest(t, host, testPieceCID, raw), testPieceCID, raw)
		var pe *PaymentRequiredError
		if !errors.As(err, &pe) || pe.Code != "payment-unavailable" {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("replay nonce", func(t *testing.T) {
		svc3, pk3, client3 := testService(t, &mockDealStore{}, stubSettler{})
		q3, _ := svc3.IssueQuote(issueQuoteRequest(t, host, testPieceCID, client3), testPieceCID, testQuotePieceGiB)
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

	t.Run("allocate failure surfaces error", func(t *testing.T) {
		svc4, pk4, client4 := testService(t, &mockDealStore{allocateErr: errors.New("db down")}, stubSettler{})
		q4, _ := svc4.IssueQuote(issueQuoteRequest(t, host, testPieceCID, client4), testPieceCID, testQuotePieceGiB)
		raw := buildProof(t, pk4, q4.Challenge, client4, testPieceCID, host, "n-alloc", time.Now().Add(time.Minute).Unix())
		_, err := svc4.AuthorizeAndSettle(paidRequest(t, host, testPieceCID, raw), testPieceCID, raw)
		if err == nil {
			t.Fatal("expected allocate error")
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

func TestIssueChallengeForDeal(t *testing.T) {
	deal := &Deal{
		DealUUID:   "deal-challenge",
		Client:     "0x1111111111111111111111111111111111111111",
		CID:        testPieceCID,
		PriceUSDFC: "0.1",
		Payee0x:    "0x2222222222222222222222222222222222222222",
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/piece/"+testPieceCID, nil)
	req.Host = "example.com"
	issueChallengeForDeal(rec, req, deal, slog.Default())
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("expected WWW-Authenticate challenge")
	}
	issueChallengeForDeal(rec, req, nil, slog.Default())
}

func TestPoolLogHelpersWithPayDebug(t *testing.T) {
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	payer := "0x1111111111111111111111111111111111111111"
	payee := "0x2222222222222222222222222222222222222222"
	store := &mockDealStore{
		poolRemaining: map[string]*big.Int{
			storePoolKey(payer, payee): big.NewInt(1_000_000),
		},
	}
	svc := NewRetrievalService(Config{
		PriceUSDFCPerGB: "0.1",
		PayDebug:        true,
		Logger:          logger,
		Store:           store,
	})
	svc.logPool(context.Background(), "test_event",
		"payer", payer,
		"payee", payee,
	)
	if !strings.Contains(buf.String(), "settlement pool") || !strings.Contains(buf.String(), "pool_open") {
		t.Fatalf("log output: %s", buf.String())
	}
	attrs := svc.poolAmountAttrs("price", nil)
	if len(attrs) != 4 {
		t.Fatalf("nil amount attrs: %v", attrs)
	}
	if got, _ := payerPayeeFromLogAttrs([]any{"payer", payer, "payee", payee}); got != payer {
		t.Fatalf("payer=%q", got)
	}
}

func storePoolKey(payer, payee string) string { return payer + "|" + payee }

func TestReceiptResponseWriterWrite(t *testing.T) {
	rec := httptest.NewRecorder()
	w := newReceiptResponseWriter(rec, slog.Default(), "deal-1", "0xtxhash")
	if n, err := w.Write([]byte("payload")); err != nil || n != 7 {
		t.Fatalf("write n=%d err=%v", n, err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if rec.Header().Get("Payment-Receipt") == "" {
		t.Fatal("expected payment receipt header")
	}
}

func TestFailPaymentUnavailableServiceUnavailable(t *testing.T) {
	deal := &Deal{
		DealUUID:   "deal-unavail",
		Client:     "f1client",
		CID:        testPieceCID,
		PriceUSDFC: "0.1",
		Payee0x:    "0x2222222222222222222222222222222222222222",
	}
	for name, dealArg := range map[string]*Deal{"no deal": nil, "with deal": deal} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/piece/"+testPieceCID, nil)
			req.Host = "example.com"
			failPaymentRequired(rec, req, dealArg, nil, "payment-unavailable", "retry later")
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status %d", rec.Code)
			}
			if dealArg != nil && rec.Header().Get("WWW-Authenticate") == "" {
				t.Fatal("expected WWW-Authenticate challenge with deal")
			}
		})
	}
}
