package spproxy

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"

	"github.com/fidlabs/paid-retrievals/internal/mpp"
)

const testQuotePayee0x = "0x2222222222222222222222222222222222222222"

func newTestStore(t *testing.T) *Store {
	t.Helper()
	db := filepath.Join(t.TempDir(), "sp.db")
	s, err := OpenStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustHostFromURL(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

func mustChallengeFromResponse(t *testing.T, res *http.Response) *mpp.Challenge {
	t.Helper()
	h := res.Header.Get("WWW-Authenticate")
	ch, err := mpp.ParseWWWAuthenticate(h)
	if err != nil {
		t.Fatal(err)
	}
	return ch
}

func mustAuthorization(t *testing.T, ch mpp.Challenge, p *mpp.ProofPayload) string {
	t.Helper()
	cred, err := mpp.BuildCredential(ch, *p, p.ClientAddress)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := cred.EncodeAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type mockPaySettler struct {
	called int
	fail   error
}

func (m *mockPaySettler) SettleIfFunded(ctx context.Context, payer, payee common.Address, priceWei *big.Int) (string, error) {
	m.called++
	if m.fail != nil {
		return "", m.fail
	}
	if payer == (common.Address{}) || payee == (common.Address{}) {
		return "", os.ErrInvalid
	}
	if priceWei.Sign() <= 0 {
		return "", os.ErrInvalid
	}
	return "0xsettle", nil
}

func mustProblemType(t *testing.T, res *http.Response) string {
	t.Helper()
	var p struct {
		Type string `json:"type"`
	}
	if err := json.NewDecoder(res.Body).Decode(&p); err != nil {
		t.Fatal(err)
	}
	if p.Type == "" {
		t.Fatal("missing problem type")
	}
	return p.Type
}

func TestQuoteThenPaidSuccess(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	client := crypto.PubkeyToAddress(pk.PublicKey).Hex()
	mock := &mockPaySettler{}
	h := NewHandler(Config{
		PriceFIL:     "0.1",
		FilecoinPay:  mock,
		QuotePayee0x: testQuotePayee0x,
	}, s)
	ts := httptest.NewServer(h)
	defer ts.Close()

	cid := "bafyquote"
	quoteReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/"+cid+"?client="+client, nil)
	quoteRes, err := http.DefaultClient.Do(quoteReq)
	if err != nil {
		t.Fatal(err)
	}
	defer quoteRes.Body.Close()
	if quoteRes.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("expected 402 got %d", quoteRes.StatusCode)
	}
	challenge := mustChallengeFromResponse(t, quoteRes)
	hdr := &mpp.ProofPayload{
		Version:       mpp.VersionV1,
		ChallengeID:   challenge.ID,
		DealUUID:      challenge.Request.DealUUID,
		ClientAddress: client,
		CID:           cid,
		Method:        http.MethodGet,
		Path:          "/piece/" + cid,
		Host:          mustHostFromURL(t, ts.URL),
		Nonce:         "n-1",
		ExpiresUnix:   time.Now().Add(time.Minute).Unix(),
	}
	st, sig, err := mpp.SignEVM(pk, hdr.CanonicalMessage())
	if err != nil {
		t.Fatal(err)
	}
	hdr.SigType = st
	hdr.Signature = sig
	raw := mustAuthorization(t, *challenge, hdr)
	paidReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/"+cid, nil)
	paidReq.Header.Set("Authorization", raw)
	paidRes, err := http.DefaultClient.Do(paidReq)
	if err != nil {
		t.Fatal(err)
	}
	defer paidRes.Body.Close()
	if paidRes.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 got %d", paidRes.StatusCode)
	}
	if mock.called != 1 {
		t.Fatalf("expected settle called once, got %d", mock.called)
	}
}

func TestTamperedCIDRejected(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	client := crypto.PubkeyToAddress(pk.PublicKey).Hex()
	mock := &mockPaySettler{}
	h := NewHandler(Config{
		PriceFIL:     "0.1",
		FilecoinPay:  mock,
		QuotePayee0x: testQuotePayee0x,
	}, s)
	ts := httptest.NewServer(h)
	defer ts.Close()

	qres, err := http.Get(ts.URL + "/piece/bafyone1?client=" + client)
	if err != nil {
		t.Fatal(err)
	}
	defer qres.Body.Close()
	challenge := mustChallengeFromResponse(t, qres)
	hdr := &mpp.ProofPayload{
		Version:       mpp.VersionV1,
		ChallengeID:   challenge.ID,
		DealUUID:      challenge.Request.DealUUID,
		ClientAddress: client,
		CID:           "bafyone1",
		Method:        "GET",
		Path:          "/piece/bafytwo2",
		Host:          mustHostFromURL(t, ts.URL),
		Nonce:         "n-2",
		ExpiresUnix:   time.Now().Add(time.Minute).Unix(),
		SigType:       mpp.SigTypeEVM,
		Signature:     "00",
	}
	raw := mustAuthorization(t, *challenge, hdr)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/bafytwo2", nil)
	req.Header.Set("Authorization", raw)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("expected 402 got %d", res.StatusCode)
	}
}

func TestReplayNonceRejected(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	client := crypto.PubkeyToAddress(pk.PublicKey).Hex()
	mock := &mockPaySettler{}
	h := NewHandler(Config{
		PriceFIL:     "0.1",
		FilecoinPay:  mock,
		QuotePayee0x: testQuotePayee0x,
	}, s)
	ts := httptest.NewServer(h)
	defer ts.Close()

	qres, err := http.Get(ts.URL + "/piece/bafyrepl1?client=" + client)
	if err != nil {
		t.Fatal(err)
	}
	defer qres.Body.Close()
	challenge := mustChallengeFromResponse(t, qres)
	hdr := &mpp.ProofPayload{
		Version:       mpp.VersionV1,
		ChallengeID:   challenge.ID,
		DealUUID:      challenge.Request.DealUUID,
		ClientAddress: client,
		CID:           "bafyrepl1",
		Method:        http.MethodGet,
		Path:          "/piece/bafyrepl1",
		Host:          mustHostFromURL(t, ts.URL),
		Nonce:         "same-nonce",
		ExpiresUnix:   time.Now().Add(time.Minute).Unix(),
	}
	st, sig, err := mpp.SignEVM(pk, hdr.CanonicalMessage())
	if err != nil {
		t.Fatal(err)
	}
	hdr.SigType = st
	hdr.Signature = sig
	raw := mustAuthorization(t, *challenge, hdr)

	req1, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/bafyrepl1", nil)
	req1.Header.Set("Authorization", raw)
	res1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatal(err)
	}
	defer res1.Body.Close()
	if res1.StatusCode != http.StatusOK {
		t.Fatalf("expected first 200 got %d", res1.StatusCode)
	}

	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/bafyrepl1", nil)
	req2.Header.Set("Authorization", raw)
	res2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	if res2.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("expected replay 402 got %d", res2.StatusCode)
	}
	if got := res2.Header.Get("WWW-Authenticate"); got == "" {
		t.Fatal("expected WWW-Authenticate header on replay 402")
	}
	pt := mustProblemType(t, res2)
	if pt != "https://paymentauth.org/problems/invalid-challenge" {
		t.Fatalf("expected invalid-challenge type, got %s", pt)
	}
}

func TestFilecoinPayEVMSettleBeforeServe(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	client := crypto.PubkeyToAddress(pk.PublicKey).Hex()
	dealID := uuid.NewString()
	cid := "bafyfpayevm1"
	if err := s.InsertQuote(context.Background(), dealID, client, cid, "0.01", testQuotePayee0x); err != nil {
		t.Fatal(err)
	}

	mock := &mockPaySettler{}
	h := NewHandler(Config{
		PriceFIL:     "0.01",
		FilecoinPay:  mock,
		QuotePayee0x: testQuotePayee0x,
	}, s)
	ts := httptest.NewServer(h)
	defer ts.Close()

	piecePath := "/piece/" + cid
	challenge := mpp.Challenge{
		ID:     dealID,
		Realm:  mpp.RealmPrefix + mustHostFromURL(t, ts.URL),
		Method: mpp.MethodID,
		Intent: mpp.IntentID,
		Request: mpp.PaymentRequest{
			DealUUID: dealID,
			CID:      cid,
			PriceFIL: "0.01",
			Payee0x:  testQuotePayee0x,
			Method:   http.MethodGet,
			Path:     piecePath,
			Host:     mustHostFromURL(t, ts.URL),
		},
		Expires: time.Now().Add(time.Minute).UTC().Format(time.RFC3339),
	}
	hdr := &mpp.ProofPayload{
		Version:       mpp.VersionV1,
		ChallengeID:   dealID,
		DealUUID:      dealID,
		ClientAddress: client,
		CID:           cid,
		Method:        http.MethodGet,
		Path:          piecePath,
		Host:          mustHostFromURL(t, ts.URL),
		Nonce:         "n-filpay",
		ExpiresUnix:   time.Now().Add(time.Minute).Unix(),
	}
	st, sig, err := mpp.SignEVM(pk, hdr.CanonicalMessage())
	if err != nil {
		t.Fatal(err)
	}
	hdr.SigType = st
	hdr.Signature = sig
	raw := mustAuthorization(t, challenge, hdr)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+piecePath, nil)
	req.Header.Set("Authorization", raw)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 got %d", res.StatusCode)
	}
	if mock.called != 1 {
		t.Fatalf("expected settle called once, got %d", mock.called)
	}
}

func TestMalformedCredentialReturnsProblemDetails(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	mock := &mockPaySettler{}
	h := NewHandler(Config{
		PriceFIL:     "0.1",
		FilecoinPay:  mock,
		QuotePayee0x: testQuotePayee0x,
	}, s)
	ts := httptest.NewServer(h)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/bafymalformed1", nil)
	req.Header.Set("Authorization", "Payment !!!not-base64url!!!")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("expected 402 got %d", res.StatusCode)
	}
	if got := res.Header.Get("WWW-Authenticate"); got == "" {
		t.Fatal("expected WWW-Authenticate header on malformed credential 402")
	}
	pt := mustProblemType(t, res)
	if pt != "https://paymentauth.org/problems/malformed-credential" {
		t.Fatalf("expected malformed-credential type, got %s", pt)
	}
}

func TestSettleFailureReturnsPaymentInsufficientProblem(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	client := crypto.PubkeyToAddress(pk.PublicKey).Hex()
	mock := &mockPaySettler{fail: errors.New("insufficient")}
	h := NewHandler(Config{
		PriceFIL:     "0.1",
		FilecoinPay:  mock,
		QuotePayee0x: testQuotePayee0x,
	}, s)
	ts := httptest.NewServer(h)
	defer ts.Close()

	qres, err := http.Get(ts.URL + "/piece/bafyinsuff1?client=" + client)
	if err != nil {
		t.Fatal(err)
	}
	defer qres.Body.Close()
	challenge := mustChallengeFromResponse(t, qres)
	hdr := &mpp.ProofPayload{
		Version:       mpp.VersionV1,
		ChallengeID:   challenge.ID,
		DealUUID:      challenge.Request.DealUUID,
		ClientAddress: client,
		CID:           "bafyinsuff1",
		Method:        http.MethodGet,
		Path:          "/piece/bafyinsuff1",
		Host:          mustHostFromURL(t, ts.URL),
		Nonce:         "n-insuff",
		ExpiresUnix:   time.Now().Add(time.Minute).Unix(),
	}
	st, sig, err := mpp.SignEVM(pk, hdr.CanonicalMessage())
	if err != nil {
		t.Fatal(err)
	}
	hdr.SigType = st
	hdr.Signature = sig
	raw := mustAuthorization(t, *challenge, hdr)
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/bafyinsuff1", nil)
	req.Header.Set("Authorization", raw)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("expected 402 got %d", res.StatusCode)
	}
	if got := res.Header.Get("WWW-Authenticate"); got == "" {
		t.Fatal("expected WWW-Authenticate header on insufficient payment 402")
	}
	pt := mustProblemType(t, res)
	if pt != "https://paymentauth.org/problems/payment-insufficient" {
		t.Fatalf("expected payment-insufficient type, got %s", pt)
	}
}
