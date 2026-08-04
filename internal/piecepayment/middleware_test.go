package piecepayment_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/fidlabs/paid-retrievals/internal/mpp"
	"github.com/fidlabs/paid-retrievals/internal/paymentheader"
	pp "github.com/fidlabs/paid-retrievals/internal/piecepayment"
	"github.com/fidlabs/paid-retrievals/internal/sqlitestore"
)

const (
	testQuotePayee0x  = "0x2222222222222222222222222222222222222222"
	testPaymentTxHash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func newTestStore(t *testing.T) *sqlitestore.Store {
	t.Helper()
	db := filepath.Join(t.TempDir(), "sp.db")
	s, err := sqlitestore.OpenStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newTestHandler(cfg pp.Config) http.Handler {
	if cfg.PriceUSDFCPerGB == "" {
		cfg.PriceUSDFCPerGB = "0.01"
	}
	if cfg.ClientQuery == "" {
		cfg.ClientQuery = "client"
	}
	if cfg.ClientHeader == "" {
		cfg.ClientHeader = "X-Client-Address"
	}
	if cfg.MaxClockSkew <= 0 {
		cfg.MaxClockSkew = 30 * time.Second
	}
	svc := pp.NewRetrievalService(cfg)
	const advertisedBytes = 1 << 30
	pieceHandler := svc.PiecePaymentMiddleware(4096)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := []byte("DUMMY-CAR\nPATH=" + r.URL.Path + "\n")
		w.Header().Set("Content-Type", "application/vnd.ipld.car")
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", strconv.FormatInt(advertisedBytes, 10))
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("ok"))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/piece/") {
			pieceHandler.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
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

func (m *mockPaySettler) CreditRailPayment(ctx context.Context, payer, payee common.Address, paymentTxHash string) (string, *big.Int, error) {
	m.called++
	if m.fail != nil {
		return "", nil, m.fail
	}
	if payer == (common.Address{}) || payee == (common.Address{}) {
		return "", nil, os.ErrInvalid
	}
	if strings.TrimSpace(paymentTxHash) == "" {
		paymentTxHash = testPaymentTxHash
	}
	return paymentTxHash, new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil), nil
}

type expiredPaidDealStore struct {
	deals         map[string]*pp.Deal
	nonces        map[string]struct{}
	paidAt        map[string]int64
	paidTime      func() time.Time
	poolRemaining map[string]*big.Int
	allocations   map[string]*pp.DealAllocation
	credits       map[string]struct{}
}

func newExpiredPaidDealStore() *expiredPaidDealStore {
	return &expiredPaidDealStore{
		deals:  map[string]*pp.Deal{},
		nonces: map[string]struct{}{},
		paidAt: map[string]int64{},
		paidTime: func() time.Time {
			// Simulate a previous payment that is already outside paidAccessTTL.
			return time.Now().Add(-(12 * time.Hour) - time.Minute)
		},
	}
}

func (s *expiredPaidDealStore) InsertQuote(_ context.Context, dealUUID, client, cid, priceUSDFC, payee0x string) error {
	s.deals[dealUUID] = &pp.Deal{
		DealUUID:   dealUUID,
		Client:     client,
		CID:        cid,
		PriceUSDFC: priceUSDFC,
		Payee0x:    payee0x,
	}
	return nil
}

func (s *expiredPaidDealStore) GetDeal(_ context.Context, dealUUID string) (*pp.Deal, error) {
	d, ok := s.deals[dealUUID]
	if !ok {
		return nil, pp.ErrDealNotFound
	}
	return d, nil
}

func (s *expiredPaidDealStore) GetActiveAllocation(_ context.Context, dealUUID, client, cid string, nowUnix int64) (*pp.DealAllocation, error) {
	if s.allocations == nil {
		return nil, nil
	}
	a, ok := s.allocations[dealUUID]
	if !ok || a.Client != client || a.CID != cid || a.AccessExpiresAt <= nowUnix {
		return nil, nil
	}
	return a, nil
}

func (s *expiredPaidDealStore) OpenPool(_ context.Context, payer, payee string) (*pp.PoolSnapshot, error) {
	if s.poolRemaining == nil {
		return nil, nil
	}
	key := payer + "|" + payee
	cur := s.poolRemaining[key]
	if cur == nil || cur.Sign() <= 0 {
		return nil, nil
	}
	return &pp.PoolSnapshot{
		PoolID:             "mock:" + key,
		RemainingBaseUnits: cur.String(),
		SettledBaseUnits:   cur.String(),
	}, nil
}

func (s *expiredPaidDealStore) CreditPool(_ context.Context, credit pp.PoolCredit) error {
	if s.credits == nil {
		s.credits = map[string]struct{}{}
	}
	if _, ok := s.credits[credit.SettleTxHash]; ok {
		return nil
	}
	s.credits[credit.SettleTxHash] = struct{}{}
	if s.poolRemaining == nil {
		s.poolRemaining = map[string]*big.Int{}
	}
	key := credit.Payer + "|" + credit.Payee
	cur := s.poolRemaining[key]
	if cur == nil {
		cur = big.NewInt(0)
	}
	s.poolRemaining[key] = new(big.Int).Add(cur, credit.CreditedBaseUnits)
	return nil
}

func (s *expiredPaidDealStore) TryAllocateDeal(_ context.Context, req pp.AllocateDealRequest) (*pp.DealAllocation, error) {
	if s.poolRemaining == nil {
		s.poolRemaining = map[string]*big.Int{}
	}
	key := req.Payer + "|" + req.Payee
	cur := s.poolRemaining[key]
	if cur == nil || cur.Cmp(req.PriceBaseUnits) < 0 {
		return nil, pp.ErrInsufficientPool
	}
	s.poolRemaining[key] = new(big.Int).Sub(cur, req.PriceBaseUnits)
	expires := s.paidTime().Unix()
	a := &pp.DealAllocation{
		DealUUID:        req.DealUUID,
		Client:          req.Client,
		CID:             req.CID,
		PriceBaseUnits:  req.PriceBaseUnits.String(),
		SettleTxHash:    req.SettleTxHash,
		AllocatedAt:     expires,
		AccessExpiresAt: expires,
	}
	if s.allocations == nil {
		s.allocations = map[string]*pp.DealAllocation{}
	}
	s.allocations[req.DealUUID] = a
	s.paidAt[req.DealUUID] = expires
	if d, ok := s.deals[req.DealUUID]; ok {
		d.Client = req.Client
		d.LastPaidTxHash = req.SettleTxHash
	}
	return a, nil
}

func (s *expiredPaidDealStore) ConsumeNonce(_ context.Context, dealUUID, nonce string, _ int64) error {
	key := dealUUID + ":" + nonce
	if _, used := s.nonces[key]; used {
		return pp.ErrReplayNonce
	}
	s.nonces[key] = struct{}{}
	return nil
}

func (*expiredPaidDealStore) DumpState(context.Context, io.Writer) error { return nil }

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
	h := newTestHandler(pp.Config{
		PriceUSDFCPerGB: "0.1",
		FilecoinPay:     mock,
		QuotePayee0x:    testQuotePayee0x,
		Store:           s,
	})
	ts := httptest.NewServer(h)
	defer ts.Close()

	cid := "bafkreidde4sfyosf2pm6u4vxb65wogjg464a6y6tcg75opo6q5wv34bley"
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
		PaymentTxHash: testPaymentTxHash,
	}
	st, sig, err := mpp.SignEVM(pk, hdr.CanonicalMessage())
	if err != nil {
		t.Fatal(err)
	}
	hdr.SigType = st
	hdr.Signature = sig
	raw := mustAuthorization(t, *challenge, hdr)
	paidReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/"+cid+"?client="+client, nil)
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

func TestQuoteIgnoresBearerVoucherAuthorization(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	client := "0x1111111111111111111111111111111111111111"
	h := newTestHandler(pp.Config{
		PriceUSDFCPerGB: "0.1",
		FilecoinPay:     &mockPaySettler{},
		QuotePayee0x:    testQuotePayee0x,
		Store:           s,
	})
	ts := httptest.NewServer(h)
	defer ts.Close()

	cid := "bafkreidde4sfyosf2pm6u4vxb65wogjg464a6y6tcg75opo6q5wv34bley"
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/"+cid+"?client="+client, nil)
	req.Header.Add("Authorization", "Bearer voucher-for-deal-1")
	req.Header.Add("Authorization", "Bearer voucher-for-deal-2")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("expected 402 quote got %d", res.StatusCode)
	}
	if _, err := mpp.ParseWWWAuthenticate(res.Header.Get("WWW-Authenticate")); err != nil {
		t.Fatalf("expected parseable MPP challenge, got %v (wa=%q)", err, res.Header.Get("WWW-Authenticate"))
	}
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if strings.Contains(string(body), "malformed-credential") {
		t.Fatalf("Bearer vouchers must not be treated as Payment credentials, body=%s", body)
	}
}

func TestReplayNonceAllowedWithinPaidWindow(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	client := crypto.PubkeyToAddress(pk.PublicKey).Hex()
	mock := &mockPaySettler{}
	h := newTestHandler(pp.Config{
		PriceUSDFCPerGB: "0.1",
		FilecoinPay:     mock,
		QuotePayee0x:    testQuotePayee0x,
		Store:           s,
	})
	ts := httptest.NewServer(h)
	defer ts.Close()

	const replayCID = "bafkreierdmi2f7hhmec5awa7ed2wtc46uhywmsquzq7lztdyu5rskuucqe"
	qres, err := http.Get(ts.URL + "/piece/" + replayCID + "?client=" + client)
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
		CID:           replayCID,
		Method:        http.MethodGet,
		Path:          "/piece/" + replayCID,
		Host:          mustHostFromURL(t, ts.URL),
		Nonce:         "same-nonce",
		ExpiresUnix:   time.Now().Add(time.Minute).Unix(),
		PaymentTxHash: testPaymentTxHash,
	}
	st, sig, err := mpp.SignEVM(pk, hdr.CanonicalMessage())
	if err != nil {
		t.Fatal(err)
	}
	hdr.SigType = st
	hdr.Signature = sig
	raw := mustAuthorization(t, *challenge, hdr)

	req1, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/"+replayCID, nil)
	req1.Header.Set("Authorization", raw)
	res1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatal(err)
	}
	defer res1.Body.Close()
	if res1.StatusCode != http.StatusOK {
		t.Fatalf("expected first 200 got %d", res1.StatusCode)
	}

	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/"+replayCID, nil)
	req2.Header.Set("Authorization", raw)
	res2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("expected replay 200 got %d", res2.StatusCode)
	}
}

func TestDownloadRetryStopsAfterPaidAccessTTL(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	client := crypto.PubkeyToAddress(pk.PublicKey).Hex()
	mock := &mockPaySettler{}
	h := newTestHandler(pp.Config{
		PriceUSDFCPerGB: "0.1",
		FilecoinPay:     mock,
		QuotePayee0x:    testQuotePayee0x,
		Store:           s,
	})
	ts := httptest.NewServer(h)
	defer ts.Close()

	const cid = "bafkreif6in2d6leqaxf45b4x6s2x5qncg2puu6n2v4f7rfz4gbx2yldl3e"
	qres, err := http.Get(ts.URL + "/piece/" + cid + "?client=" + client)
	if err != nil {
		t.Fatal(err)
	}
	defer qres.Body.Close()
	challenge := mustChallengeFromResponse(t, qres)
	host := mustHostFromURL(t, ts.URL)
	expires := time.Now().Add(time.Minute).Unix()

	buildAuth := func(nonce string) string {
		hdr := &mpp.ProofPayload{
			Version:       mpp.VersionV1,
			ChallengeID:   challenge.ID,
			DealUUID:      challenge.Request.DealUUID,
			ClientAddress: client,
			CID:           cid,
			Method:        http.MethodGet,
			Path:          "/piece/" + cid,
			Host:          host,
			Nonce:         nonce,
			ExpiresUnix:   expires,
			PaymentTxHash: testPaymentTxHash,
		}
		st, sig, err := mpp.SignEVM(pk, hdr.CanonicalMessage())
		if err != nil {
			t.Fatal(err)
		}
		hdr.SigType = st
		hdr.Signature = sig
		return mustAuthorization(t, *challenge, hdr)
	}

	paidGET := func(auth string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, ts.URL+"/piece/"+cid, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", auth)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	raw := buildAuth("ttl-nonce-1")
	res1 := paidGET(raw)
	defer res1.Body.Close()
	if res1.StatusCode != http.StatusOK {
		t.Fatalf("expected first 200 got %d", res1.StatusCode)
	}
	if mock.called != 1 {
		t.Fatalf("expected one settlement, got %d", mock.called)
	}

	res2 := paidGET(raw)
	defer res2.Body.Close()
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("expected in-window replay 200 got %d", res2.StatusCode)
	}
	if mock.called != 1 {
		t.Fatalf("expected no second settlement during paid window, got %d", mock.called)
	}

	if err := s.SetAllocationAccessExpiresForTest(context.Background(), challenge.ID, time.Now().Add(-time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	alloc, err := s.GetActiveAllocation(context.Background(), challenge.ID, client, cid, time.Now().Unix())
	if err != nil || alloc != nil {
		t.Fatalf("expected expired allocation: %+v err=%v", alloc, err)
	}

	res3 := paidGET(raw)
	defer res3.Body.Close()
	if res3.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("expected post-ttl replay 402 got %d", res3.StatusCode)
	}
	if mock.called != 1 {
		t.Fatalf("expected no settlement on expired replay with reused nonce, got %d", mock.called)
	}

	// Same deal cannot be re-allocated once its window expired; client must obtain a new quote.
	qres2, err := http.Get(ts.URL + "/piece/" + cid + "?client=" + client)
	if err != nil {
		t.Fatal(err)
	}
	defer qres2.Body.Close()
	challenge2 := mustChallengeFromResponse(t, qres2)
	hdr2 := &mpp.ProofPayload{
		Version:       mpp.VersionV1,
		ChallengeID:   challenge2.ID,
		DealUUID:      challenge2.Request.DealUUID,
		ClientAddress: client,
		CID:           cid,
		Method:        http.MethodGet,
		Path:          "/piece/" + cid,
		Host:          host,
		Nonce:         "ttl-nonce-2",
		ExpiresUnix:   time.Now().Add(time.Minute).Unix(),
		PaymentTxHash: testPaymentTxHash,
	}
	st2, sig2, err := mpp.SignEVM(pk, hdr2.CanonicalMessage())
	if err != nil {
		t.Fatal(err)
	}
	hdr2.SigType = st2
	hdr2.Signature = sig2
	raw2 := mustAuthorization(t, *challenge2, hdr2)

	res4 := paidGET(raw2)
	defer res4.Body.Close()
	if res4.StatusCode != http.StatusOK {
		t.Fatalf("expected new quote after ttl 200 got %d", res4.StatusCode)
	}
	alloc2, err := s.GetActiveAllocation(context.Background(), challenge2.ID, client, cid, time.Now().Unix())
	if err != nil || alloc2 == nil {
		t.Fatalf("expected active allocation on new deal: %+v err=%v", alloc2, err)
	}
}

func TestAnonymousQuoteReplayWithinPaidWindow(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	client := crypto.PubkeyToAddress(pk.PublicKey).Hex()
	mock := &mockPaySettler{}
	h := newTestHandler(pp.Config{
		PriceUSDFCPerGB: "0.1",
		FilecoinPay:     mock,
		QuotePayee0x:    testQuotePayee0x,
		Store:           s,
	})
	ts := httptest.NewServer(h)
	defer ts.Close()

	const replayCID = "bafkreif6in2d6leqaxf45b4x6s2x5qncg2puu6n2v4f7rfz4gbx2yldl3e"
	qres, err := http.Get(ts.URL + "/piece/" + replayCID)
	if err != nil {
		t.Fatal(err)
	}
	defer qres.Body.Close()
	if qres.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("quote status %d", qres.StatusCode)
	}
	challenge := mustChallengeFromResponse(t, qres)
	hdr := &mpp.ProofPayload{
		Version:       mpp.VersionV1,
		ChallengeID:   challenge.ID,
		DealUUID:      challenge.Request.DealUUID,
		ClientAddress: client,
		CID:           replayCID,
		Method:        http.MethodGet,
		Path:          "/piece/" + replayCID,
		Host:          mustHostFromURL(t, ts.URL),
		Nonce:         "anon-same-nonce",
		ExpiresUnix:   time.Now().Add(time.Minute).Unix(),
		PaymentTxHash: testPaymentTxHash,
	}
	st, sig, err := mpp.SignEVM(pk, hdr.CanonicalMessage())
	if err != nil {
		t.Fatal(err)
	}
	hdr.SigType = st
	hdr.Signature = sig
	raw := mustAuthorization(t, *challenge, hdr)

	req1, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/"+replayCID, nil)
	req1.Header.Set("Authorization", raw)
	res1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatal(err)
	}
	defer res1.Body.Close()
	if res1.StatusCode != http.StatusOK {
		t.Fatalf("expected first 200 got %d", res1.StatusCode)
	}

	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/"+replayCID, nil)
	req2.Header.Set("Authorization", raw)
	res2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("expected replay 200 got %d", res2.StatusCode)
	}
	if mock.called != 1 {
		t.Fatalf("expected settle called once, got %d", mock.called)
	}
}

func TestReplayGETAfterPaidAccessTTLReturnsChallenge(t *testing.T) {
	store := newExpiredPaidDealStore()
	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	client := crypto.PubkeyToAddress(pk.PublicKey).Hex()
	mock := &mockPaySettler{}
	h := newTestHandler(pp.Config{
		PriceUSDFCPerGB: "0.1",
		FilecoinPay:     mock,
		QuotePayee0x:    testQuotePayee0x,
		Store:           store,
	})
	ts := httptest.NewServer(h)
	defer ts.Close()

	const cid = "bafkreidw2tr22fnhoj6z3jg2tlat4fzq5w2xpqg6m7w5ytv3qd2p4xqtba"
	qres, err := http.Get(ts.URL + "/piece/" + cid + "?client=" + client)
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
		CID:           cid,
		Method:        http.MethodGet,
		Path:          "/piece/" + cid,
		Host:          mustHostFromURL(t, ts.URL),
		Nonce:         "expired-window-replay",
		ExpiresUnix:   time.Now().Add(time.Minute).Unix(),
		PaymentTxHash: testPaymentTxHash,
	}
	st, sig, err := mpp.SignEVM(pk, hdr.CanonicalMessage())
	if err != nil {
		t.Fatal(err)
	}
	hdr.SigType = st
	hdr.Signature = sig
	raw := mustAuthorization(t, *challenge, hdr)

	firstReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/"+cid, nil)
	firstReq.Header.Set("Authorization", raw)
	firstRes, err := http.DefaultClient.Do(firstReq)
	if err != nil {
		t.Fatal(err)
	}
	defer firstRes.Body.Close()
	if firstRes.StatusCode != http.StatusOK {
		t.Fatalf("expected first 200 got %d", firstRes.StatusCode)
	}

	retryReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/"+cid, nil)
	retryReq.Header.Set("Authorization", raw)
	retryRes, err := http.DefaultClient.Do(retryReq)
	if err != nil {
		t.Fatal(err)
	}
	defer retryRes.Body.Close()
	if retryRes.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("expected retry 402 got %d", retryRes.StatusCode)
	}
	retryChallenge := mustChallengeFromResponse(t, retryRes)
	if retryChallenge.Request.CID != cid {
		t.Fatalf("challenge CID %q want %q", retryChallenge.Request.CID, cid)
	}
	if mock.called != 1 {
		t.Fatalf("expected one settlement before ttl expiry challenge, got %d", mock.called)
	}
}

func TestRepeatGETWithoutAuthorizationReturnsChallenge(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	client := crypto.PubkeyToAddress(pk.PublicKey).Hex()
	mock := &mockPaySettler{}
	h := newTestHandler(pp.Config{
		PriceUSDFCPerGB: "0.1",
		FilecoinPay:     mock,
		QuotePayee0x:    testQuotePayee0x,
		Store:           s,
	})
	ts := httptest.NewServer(h)
	defer ts.Close()

	cid := "bafkreif6in2d6leqaxf45b4x6s2x5qncg2puu6n2v4f7rfz4gbx2yldl3e"
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
		Nonce:         "n-repeat",
		ExpiresUnix:   time.Now().Add(time.Minute).Unix(),
		PaymentTxHash: testPaymentTxHash,
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
		t.Fatalf("expected first paid 200 got %d", paidRes.StatusCode)
	}
	if mock.called != 1 {
		t.Fatalf("expected settle called once, got %d", mock.called)
	}

	repeatReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/"+cid+"?client="+client, nil)
	repeatRes, err := http.DefaultClient.Do(repeatReq)
	if err != nil {
		t.Fatal(err)
	}
	defer repeatRes.Body.Close()
	if repeatRes.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("expected repeat 402 got %d", repeatRes.StatusCode)
	}
	if !strings.Contains(repeatRes.Header.Get("WWW-Authenticate"), "Payment") {
		t.Fatal("missing payment challenge header on repeat without auth")
	}
}

func TestInvalidPiecePathNotFound(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	h := newTestHandler(pp.Config{Store: s, FilecoinPay: &mockPaySettler{}})
	ts := httptest.NewServer(h)
	defer ts.Close()

	res, err := http.Get(ts.URL + "/piece/short")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d", res.StatusCode)
	}
}

func TestBadClientAddress(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	h := newTestHandler(pp.Config{Store: s, FilecoinPay: &mockPaySettler{}, QuotePayee0x: testQuotePayee0x})
	ts := httptest.NewServer(h)
	defer ts.Close()

	res, err := http.Get(ts.URL + "/piece/" + testPieceCID + "?client=not-valid")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", res.StatusCode)
	}
	if wa := res.Header.Get("WWW-Authenticate"); wa != "" {
		t.Fatalf("unexpected WWW-Authenticate: %q", wa)
	}
	if mustProblemType(t, res) != "https://paymentauth.org/problems/bad-request" {
		t.Fatal("problem type")
	}
}

func TestRawGETIssues402(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	h := newTestHandler(pp.Config{Store: s, FilecoinPay: &mockPaySettler{}, QuotePayee0x: testQuotePayee0x})
	ts := httptest.NewServer(h)
	defer ts.Close()

	res, err := http.Get(ts.URL + "/piece/" + testPieceCID)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("status %d", res.StatusCode)
	}
	if _, err := mpp.ParseWWWAuthenticate(res.Header.Get("WWW-Authenticate")); err != nil {
		t.Fatalf("WWW-Authenticate: %v", err)
	}
}

func TestClientFromHeader(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	h := newTestHandler(pp.Config{Store: s, FilecoinPay: &mockPaySettler{}, QuotePayee0x: testQuotePayee0x})
	ts := httptest.NewServer(h)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/"+testPieceCID, nil)
	req.Header.Set("X-Client-Address", "0x3333333333333333333333333333333333333333")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("status %d", res.StatusCode)
	}
}

func TestOversizedAuthorizationForbidden(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	cfg := pp.Config{Store: s, FilecoinPay: &mockPaySettler{}, QuotePayee0x: testQuotePayee0x}
	svc := pp.NewRetrievalService(cfg)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := svc.PiecePaymentMiddleware(8)(next)
	ts := httptest.NewServer(h)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/"+testPieceCID, nil)
	req.Header.Set("Authorization", "Payment "+strings.Repeat("x", 64))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", res.StatusCode)
	}
}

func TestUpstreamHEADFailureReturnsPaymentUnavailable(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	cfg := pp.Config{Store: s, FilecoinPay: &mockPaySettler{}, QuotePayee0x: testQuotePayee0x}
	svc := pp.NewRetrievalService(cfg)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(svc.PiecePaymentMiddleware(4096)(next))
	defer ts.Close()

	res, err := http.Get(ts.URL + "/piece/" + testPieceCID + "?client=0x3333333333333333333333333333333333333333")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d", res.StatusCode)
	}
}

func TestUpstreamHEADNotAllowedReturnsPaymentUnavailable(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	cfg := pp.Config{
		PriceUSDFCPerGB: "0.01",
		Store:           s,
		FilecoinPay:     &mockPaySettler{},
		QuotePayee0x:    testQuotePayee0x,
		ClientQuery:     "client",
	}
	svc := pp.NewRetrievalService(cfg)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Length", "9")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("DUMMY-CAR"))
	})
	ts := httptest.NewServer(svc.PiecePaymentMiddleware(4096)(next))
	defer ts.Close()

	client := "0x3333333333333333333333333333333333333333"
	res, err := http.Get(ts.URL + "/piece/" + testPieceCID + "?client=" + client)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d want 503 when HEAD cannot quote", res.StatusCode)
	}
}

func TestQuoteWithoutContentLengthUnavailable(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	cfg := pp.Config{
		PriceUSDFCPerGB: "0.01",
		Store:           s,
		FilecoinPay:     &mockPaySettler{},
		QuotePayee0x:    testQuotePayee0x,
		ClientQuery:     "client",
	}
	svc := pp.NewRetrievalService(cfg)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(svc.PiecePaymentMiddleware(4096)(next))
	defer ts.Close()

	client := "0x3333333333333333333333333333333333333333"
	res, err := http.Get(ts.URL + "/piece/" + testPieceCID + "?client=" + client)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d", res.StatusCode)
	}
	if mustProblemType(t, res) != "https://paymentauth.org/problems/payment-unavailable" {
		t.Fatal("problem type")
	}
}

func TestQuoteZeroContentLengthUnavailable(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	cfg := pp.Config{
		PriceUSDFCPerGB: "0.01",
		Store:           s,
		FilecoinPay:     &mockPaySettler{},
		QuotePayee0x:    testQuotePayee0x,
		ClientQuery:     "client",
	}
	svc := pp.NewRetrievalService(cfg)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(svc.PiecePaymentMiddleware(4096)(next))
	defer ts.Close()

	client := "0x3333333333333333333333333333333333333333"
	res, err := http.Get(ts.URL + "/piece/" + testPieceCID + "?client=" + client)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d", res.StatusCode)
	}
}

func TestQuoteNoContentHEADUnavailable(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	cfg := pp.Config{
		PriceUSDFCPerGB: "0.01",
		Store:           s,
		FilecoinPay:     &mockPaySettler{},
		QuotePayee0x:    testQuotePayee0x,
		ClientQuery:     "client",
	}
	svc := pp.NewRetrievalService(cfg)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(svc.PiecePaymentMiddleware(4096)(next))
	defer ts.Close()

	client := "0x3333333333333333333333333333333333333333"
	res, err := http.Get(ts.URL + "/piece/" + testPieceCID + "?client=" + client)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d", res.StatusCode)
	}
}

func TestQuoteIgnoresClientRangeForPricing(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	const fullBytes = int64(1 << 30)
	cfg := pp.Config{
		PriceUSDFCPerGB: "0.01",
		Store:           s,
		FilecoinPay:     &mockPaySettler{},
		QuotePayee0x:    testQuotePayee0x,
		ClientQuery:     "client",
	}
	svc := pp.NewRetrievalService(cfg)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			if r.Header.Get("Range") != "" {
				w.Header().Set("Content-Length", "100")
				w.WriteHeader(http.StatusPartialContent)
				return
			}
			w.Header().Set("Content-Length", strconv.FormatInt(fullBytes, 10))
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(svc.PiecePaymentMiddleware(4096)(next))
	defer ts.Close()

	client := "0x3333333333333333333333333333333333333333"
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/piece/"+testPieceCID+"?client="+client, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Range", "bytes=0-99")
	req.Header.Set("Accept-Encoding", "gzip")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("status %d", res.StatusCode)
	}
	ch, err := mpp.ParseWWWAuthenticate(res.Header.Get("WWW-Authenticate"))
	if err != nil {
		t.Fatal(err)
	}
	wantPrice, err := paymentheader.PriceUSDFCForBytes("0.01", fullBytes)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Request.PriceUSDFC != wantPrice {
		t.Fatalf("price_usdfc=%q want %q (full piece, not Range-sized probe)", ch.Request.PriceUSDFC, wantPrice)
	}
}

func TestPieceHEADPassthrough(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	cfg := pp.Config{Store: s, FilecoinPay: &mockPaySettler{}, QuotePayee0x: testQuotePayee0x}
	svc := pp.NewRetrievalService(cfg)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			http.Error(w, "expected HEAD", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Length", "99")
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(svc.PiecePaymentMiddleware(4096)(next))
	defer ts.Close()

	req, err := http.NewRequest(http.MethodHead, ts.URL+"/piece/"+testPieceCID, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
	if res.ContentLength != 99 {
		t.Fatalf("Content-Length=%d", res.ContentLength)
	}
}

func TestMalformedAuthorizationProblem(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	cfg := pp.Config{Store: s, FilecoinPay: &mockPaySettler{}, QuotePayee0x: testQuotePayee0x}
	svc := pp.NewRetrievalService(cfg)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	ts := httptest.NewServer(svc.PiecePaymentMiddleware(4096)(next))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/"+testPieceCID, nil)
	req.Header.Set("Authorization", "Payment not-valid-b64!!!")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("status %d", res.StatusCode)
	}
	if mustProblemType(t, res) != "https://paymentauth.org/problems/malformed-credential" {
		t.Fatal("problem type")
	}
}

func TestSettlementFailureProblem(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	client := crypto.PubkeyToAddress(pk.PublicKey).Hex()
	mock := &mockPaySettler{fail: errors.New("insufficient")}
	h := newTestHandler(pp.Config{
		PriceUSDFCPerGB: "0.1", FilecoinPay: mock, QuotePayee0x: testQuotePayee0x, Store: s,
	})
	ts := httptest.NewServer(h)
	defer ts.Close()

	const cid = testPieceCID
	qres, err := http.Get(ts.URL + "/piece/" + cid + "?client=" + client)
	if err != nil {
		t.Fatal(err)
	}
	defer qres.Body.Close()
	challenge := mustChallengeFromResponse(t, qres)
	hdr := &mpp.ProofPayload{
		Version: mpp.VersionV1, ChallengeID: challenge.ID, DealUUID: challenge.ID,
		ClientAddress: client, CID: cid, Method: http.MethodGet, Path: "/piece/" + cid,
		Host: mustHostFromURL(t, ts.URL), Nonce: "pay-fail", ExpiresUnix: time.Now().Add(time.Minute).Unix(), PaymentTxHash: testPaymentTxHash,
	}
	st, sig, err := mpp.SignEVM(pk, hdr.CanonicalMessage())
	if err != nil {
		t.Fatal(err)
	}
	hdr.SigType, hdr.Signature = st, sig
	raw := mustAuthorization(t, *challenge, hdr)
	paidReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/"+cid, nil)
	paidReq.Header.Set("Authorization", raw)
	paidRes, err := http.DefaultClient.Do(paidReq)
	if err != nil {
		t.Fatal(err)
	}
	defer paidRes.Body.Close()
	if paidRes.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("status %d", paidRes.StatusCode)
	}
	if mustProblemType(t, paidRes) != "https://paymentauth.org/problems/payment-insufficient" {
		t.Fatal("problem type")
	}
}

func TestPieceAuthContextAndReceipt(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()
	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	client := crypto.PubkeyToAddress(pk.PublicKey).Hex()
	mock := &mockPaySettler{}
	cfg := pp.Config{
		PriceUSDFCPerGB: "0.1", FilecoinPay: mock, QuotePayee0x: testQuotePayee0x, Store: s,
		ClientQuery: "client", ClientHeader: "X-Client-Address", MaxClockSkew: 30 * time.Second,
	}
	svc := pp.NewRetrievalService(cfg)
	var sawAuth bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", strconv.FormatInt(1<<30, 10))
			w.WriteHeader(http.StatusOK)
			return
		}
		auth, ok := pp.PieceAuthFromContext(r.Context())
		sawAuth = ok && auth.TxHash != "" && auth.CID != ""
		_, _ = w.Write([]byte("car-bytes"))
	})
	ts := httptest.NewServer(svc.PiecePaymentMiddleware(4096)(next))
	defer ts.Close()

	const cid = testPieceCID
	qres, err := http.Get(ts.URL + "/piece/" + cid + "?client=" + client)
	if err != nil {
		t.Fatal(err)
	}
	defer qres.Body.Close()
	challenge := mustChallengeFromResponse(t, qres)
	hdr := &mpp.ProofPayload{
		Version: mpp.VersionV1, ChallengeID: challenge.ID, DealUUID: challenge.ID,
		ClientAddress: client, CID: cid, Method: http.MethodGet, Path: "/piece/" + cid,
		Host: mustHostFromURL(t, ts.URL), Nonce: "ctx-n", ExpiresUnix: time.Now().Add(time.Minute).Unix(), PaymentTxHash: testPaymentTxHash,
	}
	st, sig, err := mpp.SignEVM(pk, hdr.CanonicalMessage())
	if err != nil {
		t.Fatal(err)
	}
	hdr.SigType, hdr.Signature = st, sig
	raw := mustAuthorization(t, *challenge, hdr)
	paidReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/piece/"+cid, nil)
	paidReq.Header.Set("Authorization", raw)
	paidRes, err := http.DefaultClient.Do(paidReq)
	if err != nil {
		t.Fatal(err)
	}
	defer paidRes.Body.Close()
	if paidRes.StatusCode != http.StatusOK || !sawAuth {
		t.Fatalf("status=%d sawAuth=%v", paidRes.StatusCode, sawAuth)
	}
	if paidRes.Header.Get("Payment-Receipt") == "" {
		t.Fatal("missing Payment-Receipt header")
	}
}

const testPieceCID = "bafkreidde4sfyosf2pm6u4vxb65wogjg464a6y6tcg75opo6q5wv34bley"
