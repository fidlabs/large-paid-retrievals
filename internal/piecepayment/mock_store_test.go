package piecepayment

import (
	"context"
	"io"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

type mockDealStore struct {
	deals       map[string]*Deal
	insertErr   error
	getErr      error
	consumeErr  error
	allocateErr error

	poolRemaining map[string]*big.Int
	allocations   map[string]*DealAllocation
	credits       map[string]struct{}
}

func (m *mockDealStore) poolKey(payer, payee string) string { return payer + "|" + payee }

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

func (m *mockDealStore) GetActiveAllocation(_ context.Context, dealUUID, client, cid string, nowUnix int64) (*DealAllocation, error) {
	if m.allocations == nil {
		return nil, nil
	}
	a, ok := m.allocations[dealUUID]
	if !ok || a.Client != client || a.CID != cid || a.AccessExpiresAt <= nowUnix {
		return nil, nil
	}
	return a, nil
}

func (m *mockDealStore) OpenPool(_ context.Context, payer, payee string) (*PoolSnapshot, error) {
	if m.poolRemaining == nil {
		return nil, nil
	}
	key := m.poolKey(payer, payee)
	cur := m.poolRemaining[key]
	if cur == nil || cur.Sign() <= 0 {
		return nil, nil
	}
	return &PoolSnapshot{
		PoolID:             "mock:" + key,
		RemainingBaseUnits: cur.String(),
		SettledBaseUnits:   cur.String(),
	}, nil
}

func (m *mockDealStore) CreditPool(_ context.Context, credit PoolCredit) error {
	if m.credits == nil {
		m.credits = map[string]struct{}{}
	}
	if _, ok := m.credits[credit.SettleTxHash]; ok {
		return nil
	}
	m.credits[credit.SettleTxHash] = struct{}{}
	if m.poolRemaining == nil {
		m.poolRemaining = map[string]*big.Int{}
	}
	key := m.poolKey(credit.Payer, credit.Payee)
	cur := m.poolRemaining[key]
	if cur == nil {
		cur = big.NewInt(0)
	}
	m.poolRemaining[key] = new(big.Int).Add(cur, credit.CreditedBaseUnits)
	return nil
}

func (m *mockDealStore) TryAllocateDeal(_ context.Context, req AllocateDealRequest) (*DealAllocation, error) {
	if m.allocateErr != nil {
		return nil, m.allocateErr
	}
	if a, ok := m.allocations[req.DealUUID]; ok && a.AccessExpiresAt > time.Now().Unix() {
		return a, nil
	}
	if m.poolRemaining == nil {
		m.poolRemaining = map[string]*big.Int{}
	}
	key := m.poolKey(req.Payer, req.Payee)
	cur := m.poolRemaining[key]
	if cur == nil || cur.Cmp(req.PriceBaseUnits) < 0 {
		return nil, ErrInsufficientPool
	}
	m.poolRemaining[key] = new(big.Int).Sub(cur, req.PriceBaseUnits)
	now := time.Now().Unix()
	a := &DealAllocation{
		DealUUID:        req.DealUUID,
		Client:          req.Client,
		CID:             req.CID,
		PriceBaseUnits:  req.PriceBaseUnits.String(),
		SettleTxHash:    req.SettleTxHash,
		AllocatedAt:     now,
		AccessExpiresAt: now + int64(req.AccessTTL.Seconds()),
	}
	if m.allocations == nil {
		m.allocations = map[string]*DealAllocation{}
	}
	m.allocations[req.DealUUID] = a
	if m.deals != nil {
		if d, ok := m.deals[req.DealUUID]; ok {
			d.Client = req.Client
			d.LastPaidTxHash = req.SettleTxHash
		}
	}
	return a, nil
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

func (*mockDealStore) DumpState(context.Context, io.Writer) error { return nil }

type stubSettler struct {
	creditRef string
	credited  *big.Int
	err       error
}

func (s stubSettler) CreditRailPayment(_ context.Context, _, _ common.Address, paymentTxHash string) (string, *big.Int, error) {
	if s.err != nil {
		return "", nil, s.err
	}
	ref := s.creditRef
	if ref == "" {
		ref = paymentTxHash
		if ref == "" {
			ref = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}
	}
	credited := s.credited
	if credited == nil {
		credited = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil) // 1 USDFC
	}
	return ref, credited, nil
}
