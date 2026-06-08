// Package dealstore defines the persistence contract for paid piece retrieval:
// quotes, settlement pools, and paid-access allocations.
//
// Flow (implemented by sqlitestore.Store, orchestrated by piecepayment):
//
//  1. InsertQuote — client receives 402; a Deal row is created (one deal_uuid per quote).
//  2. On first paid GET, CreditSettlement adds verified rail proceeds to the payer→payee pool
//     (keyed by SettlementCredit.SettleTxHash for idempotency).
//  3. TryAllocateDeal debits the pool (AllocateDealRequest) and creates a DealAllocation
//     granting the client a time-limited paid-access window for that deal/cid.
//  4. GetActiveAllocation — while AccessExpiresAt is in the future, retries reuse the same
//     credential without debiting the pool again.
//
// Pools are per (payer, payee) address pair, not per deal. Multiple deals from the same
// client to the same SP share one pool balance.
package dealstore

import (
	"context"
	"errors"
	"io"
	"math/big"
	"time"
)

var (
	ErrDealNotFound     = errors.New("deal not found")
	ErrReplayNonce      = errors.New("nonce already used")
	ErrInsufficientPool = errors.New("settlement pool balance insufficient")
	ErrZeroSettlement   = errors.New("settlement credit amount must be positive")
)

// Deal is the quoted retrieval offer embedded in the MPP 402 challenge.
// DealUUID is the challenge id; Client may be empty on anonymous quotes and is
// bound to the payer when payment succeeds.
type Deal struct {
	DealUUID       string
	Client         string
	CID            string
	PriceUSDFC     string
	Payee0x        string
	LastPaidTxHash string // rail payment or settlement tx that funded this deal's allocation
}

// DealStore persists quotes, settlement ledger state, and paid-access grants.
// piecepayment aliases these types; sqlitestore is the production implementation.
type DealStore interface {
	InsertQuote(ctx context.Context, dealUUID, client, cid, priceUSDFC, payee0x string) error
	GetDeal(ctx context.Context, dealUUID string) (*Deal, error)
	GetActiveAllocation(ctx context.Context, dealUUID, client, cid string, nowUnix int64) (*DealAllocation, error)
	TryAllocateDeal(ctx context.Context, req AllocateDealRequest) (*DealAllocation, error)
	CreditSettlement(ctx context.Context, credit SettlementCredit) error
	OpenSettlementPool(ctx context.Context, payer, payee string) (*SettlementPoolSnapshot, error)
	ConsumeNonce(ctx context.Context, dealUUID, nonce string, expiresUnix int64) error
	// DumpState writes quotes, pools, credits, and allocations to w (e.g. SIGUSR1 diagnostics).
	DumpState(ctx context.Context, w io.Writer) error
}

// DealAllocation is the paid-access grant created when a pool is debited for a deal.
// It outlives the MPP credential expiry: clients may retry GETs with the same
// Authorization header until AccessExpiresAt (default 12h) without paying again.
// One allocation per deal_uuid; a new quote after expiry uses a new deal_uuid.
type DealAllocation struct {
	DealUUID        string
	PoolID          string // settlement pool that was debited
	Client          string
	CID             string
	PriceBaseUnits  string
	SettleTxHash    string // payment_tx_hash or credit ref tied to this drawdown
	AllocatedAt     int64
	AccessExpiresAt int64
}

// AllocateDealRequest draws PriceBaseUnits from the open (Payer, Payee) pool to
// authorize one piece retrieval. Payer/Payee are EIP-55 hex addresses; Client is
// the credential signer (usually same as Payer). AccessTTL sets the retry window.
type AllocateDealRequest struct {
	DealUUID       string
	Payer          string
	Payee          string
	Client         string
	CID            string
	PriceBaseUnits *big.Int
	SettleTxHash   string
	AccessTTL      time.Duration
}

// SettlementCredit records verified on-chain rail proceeds added to a payer's pool
// for a given payee. CreditedBaseUnits is the gross charge (quoted price); the SP
// absorbs operator commission and network fees on-chain. SettleTxHash is typically
// the client's modifyRailPayment tx hash and must be unique per credit.
type SettlementCredit struct {
	Payer             string
	Payee             string
	SettleTxHash      string
	CreditedBaseUnits *big.Int
}

// SettlementPoolSnapshot is the current open ledger pool for one (payer, payee) pair.
// RemainingBaseUnits is what TryAllocateDeal can still draw; SettledBaseUnits is
// the cumulative gross credited from rail payments.
type SettlementPoolSnapshot struct {
	PoolID             string
	RemainingBaseUnits string
	SettledBaseUnits   string
}
