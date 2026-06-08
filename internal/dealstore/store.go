package dealstore

import (
	"context"
	"errors"
	"math/big"
	"time"
)

var (
	ErrDealNotFound     = errors.New("deal not found")
	ErrReplayNonce      = errors.New("nonce already used")
	ErrInsufficientPool = errors.New("settlement pool balance insufficient")
	ErrZeroSettlement   = errors.New("settlement credit amount must be positive")
)

type Deal struct {
	DealUUID       string
	Client         string
	CID            string
	PriceUSDFC     string
	Payee0x        string
	LastPaidTxHash string
}

type DealStore interface {
	InsertQuote(ctx context.Context, dealUUID, client, cid, priceUSDFC, payee0x string) error
	GetDeal(ctx context.Context, dealUUID string) (*Deal, error)
	GetActiveAllocation(ctx context.Context, dealUUID, client, cid string, nowUnix int64) (*DealAllocation, error)
	TryAllocateDeal(ctx context.Context, req AllocateDealRequest) (*DealAllocation, error)
	CreditSettlement(ctx context.Context, credit SettlementCredit) error
	OpenSettlementPool(ctx context.Context, payer, payee string) (*SettlementPoolSnapshot, error)
	ConsumeNonce(ctx context.Context, dealUUID, nonce string, expiresUnix int64) error
}

// DealAllocation records a deal's paid access window debited from a settlement pool.
type DealAllocation struct {
	DealUUID        string
	PoolID          string
	Client          string
	CID             string
	PriceBaseUnits  string
	SettleTxHash    string
	AllocatedAt     int64
	AccessExpiresAt int64
}

// AllocateDealRequest debits an open (payer, payee) pool for one piece retrieval.
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

// SettlementCredit records on-chain settlement proceeds credited to a pool.
type SettlementCredit struct {
	Payer             string
	Payee             string
	SettleTxHash      string
	CreditedBaseUnits *big.Int
}

// SettlementPoolSnapshot is the open ledger pool for a (payer, payee) pair.
type SettlementPoolSnapshot struct {
	PoolID             string
	RemainingBaseUnits string
	SettledBaseUnits   string
}
