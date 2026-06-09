package filpay

import (
	"context"
	"math/big"

	"github.com/data-preservation-programs/go-synapse/contracts"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

// paymentsAPI is the subset of PaymentsContract used by Client (enables test doubles).
type paymentsAPI interface {
	GetOperatorApproval(ctx context.Context, token, client, operator common.Address) (isApproved bool, rateAllowance, lockupAllowance, rateUsed, lockupUsed, maxLockupPeriod *big.Int, err error)
	GetAccountInfoIfSettled(ctx context.Context, token, owner common.Address) (fundedUntilEpoch, currentFunds, availableFunds, currentLockupRate *big.Int, err error)
	GetRailsForPayerAndToken(ctx context.Context, payer, token common.Address, offset, limit *big.Int) (results []contracts.RailInfoResult, nextOffset, total *big.Int, err error)
	GetRail(ctx context.Context, railID *big.Int) (*contracts.RailViewResult, error)
	SetOperatorApproval(opts *bind.TransactOpts, token, operator common.Address, approved bool, rateAllowance, lockupAllowance, maxLockupPeriod *big.Int) (*types.Transaction, error)
	Deposit(opts *bind.TransactOpts, token, to common.Address, amount *big.Int) (*types.Transaction, error)
}

// erc20API is the subset of ERC20Contract used for USDFC deposit/approve flows.
type erc20API interface {
	BalanceOf(ctx context.Context, account common.Address) (*big.Int, error)
	Allowance(ctx context.Context, owner, spender common.Address) (*big.Int, error)
	Approve(opts *bind.TransactOpts, spender common.Address, amount *big.Int) (*types.Transaction, error)
}

// ethClient is the JSON-RPC client used for bound-contract transacts, receipts, and tx wait.
type ethClient interface {
	bind.ContractBackend
	bind.DeployBackend
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
	Close()
}

var (
	_ paymentsAPI = (*contracts.PaymentsContract)(nil)
	_ erc20API    = (*contracts.ERC20Contract)(nil)
	_ ethClient   = (*ethclient.Client)(nil)
)
