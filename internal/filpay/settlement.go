package filpay

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/data-preservation-programs/go-synapse/constants"
	"github.com/data-preservation-programs/go-synapse/contracts"
	synpayments "github.com/data-preservation-programs/go-synapse/payments"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

var filToken = common.Address{}
var uint256Max = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

const createRailABIJSON = `[
	{
		"type": "function",
		"name": "createRail",
		"inputs": [
			{"name": "token", "type": "address"},
			{"name": "from", "type": "address"},
			{"name": "to", "type": "address"},
			{"name": "validator", "type": "address"},
			{"name": "commissionRateBps", "type": "uint256"},
			{"name": "serviceFeeRecipient", "type": "address"}
		],
		"outputs": [{"name": "", "type": "uint256"}],
		"stateMutability": "nonpayable"
	}
]`

const modifyRailPaymentABIJSON = `[
	{
		"type": "function",
		"name": "modifyRailPayment",
		"inputs": [
			{"name": "railId", "type": "uint256"},
			{"name": "newRate", "type": "uint256"},
			{"name": "oneTimePayment", "type": "uint256"}
		],
		"outputs": [],
		"stateMutability": "nonpayable"
	}
]`

const modifyRailLockupABIJSON = `[
	{
		"type": "function",
		"name": "modifyRailLockup",
		"inputs": [
			{"name": "railId", "type": "uint256"},
			{"name": "period", "type": "uint256"},
			{"name": "lockupFixed", "type": "uint256"}
		],
		"outputs": [],
		"stateMutability": "nonpayable"
	}
]`

const withdrawABIJSON = `[
	{
		"type": "function",
		"name": "withdraw",
		"inputs": [
			{"name": "token", "type": "address"},
			{"name": "amount", "type": "uint256"}
		],
		"outputs": [],
		"stateMutability": "nonpayable"
	}
]`

// Client performs Filecoin Pay reads and settlement txs for native FIL (token address 0x0).
type Client struct {
	eth            *ethclient.Client
	payments       *contracts.PaymentsContract
	chainID        *big.Int
	signerKey      *ecdsa.PrivateKey
	signerAddr     common.Address
	paymentsAddr   common.Address
	log            *slog.Logger
	payTrace       bool // Info-level step logs (--pay-debug); independent of global log level
}

type OperatorApprovalStatus struct {
	Approved        bool
	RateAllowance   *big.Int
	LockupAllowance *big.Int
	RateUsed        *big.Int
	LockupUsed      *big.Int
	MaxLockupPeriod *big.Int
}

type FILRailDetail struct {
	RailID       *big.Int
	IsTerminated bool
	EndEpoch     *big.Int
	From         common.Address
	To           common.Address
	Operator     common.Address
	Token        common.Address
	SettledUpTo  *big.Int
}

// Option configures Client after connect.
type Option func(*Client)

// WithPayLogging attaches a logger. If trace is true, emits Info-level "filpay" operation logs
// (--pay-debug). Debug-level filpay logs are emitted when the handler has Debug enabled (--verbose on sp-proxy).
func WithPayLogging(log *slog.Logger, trace bool) Option {
	return func(c *Client) {
		c.log = log
		c.payTrace = trace
	}
}

// NewClient connects to RPC, parses private key, and binds the payments contract.
// paymentsAddress: empty uses go-synapse known address for the chain ID from RPC.
func NewClient(ctx context.Context, rpcURL, privateKeyHex, privateKeyFile, privateKeyEnv, paymentsAddress string, opts ...Option) (*Client, error) {
	rpcURL = strings.TrimSpace(rpcURL)
	if rpcURL == "" {
		return nil, errors.New("filpay: empty RPC URL")
	}
	pk, err := loadPrivateKey(privateKeyHex, privateKeyFile, privateKeyEnv)
	if err != nil {
		return nil, err
	}
	eth, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, fmt.Errorf("filpay: dial RPC: %w", err)
	}
	chainID, err := eth.ChainID(ctx)
	if err != nil {
		eth.Close()
		return nil, fmt.Errorf("filpay: chain ID: %w", err)
	}
	payAddr := resolvePaymentsAddress(strings.TrimSpace(paymentsAddress), chainID.Int64())
	if payAddr == (common.Address{}) {
		eth.Close()
		return nil, fmt.Errorf("filpay: unknown payments contract for chain %d (set payments address explicitly)", chainID.Int64())
	}
	pc, err := contracts.NewPaymentsContract(payAddr, eth)
	if err != nil {
		eth.Close()
		return nil, fmt.Errorf("filpay: bind payments: %w", err)
	}
	addr := crypto.PubkeyToAddress(pk.PublicKey)
	c := &Client{
		eth:          eth,
		payments:     pc,
		chainID:      chainID,
		signerKey:    pk,
		signerAddr:   addr,
		paymentsAddr: payAddr,
	}
	for _, o := range opts {
		o(c)
	}
	c.payInfo("client initialized",
		"chain_id", chainID.String(),
		"payments_contract", payAddr.Hex(),
		"settler_address", addr.Hex(),
	)
	return c, nil
}

func (c *Client) payInfo(msg string, args ...any) {
	if c == nil || c.log == nil || !c.payTrace {
		return
	}
	c.log.Info(msg, append([]any{"scope", "filpay"}, args...)...)
}

func (c *Client) payDebug(msg string, args ...any) {
	if c == nil || c.log == nil {
		return
	}
	if !c.log.Handler().Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	c.log.Debug(msg, append([]any{"scope", "filpay"}, args...)...)
}

func (c *Client) Close() {
	if c != nil && c.eth != nil {
		c.eth.Close()
	}
}

func (c *Client) SignerAddress() common.Address { return c.signerAddr }

func (c *Client) PaymentsAddress() common.Address { return c.paymentsAddr }

func (c *Client) ChainID() *big.Int {
	if c == nil || c.chainID == nil {
		return nil
	}
	return new(big.Int).Set(c.chainID)
}

func (c *Client) OperatorApproval(ctx context.Context, payer, operator common.Address) (*OperatorApprovalStatus, error) {
	approved, rateAllowance, lockupAllowance, rateUsed, lockupUsed, maxLockupPeriod, err := c.payments.GetOperatorApproval(ctx, filToken, payer, operator)
	if err != nil {
		return nil, fmt.Errorf("filpay: get operator approval: %w", err)
	}
	return &OperatorApprovalStatus{
		Approved:        approved,
		RateAllowance:   rateAllowance,
		LockupAllowance: lockupAllowance,
		RateUsed:        rateUsed,
		LockupUsed:      lockupUsed,
		MaxLockupPeriod: maxLockupPeriod,
	}, nil
}

func (c *Client) AccountInfoIfSettled(ctx context.Context, payer common.Address) (fundedUntilEpoch, currentFunds, availableFunds, currentLockupRate *big.Int, err error) {
	fundedUntilEpoch, currentFunds, availableFunds, currentLockupRate, err = c.payments.GetAccountInfoIfSettled(ctx, filToken, payer)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("filpay: getAccountInfoIfSettled: %w", err)
	}
	return fundedUntilEpoch, currentFunds, availableFunds, currentLockupRate, nil
}

func (c *Client) ListFILRailsAsPayer(ctx context.Context, payer common.Address) ([]FILRailDetail, error) {
	offset := big.NewInt(0)
	limit := big.NewInt(100)
	var out []FILRailDetail
	for {
		results, nextOff, _, err := c.payments.GetRailsForPayerAndToken(ctx, payer, filToken, offset, limit)
		if err != nil {
			return nil, fmt.Errorf("filpay: list rails: %w", err)
		}
		for _, ri := range results {
			d := FILRailDetail{
				RailID:       ri.RailId,
				IsTerminated: ri.IsTerminated,
				EndEpoch:     ri.EndEpoch,
			}
			view, err := c.payments.GetRail(ctx, ri.RailId)
			if err == nil {
				d.From = view.From
				d.To = view.To
				d.Operator = view.Operator
				d.Token = view.Token
				d.SettledUpTo = view.SettledUpTo
			}
			out = append(out, d)
		}
		if nextOff == nil || nextOff.Cmp(big.NewInt(0)) == 0 || len(results) < int(limit.Int64()) {
			break
		}
		offset = nextOff
	}
	return out, nil
}

// PayerFILAvailable returns settled available FIL balance for owner in the payments contract.
func (c *Client) PayerFILAvailable(ctx context.Context, payer common.Address) (*big.Int, error) {
	c.payDebug("query payer FIL available (getAccountInfoIfSettled)", "payer", payer.Hex(), "token", filToken.Hex())
	_, _, avail, _, err := c.payments.GetAccountInfoIfSettled(ctx, filToken, payer)
	if err != nil {
		return nil, fmt.Errorf("filpay: getAccountInfoIfSettled: %w", err)
	}
	c.payInfo("payer FIL available (wei)", "payer", payer.Hex(), "available_wei", avail.String())
	c.payDebug("payer FIL available detail", "payer", payer.Hex(), "available_wei", avail.String())
	return avail, nil
}

// EnsureOperatorApproval checks/sets native-FIL operator approval for payer -> operator.
func (c *Client) EnsureOperatorApproval(ctx context.Context, payer, operator common.Address) error {
	if payer == (common.Address{}) || operator == (common.Address{}) {
		return errors.New("filpay: empty payer or operator")
	}
	c.payInfo("checking operator approval", "payer", payer.Hex(), "operator", operator.Hex(), "token", filToken.Hex())
	approved, rateAllowance, lockupAllowance, _, _, maxLockupPeriod, err := c.payments.GetOperatorApproval(ctx, filToken, payer, operator)
	if err != nil {
		return fmt.Errorf("filpay: get operator approval: %w", err)
	}
	if approved {
		c.payInfo("operator already approved", "payer", payer.Hex(), "operator", operator.Hex(),
			"rate_allowance", rateAllowance.String(), "lockup_allowance", lockupAllowance.String(), "max_lockup_period", maxLockupPeriod.String())
		return nil
	}
	if payer != c.signerAddr {
		return fmt.Errorf("filpay: payer %s does not match signer %s for setOperatorApproval", payer.Hex(), c.signerAddr.Hex())
	}
	c.payInfo("submitting setOperatorApproval", "payer", payer.Hex(), "operator", operator.Hex())
	opts, err := bind.NewKeyedTransactorWithChainID(c.signerKey, c.chainID)
	if err != nil {
		return fmt.Errorf("filpay: transactor: %w", err)
	}
	opts.Context = ctx
	tx, err := c.payments.SetOperatorApproval(opts, filToken, operator, true, uint256Max, uint256Max, uint256Max)
	if err != nil {
		return fmt.Errorf("filpay: setOperatorApproval: %w", err)
	}
	c.payInfo("setOperatorApproval tx submitted", "tx_hash", tx.Hash().Hex(), "payer", payer.Hex(), "operator", operator.Hex())
	if err := c.waitTxMined(ctx, tx, "setOperatorApproval"); err != nil {
		return err
	}
	return nil
}

func (c *Client) CreateFILRail(ctx context.Context, payer, payee common.Address) (string, error) {
	if payer == (common.Address{}) || payee == (common.Address{}) {
		return "", errors.New("filpay: empty payer or payee")
	}
	if payer != c.signerAddr {
		return "", fmt.Errorf("filpay: payer %s does not match signer %s for createRail", payer.Hex(), c.signerAddr.Hex())
	}
	parsed, err := abi.JSON(strings.NewReader(createRailABIJSON))
	if err != nil {
		return "", fmt.Errorf("filpay: parse createRail ABI: %w", err)
	}
	bound := bind.NewBoundContract(c.paymentsAddr, parsed, c.eth, c.eth, c.eth)
	opts, err := bind.NewKeyedTransactorWithChainID(c.signerKey, c.chainID)
	if err != nil {
		return "", fmt.Errorf("filpay: transactor: %w", err)
	}
	opts.Context = ctx
	c.payInfo("submitting createRail", "payer", payer.Hex(), "payee", payee.Hex(), "operator", c.signerAddr.Hex())
	tx, err := bound.Transact(opts, "createRail", filToken, payer, payee, common.Address{}, big.NewInt(0), common.Address{})
	if err != nil {
		return "", fmt.Errorf("filpay: createRail: %w", err)
	}
	h := tx.Hash().Hex()
	c.payInfo("createRail tx submitted", "tx_hash", h, "payer", payer.Hex(), "payee", payee.Hex())
	if err := c.waitTxMined(ctx, tx, "createRail"); err != nil {
		return "", err
	}
	return h, nil
}

// ChargeRailOneTime applies a one-time payment on the active rail.
// Requires signer to be the rail operator.
func (c *Client) ChargeRailOneTime(ctx context.Context, payer, payee common.Address, amountWei *big.Int) (string, error) {
	if amountWei == nil || amountWei.Sign() <= 0 {
		return "", errors.New("filpay: invalid one-time amount")
	}
	railID, err := c.FindActiveFILRail(ctx, payer, payee)
	if err != nil {
		return "", err
	}
	if err := c.EnsureRailLockup(ctx, railID, amountWei); err != nil {
		return "", err
	}
	parsed, err := abi.JSON(strings.NewReader(modifyRailPaymentABIJSON))
	if err != nil {
		return "", fmt.Errorf("filpay: parse modifyRailPayment ABI: %w", err)
	}
	bound := bind.NewBoundContract(c.paymentsAddr, parsed, c.eth, c.eth, c.eth)
	opts, err := bind.NewKeyedTransactorWithChainID(c.signerKey, c.chainID)
	if err != nil {
		return "", fmt.Errorf("filpay: transactor: %w", err)
	}
	opts.Context = ctx
	c.payInfo("submitting modifyRailPayment one-time charge", "rail_id", railID.String(), "payer", payer.Hex(), "payee", payee.Hex(), "one_time_payment_wei", amountWei.String())
	tx, err := bound.Transact(opts, "modifyRailPayment", railID, big.NewInt(0), amountWei)
	if err != nil {
		return "", fmt.Errorf("filpay: modifyRailPayment: %w", err)
	}
	h := tx.Hash().Hex()
	c.payInfo("modifyRailPayment tx submitted", "tx_hash", h, "rail_id", railID.String(), "one_time_payment_wei", amountWei.String())
	if err := c.waitTxMined(ctx, tx, "modifyRailPayment"); err != nil {
		return "", err
	}
	return h, nil
}

// EnsureRailLockup sets fixed lockup to at least required amount (with zero lockup period).
// Requires signer to be rail operator.
func (c *Client) EnsureRailLockup(ctx context.Context, railID, requiredWei *big.Int) error {
	if railID == nil || railID.Sign() <= 0 {
		return errors.New("filpay: invalid rail id")
	}
	if requiredWei == nil || requiredWei.Sign() <= 0 {
		return errors.New("filpay: invalid required lockup amount")
	}
	view, err := c.payments.GetRail(ctx, railID)
	if err != nil {
		return fmt.Errorf("filpay: get rail for lockup: %w", err)
	}
	if view.Operator != c.signerAddr {
		return fmt.Errorf("filpay: signer %s is not rail operator %s", c.signerAddr.Hex(), view.Operator.Hex())
	}
	currentFixed := big.NewInt(0)
	if view.LockupFixed != nil {
		currentFixed = new(big.Int).Set(view.LockupFixed)
	}
	if currentFixed.Cmp(requiredWei) >= 0 {
		c.payInfo("rail lockup already sufficient", "rail_id", railID.String(), "lockup_fixed_wei", currentFixed.String(), "required_wei", requiredWei.String())
		return nil
	}
	parsed, err := abi.JSON(strings.NewReader(modifyRailLockupABIJSON))
	if err != nil {
		return fmt.Errorf("filpay: parse modifyRailLockup ABI: %w", err)
	}
	bound := bind.NewBoundContract(c.paymentsAddr, parsed, c.eth, c.eth, c.eth)
	opts, err := bind.NewKeyedTransactorWithChainID(c.signerKey, c.chainID)
	if err != nil {
		return fmt.Errorf("filpay: transactor: %w", err)
	}
	opts.Context = ctx
	period := big.NewInt(0)
	c.payInfo("submitting modifyRailLockup", "rail_id", railID.String(), "old_lockup_fixed_wei", currentFixed.String(), "new_lockup_fixed_wei", requiredWei.String(), "period", period.String())
	tx, err := bound.Transact(opts, "modifyRailLockup", railID, period, requiredWei)
	if err != nil {
		return fmt.Errorf("filpay: modifyRailLockup: %w", err)
	}
	c.payInfo("modifyRailLockup tx submitted", "tx_hash", tx.Hash().Hex(), "rail_id", railID.String())
	if err := c.waitTxMined(ctx, tx, "modifyRailLockup"); err != nil {
		return err
	}
	return nil
}

// WithdrawFILAvailable withdraws available FIL from owner's payments account to owner's wallet.
// Requires owner == signer.
func (c *Client) WithdrawFILAvailable(ctx context.Context, owner common.Address) (txHash string, amountWei *big.Int, err error) {
	if owner != c.signerAddr {
		return "", nil, fmt.Errorf("filpay: owner %s does not match signer %s for withdraw", owner.Hex(), c.signerAddr.Hex())
	}
	avail, err := c.PayerFILAvailable(ctx, owner)
	if err != nil {
		return "", nil, err
	}
	if avail.Sign() <= 0 {
		c.payInfo("no FIL available to withdraw", "owner", owner.Hex())
		return "", big.NewInt(0), nil
	}
	parsed, err := abi.JSON(strings.NewReader(withdrawABIJSON))
	if err != nil {
		return "", nil, fmt.Errorf("filpay: parse withdraw ABI: %w", err)
	}
	bound := bind.NewBoundContract(c.paymentsAddr, parsed, c.eth, c.eth, c.eth)
	opts, err := bind.NewKeyedTransactorWithChainID(c.signerKey, c.chainID)
	if err != nil {
		return "", nil, fmt.Errorf("filpay: transactor: %w", err)
	}
	opts.Context = ctx
	c.payInfo("submitting FIL withdraw", "owner", owner.Hex(), "amount_wei", avail.String())
	tx, err := bound.Transact(opts, "withdraw", filToken, avail)
	if err != nil {
		return "", nil, fmt.Errorf("filpay: withdraw: %w", err)
	}
	h := tx.Hash().Hex()
	c.payInfo("withdraw tx submitted", "tx_hash", h, "owner", owner.Hex(), "amount_wei", avail.String())
	if err := c.waitTxMined(ctx, tx, "withdraw"); err != nil {
		return "", nil, err
	}
	return h, avail, nil
}

// EnsurePayerFILBalance deposits missing FIL into the payer payments account.
func (c *Client) EnsurePayerFILBalance(ctx context.Context, payer common.Address, requiredWei *big.Int) error {
	if requiredWei == nil || requiredWei.Sign() <= 0 {
		return errors.New("filpay: invalid required FIL amount")
	}
	avail, err := c.PayerFILAvailable(ctx, payer)
	if err != nil {
		return err
	}
	if avail.Cmp(requiredWei) >= 0 {
		c.payInfo("payer FIL balance already sufficient", "payer", payer.Hex(), "available_wei", avail.String(), "required_wei", requiredWei.String())
		return nil
	}
	if payer != c.signerAddr {
		return fmt.Errorf("filpay: payer %s does not match signer %s for deposit", payer.Hex(), c.signerAddr.Hex())
	}
	deficit := new(big.Int).Sub(requiredWei, avail)
	c.payInfo("submitting FIL deposit", "payer", payer.Hex(), "deposit_wei", deficit.String(),
		"available_wei_before", avail.String(), "required_wei", requiredWei.String())
	opts, err := bind.NewKeyedTransactorWithChainID(c.signerKey, c.chainID)
	if err != nil {
		return fmt.Errorf("filpay: transactor: %w", err)
	}
	opts.Context = ctx
	opts.Value = deficit
	tx, err := c.payments.Deposit(opts, filToken, payer, deficit)
	if err != nil {
		return fmt.Errorf("filpay: deposit FIL: %w", err)
	}
	c.payInfo("deposit tx submitted", "tx_hash", tx.Hash().Hex(), "payer", payer.Hex(), "deposit_wei", deficit.String())
	if err := c.waitTxMined(ctx, tx, "deposit"); err != nil {
		return err
	}
	return nil
}

func (c *Client) waitTxMined(ctx context.Context, tx *types.Transaction, op string) error {
	if tx == nil {
		return errors.New("filpay: nil tx")
	}
	waitCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
	}
	c.payInfo("waiting for tx confirmation", "operation", op, "tx_hash", tx.Hash().Hex())
	receipt, err := bind.WaitMined(waitCtx, c.eth, tx)
	if err != nil {
		return fmt.Errorf("filpay: wait mined (%s): %w", op, err)
	}
	if receipt == nil {
		return fmt.Errorf("filpay: wait mined (%s): nil receipt", op)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return fmt.Errorf("filpay: %s tx reverted: %s", op, tx.Hash().Hex())
	}
	c.payInfo("tx confirmed", "operation", op, "tx_hash", tx.Hash().Hex(), "block", receipt.BlockNumber.String())
	return nil
}

// PreparePayerForPayee tries to set operator approval and fund payer account.
// It then verifies a native-FIL rail exists from payer -> payee.
func (c *Client) PreparePayerForPayee(ctx context.Context, payer, payee common.Address, requiredWei *big.Int) error {
	c.payInfo("prepare payer start", "payer", payer.Hex(), "payee", payee.Hex(), "required_wei", requiredWei.String())
	if err := c.EnsureOperatorApproval(ctx, payer, payer); err != nil {
		return err
	}
	if err := c.EnsurePayerFILBalance(ctx, payer, requiredWei); err != nil {
		return err
	}
	railID, err := c.FindActiveFILRail(ctx, payer, payee)
	if err != nil {
		c.payInfo("no active rail found; attempting createRail", "payer", payer.Hex(), "payee", payee.Hex(), "operator", c.signerAddr.Hex())
		if _, createErr := c.CreateFILRail(ctx, payer, payee); createErr != nil {
			return fmt.Errorf("filpay: createRail failed after approval+deposit: %w (initial rail check: %v)", createErr, err)
		}
		railID, err = c.FindActiveFILRail(ctx, payer, payee)
		if err != nil {
			return fmt.Errorf("filpay: createRail submitted but rail still not visible yet (retry later): %w", err)
		}
	}
	c.payInfo("prepare payer complete", "payer", payer.Hex(), "payee", payee.Hex(), "rail_id", railID.String())
	return nil
}

// FindActiveFILRail returns a rail ID where payer pays payee in native FIL, rail not terminated and not past end epoch.
func (c *Client) FindActiveFILRail(ctx context.Context, payer, payee common.Address) (*big.Int, error) {
	if payer == (common.Address{}) || payee == (common.Address{}) {
		return nil, errors.New("filpay: empty payer or payee")
	}
	nowEp := synpayments.CurrentEpoch(c.chainID.Int64())
	c.payInfo("searching native-FIL rails", "payer", payer.Hex(), "payee", payee.Hex(), "current_epoch", nowEp.String())
	offset := big.NewInt(0)
	limit := big.NewInt(100)
	for {
		c.payDebug("getRailsForPayerAndToken page", "offset", offset.String(), "limit", limit.String())
		results, nextOff, total, err := c.payments.GetRailsForPayerAndToken(ctx, payer, filToken, offset, limit)
		if err != nil {
			return nil, fmt.Errorf("filpay: list rails: %w", err)
		}
		totalStr := "nil"
		if total != nil {
			totalStr = total.String()
		}
		nextStr := "nil"
		if nextOff != nil {
			nextStr = nextOff.String()
		}
		c.payDebug("rails page result", "count", len(results), "next_offset", nextStr, "total_hint", totalStr)
		for _, ri := range results {
			if ri.IsTerminated {
				c.payDebug("skip rail (terminated)", "rail_id", ri.RailId.String())
				continue
			}
			view, err := c.payments.GetRail(ctx, ri.RailId)
			if err != nil {
				c.payDebug("skip rail (getRail failed)", "rail_id", ri.RailId.String(), "error", err.Error())
				continue
			}
			if view.Token != filToken {
				c.payDebug("skip rail (wrong token)", "rail_id", ri.RailId.String(), "token", view.Token.Hex())
				continue
			}
			if view.From != payer || view.To != payee {
				c.payDebug("skip rail (from/to mismatch)", "rail_id", ri.RailId.String(),
					"from", view.From.Hex(), "to", view.To.Hex())
				continue
			}
			if view.EndEpoch != nil && view.EndEpoch.Sign() > 0 && nowEp.Sign() > 0 && view.EndEpoch.Cmp(nowEp) <= 0 {
				c.payDebug("skip rail (past end epoch)", "rail_id", ri.RailId.String(), "end_epoch", view.EndEpoch.String())
				continue
			}
			c.payInfo("selected active FIL rail", "rail_id", ri.RailId.String(),
				"from", view.From.Hex(), "to", view.To.Hex(),
				"operator", view.Operator.Hex(), "settled_up_to", view.SettledUpTo.String(), "end_epoch", view.EndEpoch.String())
			return ri.RailId, nil
		}
		if nextOff.Cmp(big.NewInt(0)) == 0 || len(results) < int(limit.Int64()) {
			break
		}
		offset = nextOff
	}
	c.payInfo("no matching FIL rail", "payer", payer.Hex(), "payee", payee.Hex())
	return nil, fmt.Errorf("filpay: no active native-FIL rail from %s to %s", payer.Hex(), payee.Hex())
}

// SettleIfFunded checks rail + payer balance, then submits settleRail through current epoch.
func (c *Client) SettleIfFunded(ctx context.Context, payer, payee common.Address, priceWei *big.Int) (txHash string, err error) {
	if priceWei == nil || priceWei.Sign() <= 0 {
		return "", errors.New("filpay: invalid price wei")
	}
	c.payInfo("SettleIfFunded start", "payer", payer.Hex(), "payee", payee.Hex(), "required_price_wei", priceWei.String())
	railID, err := c.FindActiveFILRail(ctx, payer, payee)
	if err != nil {
		return "", err
	}
	avail, err := c.PayerFILAvailable(ctx, payer)
	if err != nil {
		return "", err
	}
	if avail.Cmp(priceWei) < 0 {
		c.payInfo("payer balance below quoted price; proceeding to settleRail", "available_wei", avail.String(), "quoted_required_wei", priceWei.String())
	} else {
		c.payInfo("balance check ok", "available_wei", avail.String(), "required_wei", priceWei.String())
	}
	until, err := c.eth.BlockNumber(ctx)
	if err != nil {
		return "", fmt.Errorf("filpay: latest block number: %w", err)
	}
	untilEpoch := new(big.Int).SetUint64(until)
	expectedEpoch := synpayments.CurrentEpoch(c.chainID.Int64())
	c.payDebug("settle epoch source", "rpc_block_number", untilEpoch.String(), "computed_epoch", expectedEpoch.String())
	fee := big.NewInt(0)
	c.payInfo("submitting settleRail", "rail_id", railID.String(), "until_epoch", untilEpoch.String(),
		"settlement_fee_wei", fee.String(), "signer", c.signerAddr.Hex())
	opts, err := bind.NewKeyedTransactorWithChainID(c.signerKey, c.chainID)
	if err != nil {
		return "", fmt.Errorf("filpay: transactor: %w", err)
	}
	opts.Context = ctx
	opts.Value = fee
	tx, err := c.payments.SettleRail(opts, railID, untilEpoch)
	if err != nil {
		c.payInfo("settleRail failed", "error", err.Error())
		return "", fmt.Errorf("filpay: settleRail: %w", err)
	}
	h := tx.Hash().Hex()
	c.payInfo("settleRail tx submitted", "tx_hash", h, "rail_id", railID.String())
	if payee == c.signerAddr {
		withdrawTx, amountWei, werr := c.WithdrawFILAvailable(ctx, payee)
		if werr != nil {
			return "", fmt.Errorf("filpay: settle ok but withdraw failed: %w", werr)
		}
		c.payInfo("withdraw after settle", "withdraw_tx", withdrawTx, "amount_wei", amountWei.String(), "owner", payee.Hex())
	}
	return h, nil
}

func resolvePaymentsAddress(raw string, chainID int64) common.Address {
	if raw != "" {
		return common.HexToAddress(raw)
	}
	addr, ok := synpayments.PaymentsAddresses[chainID]
	if ok {
		return addr
	}
	var net constants.Network
	switch chainID {
	case constants.ChainIDMainnet:
		net = constants.NetworkMainnet
	case constants.ChainIDCalibration:
		net = constants.NetworkCalibration
	case constants.ChainIDDevnet:
		net = constants.NetworkDevnet
	default:
		return common.Address{}
	}
	return constants.PaymentsAddresses[net]
}

// LoadPrivateKey loads a secp256k1 key from hex string, file, or environment variable (name in envName).
func LoadPrivateKey(hexKey, keyFile, envName string) (*ecdsa.PrivateKey, error) {
	return loadPrivateKey(hexKey, keyFile, envName)
}

func loadPrivateKey(hexKey, keyFile, envName string) (*ecdsa.PrivateKey, error) {
	raw := strings.TrimSpace(hexKey)
	if raw == "" && strings.TrimSpace(keyFile) != "" {
		b, err := os.ReadFile(strings.TrimSpace(keyFile))
		if err != nil {
			return nil, fmt.Errorf("filpay: read key file: %w", err)
		}
		raw = strings.TrimSpace(string(b))
	}
	if raw == "" {
		if strings.TrimSpace(envName) == "" {
			envName = "SP_PROXY_PAY_PRIVATE_KEY"
		}
		raw = strings.TrimSpace(os.Getenv(envName))
	}
	raw = strings.TrimPrefix(strings.TrimSpace(raw), "0x")
	if raw == "" {
		return nil, errors.New("filpay: missing private key (hex flag, file, or env)")
	}
	pk, err := crypto.HexToECDSA(raw)
	if err != nil {
		return nil, fmt.Errorf("filpay: parse private key: %w", err)
	}
	return pk, nil
}
