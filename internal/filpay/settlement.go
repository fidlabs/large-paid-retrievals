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
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

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

// Client performs Filecoin Pay reads and settlement txs using USDFC on the connected chain.
type Client struct {
	eth          ethClient
	payments     paymentsAPI
	chainID      *big.Int
	signerKey    *ecdsa.PrivateKey
	signerAddr   common.Address
	paymentsAddr common.Address
	paymentToken common.Address // USDFC for the chain
	log          *slog.Logger
	payTrace     bool // Info-level step logs (--pay-debug); independent of global log level
	txProgress   TxProgress

	// Optional test hooks (nil uses eth / bind.WaitMined / ERC20 bind).
	rails              paymentsRailsTransactor
	waitMined          func(ctx context.Context, tx *types.Transaction) (*types.Receipt, error)
	transactionReceipt func(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
	usdfc              erc20API
}

type OperatorApprovalStatus struct {
	Approved        bool
	RateAllowance   *big.Int
	LockupAllowance *big.Int
	RateUsed        *big.Int
	LockupUsed      *big.Int
	MaxLockupPeriod *big.Int
}

type TokenRailDetail struct {
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
	ethCli, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, fmt.Errorf("filpay: dial RPC: %w", err)
	}
	chainID, err := ethCli.ChainID(ctx)
	if err != nil {
		ethCli.Close()
		return nil, fmt.Errorf("filpay: chain ID: %w", err)
	}
	payAddr := resolvePaymentsAddress(strings.TrimSpace(paymentsAddress), chainID.Int64())
	if payAddr == (common.Address{}) {
		ethCli.Close()
		return nil, fmt.Errorf("filpay: unknown payments contract for chain %d (set payments address explicitly)", chainID.Int64())
	}
	tokenAddr, err := resolvePaymentToken(chainID.Int64())
	if err != nil {
		ethCli.Close()
		return nil, err
	}
	pc, err := contracts.NewPaymentsContract(payAddr, ethCli)
	if err != nil {
		ethCli.Close()
		return nil, fmt.Errorf("filpay: bind payments: %w", err)
	}
	addr := crypto.PubkeyToAddress(pk.PublicKey)
	c := &Client{
		eth:          ethCli,
		payments:     pc,
		chainID:      chainID,
		signerKey:    pk,
		signerAddr:   addr,
		paymentsAddr: payAddr,
		paymentToken: tokenAddr,
	}
	for _, o := range opts {
		o(c)
	}
	c.payInfo("client initialized",
		"chain_id", chainID.String(),
		"payments_contract", payAddr.Hex(),
		"payment_token", tokenAddr.Hex(),
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
	approved, rateAllowance, lockupAllowance, rateUsed, lockupUsed, maxLockupPeriod, err := c.payments.GetOperatorApproval(ctx, c.paymentToken, payer, operator)
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
	fundedUntilEpoch, currentFunds, availableFunds, currentLockupRate, err = c.payments.GetAccountInfoIfSettled(ctx, c.paymentToken, payer)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("filpay: getAccountInfoIfSettled: %w", err)
	}
	return fundedUntilEpoch, currentFunds, availableFunds, currentLockupRate, nil
}

func (c *Client) ListTokenRailsAsPayer(ctx context.Context, payer common.Address) ([]TokenRailDetail, error) {
	offset := big.NewInt(0)
	limit := big.NewInt(100)
	var out []TokenRailDetail
	for {
		results, nextOff, _, err := c.payments.GetRailsForPayerAndToken(ctx, payer, c.paymentToken, offset, limit)
		if err != nil {
			return nil, fmt.Errorf("filpay: list rails: %w", err)
		}
		for _, ri := range results {
			d := TokenRailDetail{
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

// PayerTokenAvailable returns settled available token balance for owner in the payments contract.
func (c *Client) PayerTokenAvailable(ctx context.Context, payer common.Address) (*big.Int, error) {
	c.payDebug("query payer token available (getAccountInfoIfSettled)", "payer", payer.Hex(), "token", c.paymentToken.Hex())
	_, _, avail, _, err := c.payments.GetAccountInfoIfSettled(ctx, c.paymentToken, payer)
	if err != nil {
		return nil, fmt.Errorf("filpay: getAccountInfoIfSettled: %w", err)
	}
	c.payInfo("payer token available (base units)", "payer", payer.Hex(), "available_base_units", avail.String())
	c.payDebug("payer token available detail", "payer", payer.Hex(), "available_base_units", avail.String())
	return avail, nil
}

// EnsureOperatorApproval checks/sets token operator approval for payer -> operator.
func (c *Client) EnsureOperatorApproval(ctx context.Context, payer, operator common.Address) error {
	if payer == (common.Address{}) || operator == (common.Address{}) {
		return errors.New("filpay: empty payer or operator")
	}
	c.payInfo("checking operator approval", "payer", payer.Hex(), "operator", operator.Hex(), "token", c.paymentToken.Hex())
	approved, rateAllowance, lockupAllowance, _, _, maxLockupPeriod, err := c.payments.GetOperatorApproval(ctx, c.paymentToken, payer, operator)
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
	tx, err := c.payments.SetOperatorApproval(opts, c.paymentToken, operator, true, uint256Max, uint256Max, uint256Max)
	if err != nil {
		return fmt.Errorf("filpay: setOperatorApproval: %w", err)
	}
	c.payInfo("setOperatorApproval tx submitted", "tx_hash", tx.Hash().Hex(), "payer", payer.Hex(), "operator", operator.Hex())
	if err := c.waitTxMined(ctx, tx, "setOperatorApproval"); err != nil {
		return err
	}
	return nil
}

func (c *Client) CreateTokenRail(ctx context.Context, payer, payee common.Address) (string, error) {
	if payer == (common.Address{}) || payee == (common.Address{}) {
		return "", errors.New("filpay: empty payer or payee")
	}
	if payer != c.signerAddr {
		return "", fmt.Errorf("filpay: payer %s does not match signer %s for createRail", payer.Hex(), c.signerAddr.Hex())
	}
	rails, err := c.railsTransactor()
	if err != nil {
		return "", err
	}
	opts, err := c.transactOpts(ctx)
	if err != nil {
		return "", err
	}
	c.payInfo("submitting createRail", "payer", payer.Hex(), "payee", payee.Hex(), "operator", c.signerAddr.Hex())
	tx, err := rails.CreateTokenRail(ctx, opts, payer, payee)
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
func (c *Client) ChargeRailOneTime(ctx context.Context, payer, payee common.Address, amountBaseUnits *big.Int) (string, error) {
	if amountBaseUnits == nil || amountBaseUnits.Sign() <= 0 {
		return "", errors.New("filpay: invalid one-time amount")
	}
	railID, err := c.FindActiveTokenRail(ctx, payer, payee)
	if err != nil {
		return "", err
	}
	if err := c.EnsureRailLockup(ctx, railID, amountBaseUnits); err != nil {
		return "", err
	}
	rails, err := c.railsTransactor()
	if err != nil {
		return "", err
	}
	opts, err := c.transactOpts(ctx)
	if err != nil {
		return "", err
	}
	c.payInfo("submitting modifyRailPayment one-time charge", "rail_id", railID.String(), "payer", payer.Hex(), "payee", payee.Hex(), "one_time_payment_base_units", amountBaseUnits.String())
	tx, err := rails.ModifyRailPayment(ctx, opts, railID, amountBaseUnits)
	if err != nil {
		return "", fmt.Errorf("filpay: modifyRailPayment: %w", err)
	}
	h := tx.Hash().Hex()
	c.payInfo("modifyRailPayment tx submitted", "tx_hash", h, "rail_id", railID.String(), "one_time_payment_base_units", amountBaseUnits.String())
	if err := c.waitTxMined(ctx, tx, "modifyRailPayment"); err != nil {
		return "", err
	}
	return h, nil
}

// EnsureRailLockup sets fixed lockup to at least required amount (with zero lockup period).
// Requires signer to be rail operator.
func (c *Client) EnsureRailLockup(ctx context.Context, railID, requiredBaseUnits *big.Int) error {
	if railID == nil || railID.Sign() <= 0 {
		return errors.New("filpay: invalid rail id")
	}
	if requiredBaseUnits == nil || requiredBaseUnits.Sign() <= 0 {
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
	if currentFixed.Cmp(requiredBaseUnits) >= 0 {
		c.payInfo("rail lockup already sufficient", "rail_id", railID.String(), "lockup_fixed_base_units", currentFixed.String(), "required_base_units", requiredBaseUnits.String())
		return nil
	}
	rails, err := c.railsTransactor()
	if err != nil {
		return err
	}
	opts, err := c.transactOpts(ctx)
	if err != nil {
		return err
	}
	period := big.NewInt(0)
	c.payInfo("submitting modifyRailLockup", "rail_id", railID.String(), "old_lockup_fixed_base_units", currentFixed.String(), "new_lockup_fixed_base_units", requiredBaseUnits.String(), "period", period.String())
	tx, err := rails.ModifyRailLockup(ctx, opts, railID, period, requiredBaseUnits)
	if err != nil {
		return fmt.Errorf("filpay: modifyRailLockup: %w", err)
	}
	c.payInfo("modifyRailLockup tx submitted", "tx_hash", tx.Hash().Hex(), "rail_id", railID.String())
	if err := c.waitTxMined(ctx, tx, "modifyRailLockup"); err != nil {
		return err
	}
	return nil
}

// WithdrawTokenAvailable withdraws available tokens from owner's payments account to owner's wallet.
// Requires owner == signer.
func (c *Client) WithdrawTokenAvailable(ctx context.Context, owner common.Address) (txHash string, amountBaseUnits *big.Int, err error) {
	if owner != c.signerAddr {
		return "", nil, fmt.Errorf("filpay: owner %s does not match signer %s for withdraw", owner.Hex(), c.signerAddr.Hex())
	}
	avail, err := c.PayerTokenAvailable(ctx, owner)
	if err != nil {
		return "", nil, err
	}
	if avail.Sign() <= 0 {
		c.payInfo("no tokens available to withdraw", "owner", owner.Hex())
		return "", big.NewInt(0), nil
	}
	rails, err := c.railsTransactor()
	if err != nil {
		return "", nil, err
	}
	opts, err := c.transactOpts(ctx)
	if err != nil {
		return "", nil, err
	}
	c.payInfo("submitting token withdraw", "owner", owner.Hex(), "amount_base_units", avail.String())
	tx, err := rails.WithdrawToken(ctx, opts, avail)
	if err != nil {
		return "", nil, fmt.Errorf("filpay: withdraw: %w", err)
	}
	h := tx.Hash().Hex()
	c.payInfo("withdraw tx submitted", "tx_hash", h, "owner", owner.Hex(), "amount_base_units", avail.String())
	if err := c.waitTxMined(ctx, tx, "withdraw"); err != nil {
		return "", nil, err
	}
	return h, avail, nil
}

// WithdrawPayeeProceeds moves available USDFC from the payee's Filecoin Pay account to their wallet.
// When payee is not the filpay signer, this is a no-op.
func (c *Client) WithdrawPayeeProceeds(ctx context.Context, payee common.Address) (txHash string, amountBaseUnits *big.Int, err error) {
	if payee != c.signerAddr {
		return "", big.NewInt(0), nil
	}
	return c.WithdrawTokenAvailable(ctx, payee)
}

// EnsurePayerTokenBalance deposits missing USDFC into the payer's Filecoin Pay account.
func (c *Client) EnsurePayerTokenBalance(ctx context.Context, payer common.Address, requiredBaseUnits *big.Int) error {
	if requiredBaseUnits == nil || requiredBaseUnits.Sign() <= 0 {
		return errors.New("filpay: invalid required payment amount")
	}
	avail, err := c.PayerTokenAvailable(ctx, payer)
	if err != nil {
		return err
	}
	if avail.Cmp(requiredBaseUnits) >= 0 {
		c.payInfo("payer USDFC balance already sufficient", "payer", payer.Hex(), "available_base_units", avail.String(), "required_base_units", requiredBaseUnits.String())
		return nil
	}
	if payer != c.signerAddr {
		return fmt.Errorf("filpay: payer %s does not match signer %s for deposit", payer.Hex(), c.signerAddr.Hex())
	}
	deficit := new(big.Int).Sub(requiredBaseUnits, avail)

	usdfc, err := c.erc20()
	if err != nil {
		return err
	}
	walletBal, err := usdfc.BalanceOf(ctx, payer)
	if err != nil {
		return fmt.Errorf("filpay: USDFC wallet balance: %w", err)
	}
	if walletBal.Cmp(deficit) < 0 {
		return fmt.Errorf("filpay: insufficient USDFC in wallet for %s: have %s, need %s more for Filecoin Pay deposit",
			payer.Hex(), walletBal.String(), deficit.String())
	}
	if err := c.ensureUSDFCApproval(ctx, payer, deficit); err != nil {
		return err
	}

	c.payInfo("submitting USDFC deposit", "payer", payer.Hex(), "token", c.paymentToken.Hex(), "deposit_base_units", deficit.String(),
		"available_base_units_before", avail.String(), "required_base_units", requiredBaseUnits.String())
	opts, err := bind.NewKeyedTransactorWithChainID(c.signerKey, c.chainID)
	if err != nil {
		return fmt.Errorf("filpay: transactor: %w", err)
	}
	opts.Context = ctx
	opts.Value = nil // ERC20 deposit must not send native token
	tx, err := c.payments.Deposit(opts, c.paymentToken, payer, deficit)
	if err != nil {
		return fmt.Errorf("filpay: deposit USDFC: %w", err)
	}
	c.payInfo("deposit tx submitted", "tx_hash", tx.Hash().Hex(), "payer", payer.Hex(), "deposit_base_units", deficit.String())
	if err := c.waitTxMined(ctx, tx, "deposit"); err != nil {
		return err
	}
	return nil
}

func (c *Client) ensureUSDFCApproval(ctx context.Context, owner common.Address, amount *big.Int) error {
	usdfc, err := c.erc20()
	if err != nil {
		return err
	}
	allowance, err := usdfc.Allowance(ctx, owner, c.paymentsAddr)
	if err != nil {
		return fmt.Errorf("filpay: get USDFC allowance: %w", err)
	}
	if allowance.Cmp(amount) >= 0 {
		c.payInfo("USDFC allowance sufficient", "owner", owner.Hex(), "allowance", allowance.String(), "required", amount.String())
		return nil
	}
	c.payInfo("submitting USDFC approve", "owner", owner.Hex(), "spender", c.paymentsAddr.Hex(), "amount", amount.String(),
		"current_allowance", allowance.String())
	opts, err := bind.NewKeyedTransactorWithChainID(c.signerKey, c.chainID)
	if err != nil {
		return fmt.Errorf("filpay: transactor: %w", err)
	}
	opts.Context = ctx
	tx, err := usdfc.Approve(opts, c.paymentsAddr, amount)
	if err != nil {
		return fmt.Errorf("filpay: approve USDFC: %w", err)
	}
	c.payInfo("approve tx submitted", "tx_hash", tx.Hash().Hex(), "owner", owner.Hex(), "amount", amount.String())
	return c.waitTxMined(ctx, tx, "approve USDFC")
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
	txHash := tx.Hash().Hex()
	c.payInfo("waiting for tx confirmation", "operation", op, "tx_hash", txHash)
	if c.txProgress != nil {
		c.txProgress.TxSubmitted(op, txHash)
	}
	start := time.Now()
	done := make(chan struct{})
	if c.txProgress != nil {
		go c.runTxWaitProgress(op, txHash, start, done)
	}
	receipt, err := c.receiptForTx(waitCtx, tx)
	close(done)
	elapsed := time.Since(start)
	if err != nil {
		return fmt.Errorf("filpay: wait mined (%s): %w", op, err)
	}
	if receipt == nil {
		return fmt.Errorf("filpay: wait mined (%s): nil receipt", op)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return fmt.Errorf("filpay: %s tx reverted: %s", op, txHash)
	}
	block := receipt.BlockNumber.String()
	c.payInfo("tx confirmed", "operation", op, "tx_hash", txHash, "block", block)
	if c.txProgress != nil {
		c.txProgress.TxConfirmed(op, txHash, elapsed, block)
	}
	return nil
}

func (c *Client) runTxWaitProgress(op, txHash string, start time.Time, done <-chan struct{}) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			c.txProgress.TxWaiting(op, txHash, time.Since(start))
		}
	}
}

// PreparePayerForPayee tries to set operator approval and fund payer account.
// It then verifies a token rail exists from payer -> payee.
func (c *Client) PreparePayerForPayee(ctx context.Context, payer, payee common.Address, requiredBaseUnits *big.Int) error {
	c.payInfo("prepare payer start", "payer", payer.Hex(), "payee", payee.Hex(), "required_base_units", requiredBaseUnits.String())
	if err := c.EnsureOperatorApproval(ctx, payer, payer); err != nil {
		return err
	}
	if err := c.EnsurePayerTokenBalance(ctx, payer, requiredBaseUnits); err != nil {
		return err
	}
	railID, err := c.FindActiveTokenRail(ctx, payer, payee)
	if err != nil {
		c.payInfo("no active rail found; attempting createRail", "payer", payer.Hex(), "payee", payee.Hex(), "operator", c.signerAddr.Hex())
		if _, createErr := c.CreateTokenRail(ctx, payer, payee); createErr != nil {
			return fmt.Errorf("filpay: createRail failed after approval+deposit: %w (initial rail check: %v)", createErr, err)
		}
		railID, err = c.FindActiveTokenRail(ctx, payer, payee)
		if err != nil {
			return fmt.Errorf("filpay: createRail submitted but rail still not visible yet (retry later): %w", err)
		}
	}
	c.payInfo("prepare payer complete", "payer", payer.Hex(), "payee", payee.Hex(), "rail_id", railID.String())
	return nil
}

// FindActiveTokenRail returns a rail ID where payer pays payee in the correct token, rail not terminated and not past end epoch.
func (c *Client) FindActiveTokenRail(ctx context.Context, payer, payee common.Address) (*big.Int, error) {
	if payer == (common.Address{}) || payee == (common.Address{}) {
		return nil, errors.New("filpay: empty payer or payee")
	}
	nowEp := synpayments.CurrentEpoch(c.chainID.Int64())
	c.payInfo("searching token rails", "payer", payer.Hex(), "payee", payee.Hex(), "current_epoch", nowEp.String())
	offset := big.NewInt(0)
	limit := big.NewInt(100)
	for {
		c.payDebug("getRailsForPayerAndToken page", "offset", offset.String(), "limit", limit.String())
		results, nextOff, total, err := c.payments.GetRailsForPayerAndToken(ctx, payer, c.paymentToken, offset, limit)
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
			if view.Token != c.paymentToken {
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
			c.payInfo("selected active token rail", "rail_id", ri.RailId.String(),
				"from", view.From.Hex(), "to", view.To.Hex(),
				"operator", view.Operator.Hex(), "settled_up_to", view.SettledUpTo.String(), "end_epoch", view.EndEpoch.String())
			return ri.RailId, nil
		}
		if nextOff.Cmp(big.NewInt(0)) == 0 || len(results) < int(limit.Int64()) {
			break
		}
		offset = nextOff
	}
	c.payInfo("no matching token rail", "payer", payer.Hex(), "payee", payee.Hex())
	return nil, fmt.Errorf("filpay: no active token rail from %s to %s", payer.Hex(), payee.Hex())
}

// CreditRailPayment verifies a client modifyRailPayment tx and returns the gross charge
// parsed from RailOneTimePaymentProcessed for the payer→payee rail (net payee amount plus
// operator commission and network fee). The settlement ledger credits the payer pool at this
// gross so it matches the quoted price; only the net payee amount is withdrawable on-chain
// and the SP absorbs commission and network fees as transaction costs.
func (c *Client) CreditRailPayment(ctx context.Context, payer, payee common.Address, paymentTxHash string) (creditRef string, creditedBaseUnits *big.Int, err error) {
	txHash := strings.TrimSpace(paymentTxHash)
	c.payInfo("CreditRailPayment start", "payer", payer.Hex(), "payee", payee.Hex(), "payment_tx_hash", txHash)
	if len(txHash) != 66 || !strings.HasPrefix(txHash, "0x") {
		return "", nil, fmt.Errorf("filpay: invalid payment tx hash %q", paymentTxHash)
	}
	txHashBytes := common.FromHex(txHash)
	if len(txHashBytes) != common.HashLength {
		return "", nil, fmt.Errorf("filpay: invalid payment tx hash %q", paymentTxHash)
	}
	receipt, err := c.fetchTransactionReceipt(ctx, common.BytesToHash(txHashBytes))
	if err != nil {
		return "", nil, fmt.Errorf("filpay: payment tx receipt: %w", err)
	}
	byRail, err := sumRailOneTimePaymentGross(receipt, c.paymentsAddr)
	if err != nil {
		return "", nil, err
	}
	if len(byRail) == 0 {
		return "", nil, fmt.Errorf("filpay: payment tx has no RailOneTimePaymentProcessed events")
	}

	total := new(big.Int)
	var matchedRail string
	for railKey, gross := range byRail {
		if gross == nil || gross.Sign() <= 0 {
			continue
		}
		railID, ok := new(big.Int).SetString(railKey, 10)
		if !ok {
			return "", nil, fmt.Errorf("filpay: invalid rail id %q in payment receipt", railKey)
		}
		view, err := c.payments.GetRail(ctx, railID)
		if err != nil {
			return "", nil, fmt.Errorf("filpay: get rail %s from payment tx: %w", railKey, err)
		}
		if view.Token != c.paymentToken || view.From != payer || view.To != payee {
			continue
		}
		total.Add(total, gross)
		matchedRail = railKey
	}
	if total.Sign() <= 0 {
		return "", nil, fmt.Errorf("filpay: payment tx has no RailOneTimePaymentProcessed for rail from %s to %s", payer.Hex(), payee.Hex())
	}
	c.payInfo("CreditRailPayment complete", "payment_tx_hash", txHash, "rail_id", matchedRail,
		"credited_base_units", total.String(), "payer", payer.Hex(), "payee", payee.Hex())
	return txHash, total, nil
}

func (c *Client) fetchTransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
	if c.transactionReceipt != nil {
		return c.transactionReceipt(ctx, txHash)
	}
	if c.eth == nil {
		return nil, errors.New("filpay: no eth client for tx receipt")
	}
	return c.eth.TransactionReceipt(ctx, txHash)
}

func (c *Client) erc20() (erc20API, error) {
	if c.usdfc != nil {
		return c.usdfc, nil
	}
	cli, ok := c.eth.(*ethclient.Client)
	if !ok || cli == nil {
		return nil, errors.New("filpay: no eth client for USDFC")
	}
	erc, err := contracts.NewERC20Contract(c.paymentToken, cli)
	if err != nil {
		return nil, fmt.Errorf("filpay: bind USDFC: %w", err)
	}
	return erc, nil
}

func (c *Client) receiptForTx(ctx context.Context, tx *types.Transaction) (*types.Receipt, error) {
	if c.waitMined != nil {
		return c.waitMined(ctx, tx)
	}
	if c.eth == nil {
		return nil, errors.New("filpay: no eth client for tx wait")
	}
	return bind.WaitMined(ctx, c.eth, tx)
}

func resolvePaymentToken(chainID int64) (common.Address, error) {
	if addr, ok := constants.USDFCAddressesByChainID[chainID]; ok && addr != (common.Address{}) {
		return addr, nil
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
		return common.Address{}, fmt.Errorf("filpay: unknown USDFC token for chain %d", chainID)
	}
	addr := constants.USDFCAddresses[net]
	if addr == (common.Address{}) {
		return common.Address{}, fmt.Errorf("filpay: unknown USDFC token for chain %d", chainID)
	}
	return addr, nil
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
