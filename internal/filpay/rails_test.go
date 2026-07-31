// Tests for paymentsRailsTransactor injection: successful createRail, modifyRail*, and withdraw
// paths without bind.NewBoundContract or a live eth backend.
package filpay

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/data-preservation-programs/go-synapse/constants"
	"github.com/data-preservation-programs/go-synapse/contracts"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// mockRailsTransactor implements paymentsRailsTransactor for unit tests (no bind.NewBoundContract / eth).
type mockRailsTransactor struct {
	createRail        func(ctx context.Context, opts *bind.TransactOpts, payer, payee common.Address) (*types.Transaction, error)
	modifyRailPayment func(ctx context.Context, opts *bind.TransactOpts, railID, oneTimePayment *big.Int) (*types.Transaction, error)
	modifyRailLockup  func(ctx context.Context, opts *bind.TransactOpts, railID, period, lockupFixed *big.Int) (*types.Transaction, error)
	withdrawToken     func(ctx context.Context, opts *bind.TransactOpts, amount *big.Int) (*types.Transaction, error)
}

func (m *mockRailsTransactor) CreateTokenRail(ctx context.Context, opts *bind.TransactOpts, payer, payee common.Address) (*types.Transaction, error) {
	if m.createRail != nil {
		return m.createRail(ctx, opts, payer, payee)
	}
	return nil, errors.New("createRail not configured")
}

func (m *mockRailsTransactor) ModifyRailPayment(ctx context.Context, opts *bind.TransactOpts, railID, oneTimePayment *big.Int) (*types.Transaction, error) {
	if m.modifyRailPayment != nil {
		return m.modifyRailPayment(ctx, opts, railID, oneTimePayment)
	}
	return nil, errors.New("modifyRailPayment not configured")
}

func (m *mockRailsTransactor) ModifyRailLockup(ctx context.Context, opts *bind.TransactOpts, railID, period, lockupFixed *big.Int) (*types.Transaction, error) {
	if m.modifyRailLockup != nil {
		return m.modifyRailLockup(ctx, opts, railID, period, lockupFixed)
	}
	return nil, errors.New("modifyRailLockup not configured")
}

func (m *mockRailsTransactor) WithdrawToken(ctx context.Context, opts *bind.TransactOpts, amount *big.Int) (*types.Transaction, error) {
	if m.withdrawToken != nil {
		return m.withdrawToken(ctx, opts, amount)
	}
	return nil, errors.New("withdraw not configured")
}

func withMockRails(m *mockRailsTransactor) func(*Client) {
	return func(c *Client) {
		c.rails = m
		c.waitMined = func(ctx context.Context, tx *types.Transaction) (*types.Receipt, error) {
			return successReceipt(), nil
		}
	}
}

func activeRailPayments(payer, payee, operator common.Address, railID *big.Int) *mockPayments {
	token := constants.USDFCAddressesByChainID[constants.ChainIDCalibration]
	return &mockPayments{
		railsForPayer: func(ctx context.Context, p, tok common.Address, offset, limit *big.Int) ([]contracts.RailInfoResult, *big.Int, *big.Int, error) {
			return []contracts.RailInfoResult{{RailId: railID, IsTerminated: false, EndEpoch: big.NewInt(0)}}, big.NewInt(0), big.NewInt(1), nil
		},
		rail: func(ctx context.Context, id *big.Int) (*contracts.RailViewResult, error) {
			return &contracts.RailViewResult{
				Token: token, From: payer, To: payee, Operator: operator,
				LockupFixed: big.NewInt(0), EndEpoch: big.NewInt(0),
			}, nil
		},
	}
}

func TestCreateTokenRailSuccess(t *testing.T) {
	ctx := context.Background()
	payee := common.HexToAddress("0x2000000000000000000000000000000000000002")
	tx := testTx(t)
	c := testClient(t, &mockPayments{}, withMockRails(&mockRailsTransactor{
		createRail: func(ctx context.Context, opts *bind.TransactOpts, payer, payee common.Address) (*types.Transaction, error) {
			return tx, nil
		},
	}))
	hash, err := c.CreateTokenRail(ctx, c.signerAddr, payee)
	if err != nil || hash != tx.Hash().Hex() {
		t.Fatalf("hash=%q err=%v", hash, err)
	}
}

func TestEnsureRailLockupSubmitsModify(t *testing.T) {
	ctx := context.Background()
	railID := big.NewInt(3)
	amount := big.NewInt(100)
	tx := testTx(t)
	c := testClient(t, &mockPayments{})
	c.payments = &mockPayments{
		rail: func(ctx context.Context, id *big.Int) (*contracts.RailViewResult, error) {
			return &contracts.RailViewResult{Operator: c.signerAddr, LockupFixed: big.NewInt(0)}, nil
		},
	}
	withMockRails(&mockRailsTransactor{
		modifyRailLockup: func(ctx context.Context, opts *bind.TransactOpts, rid, period, lockup *big.Int) (*types.Transaction, error) {
			if rid.Cmp(railID) != 0 || lockup.Cmp(amount) != 0 {
				t.Fatalf("rail=%s lockup=%s", rid, lockup)
			}
			return tx, nil
		},
	})(c)
	if err := c.EnsureRailLockup(ctx, railID, amount); err != nil {
		t.Fatal(err)
	}
}

func TestChargeRailOneTimeSuccess(t *testing.T) {
	ctx := context.Background()
	payer := common.HexToAddress("0x1000000000000000000000000000000000000001")
	payee := common.HexToAddress("0x2000000000000000000000000000000000000002")
	railID := big.NewInt(8)
	tx := testTx(t)

	c := testClient(t, &mockPayments{})
	c.payments = activeRailPayments(payer, payee, c.signerAddr, railID)
	withMockRails(&mockRailsTransactor{
		modifyRailLockup: func(ctx context.Context, opts *bind.TransactOpts, rid, period, lockup *big.Int) (*types.Transaction, error) {
			return tx, nil
		},
		modifyRailPayment: func(ctx context.Context, opts *bind.TransactOpts, rid, oneTime *big.Int) (*types.Transaction, error) {
			return tx, nil
		},
	})(c)

	hash, err := c.ChargeRailOneTime(ctx, payer, payee, big.NewInt(50))
	if err != nil || hash != tx.Hash().Hex() {
		t.Fatalf("hash=%q err=%v", hash, err)
	}
}

func TestWithdrawPayeeProceeds(t *testing.T) {
	ctx := context.Background()
	other := common.HexToAddress("0x2000000000000000000000000000000000000002")
	tx := testTx(t)
	c := testClient(t, &mockPayments{
		accountInfo: func(ctx context.Context, token, owner common.Address) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
			return big.NewInt(0), big.NewInt(0), big.NewInt(42), big.NewInt(0), nil
		},
	}, withMockRails(&mockRailsTransactor{
		withdrawToken: func(ctx context.Context, opts *bind.TransactOpts, amount *big.Int) (*types.Transaction, error) {
			return tx, nil
		},
	}))

	hash, amt, err := c.WithdrawPayeeProceeds(ctx, other)
	if err != nil || hash != "" || amt.Sign() != 0 {
		t.Fatalf("other payee: hash=%q amt=%s err=%v", hash, amt, err)
	}
	hash, amt, err = c.WithdrawPayeeProceeds(ctx, c.signerAddr)
	if err != nil || hash != tx.Hash().Hex() || amt.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("signer payee: hash=%q amt=%s err=%v", hash, amt, err)
	}
}

func TestWithdrawTokenAvailableSuccess(t *testing.T) {
	ctx := context.Background()
	tx := testTx(t)
	c := testClient(t, &mockPayments{
		accountInfo: func(ctx context.Context, token, owner common.Address) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
			return big.NewInt(0), big.NewInt(0), big.NewInt(42), big.NewInt(0), nil
		},
	}, withMockRails(&mockRailsTransactor{
		withdrawToken: func(ctx context.Context, opts *bind.TransactOpts, amount *big.Int) (*types.Transaction, error) {
			if amount.Cmp(big.NewInt(42)) != 0 {
				t.Fatalf("amount %s", amount)
			}
			return tx, nil
		},
	}))
	hash, amt, err := c.WithdrawTokenAvailable(ctx, c.signerAddr)
	if err != nil || hash != tx.Hash().Hex() || amt.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("hash=%q amt=%s err=%v", hash, amt, err)
	}
}

func TestPreparePayerForPayeeCreatesRail(t *testing.T) {
	ctx := context.Background()
	payer := common.HexToAddress("0x1000000000000000000000000000000000000001")
	payee := common.HexToAddress("0x2000000000000000000000000000000000000002")
	token := constants.USDFCAddressesByChainID[constants.ChainIDCalibration]
	railID := big.NewInt(5)
	tx := testTx(t)
	listCalls := 0

	c := testClient(t, &mockPayments{
		operatorApproval: func(ctx context.Context, token, client, operator common.Address) (bool, *big.Int, *big.Int, *big.Int, *big.Int, *big.Int, error) {
			return true, big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), nil
		},
		accountInfo: func(ctx context.Context, token, owner common.Address) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
			return big.NewInt(0), big.NewInt(0), big.NewInt(500), big.NewInt(0), nil
		},
		railsForPayer: func(ctx context.Context, p, tok common.Address, offset, limit *big.Int) ([]contracts.RailInfoResult, *big.Int, *big.Int, error) {
			listCalls++
			if listCalls == 1 {
				return []contracts.RailInfoResult{}, big.NewInt(0), big.NewInt(0), nil
			}
			return []contracts.RailInfoResult{{RailId: railID, IsTerminated: false, EndEpoch: big.NewInt(0)}}, big.NewInt(0), big.NewInt(1), nil
		},
		rail: func(ctx context.Context, id *big.Int) (*contracts.RailViewResult, error) {
			return &contracts.RailViewResult{Token: token, From: payer, To: payee, Operator: payer, EndEpoch: big.NewInt(0)}, nil
		},
	})
	c.signerAddr = payer
	withMockRails(&mockRailsTransactor{
		createRail: func(ctx context.Context, opts *bind.TransactOpts, p, pe common.Address) (*types.Transaction, error) {
			return tx, nil
		},
	})(c)

	if err := c.PreparePayerForPayee(ctx, payer, payee, big.NewInt(10)); err != nil {
		t.Fatal(err)
	}
	if listCalls < 2 {
		t.Fatalf("expected rail list after create, got %d calls", listCalls)
	}
}

func TestPreparePayerForPayeeSkipsForeignOperatorCreatesRail(t *testing.T) {
	ctx := context.Background()
	payer := common.HexToAddress("0x1000000000000000000000000000000000000001")
	payee := common.HexToAddress("0x2000000000000000000000000000000000000002")
	foreignOp := common.HexToAddress("0x5607327BDc0CA5538faA108555Ce09D89075B527")
	token := constants.USDFCAddressesByChainID[constants.ChainIDCalibration]
	selfRailID := big.NewInt(11)
	tx := testTx(t)
	listCalls := 0
	created := false

	c := testClient(t, &mockPayments{
		operatorApproval: func(ctx context.Context, token, client, operator common.Address) (bool, *big.Int, *big.Int, *big.Int, *big.Int, *big.Int, error) {
			return true, big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), nil
		},
		accountInfo: func(ctx context.Context, token, owner common.Address) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
			return big.NewInt(0), big.NewInt(0), big.NewInt(500), big.NewInt(0), nil
		},
		railsForPayer: func(ctx context.Context, p, tok common.Address, offset, limit *big.Int) ([]contracts.RailInfoResult, *big.Int, *big.Int, error) {
			listCalls++
			if !created {
				return []contracts.RailInfoResult{{RailId: big.NewInt(10), IsTerminated: false, EndEpoch: big.NewInt(0)}}, big.NewInt(0), big.NewInt(1), nil
			}
			return []contracts.RailInfoResult{
				{RailId: big.NewInt(10), IsTerminated: false, EndEpoch: big.NewInt(0)},
				{RailId: selfRailID, IsTerminated: false, EndEpoch: big.NewInt(0)},
			}, big.NewInt(0), big.NewInt(2), nil
		},
		rail: func(ctx context.Context, id *big.Int) (*contracts.RailViewResult, error) {
			op := foreignOp
			if id.Cmp(selfRailID) == 0 {
				op = payer
			}
			return &contracts.RailViewResult{Token: token, From: payer, To: payee, Operator: op, EndEpoch: big.NewInt(0)}, nil
		},
	})
	c.signerAddr = payer
	withMockRails(&mockRailsTransactor{
		createRail: func(ctx context.Context, opts *bind.TransactOpts, p, pe common.Address) (*types.Transaction, error) {
			created = true
			return tx, nil
		},
	})(c)

	if err := c.PreparePayerForPayee(ctx, payer, payee, big.NewInt(10)); err != nil {
		t.Fatal(err)
	}
	if !created || listCalls < 2 {
		t.Fatalf("expected create after skipping foreign rail; created=%v listCalls=%d", created, listCalls)
	}
}

func TestCreateTokenRailRequiresTransactor(t *testing.T) {
	c := testClient(t, &mockPayments{})
	_, err := c.CreateTokenRail(context.Background(), c.signerAddr, common.HexToAddress("0x2"))
	if err == nil || !strings.Contains(err.Error(), "no eth client for payments transacts") {
		t.Fatalf("got %v", err)
	}
}

func TestEnsureUSDFCApprovalSubmitsApprove(t *testing.T) {
	ctx := context.Background()
	tx := testTx(t)
	c := testClient(t, &mockPayments{}, func(cl *Client) {
		cl.usdfc = &mockERC20{
			allowance: func(ctx context.Context, owner, spender common.Address) (*big.Int, error) {
				return big.NewInt(0), nil
			},
			approve: func(opts *bind.TransactOpts, spender common.Address, amount *big.Int) (*types.Transaction, error) {
				return tx, nil
			},
		}
		cl.waitMined = func(ctx context.Context, tx *types.Transaction) (*types.Receipt, error) {
			return successReceipt(), nil
		}
	})
	if err := c.ensureUSDFCApproval(ctx, c.signerAddr, big.NewInt(10)); err != nil {
		t.Fatal(err)
	}
}

func TestChargeRailOneTimeEnsureLockupFails(t *testing.T) {
	ctx := context.Background()
	payer := common.HexToAddress("0x1000000000000000000000000000000000000001")
	payee := common.HexToAddress("0x2000000000000000000000000000000000000002")
	railID := big.NewInt(8)

	c := testClient(t, &mockPayments{})
	// Foreign-operated rail is invisible to FindActiveTokenRail (signer must be operator).
	c.payments = activeRailPayments(payer, payee, common.HexToAddress("0x9999"), railID)
	_, err := c.ChargeRailOneTime(ctx, payer, payee, big.NewInt(50))
	if err == nil || !strings.Contains(err.Error(), "no active token rail") {
		t.Fatalf("got %v", err)
	}
}

func TestPreparePayerForPayeeRailNotVisibleAfterCreate(t *testing.T) {
	ctx := context.Background()
	payer := common.HexToAddress("0x1000000000000000000000000000000000000001")
	payee := common.HexToAddress("0x2000000000000000000000000000000000000002")
	tx := testTx(t)

	c := testClient(t, &mockPayments{
		operatorApproval: func(ctx context.Context, token, client, operator common.Address) (bool, *big.Int, *big.Int, *big.Int, *big.Int, *big.Int, error) {
			return true, big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), nil
		},
		accountInfo: func(ctx context.Context, token, owner common.Address) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
			return big.NewInt(0), big.NewInt(0), big.NewInt(500), big.NewInt(0), nil
		},
		railsForPayer: func(ctx context.Context, p, tok common.Address, offset, limit *big.Int) ([]contracts.RailInfoResult, *big.Int, *big.Int, error) {
			return []contracts.RailInfoResult{}, big.NewInt(0), big.NewInt(0), nil
		},
	})
	c.signerAddr = payer
	withMockRails(&mockRailsTransactor{
		createRail: func(ctx context.Context, opts *bind.TransactOpts, p, pe common.Address) (*types.Transaction, error) {
			return tx, nil
		},
	})(c)

	err := c.PreparePayerForPayee(ctx, payer, payee, big.NewInt(10))
	if err == nil || !strings.Contains(err.Error(), "rail still not visible") {
		t.Fatalf("got %v", err)
	}
}

func TestPreparePayerForPayeeCreateRailFails(t *testing.T) {
	ctx := context.Background()
	payer := common.HexToAddress("0x1000000000000000000000000000000000000001")
	payee := common.HexToAddress("0x2000000000000000000000000000000000000002")

	c := testClient(t, &mockPayments{
		operatorApproval: func(ctx context.Context, token, client, operator common.Address) (bool, *big.Int, *big.Int, *big.Int, *big.Int, *big.Int, error) {
			return true, big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), nil
		},
		accountInfo: func(ctx context.Context, token, owner common.Address) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
			return big.NewInt(0), big.NewInt(0), big.NewInt(500), big.NewInt(0), nil
		},
		railsForPayer: func(ctx context.Context, p, tok common.Address, offset, limit *big.Int) ([]contracts.RailInfoResult, *big.Int, *big.Int, error) {
			return []contracts.RailInfoResult{}, big.NewInt(0), big.NewInt(0), nil
		},
	})
	c.signerAddr = payer
	withMockRails(&mockRailsTransactor{
		createRail: func(ctx context.Context, opts *bind.TransactOpts, p, pe common.Address) (*types.Transaction, error) {
			return nil, errors.New("create denied")
		},
	})(c)

	err := c.PreparePayerForPayee(ctx, payer, payee, big.NewInt(10))
	if err == nil || !strings.Contains(err.Error(), "createRail failed") {
		t.Fatalf("got %v", err)
	}
}
