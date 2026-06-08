// Unit tests for filpay settlement logic using injectable mocks (paymentsAPI, erc20API,
// waitMined) via testClient. Production code paths are unchanged when hooks are nil.
//
// Trade-offs:
//   - Speed and determinism: no live RPC or simulated chain; tests run entirely in-process.
//   - Coverage focus: business rules, validation, rail selection, balance/approval checks, and
//     error wrapping. Bound-contract writes (createRail, modifyRailPayment, modifyRailLockup,
//     withdraw) are exercised via injectable paymentsRailsTransactor (see rails_test.go), not
//     bind.NewBoundContract against a live RPC backend.
//   - Tx confirmation: waitMined is stubbed to return synthetic receipts; bind.WaitMined and
//     receipt status handling are covered without mining blocks.
//   - USDFC: tests inject mockERC20; the real erc20() path still requires *ethclient.Client
//     (see TestEnsurePayerTokenBalanceNoERC20Client). Deposit/approve flows are tested with mocks,
//     not go-synapse ERC20Contract binding against an RPC backend.
//   - Client construction: NewClient dial/bind coverage lives in rpc_test.go; here we build
//     Client structs directly to avoid coupling every test to JSON-RPC.
package filpay

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/data-preservation-programs/go-synapse/constants"
	"github.com/data-preservation-programs/go-synapse/contracts"
	synpayments "github.com/data-preservation-programs/go-synapse/payments"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

func testPrivateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	pk, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func testHexKey(t *testing.T, pk *ecdsa.PrivateKey) string {
	t.Helper()
	return common.Bytes2Hex(crypto.FromECDSA(pk))
}

// testClient builds a calibration-chain Client with no eth field; use opts to set waitMined,
// usdfc, or replace payments for a scenario.
func testClient(t *testing.T, pay paymentsAPI, opts ...func(*Client)) *Client {
	t.Helper()
	pk := testPrivateKey(t)
	signer := crypto.PubkeyToAddress(pk.PublicKey)
	token := constants.USDFCAddressesByChainID[constants.ChainIDCalibration]
	c := &Client{
		payments:     pay,
		chainID:      big.NewInt(constants.ChainIDCalibration),
		signerKey:    pk,
		signerAddr:   signer,
		paymentsAddr: common.HexToAddress("0x1111111111111111111111111111111111111111"),
		paymentToken: token,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

func testTx(t *testing.T) *types.Transaction {
	t.Helper()
	pk := testPrivateKey(t)
	signer := types.NewEIP155Signer(big.NewInt(constants.ChainIDCalibration))
	tx := types.NewTransaction(1, common.Address{}, big.NewInt(0), 21000, big.NewInt(1), nil)
	signed, err := types.SignTx(tx, signer, pk)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func successReceipt() *types.Receipt {
	return &types.Receipt{Status: types.ReceiptStatusSuccessful, BlockNumber: big.NewInt(42)}
}

// mockPayments implements paymentsAPI. Per-test func fields keep scenarios isolated without
// a full eth/simulated backend; unset methods return safe zero values or explicit errors.
type mockPayments struct {
	operatorApproval func(ctx context.Context, token, client, operator common.Address) (bool, *big.Int, *big.Int, *big.Int, *big.Int, *big.Int, error)
	accountInfo      func(ctx context.Context, token, owner common.Address) (*big.Int, *big.Int, *big.Int, *big.Int, error)
	railsForPayer    func(ctx context.Context, payer, token common.Address, offset, limit *big.Int) ([]contracts.RailInfoResult, *big.Int, *big.Int, error)
	rail             func(ctx context.Context, railID *big.Int) (*contracts.RailViewResult, error)
	setOperator      func(opts *bind.TransactOpts, token, operator common.Address, approved bool, rateAllowance, lockupAllowance, maxLockupPeriod *big.Int) (*types.Transaction, error)
	deposit          func(opts *bind.TransactOpts, token, to common.Address, amount *big.Int) (*types.Transaction, error)
}

func (m *mockPayments) GetOperatorApproval(ctx context.Context, token, client, operator common.Address) (bool, *big.Int, *big.Int, *big.Int, *big.Int, *big.Int, error) {
	if m.operatorApproval != nil {
		return m.operatorApproval(ctx, token, client, operator)
	}
	return false, big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), nil
}

func (m *mockPayments) GetAccountInfoIfSettled(ctx context.Context, token, owner common.Address) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
	if m.accountInfo != nil {
		return m.accountInfo(ctx, token, owner)
	}
	return big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), nil
}

func (m *mockPayments) GetRailsForPayerAndToken(ctx context.Context, payer, token common.Address, offset, limit *big.Int) ([]contracts.RailInfoResult, *big.Int, *big.Int, error) {
	if m.railsForPayer != nil {
		return m.railsForPayer(ctx, payer, token, offset, limit)
	}
	return nil, big.NewInt(0), big.NewInt(0), nil
}

func (m *mockPayments) GetRail(ctx context.Context, railID *big.Int) (*contracts.RailViewResult, error) {
	if m.rail != nil {
		return m.rail(ctx, railID)
	}
	return nil, errors.New("no rail")
}

func (m *mockPayments) SetOperatorApproval(opts *bind.TransactOpts, token, operator common.Address, approved bool, rateAllowance, lockupAllowance, maxLockupPeriod *big.Int) (*types.Transaction, error) {
	if m.setOperator != nil {
		return m.setOperator(opts, token, operator, approved, rateAllowance, lockupAllowance, maxLockupPeriod)
	}
	return nil, errors.New("setOperatorApproval not configured")
}

func (m *mockPayments) Deposit(opts *bind.TransactOpts, token, to common.Address, amount *big.Int) (*types.Transaction, error) {
	if m.deposit != nil {
		return m.deposit(opts, token, to, amount)
	}
	return nil, errors.New("deposit not configured")
}

// mockERC20 implements erc20API so EnsurePayerTokenBalance / ensureUSDFCApproval avoid
// binding USDFC against a real ethclient in unit tests.
type mockERC20 struct {
	balance   func(ctx context.Context, account common.Address) (*big.Int, error)
	allowance func(ctx context.Context, owner, spender common.Address) (*big.Int, error)
	approve   func(opts *bind.TransactOpts, spender common.Address, amount *big.Int) (*types.Transaction, error)
}

func (m *mockERC20) BalanceOf(ctx context.Context, account common.Address) (*big.Int, error) {
	if m.balance != nil {
		return m.balance(ctx, account)
	}
	return big.NewInt(0), nil
}

func (m *mockERC20) Allowance(ctx context.Context, owner, spender common.Address) (*big.Int, error) {
	if m.allowance != nil {
		return m.allowance(ctx, owner, spender)
	}
	return big.NewInt(0), nil
}

func (m *mockERC20) Approve(opts *bind.TransactOpts, spender common.Address, amount *big.Int) (*types.Transaction, error) {
	if m.approve != nil {
		return m.approve(opts, spender, amount)
	}
	return nil, errors.New("approve not configured")
}

func TestLoadPrivateKey(t *testing.T) {
	pk := testPrivateKey(t)
	hex := testHexKey(t, pk)

	t.Run("hex", func(t *testing.T) {
		got, err := LoadPrivateKey(hex, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if crypto.PubkeyToAddress(got.PublicKey) != crypto.PubkeyToAddress(pk.PublicKey) {
			t.Fatal("key mismatch")
		}
	})

	t.Run("0x prefix", func(t *testing.T) {
		got, err := loadPrivateKey("0x"+hex, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if crypto.PubkeyToAddress(got.PublicKey) != crypto.PubkeyToAddress(pk.PublicKey) {
			t.Fatal("key mismatch")
		}
	})

	t.Run("file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "key.txt")
		if err := os.WriteFile(path, []byte(hex), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := loadPrivateKey("", path, "")
		if err != nil {
			t.Fatal(err)
		}
		if crypto.PubkeyToAddress(got.PublicKey) != crypto.PubkeyToAddress(pk.PublicKey) {
			t.Fatal("key mismatch")
		}
	})

	t.Run("env", func(t *testing.T) {
		t.Setenv("FILPAY_TEST_KEY", hex)
		got, err := loadPrivateKey("", "", "FILPAY_TEST_KEY")
		if err != nil {
			t.Fatal(err)
		}
		if crypto.PubkeyToAddress(got.PublicKey) != crypto.PubkeyToAddress(pk.PublicKey) {
			t.Fatal("key mismatch")
		}
	})

	t.Run("default env name", func(t *testing.T) {
		t.Setenv("SP_PROXY_PAY_PRIVATE_KEY", hex)
		got, err := loadPrivateKey("", "", "")
		if err != nil {
			t.Fatal(err)
		}
		if crypto.PubkeyToAddress(got.PublicKey) != crypto.PubkeyToAddress(pk.PublicKey) {
			t.Fatal("key mismatch")
		}
	})

	t.Run("missing", func(t *testing.T) {
		_, err := loadPrivateKey("", "", "")
		if err == nil || !strings.Contains(err.Error(), "missing private key") {
			t.Fatalf("expected missing key error, got %v", err)
		}
	})

	t.Run("bad hex", func(t *testing.T) {
		_, err := loadPrivateKey("not-hex", "", "")
		if err == nil || !strings.Contains(err.Error(), "parse private key") {
			t.Fatalf("expected parse error, got %v", err)
		}
	})

	t.Run("bad file", func(t *testing.T) {
		_, err := loadPrivateKey("", filepath.Join(t.TempDir(), "missing.txt"), "")
		if err == nil || !strings.Contains(err.Error(), "read key file") {
			t.Fatalf("expected read error, got %v", err)
		}
	})
}

func TestResolvePaymentsAddress(t *testing.T) {
	explicit := common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if got := resolvePaymentsAddress(explicit.Hex(), constants.ChainIDCalibration); got != explicit {
		t.Fatalf("explicit: got %s", got.Hex())
	}
	if got := resolvePaymentsAddress("", constants.ChainIDCalibration); got == (common.Address{}) {
		t.Fatal("expected calibration default address")
	}
	if got := resolvePaymentsAddress("", 999999); got != (common.Address{}) {
		t.Fatalf("unknown chain should be zero, got %s", got.Hex())
	}
	if addr, ok := synpayments.PaymentsAddresses[constants.ChainIDMainnet]; ok {
		if got := resolvePaymentsAddress("", constants.ChainIDMainnet); got != addr {
			t.Fatalf("mainnet map: got %s want %s", got.Hex(), addr.Hex())
		}
	}
}

func TestResolvePaymentTokenDevnet(t *testing.T) {
	got, err := resolvePaymentToken(constants.ChainIDDevnet)
	if err != nil {
		t.Fatal(err)
	}
	if got != constants.USDFCAddresses[constants.NetworkDevnet] {
		t.Fatalf("got %s", got.Hex())
	}
}

func TestResolvePaymentsAddressDevnet(t *testing.T) {
	got := resolvePaymentsAddress("", constants.ChainIDDevnet)
	want := constants.PaymentsAddresses[constants.NetworkDevnet]
	if got != want {
		t.Fatalf("got %s want %s", got.Hex(), want.Hex())
	}
}

func TestResolvePaymentToken(t *testing.T) {
	calib := constants.USDFCAddressesByChainID[constants.ChainIDCalibration]
	got, err := resolvePaymentToken(constants.ChainIDCalibration)
	if err != nil || got != calib {
		t.Fatalf("calibration: got %s err %v", got.Hex(), err)
	}
	got, err = resolvePaymentToken(constants.ChainIDMainnet)
	if err != nil || got != constants.USDFCAddresses[constants.NetworkMainnet] {
		t.Fatalf("mainnet: got %s err %v", got.Hex(), err)
	}
	got, err = resolvePaymentToken(constants.ChainIDDevnet)
	if err != nil || got != constants.USDFCAddresses[constants.NetworkDevnet] {
		t.Fatalf("devnet: got %s err %v", got.Hex(), err)
	}
	_, err = resolvePaymentToken(424242)
	if err == nil || !strings.Contains(err.Error(), "unknown USDFC") {
		t.Fatalf("expected unknown chain error, got %v", err)
	}
}

func TestNewClientEmptyRPC(t *testing.T) {
	_, err := NewClient(context.Background(), "  ", testHexKey(t, testPrivateKey(t)), "", "", "")
	if err == nil || err.Error() != "filpay: empty RPC URL" {
		t.Fatalf("got %v", err)
	}
}

func TestWithPayLogging(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c := testClient(t, &mockPayments{}, WithPayLogging(log, true))
	c.payInfo("trace-me", "k", "v")
	if !strings.Contains(buf.String(), "trace-me") || !strings.Contains(buf.String(), "filpay") {
		t.Fatalf("expected trace log, got %q", buf.String())
	}
	buf.Reset()
	c.payTrace = false
	c.payInfo("hidden")
	if buf.Len() != 0 {
		t.Fatalf("expected no log without trace, got %q", buf.String())
	}
	c.payDebug("debug-me")
	if !strings.Contains(buf.String(), "debug-me") {
		t.Fatalf("expected debug log, got %q", buf.String())
	}
}

func TestClientAccessors(t *testing.T) {
	var c *Client
	if c.ChainID() != nil {
		t.Fatal("nil client ChainID should be nil")
	}
	c = testClient(t, &mockPayments{})
	if c.ChainID().Int64() != constants.ChainIDCalibration {
		t.Fatalf("chain id %s", c.ChainID())
	}
	if c.SignerAddress() != c.signerAddr {
		t.Fatal("signer mismatch")
	}
	if c.PaymentsAddress() != c.paymentsAddr {
		t.Fatal("payments addr mismatch")
	}
	c.Close() // nil eth is fine
}

func TestOperatorApproval(t *testing.T) {
	payer := common.HexToAddress("0x1000000000000000000000000000000000000001")
	op := common.HexToAddress("0x2000000000000000000000000000000000000002")
	c := testClient(t, &mockPayments{
		operatorApproval: func(ctx context.Context, token, client, operator common.Address) (bool, *big.Int, *big.Int, *big.Int, *big.Int, *big.Int, error) {
			return true, big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4), big.NewInt(5), nil
		},
	})
	st, err := c.OperatorApproval(context.Background(), payer, op)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Approved || st.RateAllowance.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("unexpected status %+v", st)
	}
}

func TestPayerTokenAvailable(t *testing.T) {
	payer := common.HexToAddress("0x1000000000000000000000000000000000000001")
	c := testClient(t, &mockPayments{
		accountInfo: func(ctx context.Context, token, owner common.Address) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
			return big.NewInt(0), big.NewInt(0), big.NewInt(99), big.NewInt(0), nil
		},
	})
	avail, err := c.PayerTokenAvailable(context.Background(), payer)
	if err != nil || avail.Cmp(big.NewInt(99)) != 0 {
		t.Fatalf("avail=%s err=%v", avail, err)
	}
}

func TestEnsureOperatorApproval(t *testing.T) {
	ctx := context.Background()
	payer := common.HexToAddress("0x1000000000000000000000000000000000000001")

	c := testClient(t, &mockPayments{})
	if err := c.EnsureOperatorApproval(ctx, common.Address{}, payer); err == nil {
		t.Fatal("expected empty payer error")
	}
	if err := c.EnsureOperatorApproval(ctx, payer, common.Address{}); err == nil {
		t.Fatal("expected empty operator error")
	}

	approved := testClient(t, &mockPayments{
		operatorApproval: func(ctx context.Context, token, client, operator common.Address) (bool, *big.Int, *big.Int, *big.Int, *big.Int, *big.Int, error) {
			return true, big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), nil
		},
	})
	if err := approved.EnsureOperatorApproval(ctx, approved.signerAddr, approved.signerAddr); err != nil {
		t.Fatal(err)
	}

	mismatch := testClient(t, &mockPayments{
		operatorApproval: func(ctx context.Context, token, client, operator common.Address) (bool, *big.Int, *big.Int, *big.Int, *big.Int, *big.Int, error) {
			return false, nil, nil, nil, nil, nil, nil
		},
	})
	if err := mismatch.EnsureOperatorApproval(ctx, payer, payer); err == nil || !strings.Contains(err.Error(), "does not match signer") {
		t.Fatalf("expected signer mismatch, got %v", err)
	}
}

func TestFindActiveTokenRail(t *testing.T) {
	ctx := context.Background()
	payer := common.HexToAddress("0x1000000000000000000000000000000000000001")
	payee := common.HexToAddress("0x2000000000000000000000000000000000000002")
	token := constants.USDFCAddressesByChainID[constants.ChainIDCalibration]
	railID := big.NewInt(7)

	c := testClient(t, &mockPayments{})
	if _, err := c.FindActiveTokenRail(ctx, common.Address{}, payee); err == nil {
		t.Fatal("expected empty payer error")
	}

	active := testClient(t, &mockPayments{
		railsForPayer: func(ctx context.Context, p, tok common.Address, offset, limit *big.Int) ([]contracts.RailInfoResult, *big.Int, *big.Int, error) {
			return []contracts.RailInfoResult{{
				RailId:       railID,
				IsTerminated: false,
				EndEpoch:     big.NewInt(0),
			}}, big.NewInt(0), big.NewInt(1), nil
		},
		rail: func(ctx context.Context, id *big.Int) (*contracts.RailViewResult, error) {
			return &contracts.RailViewResult{
				Token: token, From: payer, To: payee,
				SettledUpTo: big.NewInt(0), EndEpoch: big.NewInt(0),
			}, nil
		},
	})
	got, err := active.FindActiveTokenRail(ctx, payer, payee)
	if err != nil || got.Cmp(railID) != 0 {
		t.Fatalf("rail=%s err=%v", got, err)
	}

	skips := testClient(t, &mockPayments{
		railsForPayer: func(ctx context.Context, p, tok common.Address, offset, limit *big.Int) ([]contracts.RailInfoResult, *big.Int, *big.Int, error) {
			return []contracts.RailInfoResult{
				{RailId: big.NewInt(1), IsTerminated: true},
				{RailId: big.NewInt(2), IsTerminated: false},
				{RailId: big.NewInt(3), IsTerminated: false},
				{RailId: big.NewInt(4), IsTerminated: false},
			}, big.NewInt(0), big.NewInt(4), nil
		},
		rail: func(ctx context.Context, id *big.Int) (*contracts.RailViewResult, error) {
			switch id.Int64() {
			case 2:
				return &contracts.RailViewResult{Token: common.HexToAddress("0xdead"), From: payer, To: payee}, nil
			case 3:
				return &contracts.RailViewResult{Token: token, From: payer, To: common.HexToAddress("0xbad")}, nil
			case 4:
				return &contracts.RailViewResult{Token: token, From: payer, To: payee, EndEpoch: big.NewInt(1)}, nil
			default:
				return nil, errors.New("skip")
			}
		},
	})
	if _, err := skips.FindActiveTokenRail(ctx, payer, payee); err == nil || !strings.Contains(err.Error(), "no active token rail") {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestListTokenRailsAsPayer(t *testing.T) {
	payer := common.HexToAddress("0x1000000000000000000000000000000000000001")
	token := constants.USDFCAddressesByChainID[constants.ChainIDCalibration]
	r1, r2 := big.NewInt(1), big.NewInt(2)

	c := testClient(t, &mockPayments{
		railsForPayer: func(ctx context.Context, p, tok common.Address, offset, limit *big.Int) ([]contracts.RailInfoResult, *big.Int, *big.Int, error) {
			return []contracts.RailInfoResult{
				{RailId: r1, IsTerminated: false},
				{RailId: r2, IsTerminated: true},
			}, big.NewInt(0), big.NewInt(2), nil
		},
		rail: func(ctx context.Context, id *big.Int) (*contracts.RailViewResult, error) {
			if id.Cmp(r2) == 0 {
				return nil, errors.New("get rail failed")
			}
			return &contracts.RailViewResult{Token: token, From: payer, To: common.HexToAddress("0x2")}, nil
		},
	})
	rails, err := c.ListTokenRailsAsPayer(context.Background(), payer)
	if err != nil || len(rails) != 2 {
		t.Fatalf("len=%d err=%v", len(rails), err)
	}
	if rails[0].RailID.Cmp(r1) != 0 || rails[0].From != payer {
		t.Fatalf("first rail %+v", rails[0])
	}
	if rails[1].To != (common.Address{}) {
		t.Fatalf("second rail should lack view on getRail error: %+v", rails[1])
	}
}

func TestEnsureRailLockup(t *testing.T) {
	ctx := context.Background()
	railID := big.NewInt(3)
	amount := big.NewInt(100)

	c := testClient(t, &mockPayments{})
	if err := c.EnsureRailLockup(ctx, nil, amount); err == nil {
		t.Fatal("expected invalid rail id")
	}
	if err := c.EnsureRailLockup(ctx, railID, big.NewInt(0)); err == nil {
		t.Fatal("expected invalid amount")
	}

	sufficient := testClient(t, &mockPayments{})
	sufficient.payments = &mockPayments{
		rail: func(ctx context.Context, id *big.Int) (*contracts.RailViewResult, error) {
			return &contracts.RailViewResult{Operator: sufficient.signerAddr, LockupFixed: big.NewInt(200)}, nil
		},
	}
	if err := sufficient.EnsureRailLockup(ctx, railID, amount); err != nil {
		t.Fatal(err)
	}

	notOp := testClient(t, &mockPayments{
		rail: func(ctx context.Context, id *big.Int) (*contracts.RailViewResult, error) {
			return &contracts.RailViewResult{Operator: common.HexToAddress("0x9999"), LockupFixed: big.NewInt(0)}, nil
		},
	})
	if err := notOp.EnsureRailLockup(ctx, railID, amount); err == nil || !strings.Contains(err.Error(), "not rail operator") {
		t.Fatalf("got %v", err)
	}
}

func TestEnsurePayerTokenBalance(t *testing.T) {
	ctx := context.Background()
	required := big.NewInt(100)

	c := testClient(t, &mockPayments{})
	if err := c.EnsurePayerTokenBalance(ctx, c.signerAddr, nil); err == nil {
		t.Fatal("expected invalid amount")
	}

	sufficient := testClient(t, &mockPayments{
		accountInfo: func(ctx context.Context, token, owner common.Address) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
			return big.NewInt(0), big.NewInt(0), big.NewInt(200), big.NewInt(0), nil
		},
	})
	if err := sufficient.EnsurePayerTokenBalance(ctx, sufficient.signerAddr, required); err != nil {
		t.Fatal(err)
	}

	otherPayer := common.HexToAddress("0x1000000000000000000000000000000000000001")
	lowBal := testClient(t, &mockPayments{
		accountInfo: func(ctx context.Context, token, owner common.Address) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
			return big.NewInt(0), big.NewInt(0), big.NewInt(10), big.NewInt(0), nil
		},
	}, func(cl *Client) {
		cl.usdfc = &mockERC20{
			balance: func(ctx context.Context, account common.Address) (*big.Int, error) {
				return big.NewInt(5), nil
			},
		}
	})
	if err := lowBal.EnsurePayerTokenBalance(ctx, lowBal.signerAddr, required); err == nil || !strings.Contains(err.Error(), "insufficient USDFC") {
		t.Fatalf("got %v", err)
	}
	if err := lowBal.EnsurePayerTokenBalance(ctx, otherPayer, required); err == nil || !strings.Contains(err.Error(), "does not match signer") {
		t.Fatalf("got %v", err)
	}
}

func TestEnsureUSDFCApprovalViaDepositPath(t *testing.T) {
	ctx := context.Background()
	tx := testTx(t)
	pay := &mockPayments{
		accountInfo: func(ctx context.Context, token, owner common.Address) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
			return big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), nil
		},
		deposit: func(opts *bind.TransactOpts, token, to common.Address, amount *big.Int) (*types.Transaction, error) {
			return tx, nil
		},
	}
	c := testClient(t, pay, func(cl *Client) {
		cl.usdfc = &mockERC20{
			balance: func(ctx context.Context, account common.Address) (*big.Int, error) {
				return big.NewInt(1000), nil
			},
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
	if err := c.EnsurePayerTokenBalance(ctx, c.signerAddr, big.NewInt(50)); err != nil {
		t.Fatal(err)
	}
}

func TestWithdrawTokenAvailable(t *testing.T) {
	ctx := context.Background()
	other := common.HexToAddress("0x1000000000000000000000000000000000000001")
	c := testClient(t, &mockPayments{
		accountInfo: func(ctx context.Context, token, owner common.Address) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
			return big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), nil
		},
	})
	if _, _, err := c.WithdrawTokenAvailable(ctx, other); err == nil || !strings.Contains(err.Error(), "does not match signer") {
		t.Fatalf("got %v", err)
	}
	h, amt, err := c.WithdrawTokenAvailable(ctx, c.signerAddr)
	if err != nil || h != "" || amt.Sign() != 0 {
		t.Fatalf("hash=%q amt=%s err=%v", h, amt, err)
	}
}

func TestWaitTxMined(t *testing.T) {
	ctx := context.Background()
	c := testClient(t, &mockPayments{})
	if err := c.waitTxMined(ctx, nil, "op"); err == nil || !strings.Contains(err.Error(), "nil tx") {
		t.Fatalf("got %v", err)
	}
	c.waitMined = func(ctx context.Context, tx *types.Transaction) (*types.Receipt, error) {
		return nil, errors.New("wait failed")
	}
	if err := c.waitTxMined(ctx, testTx(t), "op"); err == nil || !strings.Contains(err.Error(), "wait mined") {
		t.Fatalf("got %v", err)
	}
	c.waitMined = func(ctx context.Context, tx *types.Transaction) (*types.Receipt, error) {
		return nil, nil
	}
	if err := c.waitTxMined(ctx, testTx(t), "op"); err == nil || !strings.Contains(err.Error(), "nil receipt") {
		t.Fatalf("got %v", err)
	}
	c.waitMined = func(ctx context.Context, tx *types.Transaction) (*types.Receipt, error) {
		return &types.Receipt{Status: types.ReceiptStatusFailed}, nil
	}
	if err := c.waitTxMined(ctx, testTx(t), "op"); err == nil || !strings.Contains(err.Error(), "reverted") {
		t.Fatalf("got %v", err)
	}
	c.waitMined = func(ctx context.Context, tx *types.Transaction) (*types.Receipt, error) {
		return successReceipt(), nil
	}
	if err := c.waitTxMined(ctx, testTx(t), "op"); err != nil {
		t.Fatal(err)
	}
}

func TestPreparePayerForPayeeExistingRail(t *testing.T) {
	ctx := context.Background()
	payer := common.HexToAddress("0x1000000000000000000000000000000000000001")
	payee := common.HexToAddress("0x2000000000000000000000000000000000000002")
	token := constants.USDFCAddressesByChainID[constants.ChainIDCalibration]
	railID := big.NewInt(5)

	c := testClient(t, &mockPayments{
		operatorApproval: func(ctx context.Context, token, client, operator common.Address) (bool, *big.Int, *big.Int, *big.Int, *big.Int, *big.Int, error) {
			return true, big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), nil
		},
		accountInfo: func(ctx context.Context, token, owner common.Address) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
			return big.NewInt(0), big.NewInt(0), big.NewInt(500), big.NewInt(0), nil
		},
		railsForPayer: func(ctx context.Context, p, tok common.Address, offset, limit *big.Int) ([]contracts.RailInfoResult, *big.Int, *big.Int, error) {
			return []contracts.RailInfoResult{{RailId: railID, IsTerminated: false, EndEpoch: big.NewInt(0)}}, big.NewInt(0), big.NewInt(1), nil
		},
		rail: func(ctx context.Context, id *big.Int) (*contracts.RailViewResult, error) {
			return &contracts.RailViewResult{Token: token, From: payer, To: payee, EndEpoch: big.NewInt(0)}, nil
		},
	})
	// PreparePayerForPayee uses payer as operator too; use signer as payer for approval path.
	c.signerAddr = payer
	if err := c.PreparePayerForPayee(ctx, payer, payee, big.NewInt(10)); err != nil {
		t.Fatal(err)
	}
}

func TestChargeRailOneTimeValidation(t *testing.T) {
	c := testClient(t, &mockPayments{})
	if _, err := c.ChargeRailOneTime(context.Background(), c.signerAddr, c.signerAddr, big.NewInt(0)); err == nil {
		t.Fatal("expected invalid amount")
	}
}

func TestCreateTokenRailValidation(t *testing.T) {
	c := testClient(t, &mockPayments{})
	if _, err := c.CreateTokenRail(context.Background(), common.Address{}, c.signerAddr); err == nil {
		t.Fatal("expected empty payer")
	}
	other := common.HexToAddress("0x1000000000000000000000000000000000000001")
	if _, err := c.CreateTokenRail(context.Background(), other, c.signerAddr); err == nil || !strings.Contains(err.Error(), "does not match signer") {
		t.Fatalf("got %v", err)
	}
}

func TestEnsurePayerTokenBalanceNoERC20Client(t *testing.T) {
	c := testClient(t, &mockPayments{
		accountInfo: func(ctx context.Context, token, owner common.Address) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
			return big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), nil
		},
	})
	c.eth = nil
	err := c.EnsurePayerTokenBalance(context.Background(), c.signerAddr, big.NewInt(10))
	if err == nil || !strings.Contains(err.Error(), "no eth client for USDFC") {
		t.Fatalf("got %v", err)
	}
}

func TestFindActiveTokenRailListError(t *testing.T) {
	c := testClient(t, &mockPayments{
		railsForPayer: func(ctx context.Context, payer, token common.Address, offset, limit *big.Int) ([]contracts.RailInfoResult, *big.Int, *big.Int, error) {
			return nil, nil, nil, errors.New("rpc")
		},
	})
	_, err := c.FindActiveTokenRail(context.Background(), c.signerAddr, common.HexToAddress("0x2"))
	if err == nil || !strings.Contains(err.Error(), "list rails") {
		t.Fatalf("got %v", err)
	}
}

func TestAccountInfoIfSettledError(t *testing.T) {
	c := testClient(t, &mockPayments{
		accountInfo: func(ctx context.Context, token, owner common.Address) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
			return nil, nil, nil, nil, errors.New("not settled")
		},
	})
	_, _, _, _, err := c.AccountInfoIfSettled(context.Background(), c.signerAddr)
	if err == nil || !strings.Contains(err.Error(), "getAccountInfoIfSettled") {
		t.Fatalf("got %v", err)
	}
}

func TestEnsurePayerTokenBalanceDepositError(t *testing.T) {
	ctx := context.Background()
	tx := testTx(t)
	c := testClient(t, &mockPayments{
		accountInfo: func(ctx context.Context, token, owner common.Address) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
			return big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), nil
		},
		deposit: func(opts *bind.TransactOpts, token, to common.Address, amount *big.Int) (*types.Transaction, error) {
			return nil, errors.New("deposit rejected")
		},
	}, func(cl *Client) {
		cl.usdfc = &mockERC20{
			balance: func(ctx context.Context, account common.Address) (*big.Int, error) {
				return big.NewInt(100), nil
			},
			allowance: func(ctx context.Context, owner, spender common.Address) (*big.Int, error) {
				return big.NewInt(100), nil
			},
		}
	})
	if err := c.EnsurePayerTokenBalance(ctx, c.signerAddr, big.NewInt(50)); err == nil || !strings.Contains(err.Error(), "deposit USDFC") {
		t.Fatalf("got %v", err)
	}
	_ = tx
}

func TestAccountInfoIfSettled(t *testing.T) {
	payer := common.HexToAddress("0x1000000000000000000000000000000000000001")
	c := testClient(t, &mockPayments{
		accountInfo: func(ctx context.Context, token, owner common.Address) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
			return big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4), nil
		},
	})
	until, cur, avail, rate, err := c.AccountInfoIfSettled(context.Background(), payer)
	if err != nil {
		t.Fatal(err)
	}
	if until.Cmp(big.NewInt(1)) != 0 || cur.Cmp(big.NewInt(2)) != 0 || avail.Cmp(big.NewInt(3)) != 0 || rate.Cmp(big.NewInt(4)) != 0 {
		t.Fatalf("until=%s cur=%s avail=%s rate=%s", until, cur, avail, rate)
	}
}

func TestEnsureOperatorApprovalSetOperatorFails(t *testing.T) {
	ctx := context.Background()
	c := testClient(t, &mockPayments{
		operatorApproval: func(ctx context.Context, token, client, operator common.Address) (bool, *big.Int, *big.Int, *big.Int, *big.Int, *big.Int, error) {
			return false, big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), nil
		},
		setOperator: func(opts *bind.TransactOpts, token, operator common.Address, approved bool, rateAllowance, lockupAllowance, maxLockupPeriod *big.Int) (*types.Transaction, error) {
			return nil, errors.New("denied")
		},
	})
	err := c.EnsureOperatorApproval(ctx, c.signerAddr, c.signerAddr)
	if err == nil || !strings.Contains(err.Error(), "setOperatorApproval") {
		t.Fatalf("got %v", err)
	}
}

func TestEnsureOperatorApprovalSubmits(t *testing.T) {
	ctx := context.Background()
	op := common.HexToAddress("0x2000000000000000000000000000000000000002")
	tx := testTx(t)
	c := testClient(t, &mockPayments{
		operatorApproval: func(ctx context.Context, token, client, operator common.Address) (bool, *big.Int, *big.Int, *big.Int, *big.Int, *big.Int, error) {
			return false, big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), nil
		},
		setOperator: func(opts *bind.TransactOpts, token, operator common.Address, approved bool, rateAllowance, lockupAllowance, maxLockupPeriod *big.Int) (*types.Transaction, error) {
			return tx, nil
		},
	}, func(cl *Client) {
		cl.waitMined = func(ctx context.Context, tx *types.Transaction) (*types.Receipt, error) {
			return successReceipt(), nil
		}
	})
	if err := c.EnsureOperatorApproval(ctx, c.signerAddr, op); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureUSDFCAllowanceAlreadySufficient(t *testing.T) {
	ctx := context.Background()
	tx := testTx(t)
	c := testClient(t, &mockPayments{
		accountInfo: func(ctx context.Context, token, owner common.Address) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
			return big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), nil
		},
		deposit: func(opts *bind.TransactOpts, token, to common.Address, amount *big.Int) (*types.Transaction, error) {
			return tx, nil
		},
	}, func(cl *Client) {
		cl.usdfc = &mockERC20{
			balance: func(ctx context.Context, account common.Address) (*big.Int, error) {
				return big.NewInt(500), nil
			},
			allowance: func(ctx context.Context, owner, spender common.Address) (*big.Int, error) {
				return big.NewInt(500), nil
			},
		}
		cl.waitMined = func(ctx context.Context, tx *types.Transaction) (*types.Receipt, error) {
			return successReceipt(), nil
		}
	})
	if err := c.EnsurePayerTokenBalance(ctx, c.signerAddr, big.NewInt(100)); err != nil {
		t.Fatal(err)
	}
}

func TestPayerTokenAvailableError(t *testing.T) {
	c := testClient(t, &mockPayments{
		accountInfo: func(ctx context.Context, token, owner common.Address) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
			return nil, nil, nil, nil, errors.New("account unavailable")
		},
	})
	_, err := c.PayerTokenAvailable(context.Background(), c.signerAddr)
	if err == nil || !strings.Contains(err.Error(), "getAccountInfoIfSettled") {
		t.Fatalf("got %v", err)
	}
}

func TestListTokenRailsAsPayerError(t *testing.T) {
	c := testClient(t, &mockPayments{
		railsForPayer: func(ctx context.Context, payer, token common.Address, offset, limit *big.Int) ([]contracts.RailInfoResult, *big.Int, *big.Int, error) {
			return nil, nil, nil, errors.New("list failed")
		},
	})
	_, err := c.ListTokenRailsAsPayer(context.Background(), c.signerAddr)
	if err == nil || !strings.Contains(err.Error(), "list rails") {
		t.Fatalf("got %v", err)
	}
}

func TestFindActiveTokenRailPaginates(t *testing.T) {
	ctx := context.Background()
	payer := common.HexToAddress("0x1000000000000000000000000000000000000001")
	payee := common.HexToAddress("0x2000000000000000000000000000000000000002")
	token := constants.USDFCAddressesByChainID[constants.ChainIDCalibration]
	target := big.NewInt(100)
	page := 0
	c := testClient(t, &mockPayments{
		railsForPayer: func(ctx context.Context, p, tok common.Address, offset, limit *big.Int) ([]contracts.RailInfoResult, *big.Int, *big.Int, error) {
			page++
			if page == 1 {
				out := make([]contracts.RailInfoResult, 100)
				for i := range out {
					out[i] = contracts.RailInfoResult{RailId: big.NewInt(int64(i)), IsTerminated: true}
				}
				return out, big.NewInt(100), big.NewInt(101), nil
			}
			return []contracts.RailInfoResult{{RailId: target, IsTerminated: false, EndEpoch: big.NewInt(0)}}, big.NewInt(0), big.NewInt(101), nil
		},
		rail: func(ctx context.Context, id *big.Int) (*contracts.RailViewResult, error) {
			return &contracts.RailViewResult{Token: token, From: payer, To: payee, EndEpoch: big.NewInt(0)}, nil
		},
	})
	got, err := c.FindActiveTokenRail(ctx, payer, payee)
	if err != nil || got.Cmp(target) != 0 {
		t.Fatalf("rail=%s err=%v page=%d", got, err, page)
	}
}

func TestEnsureRailLockupGetRailError(t *testing.T) {
	c := testClient(t, &mockPayments{
		rail: func(ctx context.Context, id *big.Int) (*contracts.RailViewResult, error) {
			return nil, errors.New("missing rail")
		},
	})
	err := c.EnsureRailLockup(context.Background(), big.NewInt(1), big.NewInt(10))
	if err == nil || !strings.Contains(err.Error(), "get rail for lockup") {
		t.Fatalf("got %v", err)
	}
}

func TestEnsureOperatorApprovalRPCError(t *testing.T) {
	c := testClient(t, &mockPayments{
		operatorApproval: func(ctx context.Context, token, client, operator common.Address) (bool, *big.Int, *big.Int, *big.Int, *big.Int, *big.Int, error) {
			return false, nil, nil, nil, nil, nil, errors.New("rpc")
		},
	})
	err := c.EnsureOperatorApproval(context.Background(), c.signerAddr, c.signerAddr)
	if err == nil || !strings.Contains(err.Error(), "get operator approval") {
		t.Fatalf("got %v", err)
	}
}

func TestOperatorApprovalError(t *testing.T) {
	c := testClient(t, &mockPayments{
		operatorApproval: func(ctx context.Context, token, client, operator common.Address) (bool, *big.Int, *big.Int, *big.Int, *big.Int, *big.Int, error) {
			return false, nil, nil, nil, nil, nil, errors.New("rpc down")
		},
	})
	_, err := c.OperatorApproval(context.Background(), c.signerAddr, c.signerAddr)
	if err == nil || !strings.Contains(err.Error(), "get operator approval") {
		t.Fatalf("got %v", err)
	}
}

func TestPayLoggingNoLogger(t *testing.T) {
	c := testClient(t, &mockPayments{})
	c.payInfo("x")
	c.payDebug("y")
	c.log = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
	c.payDebug("z") // debug disabled at info level
}

func TestReceiptForTxNoEth(t *testing.T) {
	c := testClient(t, &mockPayments{})
	_, err := c.receiptForTx(context.Background(), testTx(t))
	if err == nil || !strings.Contains(err.Error(), "no eth client") {
		t.Fatalf("got %v", err)
	}
}

func TestErc20NoClient(t *testing.T) {
	c := testClient(t, &mockPayments{})
	_, err := c.erc20()
	if err == nil || !strings.Contains(err.Error(), "no eth client") {
		t.Fatalf("got %v", err)
	}
}
