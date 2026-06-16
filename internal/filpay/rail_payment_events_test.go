package filpay

import (
	"context"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/data-preservation-programs/go-synapse/constants"
	"github.com/data-preservation-programs/go-synapse/contracts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/fidlabs/paid-retrievals/internal/dealstore"
)

func mustBigInt(t *testing.T, s string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		t.Fatalf("invalid big.Int %q", s)
	}
	return n
}

func testRailOneTimePaymentReceipt(t *testing.T, paymentsAddr common.Address, railID, netPayee, commission, networkFee *big.Int) *types.Receipt {
	t.Helper()
	parsed, err := abi.JSON(strings.NewReader(railOneTimePaymentProcessedABI))
	if err != nil {
		t.Fatal(err)
	}
	ev := parsed.Events["RailOneTimePaymentProcessed"]
	data, err := ev.Inputs.NonIndexed().Pack(netPayee, commission, networkFee)
	if err != nil {
		t.Fatal(err)
	}
	return &types.Receipt{
		Status:      types.ReceiptStatusSuccessful,
		BlockNumber: big.NewInt(42),
		Logs: []*types.Log{{
			Address: paymentsAddr,
			Topics:  []common.Hash{railOneTimePaymentProcessedTopic, common.BigToHash(railID)},
			Data:    data,
		}},
	}
}

func withFreshBlockHeader(cl *Client) {
	cl.blockHeader = func(ctx context.Context, blockNumber *big.Int) (*types.Header, error) {
		return &types.Header{Time: uint64(time.Now().Unix())}, nil
	}
}

func TestSumRailOneTimePaymentCredit(t *testing.T) {
	paymentsAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	railID := big.NewInt(9)
	netPayee := big.NewInt(5_000_000_000_000_000_000)
	receipt := testRailOneTimePaymentReceipt(t, paymentsAddr, railID, netPayee, big.NewInt(0), big.NewInt(0))

	byRail, err := sumRailOneTimePaymentCredit(receipt, paymentsAddr)
	if err != nil {
		t.Fatal(err)
	}
	got := byRail[railID.String()]
	if got == nil || got.Cmp(netPayee) != 0 {
		t.Fatalf("byRail[%s]=%v want %s", railID, got, netPayee)
	}
}

func TestSumRailOneTimePaymentCreditWithFees(t *testing.T) {
	paymentsAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	railID := big.NewInt(9)
	netPayee := mustBigInt(t, "95000000000000000000")
	// A malicious client routes a large commission back to itself; it must NOT be credited.
	commission := big.NewInt(3_000_000_000_000_000_000)
	networkFee := big.NewInt(2_000_000_000_000_000_000)
	// credit = net + networkFee (commission excluded) = 95 + 2 = 97.
	wantCredit := mustBigInt(t, "97000000000000000000")
	receipt := testRailOneTimePaymentReceipt(t, paymentsAddr, railID, netPayee, commission, networkFee)

	byRail, err := sumRailOneTimePaymentCredit(receipt, paymentsAddr)
	if err != nil {
		t.Fatal(err)
	}
	got := byRail[railID.String()]
	if got == nil || got.Cmp(wantCredit) != 0 {
		t.Fatalf("byRail[%s]=%v want credit %s (commission must be excluded)", railID, got, wantCredit)
	}
}

func TestCreditRailPayment(t *testing.T) {
	ctx := context.Background()
	payer := common.HexToAddress("0x1000000000000000000000000000000000000001")
	payee := common.HexToAddress("0x2000000000000000000000000000000000000002")
	token := constants.USDFCAddressesByChainID[constants.ChainIDCalibration]
	railID := big.NewInt(9)
	netPayee := big.NewInt(5_000_000_000_000_000_000)
	tx := testTx(t)

	c := testClient(t, &mockPayments{
		rail: func(ctx context.Context, id *big.Int) (*contracts.RailViewResult, error) {
			return &contracts.RailViewResult{Token: token, From: payer, To: payee, EndEpoch: big.NewInt(0)}, nil
		},
	}, func(cl *Client) {
		withFreshBlockHeader(cl)
		cl.transactionReceipt = func(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
			if txHash != tx.Hash() {
				t.Fatalf("unexpected tx hash %s", txHash.Hex())
			}
			return testRailOneTimePaymentReceipt(t, cl.paymentsAddr, railID, netPayee, big.NewInt(0), big.NewInt(0)), nil
		}
	})

	ref, credited, err := c.CreditRailPayment(ctx, payer, payee, tx.Hash().Hex())
	if err != nil || ref != tx.Hash().Hex() || credited.Cmp(netPayee) != 0 {
		t.Fatalf("ref=%q credited=%s err=%v", ref, credited, err)
	}
}

func TestSumRailOneTimePaymentCreditErrors(t *testing.T) {
	paymentsAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	if _, err := sumRailOneTimePaymentCredit(nil, paymentsAddr); err == nil {
		t.Fatal("expected nil receipt error")
	}
	failed := &types.Receipt{Status: types.ReceiptStatusFailed}
	if _, err := sumRailOneTimePaymentCredit(failed, paymentsAddr); err == nil {
		t.Fatal("expected failed tx error")
	}
	empty := &types.Receipt{Status: types.ReceiptStatusSuccessful, Logs: nil}
	if byRail, err := sumRailOneTimePaymentCredit(empty, paymentsAddr); err != nil || len(byRail) != 0 {
		t.Fatalf("empty logs: byRail=%v err=%v", byRail, err)
	}
}

func TestCreditRailPaymentErrors(t *testing.T) {
	ctx := context.Background()
	payer := common.HexToAddress("0x1000000000000000000000000000000000000001")
	payee := common.HexToAddress("0x2000000000000000000000000000000000000002")
	c := testClient(t, &mockPayments{})

	if _, _, err := c.CreditRailPayment(ctx, payer, payee, "not-a-hash"); err == nil {
		t.Fatal("expected invalid hash error")
	}
	if _, _, err := c.CreditRailPayment(ctx, payer, payee, "0x1234"); err == nil {
		t.Fatal("expected short hash error")
	}

	tx := testTx(t)
	c = testClient(t, &mockPayments{}, func(cl *Client) {
		withFreshBlockHeader(cl)
		cl.transactionReceipt = func(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
			return &types.Receipt{Status: types.ReceiptStatusSuccessful, BlockNumber: big.NewInt(1), Logs: nil}, nil
		}
	})
	if _, _, err := c.CreditRailPayment(ctx, payer, payee, tx.Hash().Hex()); err == nil {
		t.Fatal("expected no events error")
	}
}

func TestFetchTransactionReceiptNoEthClient(t *testing.T) {
	c := testClient(t, &mockPayments{})
	_, err := c.fetchTransactionReceipt(context.Background(), common.Hash{1})
	if err == nil || !strings.Contains(err.Error(), "no eth client") {
		t.Fatalf("got %v", err)
	}
}

func TestCreditRailPaymentNonMatchingRail(t *testing.T) {
	ctx := context.Background()
	payer := common.HexToAddress("0x1000000000000000000000000000000000000001")
	payee := common.HexToAddress("0x2000000000000000000000000000000000000002")
	other := common.HexToAddress("0x3000000000000000000000000000000000000003")
	token := constants.USDFCAddressesByChainID[constants.ChainIDCalibration]
	railID := big.NewInt(9)
	tx := testTx(t)

	c := testClient(t, &mockPayments{
		rail: func(ctx context.Context, id *big.Int) (*contracts.RailViewResult, error) {
			return &contracts.RailViewResult{Token: token, From: payer, To: other, EndEpoch: big.NewInt(0)}, nil
		},
	}, func(cl *Client) {
		withFreshBlockHeader(cl)
		cl.transactionReceipt = func(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
			return testRailOneTimePaymentReceipt(t, cl.paymentsAddr, railID, big.NewInt(1), big.NewInt(0), big.NewInt(0)), nil
		}
	})
	if _, _, err := c.CreditRailPayment(ctx, payer, payee, tx.Hash().Hex()); err == nil {
		t.Fatal("expected no matching rail error")
	}
}

func TestWithTxProgress(t *testing.T) {
	var submitted bool
	c := testClient(t, &mockPayments{}, func(cl *Client) {
		WithTxProgress(txProgressFunc(func(op, txHash string) {
			submitted = op != "" && txHash != ""
		}))(cl)
	})
	if c.txProgress == nil {
		t.Fatal("expected tx progress")
	}
	c.txProgress.TxSubmitted("op", "0xabc")
	if !submitted {
		t.Fatal("progress callback not invoked")
	}
}

type txProgressFunc func(op, txHash string)

func (f txProgressFunc) TxSubmitted(op, txHash string) { f(op, txHash) }
func (txProgressFunc) TxWaiting(string, string, time.Duration) {
}
func (txProgressFunc) TxConfirmed(string, string, time.Duration, string) {}

func TestCreditRailPaymentWithFees(t *testing.T) {
	ctx := context.Background()
	payer := common.HexToAddress("0x1000000000000000000000000000000000000001")
	payee := common.HexToAddress("0x2000000000000000000000000000000000000002")
	token := constants.USDFCAddressesByChainID[constants.ChainIDCalibration]
	railID := big.NewInt(9)
	netPayee := mustBigInt(t, "95000000000000000000")
	commission := big.NewInt(3_000_000_000_000_000_000)
	networkFee := big.NewInt(2_000_000_000_000_000_000)
	// credit excludes the client-controllable commission: net + networkFee = 97.
	wantCredit := mustBigInt(t, "97000000000000000000")
	tx := testTx(t)

	c := testClient(t, &mockPayments{
		rail: func(ctx context.Context, id *big.Int) (*contracts.RailViewResult, error) {
			return &contracts.RailViewResult{Token: token, From: payer, To: payee, EndEpoch: big.NewInt(0)}, nil
		},
	}, func(cl *Client) {
		withFreshBlockHeader(cl)
		cl.transactionReceipt = func(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
			if txHash != tx.Hash() {
				t.Fatalf("unexpected tx hash %s", txHash.Hex())
			}
			return testRailOneTimePaymentReceipt(t, cl.paymentsAddr, railID, netPayee, commission, networkFee), nil
		}
	})

	ref, credited, err := c.CreditRailPayment(ctx, payer, payee, tx.Hash().Hex())
	if err != nil || ref != tx.Hash().Hex() || credited.Cmp(wantCredit) != 0 {
		t.Fatalf("ref=%q credited=%s want credit %s err=%v", ref, credited, wantCredit, err)
	}
}

func TestCreditRailPaymentRejectsStaleTx(t *testing.T) {
	ctx := context.Background()
	payer := common.HexToAddress("0x1000000000000000000000000000000000000001")
	payee := common.HexToAddress("0x2000000000000000000000000000000000000002")
	token := constants.USDFCAddressesByChainID[constants.ChainIDCalibration]
	railID := big.NewInt(9)
	tx := testTx(t)

	c := testClient(t, &mockPayments{
		rail: func(ctx context.Context, id *big.Int) (*contracts.RailViewResult, error) {
			return &contracts.RailViewResult{Token: token, From: payer, To: payee, EndEpoch: big.NewInt(0)}, nil
		},
	}, func(cl *Client) {
		cl.transactionReceipt = func(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
			return testRailOneTimePaymentReceipt(t, cl.paymentsAddr, railID, big.NewInt(1), big.NewInt(0), big.NewInt(0)), nil
		}
		cl.blockHeader = func(ctx context.Context, blockNumber *big.Int) (*types.Header, error) {
			stale := time.Now().Add(-dealstore.PaidAccessTTL - time.Hour)
			return &types.Header{Time: uint64(stale.Unix())}, nil
		}
	})
	if _, _, err := c.CreditRailPayment(ctx, payer, payee, tx.Hash().Hex()); err == nil || !strings.Contains(err.Error(), "older than") {
		t.Fatalf("expected stale tx error, got %v", err)
	}
}
