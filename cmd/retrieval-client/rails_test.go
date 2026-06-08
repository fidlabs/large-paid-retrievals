package main

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/data-preservation-programs/go-synapse/constants"
	"github.com/ethereum/go-ethereum/common"
	"github.com/fidlabs/paid-retrievals/internal/filpay"
)

type mockFilpayOps struct {
	signer          common.Address
	approval        *filpay.OperatorApprovalStatus
	approvalErr     error
	avail           *big.Int
	accountErr      error
	railID          *big.Int
	railErr         error
	rails           []filpay.TokenRailDetail
	listRailsErr    error
	prepareErr      error
	chargeTx        string
	chargeErr       error
	prepareCalls    int
	chargeCalls     int
	preparedByPayee map[string]*big.Int
}

func (m *mockFilpayOps) Close() {}

func (m *mockFilpayOps) SignerAddress() common.Address { return m.signer }

func (m *mockFilpayOps) ChainID() *big.Int { return big.NewInt(constants.ChainIDCalibration) }

func (m *mockFilpayOps) PaymentsAddress() common.Address {
	return common.HexToAddress("0x1111111111111111111111111111111111111111")
}

func (m *mockFilpayOps) OperatorApproval(ctx context.Context, payer, operator common.Address) (*filpay.OperatorApprovalStatus, error) {
	if m.approvalErr != nil {
		return nil, m.approvalErr
	}
	if m.approval != nil {
		return m.approval, nil
	}
	return &filpay.OperatorApprovalStatus{Approved: true}, nil
}

func (m *mockFilpayOps) AccountInfoIfSettled(ctx context.Context, payer common.Address) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
	if m.accountErr != nil {
		return nil, nil, nil, nil, m.accountErr
	}
	avail := m.avail
	if avail == nil {
		avail = big.NewInt(1_000_000)
	}
	return big.NewInt(0), big.NewInt(0), avail, big.NewInt(0), nil
}

func (m *mockFilpayOps) FindActiveTokenRail(ctx context.Context, payer, payee common.Address) (*big.Int, error) {
	if m.railErr != nil {
		return nil, m.railErr
	}
	if m.railID != nil {
		return m.railID, nil
	}
	return big.NewInt(1), nil
}

func (m *mockFilpayOps) ListTokenRailsAsPayer(ctx context.Context, payer common.Address) ([]filpay.TokenRailDetail, error) {
	if m.listRailsErr != nil {
		return nil, m.listRailsErr
	}
	return m.rails, nil
}

func (m *mockFilpayOps) PreparePayerForPayee(ctx context.Context, payer, payee common.Address, required *big.Int) error {
	m.prepareCalls++
	if m.preparedByPayee == nil {
		m.preparedByPayee = map[string]*big.Int{}
	}
	if required != nil {
		m.preparedByPayee[payee.Hex()] = new(big.Int).Set(required)
	}
	return m.prepareErr
}

func (m *mockFilpayOps) ChargeRailOneTime(ctx context.Context, payer, payee common.Address, amount *big.Int) (string, error) {
	m.chargeCalls++
	if m.chargeErr != nil {
		return "", m.chargeErr
	}
	if m.chargeTx != "" {
		return m.chargeTx, nil
	}
	return "0xcharge", nil
}

func TestPrepareRailsForChallenges(t *testing.T) {
	payee := "0x2222222222222222222222222222222222222222"
	client := "0x1111111111111111111111111111111111111111"
	mock := &mockFilpayOps{
		signer: common.HexToAddress(client),
		railID: big.NewInt(7),
	}
	items := []challengeItem{{
		CID: "bafy1", DealUUID: "11111111-2222-3333-4444-555555555555",
		PriceUSDFC: "0.01", Payee0x: payee, Free: false,
	}}
	if err := prepareRailsForChallenges(context.Background(), mock, client, items, true); err != nil {
		t.Fatal(err)
	}
	if mock.prepareCalls != 1 {
		t.Fatalf("prepare calls=%d", mock.prepareCalls)
	}
}

func TestPrepareRailsAggregatesRequiredByPayee(t *testing.T) {
	payee := "0x2222222222222222222222222222222222222222"
	client := "0x1111111111111111111111111111111111111111"
	mock := &mockFilpayOps{signer: common.HexToAddress(client)}
	items := []challengeItem{
		{CID: "bafy1", DealUUID: "d1", PriceUSDFC: "0.01", Payee0x: payee, Free: false},
		{CID: "bafy2", DealUUID: "d2", PriceUSDFC: "0.02", Payee0x: payee, Free: false},
	}
	if err := prepareRailsForChallenges(context.Background(), mock, client, items, false); err != nil {
		t.Fatal(err)
	}
	if mock.prepareCalls != 1 {
		t.Fatalf("expected one prepare call for shared payee, got %d", mock.prepareCalls)
	}
	got, ok := mock.preparedByPayee[common.HexToAddress(payee).Hex()]
	if !ok {
		t.Fatalf("missing prepared amount for payee %s", payee)
	}
	// 0.01 + 0.02 USDFC in base units.
	want := big.NewInt(30_000_000_000_000_000)
	if got.Cmp(want) != 0 {
		t.Fatalf("prepared amount=%s want=%s", got.String(), want.String())
	}
}

func TestPrepareRailsSkipsFree(t *testing.T) {
	mock := &mockFilpayOps{signer: common.HexToAddress("0x1111111111111111111111111111111111111111")}
	items := []challengeItem{{CID: "bafy1", Free: true, PriceUSDFC: "0.01", Payee0x: "0x2222222222222222222222222222222222222222"}}
	if err := prepareRailsForChallenges(context.Background(), mock, mock.signer.Hex(), items, false); err != nil {
		t.Fatal(err)
	}
	if mock.prepareCalls != 0 {
		t.Fatal("free item should skip prepare")
	}
}

func TestPrepareRailsInvalidPayee(t *testing.T) {
	mock := &mockFilpayOps{signer: common.HexToAddress("0x1111111111111111111111111111111111111111")}
	items := []challengeItem{{CID: "bafy1", DealUUID: "d", PriceUSDFC: "0.01", Payee0x: "not-an-address"}}
	err := prepareRailsForChallenges(context.Background(), mock, mock.signer.Hex(), items, false)
	if err == nil || !strings.Contains(err.Error(), "payee_0x") {
		t.Fatalf("got %v", err)
	}
}

func TestPrepareRailsInvalidPrice(t *testing.T) {
	mock := &mockFilpayOps{signer: common.HexToAddress("0x1111111111111111111111111111111111111111")}
	items := []challengeItem{{
		CID: "bafy1", DealUUID: "d", PriceUSDFC: "not-a-number",
		Payee0x: "0x2222222222222222222222222222222222222222",
	}}
	err := prepareRailsForChallenges(context.Background(), mock, mock.signer.Hex(), items, false)
	if err == nil {
		t.Fatal("expected price error")
	}
}

func TestChargeRailsForChallenges(t *testing.T) {
	payee := "0x2222222222222222222222222222222222222222"
	client := "0x1111111111111111111111111111111111111111"
	mock := &mockFilpayOps{signer: common.HexToAddress(client), chargeTx: "0xabc"}
	items := []challengeItem{{
		CID: "bafy1", DealUUID: "11111111-2222-3333-4444-555555555555",
		PriceUSDFC: "0.05", Payee0x: payee,
	}}
	txByPayee, err := chargeRailsForChallenges(context.Background(), mock, client, items, false)
	if err != nil {
		t.Fatal(err)
	}
	if mock.chargeCalls != 1 {
		t.Fatalf("charge calls=%d", mock.chargeCalls)
	}
	if txByPayee[common.HexToAddress(payee).Hex()] != "0xabc" {
		t.Fatalf("tx map=%v", txByPayee)
	}
}

func TestChargeRailsAggregatesByPayee(t *testing.T) {
	payee := "0x2222222222222222222222222222222222222222"
	client := "0x1111111111111111111111111111111111111111"
	mock := &mockFilpayOps{signer: common.HexToAddress(client)}
	items := []challengeItem{
		{CID: "bafy1", DealUUID: "d1", PriceUSDFC: "0.01", Payee0x: payee},
		{CID: "bafy2", DealUUID: "d2", PriceUSDFC: "0.02", Payee0x: payee},
	}
	if _, err := chargeRailsForChallenges(context.Background(), mock, client, items, false); err != nil {
		t.Fatal(err)
	}
	if mock.chargeCalls != 1 {
		t.Fatalf("expected single charge per payee, got %d", mock.chargeCalls)
	}
}

func TestChargeRailsError(t *testing.T) {
	mock := &mockFilpayOps{
		signer:    common.HexToAddress("0x1111111111111111111111111111111111111111"),
		chargeErr: errors.New("charge failed"),
	}
	items := []challengeItem{{
		CID: "bafy1", DealUUID: "d", PriceUSDFC: "0.01",
		Payee0x: "0x2222222222222222222222222222222222222222",
	}}
	_, err := chargeRailsForChallenges(context.Background(), mock, mock.signer.Hex(), items, false)
	if err == nil || !strings.Contains(err.Error(), "charge failed") {
		t.Fatalf("got %v", err)
	}
}
