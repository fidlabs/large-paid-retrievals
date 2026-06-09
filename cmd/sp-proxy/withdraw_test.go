package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

type stubPayeeWithdrawer struct {
	signer    common.Address
	withdraws atomic.Int32
	err       error
	amount    *big.Int
}

func (s *stubPayeeWithdrawer) SignerAddress() common.Address { return s.signer }

func (s *stubPayeeWithdrawer) WithdrawPayeeProceeds(context.Context, common.Address) (string, *big.Int, error) {
	s.withdraws.Add(1)
	if s.err != nil {
		return "", nil, s.err
	}
	amt := s.amount
	if amt == nil {
		amt = big.NewInt(0)
	}
	if amt.Sign() > 0 {
		return "0xwithdraw", amt, nil
	}
	return "", amt, nil
}

func TestStartPayeeWithdrawWorkerDisabled(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	w := &stubPayeeWithdrawer{signer: common.HexToAddress("0x1")}
	startPayeeWithdrawWorker(w, 0, logger)
	if !bytes.Contains(buf.Bytes(), []byte("payee withdraw disabled")) {
		t.Fatalf("log: %s", buf.String())
	}
	if w.withdraws.Load() != 0 {
		t.Fatalf("expected no withdraws, got %d", w.withdraws.Load())
	}
}

func TestStartPayeeWithdrawWorkerRunsOnce(t *testing.T) {
	w := &stubPayeeWithdrawer{
		signer: common.HexToAddress("0x1"),
		amount: big.NewInt(42),
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
	startPayeeWithdrawWorker(w, time.Hour, logger)
	deadline := time.Now().Add(500 * time.Millisecond)
	for w.withdraws.Load() < 1 {
		if time.Now().After(deadline) {
			t.Fatalf("expected initial withdraw, got %d", w.withdraws.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
