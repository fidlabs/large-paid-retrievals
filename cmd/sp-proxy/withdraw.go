package main

import (
	"context"
	"log/slog"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

const payWithdrawTimeout = 10 * time.Minute

// payeeWithdrawer moves available USDFC from a Filecoin Pay account to wallet.
type payeeWithdrawer interface {
	WithdrawPayeeProceeds(ctx context.Context, payee common.Address) (txHash string, amountBaseUnits *big.Int, err error)
	SignerAddress() common.Address
}

// startPayeeWithdrawWorker batches withdraw of available payee proceeds on a background
// ticker so concurrent retrievals do not race on-chain nonces. interval <= 0 disables.
func startPayeeWithdrawWorker(fc payeeWithdrawer, interval time.Duration, logger *slog.Logger) {
	if interval <= 0 {
		logger.Info("payee withdraw disabled", "pay_withdraw_interval", interval.String())
		return
	}
	payee := fc.SignerAddress()
	logger.Info("payee withdraw enabled",
		"pay_withdraw_interval", interval.String(),
		"payee", payee.Hex(),
	)
	go func() {
		withdraw := func() {
			ctx, cancel := context.WithTimeout(context.Background(), payWithdrawTimeout)
			defer cancel()
			txHash, amount, err := fc.WithdrawPayeeProceeds(ctx, payee)
			if err != nil {
				logger.Error("payee withdraw failed", "error", err, "payee", payee.Hex())
				return
			}
			if amount.Sign() > 0 {
				logger.Info("payee withdraw complete",
					"payee", payee.Hex(),
					"withdraw_tx", txHash,
					"amount_base_units", amount.String(),
				)
				return
			}
			logger.Debug("payee withdraw skipped", "payee", payee.Hex(), "reason", "no available balance")
		}
		withdraw()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			withdraw()
		}
	}()
}
