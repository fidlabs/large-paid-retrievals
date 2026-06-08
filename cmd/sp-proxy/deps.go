package main

import (
	"context"
	"net/http"

	"github.com/ethereum/go-ethereum/common"
	"github.com/fidlabs/paid-retrievals/internal/filpay"
	"github.com/fidlabs/paid-retrievals/internal/piecepayment"
	"github.com/fidlabs/paid-retrievals/internal/sqlitestore"
)

// proxyFilpay is the Filecoin Pay surface sp-proxy needs at startup and in piecepayment.Config.
type proxyFilpay interface {
	piecepayment.FilecoinPaySettler
	payeeWithdrawer
	PaymentsAddress() common.Address
	Close()
}

type openStoreFunc func(path string) (*sqlitestore.Store, error)

type newFilpayClientFunc func(
	ctx context.Context,
	rpcURL, privateKeyHex, privateKeyFile, privateKeyEnv, paymentsAddress string,
	opts ...filpay.Option,
) (proxyFilpay, error)

type listenFunc func(addr string, handler http.Handler) error

var (
	proxyOpenStore       openStoreFunc       = sqlitestore.OpenStore
	proxyNewFilpayClient newFilpayClientFunc = defaultProxyFilpayClient
	proxyListenAndServe  listenFunc          = http.ListenAndServe
)

func defaultProxyFilpayClient(
	ctx context.Context,
	rpcURL, privateKeyHex, privateKeyFile, privateKeyEnv, paymentsAddress string,
	opts ...filpay.Option,
) (proxyFilpay, error) {
	return filpay.NewClient(ctx, rpcURL, privateKeyHex, privateKeyFile, privateKeyEnv, paymentsAddress, opts...)
}
