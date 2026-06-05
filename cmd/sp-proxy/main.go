package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

const MaxHeaderSize = 4096

func main() {
	if err := root().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func root() *cobra.Command {
	var settings proxyAppSettings
	c := &cobra.Command{
		Use:   "sp-proxy",
		Short: "Internet-facing /piece/<cid> MPP challenge + paid retrieval (Filecoin Pay + EVM)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProxyApp(settings)
		},
	}
	c.Flags().StringVar(&settings.Listen, "listen", ":8787", "Listen address")
	c.Flags().StringVar(&settings.DBPath, "db", "./sp-proxy.db", "SQLite deals database path")
	c.Flags().StringVar(&settings.PriceUSDFCPerGB, "price-usdfc-per-gb", "0.01", "USDFC per GiB; total charge is rate * ceil(piece_bytes/2^30) from upstream HEAD Content-Length")
	c.Flags().StringVar(&settings.ClientQuery, "client-query", "client", "Query key used to identify client on challenge requests")
	c.Flags().StringVar(&settings.ClientHeader, "client-header", "X-Client-Address", "Header key used to identify client on challenge requests")
	c.Flags().IntVar(&settings.MaxSkewSec, "max-clock-skew-sec", 30, "Allowed clock skew in seconds for header expiry")
	c.Flags().BoolVar(&settings.Verbose, "verbose", false, "Enable debug-level structured logs")

	c.Flags().StringVar(&settings.PayRPCURL, "pay-rpc-url", getenv("SP_PROXY_PAY_RPC_URL", "https://api.node.glif.io/rpc/v1"), "Filecoin RPC (FVM) for payments contract")
	c.Flags().StringVar(&settings.PayPrivateKey, "pay-private-key", "", "Hex private key for settleRail txs (prefer env or file)")
	c.Flags().StringVar(&settings.PayPrivateKeyFile, "pay-private-key-file", "", "File containing hex private key for settleRail")
	c.Flags().StringVar(&settings.PayPrivateKeyEnv, "pay-private-key-env", getenv("SP_PROXY_PAY_PRIVATE_KEY_ENV", "SP_PROXY_PAY_PRIVATE_KEY"), "Env var for settleRail private key")
	c.Flags().StringVar(&settings.PayPaymentsAddress, "pay-payments-address", getenv("SP_PROXY_PAY_PAYMENTS_ADDRESS", ""), "Filecoin Pay payments contract (0x); empty = built-in address for chain")
	c.Flags().StringVar(&settings.PayPayeeAddress, "pay-payee-address", getenv("SP_PROXY_PAY_PAYEE_ADDRESS", ""), "FVM address clients should open/fund rails to; empty = settlement wallet address")
	c.Flags().BoolVar(&settings.PayDebug, "pay-debug", false, "Log Filecoin Pay steps (HTTP + on-chain); Info level. Implied filpay trace; use with --verbose for more RPC detail")
	c.Flags().StringVar(&settings.UpstreamHost, "upstream-host", getenv("SP_PROXY_UPSTREAM_HOST", "127.0.0.1"), "Upstream HTTP server host for proxied /piece requests")
	c.Flags().IntVar(&settings.UpstreamPort, "upstream-port", mustParsePort(getenv("SP_PROXY_UPSTREAM_PORT", "8788")), "Upstream HTTP server port for proxied /piece requests")
	initCLIUsage(c)
	return c
}

func getenv(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func mustParsePort(raw string) int {
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 8788
	}
	return v
}
