package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fidlabs/paid-retrievals/internal/pieceaccess"
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
	c.Flags().DurationVar(&settings.DBRetention, "db-retention", 7*24*time.Hour, "Max age of SQLite rows before automatic pruning (unpaid deals, expired allocations, closed pools); must be >= 12h or 0 to disable")
	c.Flags().DurationVar(&settings.PayWithdrawInterval, "pay-withdraw-interval", time.Hour, "Interval for background batch withdraw of Filecoin Pay proceeds to the settler wallet; 0 disables")
	c.Flags().StringVar(&settings.PriceUSDFCPerGB, "price-usdfc-per-gb", "0.01", "USDFC per GiB; total charge is rate * ceil(piece_bytes/2^30) from upstream HEAD Content-Length")
	c.Flags().StringVar(&settings.ClientQuery, "client-query", "client", "Query key used to identify client on challenge requests")
	c.Flags().StringVar(&settings.ClientHeader, "client-header", "X-Client-Address", "Header key used to identify client on challenge requests")
	c.Flags().IntVar(&settings.MaxSkewSec, "max-clock-skew-sec", 30, "Allowed clock skew in seconds for header expiry")
	c.Flags().BoolVar(&settings.Verbose, "verbose", false, "Enable debug-level structured logs")

	c.Flags().StringVar(&settings.PayRPCURL, "pay-rpc-url", getenv("SP_PROXY_PAY_RPC_URL", "https://api.node.glif.io/rpc/v1"), "Filecoin RPC (FVM) for payments contract")
	c.Flags().StringVar(&settings.PayPrivateKey, "pay-private-key", "", "Hex private key for Filecoin Pay settler wallet (RPC reads and on-chain withdraw); prefer env or file")
	c.Flags().StringVar(&settings.PayPrivateKeyFile, "pay-private-key-file", "", "File containing hex private key for Filecoin Pay")
	c.Flags().StringVar(&settings.PayPrivateKeyEnv, "pay-private-key-env", getenv("SP_PROXY_PAY_PRIVATE_KEY_ENV", "SP_PROXY_PAY_PRIVATE_KEY"), "Env var for Filecoin Pay private key")
	c.Flags().StringVar(&settings.PayPaymentsAddress, "pay-payments-address", getenv("SP_PROXY_PAY_PAYMENTS_ADDRESS", ""), "Filecoin Pay payments contract (0x); empty = built-in address for chain")
	c.Flags().StringVar(&settings.PayTokenAddress, "pay-token-address", getenv("SP_PROXY_PAY_TOKEN_ADDRESS", ""), "USDFC token (0x); empty = built-in address for chain (required override on Curio/FOC localnet)")
	c.Flags().StringVar(&settings.PayPayeeAddress, "pay-payee-address", getenv("SP_PROXY_PAY_PAYEE_ADDRESS", ""), "FVM address clients should open/fund rails to; empty = settlement wallet address")
	c.Flags().BoolVar(&settings.PayDebug, "pay-debug", false, "Log Filecoin Pay and settlement pool steps (funding, drawdown, balances); Info level. Implied filpay trace; use with --verbose for more RPC detail")
	c.Flags().StringVar(&settings.UpstreamHost, "upstream-host", getenv("SP_PROXY_UPSTREAM_HOST", "127.0.0.1"), "Upstream HTTP server host for proxied /piece requests")
	c.Flags().IntVar(&settings.UpstreamPort, "upstream-port", mustParsePort(getenv("SP_PROXY_UPSTREAM_PORT", "8788")), "Upstream HTTP server port for proxied /piece requests")
	c.Flags().StringVar(&settings.PorepCDPURL, "porep-cdp-url", getenv("SP_PROXY_POREP_CDP_URL", pieceaccess.DefaultCDPBaseURL), "CDP base URL for piece CID → deal (GET /po-rep/deals?pieceCID=…; default https://cdp.allocator.tech; local Curio: http://127.0.0.1:23300). Empty disables")
	c.Flags().Uint64Var(&settings.PorepProviderID, "porep-provider-id", mustParseUint64(getenv("SP_PROXY_POREP_PROVIDER_ID", "0")), "Miner actor ID (f0…) used to filter CDP deals")
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

func mustParseUint64(raw string) uint64 {
	v, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0
	}
	return v
}
