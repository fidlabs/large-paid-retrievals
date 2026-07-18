package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/fidlabs/paid-retrievals/internal/dealstore"
	"github.com/fidlabs/paid-retrievals/internal/filpay"
	"github.com/fidlabs/paid-retrievals/internal/pieceaccess"
	piecepayment "github.com/fidlabs/paid-retrievals/internal/piecepayment"
	"github.com/fidlabs/paid-retrievals/internal/sqlitestore"
)

type proxyAppSettings struct {
	Listen              string
	DBPath              string
	DBRetention         time.Duration
	PayWithdrawInterval time.Duration
	PriceUSDFCPerGB     string
	ClientQuery         string
	ClientHeader        string
	MaxSkewSec          int
	Verbose             bool

	PayRPCURL          string
	PayPrivateKey      string
	PayPrivateKeyFile  string
	PayPrivateKeyEnv   string
	PayPaymentsAddress string
	PayPayeeAddress    string
	PayDebug           bool

	UpstreamHost string
	UpstreamPort int
}

func validateUpstream(host string, port int) (*url.URL, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, fmt.Errorf("--upstream-host is required")
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid --upstream-port %d (must be in range 1-65535)", port)
	}
	upstreamURL, err := url.Parse("http://" + host + ":" + strconv.Itoa(port))
	if err != nil {
		return nil, fmt.Errorf("parse upstream URL: %w", err)
	}
	return upstreamURL, nil
}

func resolvePayee(payeeFlag string, fc proxyFilpay) (string, error) {
	payee := strings.TrimSpace(payeeFlag)
	if payee == "" {
		payee = fc.SignerAddress().Hex()
	}
	if !common.IsHexAddress(payee) {
		return "", fmt.Errorf("invalid --pay-payee-address %q (use 0x… FVM address or leave empty to use settlement wallet)", payee)
	}
	return payee, nil
}

func buildProxyHandler(
	upstreamURL *url.URL,
	upstreamHost string,
	upstreamPort int,
	store *sqlitestore.Store,
	fc proxyFilpay,
	payee string,
	settings proxyAppSettings,
	logger *slog.Logger,
) http.Handler {
	upstreamProxy := httputil.NewSingleHostReverseProxy(upstreamURL)
	upstreamProxy.ModifyResponse = preserveUpstreamContentLength
	upstreamProxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("upstream proxy request failed", "host", upstreamHost, "port", upstreamPort, "path", r.URL.Path, "error", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}

	filTrace := settings.PayDebug || settings.Verbose
	config := piecepayment.Config{
		PriceUSDFCPerGB: settings.PriceUSDFCPerGB,
		ClientQuery:     settings.ClientQuery,
		ClientHeader:    settings.ClientHeader,
		MaxClockSkew:    time.Duration(settings.MaxSkewSec) * time.Second,
		QuotePayee0x:    payee,
		PayDebug:        filTrace,
		FilecoinPay:     fc,
		Logger:          logger,
		Store:           store,
	}
	svc := piecepayment.NewRetrievalService(config)
	access := pieceaccess.NewAuthorizer()

	pieceHandler := buildPieceHandler(access, svc, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamProxy.ServeHTTP(w, r)
	}))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("incoming request", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			logger.Warn("method not allowed", "method", r.Method, "path", r.URL.Path)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == "/health" {
			logger.Debug("health check")
			w.Header().Set("Content-Type", "text/plain")
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			_, _ = w.Write([]byte("ok"))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/piece/") {
			pieceHandler.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
}

func runProxyApp(settings proxyAppSettings) error {
	upstreamURL, err := validateUpstream(settings.UpstreamHost, settings.UpstreamPort)
	if err != nil {
		return err
	}
	if err := dealstore.ValidateDBRetention(settings.DBRetention); err != nil {
		return err
	}

	store, err := proxyOpenStore(settings.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()

	level := slog.LevelInfo
	if settings.Verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	ctx := context.Background()
	filTrace := settings.PayDebug || settings.Verbose
	fc, err := proxyNewFilpayClient(ctx, settings.PayRPCURL, settings.PayPrivateKey, settings.PayPrivateKeyFile, settings.PayPrivateKeyEnv, settings.PayPaymentsAddress,
		filpay.WithPayLogging(logger, filTrace))
	if err != nil {
		return fmt.Errorf("filecoin pay: %w", err)
	}
	defer fc.Close()

	payee, err := resolvePayee(settings.PayPayeeAddress, fc)
	if err != nil {
		return err
	}

	handler := buildProxyHandler(upstreamURL, settings.UpstreamHost, settings.UpstreamPort, store, fc, payee, settings, logger)

	logger.Info("filecoin pay", "payments", fc.PaymentsAddress().Hex(), "payee_0x", payee, "settler", fc.SignerAddress().Hex(),
		"pay_debug_flag", settings.PayDebug, "filpay_trace", filTrace, "pool_trace", filTrace, "pay_http_trace", filTrace)
	logger.Info("sp-proxy listening", "listen", settings.Listen, "db", settings.DBPath, "price_usdfc_per_gb", settings.PriceUSDFCPerGB, "verbose", settings.Verbose,
		"sigusr1_dump", "Unix only: kill -USR1 <pid> dumps deals and settlement pools to stderr")

	startSIGUSR1StateDump(store, logger)
	startDBRetentionPruner(store, settings.DBRetention, logger)
	startPayeeWithdrawWorker(fc, settings.PayWithdrawInterval, logger)

	return proxyListenAndServe(settings.Listen, handler)
}

func buildPieceHandler(access *pieceaccess.Authorizer, svc *piecepayment.RetrievalService, upstream http.Handler) http.Handler {
	return access.Middleware(svc.PiecePaymentMiddleware(MaxHeaderSize)(upstream))
}

// preserveUpstreamContentLength sets resp.ContentLength from a Content-Length header
// when the upstream response is not chunked. Chunked responses are passed through
// unchanged so streaming SPs work; retrieval clients use probe HEAD for size hints.
func preserveUpstreamContentLength(resp *http.Response) error {
	if responseUsesChunkedEncoding(resp) {
		return nil
	}
	if resp.ContentLength >= 0 {
		return nil
	}
	cl := strings.TrimSpace(resp.Header.Get("Content-Length"))
	if cl == "" {
		return nil
	}
	n, err := strconv.ParseInt(cl, 10, 64)
	if err != nil || n < 0 {
		return nil
	}
	resp.ContentLength = n
	return nil
}

func responseUsesChunkedEncoding(resp *http.Response) bool {
	te := strings.ToLower(resp.Header.Get("Transfer-Encoding"))
	for _, part := range strings.Split(te, ",") {
		if strings.TrimSpace(part) == "chunked" {
			return true
		}
	}
	return false
}
