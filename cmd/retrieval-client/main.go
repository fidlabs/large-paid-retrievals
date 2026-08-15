package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/fidlabs/paid-retrievals/internal/filpay"
	"github.com/fidlabs/paid-retrievals/internal/mpp"
	"github.com/fidlabs/paid-retrievals/internal/paymentheader"
	"github.com/fidlabs/paid-retrievals/internal/pieceurls"
)

type filpayKeyOpts struct {
	privateKey     string
	privateKeyFile string
	privateKeyEnv  string
}

type problemDetails struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
}

type challengeItem struct {
	CID           string
	Base          *url.URL
	Free          bool
	TotalBytes    int64 // from probe HEAD; -1 when unknown
	DealUUID      string
	PriceUSDFC    string
	Payee0x       string
	PaymentTxHash string
	Challenge     mpp.Challenge
}

// filpayOperations is the Filecoin Pay surface used by fetch/rail-check (mockable in tests).
type filpayOperations interface {
	Close()
	SignerAddress() common.Address
	ChainID() *big.Int
	PaymentsAddress() common.Address
	OperatorApproval(ctx context.Context, payer, operator common.Address) (*filpay.OperatorApprovalStatus, error)
	AccountInfoIfSettled(ctx context.Context, payer common.Address) (fundedUntilEpoch, currentFunds, availableFunds, currentLockupRate *big.Int, err error)
	FindActiveTokenRail(ctx context.Context, payer, payee common.Address) (*big.Int, error)
	ListTokenRailsAsPayer(ctx context.Context, payer common.Address) ([]filpay.TokenRailDetail, error)
	PreparePayerForPayee(ctx context.Context, payer, payee common.Address, requiredBaseUnits *big.Int) error
	ChargeRailOneTime(ctx context.Context, payer, payee common.Address, amountBaseUnits *big.Int) (string, error)
}

// filpayNewClient is swapped in tests to avoid live RPC during command runs.
var filpayNewClient = func(ctx context.Context, rpcURL, privateKeyHex, privateKeyFile, privateKeyEnv, paymentsAddress string, opts ...filpay.Option) (filpayOperations, error) {
	return filpay.NewClient(ctx, rpcURL, privateKeyHex, privateKeyFile, privateKeyEnv, paymentsAddress, opts...)
}

// pieceDiscoveryClient discovers SP HTTP bases for a piece CID.
type pieceDiscoveryClient interface {
	DiscoverPieceHTTPBases(ctx context.Context, pieceCID string) ([]*url.URL, error)
}

// newPieceDiscoveryClient is swapped in tests to avoid live filecoin.tools / Lotus discovery.
var newPieceDiscoveryClient = func(httpClient *http.Client, lotusRPC string) pieceDiscoveryClient {
	return pieceurls.NewClient(httpClient, pieceurls.WithLotusRPC(lotusRPC))
}

// promptReader is swapped in tests (default stdin) for promptYesNo.
var promptReader io.Reader = os.Stdin

func main() {
	if err := root().ExecuteContext(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func root() *cobra.Command {
	keyOpts := &filpayKeyOpts{}
	r := &cobra.Command{
		Use:   "retrieval-client",
		Short: "Client CLI for MPP + Filecoin Pay piece retrieval (EVM client key)",
	}
	addFilpayKeyFlags(r, keyOpts)
	r.AddCommand(cmdFetch(keyOpts))
	r.AddCommand(cmdRailCheck(keyOpts))
	initCLIUsage(r)
	return r
}

func cmdFetch(keyOpts *filpayKeyOpts) *cobra.Command {
	var (
		spBaseURL          string
		outDir             string
		cids               []string
		manifest           string
		yes                bool
		dryRun             bool
		noProgress         bool
		expiresIn          int
		verbose            bool
		payDebug           bool
		parallel           int
		payRPCURL          string
		payPaymentsAddress string
		payTokenAddress    string
		vouchers           []string
		porepCDPURL        string
		porepProviderID    uint64
		porepMarketAddress string
	)
	c := &cobra.Command{
		Use:   "fetch",
		Short: "Fetch multiple piece CIDs: discover SP bases, MPP challenge (402), then EVM-signed paid retrieval",
		RunE: func(cmd *cobra.Command, args []string) error {
			evmPK, err := filpay.LoadPrivateKey(keyOpts.privateKey, keyOpts.privateKeyFile, keyOpts.privateKeyEnv)
			if err != nil {
				return fmt.Errorf("load client private key (--filpay-private-key* / %s): %w", keyOpts.privateKeyEnv, err)
			}
			client := crypto.PubkeyToAddress(evmPK.PublicKey).Hex()
			vouchers = normalizeVoucherFlags(vouchers)
			if verbose {
				fmt.Printf("Client 0x address (from private key): %s\n", client)
				if len(vouchers) > 0 {
					fmt.Printf("Access vouchers: %d\n", len(vouchers))
				}
			}
			if payDebug {
				payClientLog("client 0x=%s (derived from private key)", client)
			}

			var allCIDs []string
			if strings.TrimSpace(manifest) != "" {
				if len(cids) > 0 || len(args) > 0 {
					return errors.New("--manifest is mutually exclusive with positional CIDs and --cid")
				}
				var err error
				allCIDs, err = extractPieceCIDsFromManifest(manifest)
				if err != nil {
					return err
				}
				if len(allCIDs) == 0 {
					return fmt.Errorf("manifest %q has no pieces[].piece_cid entries", manifest)
				}
			} else {
				var err error
				allCIDs, err = collectCIDs(cids, args)
				if err != nil {
					return err
				}
				if len(allCIDs) == 0 {
					return errors.New("provide at least one CID via args or --cid (or use --manifest)")
				}
			}
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return err
			}
			// Probe uses a bounded client; paid/free downloads use an unlimited client (large CARs).
			probeCli := &http.Client{Timeout: 60 * time.Second}
			cli := &http.Client{}
			discoverCli := &http.Client{Timeout: 90 * time.Second}
			discovery := newPieceDiscoveryClient(discoverCli, payRPCURL)
			pieceProber := pieceurls.NewClient(probeCli)
			pieceProber.ProbeClient = client
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			authCfg, err := buildRetrievalAuth(ctx, evmPK, vouchers, payRPCURL, porepCDPURL, porepMarketAddress, porepProviderID)
			if err != nil {
				return fmt.Errorf("retrieval auth: %w", err)
			}
			pieceProber.AuthHeadersForPiece = func(pieceCID string) ([]string, error) {
				return authCfg.authHeadersForPiece(ctx, pieceCID)
			}

			probeLog := makeProbeLog(cmd.OutOrStdout(), verbose)
			spOverride := strings.TrimSpace(spBaseURL)
			ui := newProgressUI(os.Stderr, noProgress)

			items := make([]challengeItem, 0, len(allCIDs))
			if verbose && !ui.Enabled() {
				fmt.Printf("Step 1/2: probing discovered SP bases for %d CID(s)\n", len(allCIDs))
			}
			if ui.Enabled() {
				ui.Phase(fmt.Sprintf("probing %d piece(s)", len(allCIDs)))
			}

			for i, cid := range allCIDs {
				if verbose && !ui.Enabled() {
					fmt.Printf("  - discovering SP HTTP bases for CID %s (filecoin.tools + cid.contact / Lotus)\n", cid)
				}
				if ui.Enabled() {
					ui.PieceProbe(i+1, len(allCIDs), cid, "discovering SP HTTP bases")
				}
				bases, derr := discovery.DiscoverPieceHTTPBases(ctx, cid)
				if spOverride != "" {
					ob, perr := url.Parse(spOverride)
					if perr != nil {
						return fmt.Errorf("invalid --sp-base-url: %w", perr)
					}
					if ob.Scheme == "" || ob.Host == "" {
						return errors.New("invalid --sp-base-url: URL must include scheme and host (e.g. http://127.0.0.1:8787)")
					}
					u := *ob
					u.Path, u.RawQuery, u.Fragment = "", "", ""
					bases = []*url.URL{&u}
					if verbose {
						fmt.Printf("    --sp-base-url override: probing only %s\n", bases[0].String())
					}
				} else {
					if derr != nil {
						return fmt.Errorf("discover endpoints for CID %s: %w", cid, derr)
					}
					if len(bases) == 0 {
						return fmt.Errorf("discover: no HTTP endpoints for CID %s (empty filecoin.tools search or no resolvable multiaddrs); use --sp-base-url to force a proxy", cid)
					}
					if verbose {
						fmt.Printf("    found %d endpoint(s) for CID %s:\n", len(bases), cid)
						for _, b := range bases {
							if b != nil {
								fmt.Printf("      %s\n", b.String())
							}
						}
					}
				}

				sel, err := pieceProber.SelectBestPieceSource(ctx, cid, bases, probeLog, probeCallbackFor(ui, i+1, len(allCIDs)))
				if err != nil {
					if ui.Enabled() {
						ui.ProbeEndpointsEnd(i+1, len(allCIDs), cid, "")
					}
					return fmt.Errorf("dataset incomplete: no usable source for CID %s: %w", cid, err)
				}
				if ui.Enabled() {
					ui.ProbeEndpointsEnd(i+1, len(allCIDs), cid, probeSelectionSummary(sel))
				}
				if payDebug && !sel.Free && strings.TrimSpace(sel.Payee0x) != "" {
					payClientLog("selected payee_0x=%s (fund/open rail payer=client → payee); SP settles on paid GET", sel.Payee0x)
				}
				if verbose {
					if sel.Free {
						fmt.Printf("    free direct from %s (download after confirm)\n", sel.Base.String())
					} else {
						line := fmt.Sprintf("    selected %s — CID %s costs %s USDFC (deal %s)", sel.Base.String(), cid, sel.PriceUSDFC, sel.DealUUID)
						if strings.TrimSpace(sel.Payee0x) != "" {
							line += fmt.Sprintf(" payee_0x=%s", sel.Payee0x)
						}
						fmt.Println(line)
					}
				}
				items = append(items, challengeItem{
					CID:        cid,
					Base:       sel.Base,
					Free:       sel.Free,
					TotalBytes: sel.TotalBytes,
					DealUUID:   sel.DealUUID,
					PriceUSDFC: sel.PriceUSDFC,
					Payee0x:    strings.TrimSpace(sel.Payee0x),
					Challenge:  sel.Challenge,
				})
			}

			var prices []string
			for _, it := range items {
				if it.Free {
					continue
				}
				prices = append(prices, it.PriceUSDFC)
			}
			total, err := sumTokenValues(prices)
			if err != nil {
				return fmt.Errorf("sum token values: %w", err)
			}
			stdout := cmd.OutOrStdout()
			printFetchQuote(stdout, items, total)

			if dryRun {
				fmt.Fprintln(stdout, "\nQuote only (--dry-run): no chain transactions or downloads.")
				return nil
			}

			if !yes {
				ok, err := promptYesNo("Proceed with payment and download? [y/N]: ")
				if err != nil {
					return err
				}
				if !ok {
					return errors.New("aborted")
				}
			}

			var filpayOpts []filpay.Option
			if tok := strings.TrimSpace(payTokenAddress); tok != "" {
				filpayOpts = append(filpayOpts, filpay.WithPaymentToken(tok))
			}
			if payDebug || verbose {
				level := slog.LevelInfo
				if verbose {
					level = slog.LevelDebug
				}
				filpayLogger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
				filpayOpts = append(filpayOpts, filpay.WithPayLogging(filpayLogger, payDebug || verbose))
			}
			if ui.Enabled() {
				filpayOpts = append(filpayOpts, filpay.WithTxProgress(ui))
			}
			fc, err := filpayNewClient(
				context.Background(),
				payRPCURL,
				keyOpts.privateKey,
				keyOpts.privateKeyFile,
				keyOpts.privateKeyEnv,
				payPaymentsAddress,
				filpayOpts...,
			)
			if err != nil {
				return fmt.Errorf("init filpay client for rail setup: %w", err)
			}
			defer fc.Close()
			if fc.SignerAddress().Hex() != client {
				return fmt.Errorf("derived client %s does not match filpay signer %s", client, fc.SignerAddress().Hex())
			}

			paidPayees := countPaidPayees(items)
			if ui.Enabled() {
				ui.Phase(fmt.Sprintf("preparing Filecoin Pay (%d payee(s))", paidPayees))
			} else if verbose {
				fmt.Println("Preparing Filecoin Pay rails…")
			}
			prepStart := time.Now()
			if err := prepareRailsForChallenges(context.Background(), fc, client, items, payDebug); err != nil {
				return err
			}
			if payDebug || verbose {
				payClientLog("prepare phase complete in %s", time.Since(prepStart).Round(time.Millisecond))
			}

			if ui.Enabled() {
				ui.Phase(fmt.Sprintf("charging rails (%d payee(s))", paidPayees))
			} else if verbose {
				fmt.Println("Charging rails…")
			}
			chargeStart := time.Now()
			chargeTxByPayee, err := chargeRailsForChallenges(context.Background(), fc, client, items, payDebug)
			if err != nil {
				return err
			}
			for i := range items {
				if items[i].Free {
					continue
				}
				payeeHex := common.HexToAddress(items[i].Payee0x).Hex()
				items[i].PaymentTxHash = chargeTxByPayee[payeeHex]
			}
			if payDebug || verbose {
				payClientLog("charge phase complete in %s", time.Since(chargeStart).Round(time.Millisecond))
			}
			if verbose && !ui.Enabled() {
				fmt.Printf("Step 2/2: fetching pieces for %d CID(s)\n", len(items))
			}
			if ui.Enabled() {
				ui.Phase("downloading pieces")
			}
			if parallel < 1 {
				parallel = 1
			}
			if parallel > len(items) && len(items) > 0 {
				parallel = len(items)
			}

			runOne := func(it challengeItem, pieceUI ProgressUI) error {
				if it.Base == nil {
					return fmt.Errorf("internal: missing base URL for CID %s", it.CID)
				}
				tokens, terr := authCfg.authHeadersForPiece(ctx, it.CID)
				if terr != nil {
					return fmt.Errorf("retrieval auth for CID %s: %w", it.CID, terr)
				}
				if it.Free {
					if verbose {
						fmt.Printf("  - downloading free CAR for CID %s from %s\n", it.CID, it.Base.String())
					}
					return downloadFreeCAR(cli, it.Base, it.CID, outDir, it.TotalBytes, pieceUI, verbose, tokens)
				}
				piecePath := "/piece/" + it.CID
				if verbose {
					fmt.Printf("  - creating MPP credential for CID %s (deal %s) via %s\n", it.CID, it.DealUUID, it.Base.String())
				}
				h := &mpp.ProofPayload{
					Version:       mpp.VersionV1,
					ChallengeID:   it.Challenge.ID,
					DealUUID:      it.DealUUID,
					ClientAddress: client,
					CID:           it.CID,
					Method:        http.MethodGet,
					Path:          piecePath,
					Host:          it.Base.Host,
					Nonce:         uuid.NewString(),
					ExpiresUnix:   time.Now().Add(time.Duration(expiresIn) * time.Second).Unix(),
					PaymentTxHash: strings.TrimSpace(it.PaymentTxHash),
				}
				if h.PaymentTxHash == "" {
					return fmt.Errorf("internal: missing payment tx hash for paid CID %s", it.CID)
				}
				st, sig, err := mpp.SignEVM(evmPK, h.CanonicalMessage())
				if err != nil {
					return err
				}
				h.SigType = st
				h.Signature = sig
				if payDebug {
					payClientLog("signed mpp deal=%s cid=%s path=%s sig_type=%s sig_len=%d", it.DealUUID, it.CID, piecePath, st, len(sig))
				}
				cred, err := mpp.BuildCredential(it.Challenge, *h, client)
				if err != nil {
					return err
				}
				authz, err := cred.EncodeAuthorization()
				if err != nil {
					return err
				}
				return downloadCAR(cli, it.Base, it.CID, piecePath, client, authz, outDir, it.TotalBytes, pieceUI, verbose, tokens)
			}

			type dlResult struct {
				idx int
				err error
			}
			jobs := make(chan int)
			results := make(chan dlResult, len(items))
			var wg sync.WaitGroup

			var (
				pui     *parallelDownloadProgress
				stopUI  chan struct{}
				doneUI  chan struct{}
				pieceUI = func(it challengeItem) ProgressUI { return noopProgress{} }
			)
			if ui.Enabled() {
				cids := make([]string, 0, len(items))
				for _, it := range items {
					cids = append(cids, it.CID)
				}
				pui = newParallelDownloadProgress(os.Stderr, cids)
				stopUI = make(chan struct{})
				doneUI = make(chan struct{})
				go pui.renderLoop(stopUI, doneUI)
				pieceUI = func(it challengeItem) ProgressUI { return pui.bind(it.CID, !it.Free) }
			}

			for w := 0; w < parallel; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for idx := range jobs {
						it := items[idx]
						err := runOne(it, pieceUI(it))
						if err != nil && pui != nil {
							pui.setFailed(it.CID, err)
						}
						results <- dlResult{idx: idx, err: err}
					}
				}()
			}
			for idx := 0; idx < len(items); idx++ {
				jobs <- idx
			}
			close(jobs)
			wg.Wait()
			if stopUI != nil {
				close(stopUI)
				<-doneUI
			}

			var failures []pieceDownloadFailure
			for i := 0; i < len(items); i++ {
				r := <-results
				if r.err != nil {
					failures = append(failures, pieceDownloadFailure{
						idx: r.idx,
						cid: items[r.idx].CID,
						err: r.err,
					})
				}
			}
			if len(failures) > 0 {
				return newDownloadFailuresError(failures)
			}
			fmt.Println("Fetch complete.")
			return nil
		},
	}
	c.Flags().StringVar(&spBaseURL, "sp-base-url", "", "If set, skip using discovered endpoints and probe only this SP HTTP base (e.g. http://127.0.0.1:8787)")
	c.Flags().StringVar(&outDir, "out-dir", ".", "Output directory")
	c.Flags().StringArrayVar(&cids, "cid", nil, "CID to fetch (repeatable)")
	c.Flags().StringVar(&manifest, "manifest", "", "Path to data-prep-standard super-manifest JSON (extract pieces[].piece_cid)")
	c.Flags().BoolVar(&yes, "yes", false, "Skip interactive confirmation")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "Probe and print quote only; no chain transactions or downloads")
	c.Flags().BoolVar(&noProgress, "no-progress", false, "Disable progress output (default: on when stderr is a terminal)")
	c.Flags().IntVar(&parallel, "parallel", 6, "Max concurrent downloads")
	c.Flags().IntVar(&expiresIn, "expires-in-sec", 120, "Header expiry interval in seconds")
	c.Flags().BoolVar(&verbose, "verbose", false, "Print detailed probe/download progress (stdout) and retrieval step logs to stderr ([retrieval-client])")
	c.Flags().BoolVar(&payDebug, "pay-debug", false, "Log Filecoin Pay chain operations to stderr ([filpay-client])")
	c.Flags().StringVar(&payRPCURL, "pay-rpc-url", getenv("SP_PROXY_PAY_RPC_URL", "https://api.node.glif.io/rpc/v1"), "Filecoin JSON-RPC URL: FVM payments + Lotus StateMinerInfo for discovery")
	c.Flags().StringVar(&payPaymentsAddress, "pay-payments-address", getenv("SP_PROXY_PAY_PAYMENTS_ADDRESS", ""), "Filecoin Pay payments contract (0x); empty uses chain default")
	c.Flags().StringVar(&payTokenAddress, "pay-token-address", getenv("SP_PROXY_PAY_TOKEN_ADDRESS", ""), "USDFC token (0x); empty uses chain default (required override on Curio/FOC localnet)")
	c.Flags().StringArrayVar(&vouchers, "voucher", nil, "EIP-712 RetrievalVoucher capability (base64url); repeat for multiple deals. Each token is checked for format, expiry, and signature at startup, then forwarded as Authorization: RetrievalVoucher with a minted per-CID Authorization: RetrievalProof")
	c.Flags().StringVar(&porepCDPURL, "porep-cdp-url", firstEnv("SP_PROXY_POREP_CDP_URL", "POREP_CDP_URL"), "CDP base URL for owner-direct proof minting when --voucher is omitted (e.g. http://127.0.0.1:23300)")
	c.Flags().Uint64Var(&porepProviderID, "porep-provider-id", mustParseUint64Env("0", "SP_PROXY_POREP_PROVIDER_ID", "POREP_PROVIDER_ID"), "Miner actor ID for CDP owner-proof minting; 0 disables owner CDP lookup")
	c.Flags().StringVar(&porepMarketAddress, "porep-market-address", firstEnv("SP_PROXY_POREP_MARKET_ADDRESS", "POREP_MARKET"), "PoRep Market (0x) for owner-direct EIP-712 domain; required on chains without a built-in default")
	return c
}

func cmdRailCheck(keyOpts *filpayKeyOpts) *cobra.Command {
	var (
		spBaseURL          string
		cids               []string
		payees             []string
		requiredUSDFC      string
		payDebug           bool
		payRPCURL          string
		payPaymentsAddress string
		payTokenAddress    string
		vouchers           []string
		porepCDPURL        string
		porepProviderID    uint64
		porepMarketAddress string
	)
	c := &cobra.Command{
		Use:   "rail-check",
		Short: "Print detailed payer/payee Filecoin Pay rail readiness",
		RunE: func(cmd *cobra.Command, args []string) error {
			evmPK, err := filpay.LoadPrivateKey(keyOpts.privateKey, keyOpts.privateKeyFile, keyOpts.privateKeyEnv)
			if err != nil {
				return fmt.Errorf("load client private key (--filpay-private-key* / %s): %w", keyOpts.privateKeyEnv, err)
			}
			client := crypto.PubkeyToAddress(evmPK.PublicKey).Hex()
			vouchers = normalizeVoucherFlags(vouchers)
			fmt.Printf("Client (payer): %s\n", client)

			var filpayOpts []filpay.Option
			if tok := strings.TrimSpace(payTokenAddress); tok != "" {
				filpayOpts = append(filpayOpts, filpay.WithPaymentToken(tok))
			}
			var filpayLogger *slog.Logger
			if payDebug {
				filpayLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
			}
			filpayOpts = append(filpayOpts, filpay.WithPayLogging(filpayLogger, payDebug))
			fc, err := filpayNewClient(
				context.Background(),
				payRPCURL,
				keyOpts.privateKey,
				keyOpts.privateKeyFile,
				keyOpts.privateKeyEnv,
				payPaymentsAddress,
				filpayOpts...,
			)
			if err != nil {
				return fmt.Errorf("init filpay client: %w", err)
			}
			defer fc.Close()
			fmt.Printf("Chain ID: %s\n", fc.ChainID().String())
			fmt.Printf("Payments contract: %s\n", fc.PaymentsAddress().Hex())
			fmt.Printf("Signer (from key): %s\n", fc.SignerAddress().Hex())
			if fc.SignerAddress().Hex() != client {
				return fmt.Errorf("derived client %s does not match filpay signer %s", client, fc.SignerAddress().Hex())
			}

			// Gather payees from manual flags and optional live MPP challenges (discovery or --sp-base-url).
			challenges := make([]challengeItem, 0)
			if len(cids) > 0 || len(args) > 0 {
				allCIDs, err := collectCIDs(cids, args)
				if err != nil {
					return err
				}
				cli := &http.Client{Timeout: 120 * time.Second}
				discoverCli := &http.Client{Timeout: 90 * time.Second}
				discovery := newPieceDiscoveryClient(discoverCli, payRPCURL)
				pieceProber := pieceurls.NewClient(cli)
				pieceProber.ProbeClient = client
				ctx := cmd.Context()
				if ctx == nil {
					ctx = context.Background()
				}
				authCfg, err := buildRetrievalAuth(ctx, evmPK, vouchers, payRPCURL, porepCDPURL, porepMarketAddress, porepProviderID)
				if err != nil {
					return fmt.Errorf("retrieval auth: %w", err)
				}
				pieceProber.AuthHeadersForPiece = func(pieceCID string) ([]string, error) {
					return authCfg.authHeadersForPiece(ctx, pieceCID)
				}
				probeLog := func(format string, args ...any) {
					if payDebug {
						retrievalLog(format, args...)
					}
				}
				spOverride := strings.TrimSpace(spBaseURL)
				for _, cid := range allCIDs {
					var bases []*url.URL
					if spOverride != "" {
						ob, perr := url.Parse(spOverride)
						if perr != nil {
							return fmt.Errorf("invalid --sp-base-url: %w", perr)
						}
						if ob.Scheme == "" || ob.Host == "" {
							return errors.New("invalid --sp-base-url: URL must include scheme and host")
						}
						u := *ob
						u.Path, u.RawQuery, u.Fragment = "", "", ""
						bases = []*url.URL{&u}
					} else {
						var derr error
						bases, derr = discovery.DiscoverPieceHTTPBases(ctx, cid)
						if derr != nil {
							return fmt.Errorf("discover endpoints for CID %s: %w", cid, derr)
						}
						if len(bases) == 0 {
							return fmt.Errorf("discover: no HTTP endpoints for CID %s; use --sp-base-url to force a proxy", cid)
						}
					}
					sel, err := pieceProber.SelectBestPieceSource(ctx, cid, bases, probeLog, nil)
					if err != nil {
						return fmt.Errorf("no usable source for CID %s: %w", cid, err)
					}
					if sel.Free {
						continue
					}
					challenges = append(challenges, challengeItem{
						CID:        cid,
						Base:       sel.Base,
						Free:       false,
						TotalBytes: sel.TotalBytes,
						DealUUID:   sel.DealUUID,
						PriceUSDFC: sel.PriceUSDFC,
						Payee0x:    strings.TrimSpace(sel.Payee0x),
						Challenge:  sel.Challenge,
					})
				}
			}

			byPayeeRequired := map[string]*big.Int{}
			if strings.TrimSpace(requiredUSDFC) != "" {
				reqBaseUnits, err := paymentheader.ParseTokenToBaseUnits(requiredUSDFC)
				if err != nil {
					return fmt.Errorf("invalid --required-usdfc %q: %w", requiredUSDFC, err)
				}
				for _, p := range payees {
					if !common.IsHexAddress(strings.TrimSpace(p)) {
						return fmt.Errorf("invalid --payee address %q", p)
					}
					byPayeeRequired[common.HexToAddress(strings.TrimSpace(p)).Hex()] = new(big.Int).Set(reqBaseUnits)
				}
			}
			for _, q := range challenges {
				if !common.IsHexAddress(strings.TrimSpace(q.Payee0x)) {
					return fmt.Errorf("challenge cid=%s deal=%s has invalid payee_0x %q", q.CID, q.DealUUID, q.Payee0x)
				}
				w, err := paymentheader.ParseTokenToBaseUnits(q.PriceUSDFC)
				if err != nil {
					return fmt.Errorf("challenge cid=%s deal=%s has bad price %q: %w", q.CID, q.DealUUID, q.PriceUSDFC, err)
				}
				key := common.HexToAddress(strings.TrimSpace(q.Payee0x)).Hex()
				if byPayeeRequired[key] == nil {
					byPayeeRequired[key] = big.NewInt(0)
				}
				byPayeeRequired[key].Add(byPayeeRequired[key], w)
			}
			if len(byPayeeRequired) == 0 {
				for _, p := range payees {
					if !common.IsHexAddress(strings.TrimSpace(p)) {
						return fmt.Errorf("invalid --payee address %q", p)
					}
					byPayeeRequired[common.HexToAddress(strings.TrimSpace(p)).Hex()] = big.NewInt(0)
				}
			}
			if len(byPayeeRequired) == 0 {
				return errors.New("no payees discovered. Provide --payee or paid MPP sources for CIDs (--cid/args, with discovery or --sp-base-url)")
			}

			if len(challenges) > 0 {
				fmt.Println("\nChallenge details:")
				for _, q := range challenges {
					fmt.Printf("- cid=%s deal=%s price_usdfc=%s payee_0x=%s\n", q.CID, q.DealUUID, q.PriceUSDFC, q.Payee0x)
				}
			}

			payer := common.HexToAddress(client)
			fundedUntil, currentFunds, availableFunds, currentLockupRate, err := fc.AccountInfoIfSettled(context.Background(), payer)
			if err != nil {
				return err
			}
			fmt.Println("\nPayer account:")
			fmt.Printf("- funded_until_epoch=%s\n", fundedUntil.String())
			fmt.Printf("- current_funds_base_units=%s\n", currentFunds.String())
			fmt.Printf("- available_funds_base_units=%s\n", availableFunds.String())
			fmt.Printf("- current_lockup_rate=%s\n", currentLockupRate.String())

			rails, err := fc.ListTokenRailsAsPayer(context.Background(), payer)
			if err != nil {
				return err
			}
			fmt.Printf("\nAll payer rails: %d\n", len(rails))
			for _, r := range rails {
				settled := "n/a"
				if r.SettledUpTo != nil {
					settled = r.SettledUpTo.String()
				}
				endEpoch := "nil"
				if r.EndEpoch != nil {
					endEpoch = r.EndEpoch.String()
				}
				fmt.Printf("- rail_id=%s from=%s to=%s operator=%s token=%s terminated=%t end_epoch=%s settled_up_to=%s\n",
					r.RailID.String(), r.From.Hex(), r.To.Hex(), r.Operator.Hex(), r.Token.Hex(), r.IsTerminated, endEpoch, settled)
			}

			keys := make([]string, 0, len(byPayeeRequired))
			for k := range byPayeeRequired {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			fmt.Println("\nPer-payee readiness:")
			for _, payeeHex := range keys {
				requiredBaseUnits := byPayeeRequired[payeeHex]
				payee := common.HexToAddress(payeeHex)
				fmt.Printf("\nPayee %s\n", payeeHex)
				fmt.Printf("- required_base_units=%s\n", requiredBaseUnits.String())
				approval, err := fc.OperatorApproval(context.Background(), payer, payee)
				if err != nil {
					fmt.Printf("- operator_approval_error=%v\n", err)
				} else {
					fmt.Printf("- operator_approved=%t\n", approval.Approved)
					fmt.Printf("- rate_allowance=%s lockup_allowance=%s max_lockup_period=%s\n",
						approval.RateAllowance.String(), approval.LockupAllowance.String(), approval.MaxLockupPeriod.String())
					fmt.Printf("- rate_used=%s lockup_used=%s\n", approval.RateUsed.String(), approval.LockupUsed.String())
				}
				railID, err := fc.FindActiveTokenRail(context.Background(), payer, payee)
				if err != nil {
					fmt.Printf("- active_rail=NO (%v)\n", err)
				} else {
					fmt.Printf("- active_rail=YES rail_id=%s\n", railID.String())
				}
				if availableFunds.Cmp(requiredBaseUnits) >= 0 {
					fmt.Printf("- available_vs_required=OK (%s >= %s)\n", availableFunds.String(), requiredBaseUnits.String())
				} else {
					fmt.Printf("- available_vs_required=INSUFFICIENT (%s < %s)\n", availableFunds.String(), requiredBaseUnits.String())
				}
			}
			fmt.Println("\nrail-check complete.")
			return nil
		},
	}
	c.Flags().StringVar(&spBaseURL, "sp-base-url", "", "If set, probe only this SP HTTP base for MPP challenges; empty uses piece URL discovery")
	c.Flags().StringArrayVar(&cids, "cid", nil, "CID to probe for payee discovery (repeatable)")
	c.Flags().StringArrayVar(&payees, "payee", nil, "Explicit payee 0x address to check (repeatable)")
	c.Flags().StringVar(&requiredUSDFC, "required-usdfc", "", "Optional required USDFC amount per --payee when no challenges are used")
	c.Flags().BoolVar(&payDebug, "pay-debug", false, "Log Filecoin Pay operation details to stderr ([filpay-client])")
	c.Flags().StringVar(&payRPCURL, "pay-rpc-url", getenv("SP_PROXY_PAY_RPC_URL", "https://api.node.glif.io/rpc/v1"), "Filecoin JSON-RPC URL: FVM payments + Lotus StateMinerInfo for discovery")
	c.Flags().StringVar(&payPaymentsAddress, "pay-payments-address", getenv("SP_PROXY_PAY_PAYMENTS_ADDRESS", ""), "Filecoin Pay payments contract (0x); empty uses chain default")
	c.Flags().StringVar(&payTokenAddress, "pay-token-address", getenv("SP_PROXY_PAY_TOKEN_ADDRESS", ""), "USDFC token (0x); empty uses chain default (required override on Curio/FOC localnet)")
	c.Flags().StringArrayVar(&vouchers, "voucher", nil, "EIP-712 RetrievalVoucher capability (base64url); repeat for multiple deals. Each token is checked for format, expiry, and signature at startup, then forwarded as Authorization: RetrievalVoucher with a minted per-CID Authorization: RetrievalProof when probing CIDs for payees")
	c.Flags().StringVar(&porepCDPURL, "porep-cdp-url", firstEnv("SP_PROXY_POREP_CDP_URL", "POREP_CDP_URL"), "CDP base URL for owner-direct proof minting when --voucher is omitted")
	c.Flags().Uint64Var(&porepProviderID, "porep-provider-id", mustParseUint64Env("0", "SP_PROXY_POREP_PROVIDER_ID", "POREP_PROVIDER_ID"), "Miner actor ID for CDP owner-proof minting; 0 disables owner CDP lookup")
	c.Flags().StringVar(&porepMarketAddress, "porep-market-address", firstEnv("SP_PROXY_POREP_MARKET_ADDRESS", "POREP_MARKET"), "PoRep Market (0x) for owner-direct EIP-712 domain")
	return c
}

func payClientLog(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[filpay-client] "+format+"\n", args...)
}

func retrievalLog(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[retrieval-client] "+format+"\n", args...)
}

// normalizeVoucherFlags trims empty entries and strips a leading "Retrieval " or legacy "Bearer " prefix.
func normalizeVoucherFlags(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, v := range raw {
		tok := pieceurls.StripVoucherAuthScheme(strings.TrimSpace(v))
		if tok == "" {
			continue
		}
		if _, ok := seen[tok]; ok {
			continue
		}
		seen[tok] = struct{}{}
		out = append(out, tok)
	}
	return out
}

func truncateForLog(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func addFilpayKeyFlags(c *cobra.Command, opts *filpayKeyOpts) {
	c.PersistentFlags().StringVar(&opts.privateKey, "filpay-private-key", "", "Hex private key: client 0x identity + MPP signing (prefer env or file)")
	c.PersistentFlags().StringVar(&opts.privateKeyFile, "filpay-private-key-file", "", "File with hex private key for client identity + MPP")
	c.PersistentFlags().StringVar(&opts.privateKeyEnv, "filpay-private-key-env", getenv("FILPAY_PRIVATE_KEY_ENV", "FILPAY_PRIVATE_KEY"), "Env var for hex client key")
}

func prepareRailsForChallenges(ctx context.Context, fc filpayOperations, client string, items []challengeItem, payDebug bool) error {
	payer := common.HexToAddress(client)
	byPayee := map[string]*big.Int{}
	for _, it := range items {
		if it.Free {
			continue
		}
		if strings.TrimSpace(it.Payee0x) == "" || !common.IsHexAddress(it.Payee0x) {
			return fmt.Errorf("challenge %s for cid=%s missing valid payee_0x", it.DealUUID, it.CID)
		}
		priceBaseUnits, err := paymentheader.ParseTokenToBaseUnits(it.PriceUSDFC)
		if err != nil {
			return fmt.Errorf("challenge %s has invalid price_usdfc=%q: %w", it.DealUUID, it.PriceUSDFC, err)
		}
		key := common.HexToAddress(it.Payee0x).Hex()
		if byPayee[key] == nil {
			byPayee[key] = big.NewInt(0)
		}
		byPayee[key].Add(byPayee[key], priceBaseUnits)
	}
	payees := make([]string, 0, len(byPayee))
	for payee := range byPayee {
		payees = append(payees, payee)
	}
	sort.Strings(payees)
	for _, payeeHex := range payees {
		requiredBaseUnits := byPayee[payeeHex]
		if payDebug {
			payClientLog("preparing payer for payee=%s required_base_units=%s (check approval/balance/rail, then submit txs only if needed)", payeeHex, requiredBaseUnits.String())
			payeeAddr := common.HexToAddress(payeeHex)
			approval, aerr := fc.OperatorApproval(ctx, payer, payer)
			_, _, avail, _, berr := fc.AccountInfoIfSettled(ctx, payer)
			railID, rerr := fc.FindActiveTokenRail(ctx, payer, payeeAddr)
			approved := "unknown"
			if aerr == nil {
				approved = fmt.Sprintf("%t", approval.Approved)
			}
			availStr := "unknown"
			fundsOK := "unknown"
			if berr == nil && avail != nil {
				availStr = avail.String()
				if avail.Cmp(requiredBaseUnits) >= 0 {
					fundsOK = "yes"
				} else {
					fundsOK = "no"
				}
			}
			railState := "no"
			if rerr == nil && railID != nil {
				railState = "yes rail_id=" + railID.String()
			}
			payClientLog(
				"preflight payee=%s approved=%s available_base_units=%s required_base_units=%s funds_sufficient=%s active_rail=%s operator_check_err=%v balance_check_err=%v rail_check_err=%v",
				payeeHex, approved, availStr, requiredBaseUnits.String(), fundsOK, railState, aerr, berr, rerr,
			)
		}
		start := time.Now()
		if err := fc.PreparePayerForPayee(ctx, payer, common.HexToAddress(payeeHex), requiredBaseUnits); err != nil {
			return fmt.Errorf("prepare rail/account for payee %s failed: %w", payeeHex, err)
		}
		if payDebug {
			payClientLog("payer preparation complete for payee=%s duration=%s", payeeHex, time.Since(start).Round(time.Millisecond))
		}
	}
	return nil
}

func chargeRailsForChallenges(ctx context.Context, fc filpayOperations, client string, items []challengeItem, payDebug bool) (map[string]string, error) {
	payer := common.HexToAddress(client)
	amountByPayee := map[string]*big.Int{}
	for _, it := range items {
		if it.Free {
			continue
		}
		if strings.TrimSpace(it.Payee0x) == "" || !common.IsHexAddress(it.Payee0x) {
			return nil, fmt.Errorf("challenge %s for cid=%s missing valid payee_0x", it.DealUUID, it.CID)
		}
		priceBaseUnits, err := paymentheader.ParseTokenToBaseUnits(it.PriceUSDFC)
		if err != nil {
			return nil, fmt.Errorf("challenge %s has invalid price_usdfc=%q: %w", it.DealUUID, it.PriceUSDFC, err)
		}
		key := common.HexToAddress(it.Payee0x).Hex()
		if amountByPayee[key] == nil {
			amountByPayee[key] = big.NewInt(0)
		}
		amountByPayee[key].Add(amountByPayee[key], priceBaseUnits)
	}
	payees := make([]string, 0, len(amountByPayee))
	for payee := range amountByPayee {
		payees = append(payees, payee)
	}
	sort.Strings(payees)
	chargeTxByPayee := make(map[string]string, len(payees))
	for _, payeeHex := range payees {
		amountBaseUnits := amountByPayee[payeeHex]
		if payDebug {
			payClientLog("charging rail one-time payment payee=%s amount_base_units=%s", payeeHex, amountBaseUnits.String())
		}
		start := time.Now()
		txHash, err := fc.ChargeRailOneTime(ctx, payer, common.HexToAddress(payeeHex), amountBaseUnits)
		if err != nil {
			return nil, fmt.Errorf("charge rail for payee %s failed: %w", payeeHex, err)
		}
		chargeTxByPayee[payeeHex] = txHash
		if payDebug {
			payClientLog("modifyRailPayment submitted payee=%s tx=%s duration=%s", payeeHex, txHash, time.Since(start).Round(time.Millisecond))
		}
	}
	return chargeTxByPayee, nil
}

func collectCIDs(flagCIDs []string, args []string) ([]string, error) {
	seen := map[string]struct{}{}
	var out []string
	appendCID := func(v string) error {
		v = strings.TrimSpace(v)
		if v == "" {
			return nil
		}
		if _, ok := seen[v]; ok {
			return fmt.Errorf("duplicate CID %q", v)
		}
		seen[v] = struct{}{}
		out = append(out, v)
		return nil
	}
	for _, c := range flagCIDs {
		for _, p := range strings.Split(c, ",") {
			if err := appendCID(p); err != nil {
				return nil, err
			}
		}
	}
	for _, c := range args {
		for _, p := range strings.Split(c, ",") {
			if err := appendCID(p); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

func extractPieceCIDsFromManifest(manifestPath string) ([]string, error) {
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read manifest %q: %w", manifestPath, err)
	}

	var m struct {
		Pieces []struct {
			PieceCID string `json:"piece_cid"`
		} `json:"pieces"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse manifest %q: %w", manifestPath, err)
	}

	seen := make(map[string]struct{}, len(m.Pieces))
	out := make([]string, 0, len(m.Pieces))
	for _, p := range m.Pieces {
		piece := strings.TrimSpace(p.PieceCID)
		if piece == "" {
			continue
		}
		if _, ok := seen[piece]; ok {
			return nil, fmt.Errorf("duplicate CID %q in manifest", piece)
		}
		seen[piece] = struct{}{}
		out = append(out, piece)
	}
	return out, nil
}

func promptYesNo(prompt string) (bool, error) {
	fmt.Print(prompt)
	r := bufio.NewReader(promptReader)
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes", nil
}

func getenv(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

// firstEnv returns the first non-empty env value among keys, or "".
func firstEnv(keys ...string) string {
	for _, key := range keys {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
	}
	return ""
}

func mustParseUint64Env(fallback string, keys ...string) uint64 {
	raw := firstEnv(keys...)
	if raw == "" {
		raw = fallback
	}
	v, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func sumTokenValues(prices []string) (string, error) {
	var total float64
	for _, price := range prices {
		var x float64
		_, err := fmt.Sscanf(price, "%f", &x)
		if err != nil {
			return "0", fmt.Errorf("parse token value %q: %w", price, err)
		}
		total += x
	}
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.6f", total), "0"), "."), nil
}

func sanitizeFilename(v string) string {
	if v == "" {
		return "piece"
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-', r == '_', r == '.':
			return r
		default:
			return '_'
		}
	}, v)
}
