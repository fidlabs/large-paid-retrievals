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
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/fidlabs/paid-retrievals/internal/filpay"
	"github.com/fidlabs/paid-retrievals/internal/mpp"
	"github.com/fidlabs/paid-retrievals/internal/paymentheader"
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
	CID       string
	DealUUID  string
	PriceFIL  string
	Payee0x   string
	Challenge mpp.Challenge
}

func main() {
	if err := root().Execute(); err != nil {
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
	return r
}

func cmdFetch(keyOpts *filpayKeyOpts) *cobra.Command {
	var (
		spBaseURL          string
		outDir             string
		cids               []string
		cidFile            string
		manifest           string
		yes                bool
		expiresIn          int
		verbose            bool
		payDebug           bool
		payRPCURL          string
		payPaymentsAddress string
	)
	c := &cobra.Command{
		Use:   "fetch",
		Short: "Fetch multiple piece CIDs: MPP challenge (402) then EVM-signed paid retrieval",
		RunE: func(cmd *cobra.Command, args []string) error {
			evmPK, err := filpay.LoadPrivateKey(keyOpts.privateKey, keyOpts.privateKeyFile, keyOpts.privateKeyEnv)
			if err != nil {
				return fmt.Errorf("load client private key (--filpay-private-key* / %s): %w", keyOpts.privateKeyEnv, err)
			}
			client := crypto.PubkeyToAddress(evmPK.PublicKey).Hex()
			if verbose {
				fmt.Printf("Client 0x address (from private key): %s\n", client)
			}
			if payDebug {
				payClientLog("client 0x=%s (derived from private key)", client)
			}

			var allCIDs []string
			if strings.TrimSpace(manifest) != "" {
				if len(cids) > 0 || strings.TrimSpace(cidFile) != "" || len(args) > 0 {
					return errors.New("--manifest is mutually exclusive with positional CIDs, --cid, and --cid-file")
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
				allCIDs, err = collectCIDs(cids, cidFile, args)
				if err != nil {
					return err
				}
				if len(allCIDs) == 0 {
					return errors.New("provide at least one CID via args, --cid, or --cid-file (or use --manifest)")
				}
			}
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return err
			}
			base, err := url.Parse(strings.TrimSpace(spBaseURL))
			if err != nil {
				return fmt.Errorf("invalid --sp-base-url: %w", err)
			}
			cli := &http.Client{Timeout: 120 * time.Second}

			items := make([]challengeItem, 0, len(allCIDs))
			if verbose {
				fmt.Printf("Step 1/%d: fetching MPP challenges for %d CID(s)\n", 2, len(allCIDs))
			}

			for _, cid := range allCIDs {
				if verbose {
					fmt.Printf("  - requesting challenge for CID %s\n", cid)
				}
				q, err := requestChallenge(cli, base, cid, client, payDebug)
				if err != nil {
					return fmt.Errorf("dataset incomplete: challenge request failed for CID %s: %w", cid, err)
				}
				if payDebug && strings.TrimSpace(q.Request.Payee0x) != "" {
					payClientLog("challenge includes payee_0x=%s (fund/open native-FIL rail payer=client → payee); SP settles on paid GET", q.Request.Payee0x)
				}
				if verbose {
					line := fmt.Sprintf("    received challenge: CID %s costs %s FIL (deal %s)", cid, q.Request.PriceFIL, q.Request.DealUUID)
					if strings.TrimSpace(q.Request.Payee0x) != "" {
						line += fmt.Sprintf(" payee_0x=%s", q.Request.Payee0x)
					}
					fmt.Println(line)
				}
				items = append(items, challengeItem{
					CID:       cid,
					DealUUID:  q.Request.DealUUID,
					PriceFIL:  q.Request.PriceFIL,
					Payee0x:   strings.TrimSpace(q.Request.Payee0x),
					Challenge: *q,
				})
			}

			var prices []string
			for _, it := range items {
				prices = append(prices, it.PriceFIL)
			}
			total := sumFILValues(prices)
			fmt.Printf("Total required amount: %s FIL for %d piece(s).\n", total, len(items))

			var filpayLogger *slog.Logger
			if payDebug || verbose {
				level := slog.LevelInfo
				if verbose {
					level = slog.LevelDebug
				}
				filpayLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
			}
			fc, err := filpay.NewClient(
				context.Background(),
				payRPCURL,
				keyOpts.privateKey,
				keyOpts.privateKeyFile,
				keyOpts.privateKeyEnv,
				payPaymentsAddress,
				filpay.WithPayLogging(filpayLogger, payDebug || verbose),
			)
			if err != nil {
				return fmt.Errorf("init filpay client for rail setup: %w", err)
			}
			defer fc.Close()
			if fc.SignerAddress().Hex() != client {
				return fmt.Errorf("derived client %s does not match filpay signer %s", client, fc.SignerAddress().Hex())
			}
			prepStart := time.Now()
			if err := prepareRailsForChallenges(context.Background(), fc, client, items, payDebug); err != nil {
				return err
			}
			if payDebug || verbose {
				payClientLog("prepare phase complete in %s", time.Since(prepStart).Round(time.Millisecond))
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
			chargeStart := time.Now()
			if err := chargeRailsForChallenges(context.Background(), fc, client, items, payDebug); err != nil {
				return err
			}
			if payDebug || verbose {
				payClientLog("charge phase complete in %s", time.Since(chargeStart).Round(time.Millisecond))
			}
			if verbose {
				fmt.Printf("Step 2/%d: fetching paid pieces for %d CID(s)\n", 2, len(items))
			}

			for _, it := range items {
				piecePath := "/piece/" + it.CID
				if verbose {
					fmt.Printf("  - creating MPP proof for CID %s (deal %s)\n", it.CID, it.DealUUID)
				}
				h := &mpp.ProofPayload{
					Version:       mpp.VersionV1,
					ChallengeID:   it.Challenge.ID,
					DealUUID:      it.DealUUID,
					ClientAddress: client,
					CID:           it.CID,
					Method:        http.MethodGet,
					Path:          piecePath,
					Host:          base.Host,
					Nonce:         uuid.NewString(),
					ExpiresUnix:   time.Now().Add(time.Duration(expiresIn) * time.Second).Unix(),
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
				outPath, err := downloadCAR(cli, base, it.CID, piecePath, authz, outDir, payDebug)
				if err != nil {
					return err
				}
				if verbose {
					fmt.Printf("    piece stored: CID %s -> %s\n", it.CID, outPath)
				} else {
					fmt.Printf("stored %s\n", outPath)
				}
			}
			fmt.Println("Fetch complete.")
			return nil
		},
	}
	c.Flags().StringVar(&spBaseURL, "sp-base-url", "http://127.0.0.1:8787", "SP proxy base URL")
	c.Flags().StringVar(&outDir, "out-dir", ".", "Output directory")
	c.Flags().StringArrayVar(&cids, "cid", nil, "CID to fetch (repeatable)")
	c.Flags().StringVar(&cidFile, "cid-file", "", "File with CIDs (newline or comma separated)")
	c.Flags().StringVar(&manifest, "manifest", "", "Path to data-prep-standard super-manifest JSON (extract pieces[].piece_cid)")
	c.Flags().BoolVar(&yes, "yes", false, "Skip interactive confirmation")
	c.Flags().IntVar(&expiresIn, "expires-in-sec", 120, "Header expiry interval in seconds")
	c.Flags().BoolVar(&verbose, "verbose", false, "Print detailed per-step progress output")
	c.Flags().BoolVar(&payDebug, "pay-debug", false, "Log Filecoin Pay–related client steps to stderr ([filpay-client])")
	c.Flags().StringVar(&payRPCURL, "pay-rpc-url", getenv("SP_PROXY_PAY_RPC_URL", "https://api.calibration.node.glif.io/rpc/v1"), "Filecoin RPC (FVM) used to prepare FIL payments account + rail checks")
	c.Flags().StringVar(&payPaymentsAddress, "pay-payments-address", getenv("SP_PROXY_PAY_PAYMENTS_ADDRESS", ""), "Filecoin Pay payments contract (0x); empty uses chain default")
	return c
}

func cmdRailCheck(keyOpts *filpayKeyOpts) *cobra.Command {
	var (
		spBaseURL          string
		cids               []string
		cidFile            string
		payees             []string
		requiredFIL        string
		payDebug           bool
		payRPCURL          string
		payPaymentsAddress string
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
			fmt.Printf("Client (payer): %s\n", client)

			var filpayLogger *slog.Logger
			if payDebug {
				filpayLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
			}
			fc, err := filpay.NewClient(
				context.Background(),
				payRPCURL,
				keyOpts.privateKey,
				keyOpts.privateKeyFile,
				keyOpts.privateKeyEnv,
				payPaymentsAddress,
				filpay.WithPayLogging(filpayLogger, payDebug),
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

			// Gather payees from manual flags and optional live challenge requests.
			challenges := make([]challengeItem, 0)
			if len(cids) > 0 || strings.TrimSpace(cidFile) != "" || len(args) > 0 {
				base, err := url.Parse(strings.TrimSpace(spBaseURL))
				if err != nil {
					return fmt.Errorf("invalid --sp-base-url: %w", err)
				}
				allCIDs, err := collectCIDs(cids, cidFile, args)
				if err != nil {
					return err
				}
				cli := &http.Client{Timeout: 120 * time.Second}
				for _, cid := range allCIDs {
					q, err := requestChallenge(cli, base, cid, client, payDebug)
					if err != nil {
						return fmt.Errorf("challenge request failed for cid=%s: %w", cid, err)
					}
					challenges = append(challenges, challengeItem{
						CID:       cid,
						DealUUID:  q.Request.DealUUID,
						PriceFIL:  q.Request.PriceFIL,
						Payee0x:   strings.TrimSpace(q.Request.Payee0x),
						Challenge: *q,
					})
				}
			}

			byPayeeRequired := map[string]*big.Int{}
			if strings.TrimSpace(requiredFIL) != "" {
				reqWei, err := paymentheader.ParseFILToWei(requiredFIL)
				if err != nil {
					return fmt.Errorf("invalid --required-fil %q: %w", requiredFIL, err)
				}
				for _, p := range payees {
					if !common.IsHexAddress(strings.TrimSpace(p)) {
						return fmt.Errorf("invalid --payee address %q", p)
					}
					byPayeeRequired[common.HexToAddress(strings.TrimSpace(p)).Hex()] = new(big.Int).Set(reqWei)
				}
			}
			for _, q := range challenges {
				if !common.IsHexAddress(strings.TrimSpace(q.Payee0x)) {
					return fmt.Errorf("challenge cid=%s deal=%s has invalid payee_0x %q", q.CID, q.DealUUID, q.Payee0x)
				}
				w, err := paymentheader.ParseFILToWei(q.PriceFIL)
				if err != nil {
					return fmt.Errorf("challenge cid=%s deal=%s has bad price %q: %w", q.CID, q.DealUUID, q.PriceFIL, err)
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
				return errors.New("no payees discovered. Provide --payee or challenge CIDs (--cid/--cid-file/args)")
			}

			if len(challenges) > 0 {
				fmt.Println("\nChallenge details:")
				for _, q := range challenges {
					fmt.Printf("- cid=%s deal=%s price_fil=%s payee_0x=%s\n", q.CID, q.DealUUID, q.PriceFIL, q.Payee0x)
				}
			}

			payer := common.HexToAddress(client)
			fundedUntil, currentFunds, availableFunds, currentLockupRate, err := fc.AccountInfoIfSettled(context.Background(), payer)
			if err != nil {
				return err
			}
			fmt.Println("\nPayer account (native FIL token=0x0):")
			fmt.Printf("- funded_until_epoch=%s\n", fundedUntil.String())
			fmt.Printf("- current_funds_wei=%s\n", currentFunds.String())
			fmt.Printf("- available_funds_wei=%s\n", availableFunds.String())
			fmt.Printf("- current_lockup_rate=%s\n", currentLockupRate.String())

			rails, err := fc.ListFILRailsAsPayer(context.Background(), payer)
			if err != nil {
				return err
			}
			fmt.Printf("\nAll payer FIL rails: %d\n", len(rails))
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
				requiredWei := byPayeeRequired[payeeHex]
				payee := common.HexToAddress(payeeHex)
				fmt.Printf("\nPayee %s\n", payeeHex)
				fmt.Printf("- required_wei=%s\n", requiredWei.String())
				approval, err := fc.OperatorApproval(context.Background(), payer, payee)
				if err != nil {
					fmt.Printf("- operator_approval_error=%v\n", err)
				} else {
					fmt.Printf("- operator_approved=%t\n", approval.Approved)
					fmt.Printf("- rate_allowance=%s lockup_allowance=%s max_lockup_period=%s\n",
						approval.RateAllowance.String(), approval.LockupAllowance.String(), approval.MaxLockupPeriod.String())
					fmt.Printf("- rate_used=%s lockup_used=%s\n", approval.RateUsed.String(), approval.LockupUsed.String())
				}
				railID, err := fc.FindActiveFILRail(context.Background(), payer, payee)
				if err != nil {
					fmt.Printf("- active_rail=NO (%v)\n", err)
				} else {
					fmt.Printf("- active_rail=YES rail_id=%s\n", railID.String())
				}
				if availableFunds.Cmp(requiredWei) >= 0 {
					fmt.Printf("- available_vs_required=OK (%s >= %s)\n", availableFunds.String(), requiredWei.String())
				} else {
					fmt.Printf("- available_vs_required=INSUFFICIENT (%s < %s)\n", availableFunds.String(), requiredWei.String())
				}
			}
			fmt.Println("\nrail-check complete.")
			return nil
		},
	}
	c.Flags().StringVar(&spBaseURL, "sp-base-url", "http://127.0.0.1:8787", "SP proxy base URL (used if CID challenges are requested)")
	c.Flags().StringArrayVar(&cids, "cid", nil, "CID to request challenges for payee discovery (repeatable)")
	c.Flags().StringVar(&cidFile, "cid-file", "", "File with CIDs for payee discovery via MPP challenges (newline/comma separated)")
	c.Flags().StringArrayVar(&payees, "payee", nil, "Explicit payee 0x address to check (repeatable)")
	c.Flags().StringVar(&requiredFIL, "required-fil", "", "Optional required FIL amount per --payee when no challenges are used")
	c.Flags().BoolVar(&payDebug, "pay-debug", false, "Enable detailed challenge debug while discovering payees from challenges")
	c.Flags().StringVar(&payRPCURL, "pay-rpc-url", getenv("SP_PROXY_PAY_RPC_URL", "https://api.calibration.node.glif.io/rpc/v1"), "Filecoin RPC (FVM)")
	c.Flags().StringVar(&payPaymentsAddress, "pay-payments-address", getenv("SP_PROXY_PAY_PAYMENTS_ADDRESS", ""), "Filecoin Pay payments contract (0x); empty uses chain default")
	return c
}

func payClientLog(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[filpay-client] "+format+"\n", args...)
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

func requestChallenge(cli *http.Client, base *url.URL, cid, client string, payDebug bool) (*mpp.Challenge, error) {
	u := *base
	u.Path = "/piece/" + cid
	q := u.Query()
	q.Set("client", client)
	u.RawQuery = q.Encode()
	if payDebug {
		payClientLog("challenge GET %s (expect 402)", u.String())
	}

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	res, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if payDebug {
		payClientLog("challenge response status=%d cid=%s", res.StatusCode, cid)
		payClientLog("challenge response headers: content-type=%q cache-control=%q", res.Header.Get("Content-Type"), res.Header.Get("Cache-Control"))
		payClientLog("challenge response body (truncated): %s", truncateForLog(string(body), 2048))
	}
	if res.StatusCode != http.StatusPaymentRequired {
		return nil, fmt.Errorf("expected 402 got %d", res.StatusCode)
	}
	wa := strings.TrimSpace(res.Header.Get("WWW-Authenticate"))
	ch, err := mpp.ParseWWWAuthenticate(wa)
	if err != nil {
		return nil, fmt.Errorf("invalid WWW-Authenticate challenge: %w", err)
	}
	if ch.Request.DealUUID == "" || ch.Request.PriceFIL == "" {
		return nil, errors.New("invalid challenge request payload")
	}
	if payDebug {
		payClientLog("challenge OK payment={id:%s deal_uuid:%s cid:%s price_fil:%s payee_0x:%q}", ch.ID, ch.Request.DealUUID, ch.Request.CID, ch.Request.PriceFIL, ch.Request.Payee0x)
	}
	return ch, nil
}

func prepareRailsForChallenges(ctx context.Context, fc *filpay.Client, client string, items []challengeItem, payDebug bool) error {
	payer := common.HexToAddress(client)
	byPayee := map[string]*big.Int{}
	for _, it := range items {
		if strings.TrimSpace(it.Payee0x) == "" || !common.IsHexAddress(it.Payee0x) {
			return fmt.Errorf("challenge %s for cid=%s missing valid payee_0x", it.DealUUID, it.CID)
		}
		priceWei, err := paymentheader.ParseFILToWei(it.PriceFIL)
		if err != nil {
			return fmt.Errorf("challenge %s has invalid price_fil=%q: %w", it.DealUUID, it.PriceFIL, err)
		}
		key := common.HexToAddress(it.Payee0x).Hex()
		if byPayee[key] == nil {
			byPayee[key] = big.NewInt(0)
		}
		byPayee[key].Add(byPayee[key], priceWei)
	}
	payees := make([]string, 0, len(byPayee))
	for payee := range byPayee {
		payees = append(payees, payee)
	}
	sort.Strings(payees)
	for _, payeeHex := range payees {
		requiredWei := byPayee[payeeHex]
		if payDebug {
			payClientLog("preparing payer for payee=%s required_wei=%s (check approval/balance/rail, then submit txs only if needed)", payeeHex, requiredWei.String())
			payeeAddr := common.HexToAddress(payeeHex)
			approval, aerr := fc.OperatorApproval(ctx, payer, payer)
			_, _, avail, _, berr := fc.AccountInfoIfSettled(ctx, payer)
			railID, rerr := fc.FindActiveFILRail(ctx, payer, payeeAddr)
			approved := "unknown"
			if aerr == nil {
				approved = fmt.Sprintf("%t", approval.Approved)
			}
			availStr := "unknown"
			fundsOK := "unknown"
			if berr == nil && avail != nil {
				availStr = avail.String()
				if avail.Cmp(requiredWei) >= 0 {
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
				"preflight payee=%s approved=%s available_wei=%s required_wei=%s funds_sufficient=%s active_rail=%s operator_check_err=%v balance_check_err=%v rail_check_err=%v",
				payeeHex, approved, availStr, requiredWei.String(), fundsOK, railState, aerr, berr, rerr,
			)
		}
		start := time.Now()
		if err := fc.PreparePayerForPayee(ctx, payer, common.HexToAddress(payeeHex), requiredWei); err != nil {
			return fmt.Errorf("prepare rail/account for payee %s failed: %w", payeeHex, err)
		}
		if payDebug {
			payClientLog("payer preparation complete for payee=%s duration=%s", payeeHex, time.Since(start).Round(time.Millisecond))
		}
	}
	return nil
}

func chargeRailsForChallenges(ctx context.Context, fc *filpay.Client, client string, items []challengeItem, payDebug bool) error {
	payer := common.HexToAddress(client)
	byPayee := map[string]*big.Int{}
	for _, it := range items {
		if strings.TrimSpace(it.Payee0x) == "" || !common.IsHexAddress(it.Payee0x) {
			return fmt.Errorf("challenge %s for cid=%s missing valid payee_0x", it.DealUUID, it.CID)
		}
		priceWei, err := paymentheader.ParseFILToWei(it.PriceFIL)
		if err != nil {
			return fmt.Errorf("challenge %s has invalid price_fil=%q: %w", it.DealUUID, it.PriceFIL, err)
		}
		key := common.HexToAddress(it.Payee0x).Hex()
		if byPayee[key] == nil {
			byPayee[key] = big.NewInt(0)
		}
		byPayee[key].Add(byPayee[key], priceWei)
	}
	payees := make([]string, 0, len(byPayee))
	for payee := range byPayee {
		payees = append(payees, payee)
	}
	sort.Strings(payees)
	for _, payeeHex := range payees {
		amountWei := byPayee[payeeHex]
		if payDebug {
			payClientLog("charging rail one-time payment payee=%s amount_wei=%s", payeeHex, amountWei.String())
		}
		start := time.Now()
		txHash, err := fc.ChargeRailOneTime(ctx, payer, common.HexToAddress(payeeHex), amountWei)
		if err != nil {
			return fmt.Errorf("charge rail for payee %s failed: %w", payeeHex, err)
		}
		if payDebug {
			payClientLog("modifyRailPayment submitted payee=%s tx=%s duration=%s", payeeHex, txHash, time.Since(start).Round(time.Millisecond))
		}
	}
	return nil
}

func downloadCAR(cli *http.Client, base *url.URL, cid, piecePath, authorization, outDir string, payDebug bool) (string, error) {
	u := *base
	u.Path = piecePath
	fullURL := u.String()
	if payDebug {
		payClientLog("paid GET %s (Authorization: Payment len=%d)", fullURL, len(authorization))
	}
	req, err := http.NewRequest(http.MethodGet, fullURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", authorization)
	res, err := cli.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if payDebug {
		payClientLog("paid GET response status=%d for cid=%s", res.StatusCode, cid)
	}
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		if payDebug {
			payClientLog("paid GET error body (truncated): %s", truncateForLog(string(b), 512))
		}
		trimmed := strings.TrimSpace(string(b))
		var pd problemDetails
		if err := json.Unmarshal(b, &pd); err == nil && pd.Type != "" {
			msg := fmt.Sprintf("download %s failed: %s", cid, res.Status)
			if pd.Title != "" {
				msg += " - " + pd.Title
			}
			if pd.Detail != "" {
				msg += ": " + pd.Detail
			}
			msg += fmt.Sprintf(" (type=%s)", pd.Type)
			return "", errors.New(msg)
		}
		return "", fmt.Errorf("download %s failed: %s %s", cid, res.Status, trimmed)
	}
	outPath := filepath.Join(outDir, sanitizeFilename(cid)+".car")
	f, err := os.Create(outPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(f, res.Body); err != nil {
		return "", err
	}
	return outPath, nil
}

func collectCIDs(flagCIDs []string, cidFile string, args []string) ([]string, error) {
	seen := map[string]struct{}{}
	var out []string
	appendCID := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	for _, c := range flagCIDs {
		for _, p := range strings.Split(c, ",") {
			appendCID(p)
		}
	}
	for _, c := range args {
		for _, p := range strings.Split(c, ",") {
			appendCID(p)
		}
	}
	if cidFile != "" {
		b, err := os.ReadFile(cidFile)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(b), "\n") {
			for _, p := range strings.Split(line, ",") {
				appendCID(p)
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

	// Deduplicate while preserving order.
	seen := make(map[string]struct{}, len(m.Pieces))
	out := make([]string, 0, len(m.Pieces))
	for _, p := range m.Pieces {
		piece := strings.TrimSpace(p.PieceCID)
		if piece == "" {
			continue
		}
		if _, ok := seen[piece]; ok {
			continue
		}
		seen[piece] = struct{}{}
		out = append(out, piece)
	}
	return out, nil
}

func promptYesNo(prompt string) (bool, error) {
	fmt.Print(prompt)
	r := bufio.NewReader(os.Stdin)
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

func sumFILValues(prices []string) string {
	var total float64
	for _, price := range prices {
		var x float64
		fmt.Sscanf(price, "%f", &x)
		total += x
	}
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.6f", total), "0"), ".")
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
