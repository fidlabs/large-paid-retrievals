package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/fidlabs/paid-retrievals/internal/pieceaccess"
	"github.com/fidlabs/paid-retrievals/internal/pieceurls"
)

// retrievalAuthConfig controls per-piece Retrieval credential minting.
//
// It emits two token kinds as full Authorization header values:
//   - one "RetrievalProof <b64>" (proof of possession) bound to the piece CID,
//     signed by the requester key; and
//   - zero or more "RetrievalVoucher <b64>" capabilities forwarded verbatim.
//
// The proof's scope is advisory: the SP binds the deal via the piece CID, so a
// client never needs to know which deal a piece belongs to.
type retrievalAuthConfig struct {
	key          *ecdsa.PrivateKey
	capabilities []string // long-lived owner-signed vouchers (--voucher)

	// domain is the EIP-712 domain for owner-direct proofs (and a fallback when
	// vouchers omit a usable domain).
	domain pieceaccessDomain
}

type pieceaccessDomain struct {
	chainID *big.Int
	market  common.Address
}

func (d pieceaccessDomain) ok() bool {
	return d.chainID != nil && d.chainID.Sign() > 0 && d.market != (common.Address{})
}

func (d pieceaccessDomain) typedDomain() apitypes.TypedDataDomain {
	return pieceaccess.NewDomain(d.chainID, d.market)
}

// authHeadersForPiece returns full Authorization header values for pieceCID: one
// RetrievalProof plus every RetrievalVoucher capability (delegated), or a single
// owner-direct RetrievalProof when no vouchers are configured.
func (c *retrievalAuthConfig) authHeadersForPiece(_ context.Context, pieceCID string) ([]string, error) {
	if c == nil || c.key == nil {
		return nil, nil
	}
	pieceCID = strings.TrimSpace(pieceCID)
	if pieceCID == "" {
		return nil, nil
	}
	deadline := time.Now().Unix() + int64(pieceaccess.MaxProofTTL.Seconds())

	if len(c.capabilities) > 0 {
		return c.delegatedHeaders(pieceCID, deadline)
	}
	if !c.domain.ok() {
		return nil, fmt.Errorf("cannot mint owner-direct RetrievalProof: set --porep-market-address or POREP_MARKET (pay-rpc chain has no PoRep market default)")
	}
	proof, err := pieceaccess.MintProofForPiece(c.domain.typedDomain(), nil, pieceCID, c.key, deadline)
	if err != nil {
		return nil, err
	}
	return []string{pieceaccess.SchemeRetrievalProof + " " + proof}, nil
}

// delegatedHeaders forwards every voucher verbatim and mints one proof using the
// vouchers' domain (falling back to the configured domain).
func (c *retrievalAuthConfig) delegatedHeaders(pieceCID string, deadline int64) ([]string, error) {
	var proofDomain apitypes.TypedDataDomain
	haveDomain := false
	vouchers := make([]string, 0, len(c.capabilities))
	for _, raw := range c.capabilities {
		bare := pieceurls.StripVoucherAuthScheme(strings.TrimSpace(raw))
		if bare == "" {
			continue
		}
		vouchers = append(vouchers, pieceaccess.SchemeRetrievalVoucher+" "+bare)
		if !haveDomain {
			if cap, err := pieceaccess.ParseCapabilityToken(bare); err == nil {
				proofDomain = cap.Domain
				haveDomain = true
			}
		}
	}
	if !haveDomain && c.domain.ok() {
		proofDomain = c.domain.typedDomain()
		haveDomain = true
	}
	if !haveDomain {
		return nil, fmt.Errorf("cannot mint retrieval proof: no valid voucher domain and no --porep-market/pay-rpc domain configured")
	}
	proof, err := pieceaccess.MintProofToken(c.key, proofDomain, nil, pieceCID, deadline)
	if err != nil {
		return nil, err
	}
	// Proof first, then the vouchers (order is not significant to the SP).
	return append([]string{pieceaccess.SchemeRetrievalProof + " " + proof}, vouchers...), nil
}

func parseDealScope(dealID string) (*big.Int, error) {
	dealID = strings.TrimSpace(dealID)
	if dealID == "" {
		return nil, fmt.Errorf("empty deal id")
	}
	if strings.HasPrefix(dealID, "0x") || strings.HasPrefix(dealID, "0X") {
		n, ok := new(big.Int).SetString(dealID[2:], 16)
		if !ok {
			return nil, fmt.Errorf("invalid hex deal id %q", dealID)
		}
		return n, nil
	}
	n, ok := new(big.Int).SetString(dealID, 10)
	if ok {
		return n, nil
	}
	u, err := strconv.ParseUint(dealID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid deal id %q", dealID)
	}
	return new(big.Int).SetUint64(u), nil
}

func resolveAuthDomain(marketOverride string, chainID *big.Int) (pieceaccessDomain, error) {
	if chainID == nil || chainID.Sign() <= 0 {
		return pieceaccessDomain{}, nil
	}
	market, err := pieceaccess.ResolvePorepMarketAddress(marketOverride, chainID.Int64())
	if err != nil {
		return pieceaccessDomain{}, err
	}
	if market == (common.Address{}) {
		return pieceaccessDomain{}, nil
	}
	return pieceaccessDomain{chainID: new(big.Int).Set(chainID), market: market}, nil
}

func ethChainID(ctx context.Context, rpcURL string) (*big.Int, error) {
	rpcURL = strings.TrimSpace(rpcURL)
	if rpcURL == "" {
		return nil, fmt.Errorf("empty pay RPC URL")
	}
	cli, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, err
	}
	defer cli.Close()
	return cli.ChainID(ctx)
}

// buildRetrievalAuth resolves the EIP-712 domain (chainId from the pay RPC +
// PoRep market) used for owner-direct proofs and as a fallback for delegated
// proofs. When --voucher is set, every token is checked for wire format,
// non-expiry, and a recoverable signature before the client proceeds. The
// cdpURL/providerID arguments are accepted for CLI compatibility but are no
// longer required for client-side minting (the SP binds the deal via the piece CID).
func buildRetrievalAuth(
	ctx context.Context,
	key *ecdsa.PrivateKey,
	capabilities []string,
	payRPCURL, _cdpURL, marketOverride string,
	_providerID uint64,
) (*retrievalAuthConfig, error) {
	cfg := &retrievalAuthConfig{key: key}
	chainID, err := ethChainID(ctx, payRPCURL)
	if err != nil {
		if len(capabilities) == 0 {
			return nil, fmt.Errorf("eth_chainId for access domain: %w", err)
		}
		// Vouchers carry their own domain; continue without a pin.
	} else {
		domain, derr := resolveAuthDomain(marketOverride, chainID)
		if derr != nil {
			if len(capabilities) == 0 {
				return nil, derr
			}
		} else {
			cfg.domain = domain
		}
	}
	if len(capabilities) > 0 {
		verified, verr := validateCapabilityFlags(capabilities, cfg.domain)
		if verr != nil {
			return nil, verr
		}
		cfg.capabilities = verified
	}
	return cfg, nil
}

// validateCapabilityFlags strips optional Authorization scheme prefixes and
// verifies each --voucher token (format, deadline, signature; domain pin when
// known). Returns bare base64url tokens for forwarding.
func validateCapabilityFlags(raw []string, domain pieceaccessDomain) ([]string, error) {
	var pin *pieceaccess.DomainPin
	if domain.ok() {
		pin = &pieceaccess.DomainPin{ChainID: domain.chainID, Contract: domain.market}
	}
	now := time.Now().Unix()
	out := make([]string, 0, len(raw))
	for i, v := range raw {
		bare := pieceurls.StripVoucherAuthScheme(strings.TrimSpace(v))
		if bare == "" {
			return nil, fmt.Errorf("--voucher[%d]: empty token", i)
		}
		if _, _, err := pieceaccess.VerifyCapabilityToken(bare, now, pin); err != nil {
			return nil, fmt.Errorf("--voucher[%d]: %w", i, err)
		}
		out = append(out, bare)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--voucher: no usable tokens")
	}
	return out, nil
}
