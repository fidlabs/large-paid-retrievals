package pieceaccess

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// CapabilityVoucher is a parsed, owner-signed RetrievalVoucher token. The
// original base64url Token is retained so a client can forward it verbatim in a
// RetrievalVoucher Authorization header.
type CapabilityVoucher struct {
	Token    string
	Domain   apitypes.TypedDataDomain
	Grantee  common.Address
	Scope    *big.Int
	Deadline int64
	IssuedAt int64
}

// ParseCapabilityToken parses a base64url RetrievalVoucher token (typed data
// with the signature carried inside). The voucher must use the current shape
// (grantee, scope, issuedAt, deadline); legacy dealId-only tokens are rejected.
// It does not check expiry or the signature — use VerifyCapabilityToken for that.
func ParseCapabilityToken(token string) (*CapabilityVoucher, error) {
	token = strings.TrimSpace(token)
	obj, _, err := decodeSignedToken(token)
	if err != nil {
		return nil, err
	}
	if err := validateVoucherShape(obj); err != nil {
		return nil, err
	}
	scope, err := parseUint256Field(obj.Message[fieldScope])
	if err != nil {
		return nil, fmt.Errorf("%w: voucher.scope: %v", ErrInvalidVoucher, err)
	}
	deadlineBig, err := parseUint256Field(obj.Message[fieldDeadline])
	if err != nil {
		return nil, fmt.Errorf("%w: voucher.deadline: %v", ErrInvalidVoucher, err)
	}
	deadline, err := unixDeadline(deadlineBig)
	if err != nil {
		return nil, fmt.Errorf("%w: voucher.deadline: %v", ErrInvalidVoucher, err)
	}
	issuedBig, err := parseUint256Field(obj.Message[fieldIssuedAt])
	if err != nil {
		return nil, fmt.Errorf("%w: voucher.issuedAt: %v", ErrInvalidVoucher, err)
	}
	issuedAt, err := unixDeadline(issuedBig)
	if err != nil {
		return nil, fmt.Errorf("%w: voucher.issuedAt: %v", ErrInvalidVoucher, err)
	}
	granteeRaw, _ := obj.Message[fieldGrantee].(string)
	if !common.IsHexAddress(granteeRaw) {
		return nil, fmt.Errorf("%w: voucher.grantee is not an address", ErrInvalidVoucher)
	}
	return &CapabilityVoucher{
		Token:    token,
		Domain:   obj.Domain,
		Grantee:  common.HexToAddress(granteeRaw),
		Scope:    scope,
		Deadline: deadline,
		IssuedAt: issuedAt,
	}, nil
}

// VerifyCapabilityToken checks a RetrievalVoucher's wire format, that it is not
// expired, and that its embedded signature recovers a valid owner. When pin is
// non-nil and configured, the voucher domain must also match the pin (chainId +
// verifyingContract). Returns the capability (including Domain for proof minting)
// and the verified owner/grantee/scope fields.
func VerifyCapabilityToken(token string, nowUnix int64, pin *DomainPin) (*CapabilityVoucher, *VerifiedVoucher, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil, fmt.Errorf("%w: empty voucher token", ErrInvalidVoucher)
	}
	obj, sig, err := decodeSignedToken(token)
	if err != nil {
		return nil, nil, err
	}
	if err := validateVoucherShape(obj); err != nil {
		return nil, nil, err
	}
	var internalPin *voucherDomainPin
	if pin != nil && pin.configured() {
		internalPin = &voucherDomainPin{chainID: pin.ChainID, contract: pin.Contract}
	}
	if internalPin.configured() {
		if err := checkDomainPin(&obj.Domain, internalPin); err != nil {
			return nil, nil, err
		}
	}
	verified, err := finishVerifyVoucher(obj, sig, nowUnix)
	if err != nil {
		return nil, nil, err
	}
	return &CapabilityVoucher{
		Token:    token,
		Domain:   obj.Domain,
		Grantee:  verified.Grantee,
		Scope:    verified.Scope,
		Deadline: verified.Deadline,
		IssuedAt: verified.IssuedAt,
	}, verified, nil
}

// DomainPin is the expected EIP-712 domain for client-side voucher checks.
// Zero values mean "do not pin" (format + expiry + signature only).
type DomainPin struct {
	ChainID  *big.Int
	Contract common.Address
}

func (p *DomainPin) configured() bool {
	return p != nil && p.ChainID != nil && p.ChainID.Sign() > 0 && p.Contract != (common.Address{})
}

// MintProofForPiece signs a RetrievalProof binding requester (proofKey) to
// pieceCID and returns its base64url token. scope is advisory; pass nil to
// leave it zero (the server binds the deal via the piece CID).
func MintProofForPiece(domain apitypes.TypedDataDomain, scope *big.Int, pieceCID string, proofKey *ecdsa.PrivateKey, proofDeadline int64) (string, error) {
	if proofKey == nil {
		return "", fmt.Errorf("pieceaccess: nil proof key")
	}
	pieceCID = strings.TrimSpace(pieceCID)
	if pieceCID == "" {
		return "", fmt.Errorf("%w: empty piece CID", ErrInvalidVoucher)
	}
	if proofDeadline <= 0 {
		proofDeadline = time.Now().Unix() + int64(MaxProofTTL.Seconds())
	}
	return MintProofToken(proofKey, domain, scope, pieceCID, proofDeadline)
}

// DomainFromParts is a convenience when chainID comes from an int64.
func DomainFromParts(chainID int64, market common.Address) apitypes.TypedDataDomain {
	return NewDomain(big.NewInt(chainID), market)
}
