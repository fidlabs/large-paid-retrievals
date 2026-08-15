package pieceaccess

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// SignEIP712 signs typed data with key and returns a 0x-hex signature with v in {27,28}.
func SignEIP712(key *ecdsa.PrivateKey, typedData apitypes.TypedData) (string, error) {
	if key == nil {
		return "", fmt.Errorf("pieceaccess: nil private key")
	}
	ensureTypedDataDomainTypes(&typedData)
	digest, _, err := apitypes.TypedDataAndHash(typedData)
	if err != nil {
		return "", fmt.Errorf("pieceaccess: eip-712 hash: %w", err)
	}
	sig, err := crypto.Sign(digest, key)
	if err != nil {
		return "", fmt.Errorf("pieceaccess: sign: %w", err)
	}
	sig[64] += 27
	return "0x" + common.Bytes2Hex(sig), nil
}

// MustSignEIP712 is SignEIP712 that panics on error (tests/fixtures).
func MustSignEIP712(key *ecdsa.PrivateKey, typedData apitypes.TypedData) string {
	sig, err := SignEIP712(key, typedData)
	if err != nil {
		panic(err)
	}
	return sig
}

// NewDomain builds the PoRepPieceAccess EIP-712 domain for chainID + market.
func NewDomain(chainID *big.Int, market common.Address) apitypes.TypedDataDomain {
	if chainID == nil {
		chainID = big.NewInt(0)
	}
	return apitypes.TypedDataDomain{
		Name:              eip712DomainName,
		Version:           eip712DomainVer,
		ChainId:           (*math.HexOrDecimal256)(new(big.Int).Set(chainID)),
		VerifyingContract: market.Hex(),
	}
}

// BuildProofTypedData builds a RetrievalProof typed-data object (no signature).
func BuildProofTypedData(domain apitypes.TypedDataDomain, scope *big.Int, resource string, deadline int64) apitypes.TypedData {
	if scope == nil {
		scope = big.NewInt(0)
	}
	return apitypes.TypedData{
		Types: apitypes.Types{
			primaryTypeProof: {
				{Name: fieldScope, Type: "uint256"},
				{Name: fieldResource, Type: "string"},
				{Name: fieldDeadline, Type: "uint256"},
			},
		},
		PrimaryType: primaryTypeProof,
		Domain:      domain,
		Message: apitypes.TypedDataMessage{
			fieldScope:    scope.String(),
			fieldResource: resource,
			fieldDeadline: fmt.Sprintf("%d", deadline),
		},
	}
}

// BuildVoucherTypedData builds a RetrievalVoucher typed-data object (no signature).
func BuildVoucherTypedData(domain apitypes.TypedDataDomain, grantee common.Address, scope *big.Int, issuedAt, deadline int64) apitypes.TypedData {
	if scope == nil {
		scope = big.NewInt(0)
	}
	return apitypes.TypedData{
		Types: apitypes.Types{
			primaryTypeVoucher: {
				{Name: fieldGrantee, Type: "address"},
				{Name: fieldScope, Type: "uint256"},
				{Name: fieldIssuedAt, Type: "uint256"},
				{Name: fieldDeadline, Type: "uint256"},
			},
		},
		PrimaryType: primaryTypeVoucher,
		Domain:      domain,
		Message: apitypes.TypedDataMessage{
			fieldGrantee:  grantee.Hex(),
			fieldScope:    scope.String(),
			fieldIssuedAt: fmt.Sprintf("%d", issuedAt),
			fieldDeadline: fmt.Sprintf("%d", deadline),
		},
	}
}

// EncodeSignedToken serializes a signed EIP-712 token (typed data + signature)
// as base64url(JSON). The signature is carried inside the object and
// EIP712Domain is omitted from types (verifiers synthesize it).
func EncodeSignedToken(td apitypes.TypedData, signature string) (string, error) {
	obj := typedDataToJSON(td)
	payload := signedTypedData{
		Domain:      obj.Domain,
		Types:       obj.Types,
		PrimaryType: obj.PrimaryType,
		Message:     obj.Message,
		Signature:   strings.TrimSpace(signature),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("pieceaccess: encode token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// MustEncodeSignedToken is EncodeSignedToken that panics on error (tests/fixtures).
func MustEncodeSignedToken(td apitypes.TypedData, signature string) string {
	tok, err := EncodeSignedToken(td, signature)
	if err != nil {
		panic(err)
	}
	return tok
}

// MintProofToken signs a RetrievalProof for resource and returns its base64url
// token. scope is advisory (the server binds the deal via resource); pass nil
// to leave it zero.
func MintProofToken(key *ecdsa.PrivateKey, domain apitypes.TypedDataDomain, scope *big.Int, resource string, deadline int64) (string, error) {
	td := BuildProofTypedData(domain, scope, resource, deadline)
	sig, err := SignEIP712(key, td)
	if err != nil {
		return "", err
	}
	return EncodeSignedToken(td, sig)
}

// MintVoucherToken signs a RetrievalVoucher capability and returns its base64url
// token (shareable, long-lived).
func MintVoucherToken(key *ecdsa.PrivateKey, domain apitypes.TypedDataDomain, grantee common.Address, scope *big.Int, issuedAt, deadline int64) (string, error) {
	td := BuildVoucherTypedData(domain, grantee, scope, issuedAt, deadline)
	sig, err := SignEIP712(key, td)
	if err != nil {
		return "", err
	}
	return EncodeSignedToken(td, sig)
}

func typedDataToJSON(td apitypes.TypedData) *eip712TypedDataJSON {
	types := apitypes.Types{}
	for k, v := range td.Types {
		if k == "EIP712Domain" {
			continue // wire tokens omit EIP712Domain; verifiers synthesize it
		}
		types[k] = v
	}
	msg := make(map[string]any, len(td.Message))
	for k, v := range td.Message {
		msg[k] = v
	}
	return &eip712TypedDataJSON{
		Domain:      td.Domain,
		Types:       types,
		PrimaryType: td.PrimaryType,
		Message:     msg,
	}
}

func ensureTypedDataDomainTypes(td *apitypes.TypedData) {
	if td.Types == nil {
		td.Types = apitypes.Types{}
	}
	if _, ok := td.Types["EIP712Domain"]; ok {
		return
	}
	var fields []apitypes.Type
	if td.Domain.Name != "" {
		fields = append(fields, apitypes.Type{Name: "name", Type: "string"})
	}
	if td.Domain.Version != "" {
		fields = append(fields, apitypes.Type{Name: "version", Type: "string"})
	}
	if td.Domain.ChainId != nil {
		fields = append(fields, apitypes.Type{Name: "chainId", Type: "uint256"})
	}
	if td.Domain.VerifyingContract != "" {
		fields = append(fields, apitypes.Type{Name: "verifyingContract", Type: "address"})
	}
	if td.Domain.Salt != "" {
		fields = append(fields, apitypes.Type{Name: "salt", Type: "bytes32"})
	}
	td.Types["EIP712Domain"] = fields
}
