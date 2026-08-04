package pieceaccess

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

const (
	voucherAuthScheme   = "Bearer"
	voucherDomainName   = "PoRepPieceAccess"
	voucherDomainVer    = "1"
	voucherPrimaryType  = "RetrievalVoucher"
	voucherTypeGrantee  = "grantee"
	voucherTypeDealID   = "dealId"
	voucherTypeDeadline = "deadline"
)

// ErrInvalidVoucher is returned when a Bearer access voucher fails parse, shape,
// signature, or deadline checks.
var ErrInvalidVoucher = errors.New("pieceaccess: invalid access voucher")

// VerifiedVoucher is a Bearer EIP-712 retrieval voucher that passed verification.
type VerifiedVoucher struct {
	Owner    common.Address // recovered EIP-712 signer (deal owner who issued the voucher)
	Grantee  common.Address
	DealID   *big.Int
	Deadline int64
}

type voucherToken struct {
	Domain      apitypes.TypedDataDomain `json:"domain"`
	Types       apitypes.Types           `json:"types"`
	PrimaryType string                   `json:"primaryType"`
	Message     map[string]any           `json:"message"`
	Signature   string                   `json:"signature"`
}

type voucherErrorDetail struct {
	Index   int    `json:"index"`
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

type voucherErrorBody struct {
	Error   string               `json:"error"`
	Message string               `json:"message"`
	Details []voucherErrorDetail `json:"details"`
}

// voucherNow is overridable in tests.
var voucherNow = func() int64 { return time.Now().Unix() }

// voucherDomainPin is the expected EIP-712 domain for access vouchers.
// When configured (non-nil chainID > 0 and non-zero contract), tokens whose
// domain does not match are rejected (cross-network / cross-market replay).
type voucherDomainPin struct {
	chainID  *big.Int
	contract common.Address
}

func (p *voucherDomainPin) configured() bool {
	return p != nil && p.chainID != nil && p.chainID.Sign() > 0 && p.contract != (common.Address{})
}

// parseAndVerifyVouchers extracts Authorization: Bearer vouchers, verifies each,
// and returns verified vouchers. If any voucher fails, it returns ErrInvalidVoucher
// with a multi-detail error suitable for JSON responses.
func parseAndVerifyVouchers(r *http.Request, pin *voucherDomainPin) ([]VerifiedVoucher, error) {
	raws := bearerAuthorizationValues(r)
	if len(raws) == 0 {
		return nil, nil
	}
	out := make([]VerifiedVoucher, 0, len(raws))
	var details []voucherErrorDetail
	for i, raw := range raws {
		v, err := verifyBearerVoucher(raw, voucherNow(), pin)
		if err != nil {
			details = append(details, voucherErrorDetail{
				Index:   i,
				Error:   voucherErrorCode(err),
				Message: err.Error(),
			})
			continue
		}
		out = append(out, *v)
	}
	if len(details) > 0 {
		return nil, &voucherVerifyError{details: details}
	}
	return out, nil
}

type voucherVerifyError struct {
	details []voucherErrorDetail
}

func (e *voucherVerifyError) Error() string {
	if e == nil || len(e.details) == 0 {
		return ErrInvalidVoucher.Error()
	}
	parts := make([]string, 0, len(e.details))
	for _, d := range e.details {
		parts = append(parts, fmt.Sprintf("[%d] %s", d.Index, d.Message))
	}
	return fmt.Sprintf("%s: %s", ErrInvalidVoucher.Error(), strings.Join(parts, "; "))
}

func (e *voucherVerifyError) Unwrap() error { return ErrInvalidVoucher }

func writeVoucherError(w http.ResponseWriter, err error) {
	body := voucherErrorBody{
		Error:   "invalid_voucher",
		Message: "one or more access vouchers failed signature or deadline verification",
	}
	var ve *voucherVerifyError
	if errors.As(err, &ve) {
		body.Details = ve.details
	} else {
		body.Details = []voucherErrorDetail{{Index: 0, Error: "invalid_voucher", Message: err.Error()}}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

func voucherErrorCode(err error) string {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "expired") || strings.Contains(msg, "deadline"):
		return "voucher_expired"
	case strings.Contains(msg, "signature"):
		return "invalid_signature"
	case strings.Contains(msg, "decode") || strings.Contains(msg, "json") || strings.Contains(msg, "bearer"):
		return "malformed_voucher"
	default:
		return "invalid_voucher"
	}
}

func bearerAuthorizationValues(r *http.Request) []string {
	if r == nil {
		return nil
	}
	var out []string
	for _, raw := range r.Header.Values("Authorization") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		scheme, token, ok := strings.Cut(raw, " ")
		if !ok || !strings.EqualFold(scheme, voucherAuthScheme) {
			continue
		}
		out = append(out, strings.TrimSpace(token))
	}
	return out
}

func verifyBearerVoucher(token string, nowUnix int64, pin *voucherDomainPin) (*VerifiedVoucher, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("%w: empty bearer token", ErrInvalidVoucher)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("%w: bearer token base64url decode: %v", ErrInvalidVoucher, err)
	}
	tok, err := decodeVoucherToken(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: voucher json: %v", ErrInvalidVoucher, err)
	}
	if err := validateVoucherShape(tok); err != nil {
		return nil, err
	}

	deadlineBig, err := parseVoucherUint256(tok.Message[voucherTypeDeadline])
	if err != nil {
		return nil, fmt.Errorf("%w: deadline: %v", ErrInvalidVoucher, err)
	}
	deadline, err := unixDeadline(deadlineBig)
	if err != nil {
		return nil, fmt.Errorf("%w: deadline: %v", ErrInvalidVoucher, err)
	}
	if deadline <= nowUnix {
		return nil, fmt.Errorf("%w: voucher expired (deadline=%d now=%d)", ErrInvalidVoucher, deadline, nowUnix)
	}
	dealID, err := parseVoucherUint256(tok.Message[voucherTypeDealID])
	if err != nil {
		return nil, fmt.Errorf("%w: dealId: %v", ErrInvalidVoucher, err)
	}
	granteeRaw, _ := tok.Message[voucherTypeGrantee].(string)
	if !common.IsHexAddress(granteeRaw) {
		return nil, fmt.Errorf("%w: grantee is not an address", ErrInvalidVoucher)
	}
	grantee := common.HexToAddress(granteeRaw)

	if err := checkVoucherDomain(tok, pin); err != nil {
		return nil, err
	}

	// Normalize uint256 message fields to decimal strings so EIP-712 hashing
	// sees exact values (json.Number / float64 are awkward for go-ethereum).
	tok.Message[voucherTypeDealID] = dealID.String()
	tok.Message[voucherTypeDeadline] = deadlineBig.String()

	ensureEIP712DomainTypes(tok)
	typed := apitypes.TypedData{
		Types:       tok.Types,
		PrimaryType: tok.PrimaryType,
		Domain:      tok.Domain,
		Message:     tok.Message,
	}
	digest, _, err := apitypes.TypedDataAndHash(typed)
	if err != nil {
		return nil, fmt.Errorf("%w: eip-712 hash: %v", ErrInvalidVoucher, err)
	}
	owner, err := recoverVoucherSigner(digest, tok.Signature)
	if err != nil {
		return nil, err
	}
	return &VerifiedVoucher{
		Owner:    owner,
		Grantee:  grantee,
		DealID:   dealID,
		Deadline: deadline,
	}, nil
}

// decodeVoucherToken unmarshals a voucher payload with UseNumber so uint256
// fields keep full decimal precision instead of float64.
func decodeVoucherToken(raw []byte) (*voucherToken, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var tok voucherToken
	if err := dec.Decode(&tok); err != nil {
		return nil, err
	}
	return &tok, nil
}

func checkVoucherDomain(tok *voucherToken, pin *voucherDomainPin) error {
	if !pin.configured() {
		return fmt.Errorf("%w: voucher domain pin not configured", ErrInvalidVoucher)
	}
	if tok.Domain.ChainId == nil {
		return fmt.Errorf("%w: missing domain.chainId", ErrInvalidVoucher)
	}
	gotChain := new(big.Int).Set((*big.Int)(tok.Domain.ChainId))
	if gotChain.Cmp(pin.chainID) != 0 {
		return fmt.Errorf("%w: domain.chainId want %s got %s", ErrInvalidVoucher, pin.chainID.String(), gotChain.String())
	}
	if !common.IsHexAddress(tok.Domain.VerifyingContract) {
		return fmt.Errorf("%w: missing or invalid domain.verifyingContract", ErrInvalidVoucher)
	}
	gotContract := common.HexToAddress(tok.Domain.VerifyingContract)
	if !sameAddress(gotContract, pin.contract) {
		return fmt.Errorf("%w: domain.verifyingContract mismatch", ErrInvalidVoucher)
	}
	return nil
}

func validateVoucherShape(tok *voucherToken) error {
	if tok == nil {
		return fmt.Errorf("%w: nil voucher", ErrInvalidVoucher)
	}
	if tok.PrimaryType != voucherPrimaryType {
		return fmt.Errorf("%w: primaryType want %s got %q", ErrInvalidVoucher, voucherPrimaryType, tok.PrimaryType)
	}
	if tok.Domain.Name != voucherDomainName {
		return fmt.Errorf("%w: domain.name want %s got %q", ErrInvalidVoucher, voucherDomainName, tok.Domain.Name)
	}
	if tok.Domain.Version != voucherDomainVer {
		return fmt.Errorf("%w: domain.version want %s got %q", ErrInvalidVoucher, voucherDomainVer, tok.Domain.Version)
	}
	fields, ok := tok.Types[voucherPrimaryType]
	if !ok || len(fields) == 0 {
		return fmt.Errorf("%w: missing types.%s", ErrInvalidVoucher, voucherPrimaryType)
	}
	want := map[string]string{
		voucherTypeGrantee:  "address",
		voucherTypeDealID:   "uint256",
		voucherTypeDeadline: "uint256",
	}
	if len(fields) != len(want) {
		return fmt.Errorf("%w: unexpected %s field count", ErrInvalidVoucher, voucherPrimaryType)
	}
	seen := make(map[string]struct{}, len(want))
	for _, f := range fields {
		t, ok := want[f.Name]
		if !ok || f.Type != t {
			return fmt.Errorf("%w: unexpected type field %s %s", ErrInvalidVoucher, f.Name, f.Type)
		}
		if _, dup := seen[f.Name]; dup {
			return fmt.Errorf("%w: duplicate type field %s", ErrInvalidVoucher, f.Name)
		}
		seen[f.Name] = struct{}{}
	}
	for name := range want {
		if _, ok := seen[name]; !ok {
			return fmt.Errorf("%w: missing type field %s", ErrInvalidVoucher, name)
		}
	}
	if tok.Message == nil {
		return fmt.Errorf("%w: missing message", ErrInvalidVoucher)
	}
	for _, name := range []string{voucherTypeGrantee, voucherTypeDealID, voucherTypeDeadline} {
		if _, ok := tok.Message[name]; !ok {
			return fmt.Errorf("%w: missing message.%s", ErrInvalidVoucher, name)
		}
	}
	if strings.TrimSpace(tok.Signature) == "" {
		return fmt.Errorf("%w: missing signature", ErrInvalidVoucher)
	}
	return nil
}

func ensureEIP712DomainTypes(tok *voucherToken) {
	if tok.Types == nil {
		tok.Types = apitypes.Types{}
	}
	if _, ok := tok.Types["EIP712Domain"]; ok {
		return
	}
	// Match eth_account / tooling: domain fields present without EIP712Domain in types.
	var fields []apitypes.Type
	if tok.Domain.Name != "" {
		fields = append(fields, apitypes.Type{Name: "name", Type: "string"})
	}
	if tok.Domain.Version != "" {
		fields = append(fields, apitypes.Type{Name: "version", Type: "string"})
	}
	if tok.Domain.ChainId != nil {
		fields = append(fields, apitypes.Type{Name: "chainId", Type: "uint256"})
	}
	if tok.Domain.VerifyingContract != "" {
		fields = append(fields, apitypes.Type{Name: "verifyingContract", Type: "address"})
	}
	if tok.Domain.Salt != "" {
		fields = append(fields, apitypes.Type{Name: "salt", Type: "bytes32"})
	}
	tok.Types["EIP712Domain"] = fields
}

func recoverVoucherSigner(digest []byte, signatureHex string) (common.Address, error) {
	sig := common.FromHex(strings.TrimSpace(signatureHex))
	if len(sig) != 65 {
		return common.Address{}, fmt.Errorf("%w: signature must be 65 bytes, got %d", ErrInvalidVoucher, len(sig))
	}
	// eth_account uses v=27/28; go-ethereum Ecrecover expects 0/1.
	if sig[64] >= 27 {
		sig[64] -= 27
	}
	if sig[64] > 1 {
		return common.Address{}, fmt.Errorf("%w: invalid signature recovery id", ErrInvalidVoucher)
	}
	pub, err := crypto.SigToPub(digest, sig)
	if err != nil {
		return common.Address{}, fmt.Errorf("%w: signature recovery failed: %v", ErrInvalidVoucher, err)
	}
	return crypto.PubkeyToAddress(*pub), nil
}

// maxSafeJSONFloatInt is the largest integer exactly representable in IEEE-754
// float64 (2^53 - 1). Bare JSON numbers decoded without UseNumber cannot safely
// carry values above this.
const maxSafeJSONFloatInt = (1 << 53) - 1

// parseVoucherUint256 parses dealId/deadline from a JSON message map into a
// full uint256. Prefer json.Number (UseNumber) or decimal strings; float64 is
// accepted only for exact integers within the float64 safe-integer range.
func parseVoucherUint256(v any) (*big.Int, error) {
	switch x := v.(type) {
	case json.Number:
		return parseUint256String(string(x))
	case string:
		return parseUint256String(x)
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) || x < 0 || x != math.Trunc(x) {
			return nil, fmt.Errorf("not an integer")
		}
		if x > float64(maxSafeJSONFloatInt) {
			return nil, fmt.Errorf("float64 loses precision above 2^53; use a decimal string or json.Number")
		}
		return big.NewInt(int64(x)), nil
	default:
		return nil, fmt.Errorf("unsupported type %T", v)
	}
}

func parseUint256String(s string) (*big.Int, error) {
	n, ok := new(big.Int).SetString(strings.TrimSpace(s), 10)
	if !ok {
		return nil, fmt.Errorf("not an integer string")
	}
	if n.Sign() < 0 {
		return nil, fmt.Errorf("negative")
	}
	if n.BitLen() > 256 {
		return nil, fmt.Errorf("out of uint256 range")
	}
	return n, nil
}

// unixDeadline converts a uint256 deadline to unix seconds for expiry checks.
func unixDeadline(n *big.Int) (int64, error) {
	if n == nil || !n.IsInt64() {
		return 0, fmt.Errorf("out of int64 range")
	}
	return n.Int64(), nil
}

func voucherAuthorizesDeal(v VerifiedVoucher, d *Deal) bool {
	if d == nil || d.DealType != DealTypePrivate {
		return false
	}
	if v.Owner == (common.Address{}) || !sameAddress(v.Owner, d.Client) {
		return false
	}
	return dealIDMatches(v.DealID, d.DealID)
}

// dealIDMatches compares the signed voucher dealId to the CDP deal id string.
func dealIDMatches(voucherDealID *big.Int, dealID string) bool {
	if voucherDealID == nil {
		return false
	}
	n, ok := new(big.Int).SetString(strings.TrimSpace(dealID), 10)
	if !ok {
		return false
	}
	return voucherDealID.Cmp(n) == 0
}
