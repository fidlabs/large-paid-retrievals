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
	"github.com/fidlabs/paid-retrievals/internal/dealstore"
)

const (
	// SchemeRetrievalVoucher is the Authorization scheme for owner-signed
	// capability tokens. It is repeatable: a client may present many vouchers
	// on one request (it need not know which deal a piece belongs to).
	SchemeRetrievalVoucher = "RetrievalVoucher"
	// SchemeRetrievalProof is the Authorization scheme for the requester's
	// per-request proof of possession (PoP). At most one is used per request.
	SchemeRetrievalProof = "RetrievalProof"

	eip712DomainName = "PoRepPieceAccess"
	eip712DomainVer  = "1"

	primaryTypeProof   = "RetrievalProof"
	primaryTypeVoucher = "RetrievalVoucher"

	fieldScope    = "scope"
	fieldResource = "resource"
	fieldDeadline = "deadline"
	fieldGrantee  = "grantee"
	fieldIssuedAt = "issuedAt"
)

// ErrInvalidVoucher is returned when a Retrieval credential fails parse, shape,
// signature, deadline, or domain checks. The JSON error key remains
// "invalid_voucher" for probe/e2e compatibility.
var ErrInvalidVoucher = errors.New("pieceaccess: invalid access credential")

// MaxProofTTL is the maximum proof deadline window. It MUST equal the paid
// retrieval retry window (dealstore.PaidAccessTTL) so one proof survives the
// whole repeat-download window.
const MaxProofTTL = dealstore.PaidAccessTTL

// VerifiedProof is a validated RetrievalProof (PoP) token.
type VerifiedProof struct {
	Requester common.Address
	// Scope is signed but advisory: the server binds the deal via Resource
	// (piece CID → CDP), so a client need not know the deal id to mint a proof.
	Scope    *big.Int
	Resource string
	Deadline int64
}

// VerifiedVoucher is a validated RetrievalVoucher capability token.
type VerifiedVoucher struct {
	Owner    common.Address
	Grantee  common.Address
	Scope    *big.Int
	Deadline int64
	IssuedAt int64
}

// VerifiedAccess is the parsed access context for one request: a single PoP
// proof (when present and valid) plus zero or more delegated vouchers. Voucher
// verification is best-effort — clients present all their vouchers and the
// server uses whichever authorize; invalid ones are retained only as
// diagnostics for the denial response.
type VerifiedAccess struct {
	Proof         *VerifiedProof
	Vouchers      []VerifiedVoucher
	voucherErrors []voucherErrorDetail
}

// eip712TypedDataJSON is a complete EIP-712 typed-data object (no signature).
type eip712TypedDataJSON struct {
	Domain      apitypes.TypedDataDomain `json:"domain"`
	Types       apitypes.Types           `json:"types"`
	PrimaryType string                   `json:"primaryType"`
	Message     map[string]any           `json:"message"`
}

// signedTypedData is a self-contained EIP-712 token: typed data + a signature
// carried inside the object (base64url(JSON) on the wire).
type signedTypedData struct {
	Domain      apitypes.TypedDataDomain `json:"domain"`
	Types       apitypes.Types           `json:"types"`
	PrimaryType string                   `json:"primaryType"`
	Message     map[string]any           `json:"message"`
	Signature   string                   `json:"signature"`
}

func (s *signedTypedData) typed() *eip712TypedDataJSON {
	return &eip712TypedDataJSON{
		Domain:      s.Domain,
		Types:       s.Types,
		PrimaryType: s.PrimaryType,
		Message:     s.Message,
	}
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

// credentialNow is overridable in tests.
var credentialNow = func() int64 { return time.Now().Unix() }

// voucherDomainPin is the expected EIP-712 domain for access credentials.
// When configured (non-nil chainID > 0 and non-zero contract), tokens whose
// domain does not match are rejected (cross-network / cross-market replay).
type voucherDomainPin struct {
	chainID  *big.Int
	contract common.Address
}

func (p *voucherDomainPin) configured() bool {
	return p != nil && p.chainID != nil && p.chainID.Sign() > 0 && p.contract != (common.Address{})
}

// parseAndVerifyAccess reads RetrievalProof (0..1) and RetrievalVoucher (0..N)
// Authorization headers and verifies them against pieceCID + the domain pin.
//
// A present-but-invalid proof is fatal (returns an error → 403 JSON). Voucher
// failures are non-fatal diagnostics. When no Retrieval* header is present at
// all it returns (nil, nil).
func parseAndVerifyAccess(r *http.Request, pieceCID string, pin *voucherDomainPin) (*VerifiedAccess, error) {
	proofRaws := authTokensForScheme(r, SchemeRetrievalProof)
	voucherRaws := authTokensForScheme(r, SchemeRetrievalVoucher)
	if len(proofRaws) == 0 && len(voucherRaws) == 0 {
		return nil, nil
	}
	now := credentialNow()
	access := &VerifiedAccess{}

	if len(proofRaws) > 0 {
		proof, err := verifyProofToken(proofRaws[0], pieceCID, now, pin)
		if err != nil {
			return nil, &voucherVerifyError{details: []voucherErrorDetail{{
				Index:   0,
				Error:   voucherErrorCode(err),
				Message: err.Error(),
			}}}
		}
		access.Proof = proof
	}

	for i, raw := range voucherRaws {
		v, err := verifyVoucherToken(raw, now, pin)
		if err != nil {
			access.voucherErrors = append(access.voucherErrors, voucherErrorDetail{
				Index:   i,
				Error:   voucherErrorCode(err),
				Message: err.Error(),
			})
			continue
		}
		access.Vouchers = append(access.Vouchers, *v)
	}
	return access, nil
}

// denialError builds a 403 JSON error explaining why a presented credential set
// did not authorize a private piece. Returns nil when there is nothing to
// report (caller should fall back to a plain 403).
func (a *VerifiedAccess) denialError() error {
	var details []voucherErrorDetail
	if a == nil || a.Proof == nil {
		details = append(details, voucherErrorDetail{
			Index:   -1,
			Error:   "proof_required",
			Message: "a RetrievalProof (proof of possession) is required for private pieces",
		})
	}
	if a != nil {
		details = append(details, a.voucherErrors...)
	}
	if len(details) == 0 {
		return nil
	}
	return &voucherVerifyError{details: details}
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
		Message: "access credential (proof/voucher) verification failed",
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
	case strings.Contains(msg, "proof") && (strings.Contains(msg, "expired") || strings.Contains(msg, "deadline") || strings.Contains(msg, "ttl")):
		return "proof_expired"
	case strings.Contains(msg, "expired") || strings.Contains(msg, "deadline"):
		return "voucher_expired"
	case strings.Contains(msg, "signature"):
		return "invalid_signature"
	case strings.Contains(msg, "decode") || strings.Contains(msg, "json") || strings.Contains(msg, "scheme") || strings.Contains(msg, "primarytype"):
		return "malformed_voucher"
	default:
		return "invalid_voucher"
	}
}

// authTokensForScheme returns the base64url token bodies of every Authorization
// header whose scheme (first space-separated word) equals scheme (case-insensitive).
func authTokensForScheme(r *http.Request, scheme string) []string {
	if r == nil {
		return nil
	}
	var out []string
	for _, raw := range r.Header.Values("Authorization") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		s, tok, ok := strings.Cut(raw, " ")
		if !ok || !strings.EqualFold(s, scheme) {
			continue
		}
		tok = strings.TrimSpace(tok)
		if tok != "" {
			out = append(out, tok)
		}
	}
	return out
}

func verifyProofToken(token, pieceCID string, nowUnix int64, pin *voucherDomainPin) (*VerifiedProof, error) {
	obj, sig, err := decodeSignedToken(token)
	if err != nil {
		return nil, err
	}
	if err := validateProofShape(obj); err != nil {
		return nil, err
	}
	resource, _ := obj.Message[fieldResource].(string)
	if resource != pieceCID {
		return nil, fmt.Errorf("%w: proof.resource want %q got %q", ErrInvalidVoucher, pieceCID, resource)
	}
	deadlineBig, err := parseUint256Field(obj.Message[fieldDeadline])
	if err != nil {
		return nil, fmt.Errorf("%w: proof.deadline: %v", ErrInvalidVoucher, err)
	}
	deadline, err := unixDeadline(deadlineBig)
	if err != nil {
		return nil, fmt.Errorf("%w: proof.deadline: %v", ErrInvalidVoucher, err)
	}
	maxDeadline := nowUnix + int64(MaxProofTTL.Seconds())
	if deadline <= nowUnix {
		return nil, fmt.Errorf("%w: proof expired (deadline=%d now=%d)", ErrInvalidVoucher, deadline, nowUnix)
	}
	if deadline > maxDeadline {
		return nil, fmt.Errorf("%w: proof deadline exceeds MAX_PROOF_TTL (deadline=%d max=%d)", ErrInvalidVoucher, deadline, maxDeadline)
	}
	scope, err := parseUint256Field(obj.Message[fieldScope])
	if err != nil {
		return nil, fmt.Errorf("%w: proof.scope: %v", ErrInvalidVoucher, err)
	}
	if err := checkDomainPin(&obj.Domain, pin); err != nil {
		return nil, err
	}
	obj.Message[fieldScope] = scope.String()
	obj.Message[fieldDeadline] = deadlineBig.String()
	obj.Message[fieldResource] = resource
	requester, err := recoverTypedDataSigner(obj, sig)
	if err != nil {
		return nil, fmt.Errorf("%w: proof signature: %v", ErrInvalidVoucher, err)
	}
	return &VerifiedProof{
		Requester: requester,
		Scope:     scope,
		Resource:  resource,
		Deadline:  deadline,
	}, nil
}

func verifyVoucherToken(token string, nowUnix int64, pin *voucherDomainPin) (*VerifiedVoucher, error) {
	// Server path: domain pin is mandatory (fail closed if unset).
	obj, sig, err := decodeSignedToken(token)
	if err != nil {
		return nil, err
	}
	if err := validateVoucherShape(obj); err != nil {
		return nil, err
	}
	if err := checkDomainPin(&obj.Domain, pin); err != nil {
		return nil, err
	}
	return finishVerifyVoucher(obj, sig, nowUnix)
}

func finishVerifyVoucher(obj *eip712TypedDataJSON, sig string, nowUnix int64) (*VerifiedVoucher, error) {
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
	if deadline <= nowUnix {
		return nil, fmt.Errorf("%w: voucher expired (deadline=%d now=%d)", ErrInvalidVoucher, deadline, nowUnix)
	}
	issuedAtBig, err := parseUint256Field(obj.Message[fieldIssuedAt])
	if err != nil {
		return nil, fmt.Errorf("%w: voucher.issuedAt: %v", ErrInvalidVoucher, err)
	}
	issuedAt, err := unixDeadline(issuedAtBig)
	if err != nil {
		return nil, fmt.Errorf("%w: voucher.issuedAt: %v", ErrInvalidVoucher, err)
	}
	granteeRaw, _ := obj.Message[fieldGrantee].(string)
	if !common.IsHexAddress(granteeRaw) {
		return nil, fmt.Errorf("%w: voucher.grantee is not an address", ErrInvalidVoucher)
	}
	grantee := common.HexToAddress(granteeRaw)
	obj.Message[fieldScope] = scope.String()
	obj.Message[fieldDeadline] = deadlineBig.String()
	obj.Message[fieldIssuedAt] = issuedAtBig.String()
	obj.Message[fieldGrantee] = grantee.Hex()
	owner, err := recoverTypedDataSigner(obj, sig)
	if err != nil {
		return nil, fmt.Errorf("%w: voucher signature: %v", ErrInvalidVoucher, err)
	}
	return &VerifiedVoucher{
		Owner:    owner,
		Grantee:  grantee,
		Scope:    scope,
		Deadline: deadline,
		IssuedAt: issuedAt,
	}, nil
}

func decodeSignedToken(token string) (*eip712TypedDataJSON, string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, "", fmt.Errorf("%w: empty token", ErrInvalidVoucher)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, "", fmt.Errorf("%w: token base64url decode: %v", ErrInvalidVoucher, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var st signedTypedData
	if err := dec.Decode(&st); err != nil {
		return nil, "", fmt.Errorf("%w: token json: %v", ErrInvalidVoucher, err)
	}
	if strings.TrimSpace(st.Signature) == "" {
		return nil, "", fmt.Errorf("%w: missing signature", ErrInvalidVoucher)
	}
	return st.typed(), st.Signature, nil
}

func checkDomainPin(domain *apitypes.TypedDataDomain, pin *voucherDomainPin) error {
	if !pin.configured() {
		return fmt.Errorf("%w: voucher domain pin not configured", ErrInvalidVoucher)
	}
	if domain == nil || domain.ChainId == nil {
		return fmt.Errorf("%w: missing domain.chainId", ErrInvalidVoucher)
	}
	gotChain := new(big.Int).Set((*big.Int)(domain.ChainId))
	if gotChain.Cmp(pin.chainID) != 0 {
		return fmt.Errorf("%w: domain.chainId want %s got %s", ErrInvalidVoucher, pin.chainID.String(), gotChain.String())
	}
	if !common.IsHexAddress(domain.VerifyingContract) {
		return fmt.Errorf("%w: missing or invalid domain.verifyingContract", ErrInvalidVoucher)
	}
	gotContract := common.HexToAddress(domain.VerifyingContract)
	if !sameAddress(gotContract, pin.contract) {
		return fmt.Errorf("%w: domain.verifyingContract mismatch", ErrInvalidVoucher)
	}
	return nil
}

func validateProofShape(obj *eip712TypedDataJSON) error {
	if obj == nil {
		return fmt.Errorf("%w: nil proof", ErrInvalidVoucher)
	}
	if obj.PrimaryType != primaryTypeProof {
		return fmt.Errorf("%w: proof primaryType want %s got %q", ErrInvalidVoucher, primaryTypeProof, obj.PrimaryType)
	}
	if err := validateDomainMeta(&obj.Domain); err != nil {
		return err
	}
	want := map[string]string{
		fieldScope:    "uint256",
		fieldResource: "string",
		fieldDeadline: "uint256",
	}
	if err := validateTypeFields(obj.Types, primaryTypeProof, want); err != nil {
		return err
	}
	if obj.Message == nil {
		return fmt.Errorf("%w: missing proof.message", ErrInvalidVoucher)
	}
	for _, name := range []string{fieldScope, fieldResource, fieldDeadline} {
		if _, ok := obj.Message[name]; !ok {
			return fmt.Errorf("%w: missing proof.message.%s", ErrInvalidVoucher, name)
		}
	}
	if _, ok := obj.Message[fieldResource].(string); !ok {
		return fmt.Errorf("%w: proof.message.resource must be a string", ErrInvalidVoucher)
	}
	return nil
}

func validateVoucherShape(obj *eip712TypedDataJSON) error {
	if obj == nil {
		return fmt.Errorf("%w: nil voucher", ErrInvalidVoucher)
	}
	if obj.PrimaryType != primaryTypeVoucher {
		return fmt.Errorf("%w: voucher primaryType want %s got %q", ErrInvalidVoucher, primaryTypeVoucher, obj.PrimaryType)
	}
	if err := validateDomainMeta(&obj.Domain); err != nil {
		return err
	}
	want := map[string]string{
		fieldGrantee:  "address",
		fieldScope:    "uint256",
		fieldIssuedAt: "uint256",
		fieldDeadline: "uint256",
	}
	if err := validateTypeFields(obj.Types, primaryTypeVoucher, want); err != nil {
		return err
	}
	if obj.Message == nil {
		return fmt.Errorf("%w: missing voucher.message", ErrInvalidVoucher)
	}
	for _, name := range []string{fieldGrantee, fieldScope, fieldIssuedAt, fieldDeadline} {
		if _, ok := obj.Message[name]; !ok {
			return fmt.Errorf("%w: missing voucher.message.%s", ErrInvalidVoucher, name)
		}
	}
	return nil
}

func validateDomainMeta(domain *apitypes.TypedDataDomain) error {
	if domain == nil {
		return fmt.Errorf("%w: missing domain", ErrInvalidVoucher)
	}
	if domain.Name != eip712DomainName {
		return fmt.Errorf("%w: domain.name want %s got %q", ErrInvalidVoucher, eip712DomainName, domain.Name)
	}
	if domain.Version != eip712DomainVer {
		return fmt.Errorf("%w: domain.version want %s got %q", ErrInvalidVoucher, eip712DomainVer, domain.Version)
	}
	return nil
}

func validateTypeFields(types apitypes.Types, primary string, want map[string]string) error {
	fields, ok := types[primary]
	if !ok || len(fields) == 0 {
		return fmt.Errorf("%w: missing types.%s", ErrInvalidVoucher, primary)
	}
	if len(fields) != len(want) {
		return fmt.Errorf("%w: unexpected %s field count", ErrInvalidVoucher, primary)
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
	return nil
}

func recoverTypedDataSigner(obj *eip712TypedDataJSON, signatureHex string) (common.Address, error) {
	ensureEIP712DomainTypes(obj)
	typed := apitypes.TypedData{
		Types:       obj.Types,
		PrimaryType: obj.PrimaryType,
		Domain:      obj.Domain,
		Message:     obj.Message,
	}
	digest, _, err := apitypes.TypedDataAndHash(typed)
	if err != nil {
		return common.Address{}, fmt.Errorf("eip-712 hash: %v", err)
	}
	return recoverEIP712Signer(digest, signatureHex)
}

func ensureEIP712DomainTypes(obj *eip712TypedDataJSON) {
	if obj.Types == nil {
		obj.Types = apitypes.Types{}
	}
	if _, ok := obj.Types["EIP712Domain"]; ok {
		return
	}
	var fields []apitypes.Type
	if obj.Domain.Name != "" {
		fields = append(fields, apitypes.Type{Name: "name", Type: "string"})
	}
	if obj.Domain.Version != "" {
		fields = append(fields, apitypes.Type{Name: "version", Type: "string"})
	}
	if obj.Domain.ChainId != nil {
		fields = append(fields, apitypes.Type{Name: "chainId", Type: "uint256"})
	}
	if obj.Domain.VerifyingContract != "" {
		fields = append(fields, apitypes.Type{Name: "verifyingContract", Type: "address"})
	}
	if obj.Domain.Salt != "" {
		fields = append(fields, apitypes.Type{Name: "salt", Type: "bytes32"})
	}
	obj.Types["EIP712Domain"] = fields
}

func recoverEIP712Signer(digest []byte, signatureHex string) (common.Address, error) {
	sig := common.FromHex(strings.TrimSpace(signatureHex))
	if len(sig) != 65 {
		return common.Address{}, fmt.Errorf("signature must be 65 bytes, got %d", len(sig))
	}
	// eth_account uses v=27/28; go-ethereum Ecrecover expects 0/1.
	if sig[64] >= 27 {
		sig[64] -= 27
	}
	if sig[64] > 1 {
		return common.Address{}, fmt.Errorf("invalid signature recovery id")
	}
	pub, err := crypto.SigToPub(digest, sig)
	if err != nil {
		return common.Address{}, fmt.Errorf("signature recovery failed: %v", err)
	}
	return crypto.PubkeyToAddress(*pub), nil
}

// maxSafeJSONFloatInt is the largest integer exactly representable in IEEE-754
// float64 (2^53 - 1). Bare JSON numbers decoded without UseNumber cannot safely
// carry values above this.
const maxSafeJSONFloatInt = (1 << 53) - 1

func parseUint256Field(v any) (*big.Int, error) {
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

func unixDeadline(n *big.Int) (int64, error) {
	if n == nil || !n.IsInt64() {
		return 0, fmt.Errorf("out of int64 range")
	}
	return n.Int64(), nil
}

// accessAuthorizesDeal reports whether the verified access authorizes private
// deal d. It requires a valid proof (PoP). Owner-direct when the proof signer is
// the deal client; otherwise a delegated voucher whose owner is the deal client,
// grantee is the proof signer, and scope equals the deal id.
func accessAuthorizesDeal(a *VerifiedAccess, d *Deal) bool {
	if a == nil || a.Proof == nil || d == nil || d.DealType != DealTypePrivate {
		return false
	}
	if sameAddress(a.Proof.Requester, d.Client) {
		return true
	}
	for _, v := range a.Vouchers {
		if v.Owner == (common.Address{}) || !sameAddress(v.Owner, d.Client) {
			continue
		}
		if !sameAddress(v.Grantee, a.Proof.Requester) {
			continue
		}
		if v.Scope == nil || !dealIDMatches(v.Scope, d.DealID) {
			continue
		}
		return true
	}
	return false
}

// dealIDMatches compares a signed uint256 scope to the CDP deal id string.
func dealIDMatches(scope *big.Int, dealID string) bool {
	if scope == nil {
		return false
	}
	n, ok := new(big.Int).SetString(strings.TrimSpace(dealID), 10)
	if !ok {
		return false
	}
	return scope.Cmp(n) == 0
}
