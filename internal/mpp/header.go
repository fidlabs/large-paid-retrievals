package mpp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/textproto"
	"sort"
	"strings"
	"time"
)

const (
	VersionV1   = "mpp-v1"
	SigTypeEVM  = "evm"
	AuthScheme  = "Payment"
	MethodID    = "filecoinpay"
	IntentID    = "charge"
	RealmPrefix = "piece:"
)

var ErrInvalidHeader = errors.New("invalid mpp payment header")

type PaymentRequest struct {
	DealUUID string `json:"deal_uuid"`
	CID      string `json:"cid"`
	PriceFIL string `json:"price_fil"`
	Payee0x  string `json:"payee_0x,omitempty"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Host     string `json:"host"`
}

type Challenge struct {
	ID      string
	Realm   string
	Method  string
	Intent  string
	Request PaymentRequest
	Expires string
	Description string
	Opaque      map[string]string
	Digest      string
}

type ProofPayload struct {
	Version       string `json:"version"`
	ChallengeID   string `json:"challenge_id"`
	DealUUID      string `json:"deal_uuid"`
	ClientAddress string `json:"client"`
	CID           string `json:"cid"`
	Method        string `json:"method"`
	Path          string `json:"path"`
	Host          string `json:"host"`
	Nonce         string `json:"nonce"`
	ExpiresUnix   int64  `json:"expires_unix"`
	SigType       string `json:"sig_type"`
	Signature     string `json:"sig"`
}

type Credential struct {
	Challenge ChallengeFields `json:"challenge"`
	Payload   ProofPayload    `json:"payload"`
	Source    string          `json:"source,omitempty"`
}

type ChallengeFields struct {
	ID      string `json:"id"`
	Realm   string `json:"realm"`
	Method  string `json:"method"`
	Intent  string `json:"intent"`
	Request string `json:"request"`
	Expires string `json:"expires,omitempty"`
	Description string `json:"description,omitempty"`
	Opaque      string `json:"opaque,omitempty"`
	Digest      string `json:"digest,omitempty"`
}

func (h *ProofPayload) Validate() error {
	if h.Version == "" {
		h.Version = VersionV1
	}
	if h.Version != VersionV1 {
		return ErrInvalidHeader
	}
	if h.ChallengeID == "" || h.DealUUID == "" || h.ClientAddress == "" || h.CID == "" {
		return ErrInvalidHeader
	}
	if h.Method == "" || h.Path == "" || h.Host == "" || h.Nonce == "" || h.SigType == "" || h.Signature == "" {
		return ErrInvalidHeader
	}
	if h.ExpiresUnix <= 0 {
		return ErrInvalidHeader
	}
	return nil
}

func (h *ProofPayload) ValidateAt(now time.Time) error {
	if err := h.Validate(); err != nil {
		return err
	}
	if now.Unix() > h.ExpiresUnix {
		return fmt.Errorf("%w: expired", ErrInvalidHeader)
	}
	return nil
}

func (h *ProofPayload) CanonicalMessage() []byte {
	var b bytes.Buffer
	b.WriteString(VersionV1 + "\n")
	b.WriteString("challenge_id=" + h.ChallengeID + "\n")
	b.WriteString("deal_uuid=" + h.DealUUID + "\n")
	b.WriteString("cid=" + h.CID + "\n")
	b.WriteString("client=" + strings.ToLower(h.ClientAddress) + "\n")
	b.WriteString("method=" + strings.ToUpper(h.Method) + "\n")
	b.WriteString("path=" + h.Path + "\n")
	b.WriteString("host=" + strings.ToLower(h.Host) + "\n")
	b.WriteString("nonce=" + h.Nonce + "\n")
	b.WriteString(fmt.Sprintf("expires_unix=%d\n", h.ExpiresUnix))
	return b.Bytes()
}

func (c Challenge) RequestB64URL() (string, error) {
	raw, err := json.Marshal(c.Request)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (c Challenge) WWWAuthenticateValue() (string, error) {
	reqB64, err := c.RequestB64URL()
	if err != nil {
		return "", err
	}
	params := []string{
		fmt.Sprintf(`id="%s"`, c.ID),
		fmt.Sprintf(`realm="%s"`, c.Realm),
		fmt.Sprintf(`method="%s"`, c.Method),
		fmt.Sprintf(`intent="%s"`, c.Intent),
		fmt.Sprintf(`request="%s"`, reqB64),
	}
	if strings.TrimSpace(c.Expires) != "" {
		params = append(params, fmt.Sprintf(`expires="%s"`, c.Expires))
	}
	if strings.TrimSpace(c.Description) != "" {
		params = append(params, fmt.Sprintf(`description="%s"`, c.Description))
	}
	if strings.TrimSpace(c.Digest) != "" {
		params = append(params, fmt.Sprintf(`digest="%s"`, c.Digest))
	}
	if len(c.Opaque) > 0 {
		opaqueRaw, err := json.Marshal(c.Opaque)
		if err != nil {
			return "", err
		}
		params = append(params, fmt.Sprintf(`opaque="%s"`, base64.RawURLEncoding.EncodeToString(opaqueRaw)))
	}
	return AuthScheme + " " + strings.Join(params, ", "), nil
}

func ParseWWWAuthenticate(v string) (*Challenge, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, ErrInvalidHeader
	}
	if !strings.HasPrefix(strings.ToLower(v), strings.ToLower(AuthScheme)+" ") {
		return nil, ErrInvalidHeader
	}
	paramsRaw := strings.TrimSpace(v[len(AuthScheme):])
	params, err := parseAuthParams(paramsRaw)
	if err != nil {
		return nil, err
	}
	ch := &Challenge{
		ID:      params["id"],
		Realm:   params["realm"],
		Method:  params["method"],
		Intent:  params["intent"],
		Expires: params["expires"],
		Description: params["description"],
		Digest: params["digest"],
	}
	reqB64 := params["request"]
	if ch.ID == "" || ch.Realm == "" || ch.Method == "" || ch.Intent == "" || reqB64 == "" {
		return nil, ErrInvalidHeader
	}
	reqBytes, err := base64.RawURLEncoding.DecodeString(reqB64)
	if err != nil {
		return nil, fmt.Errorf("%w: request base64url", ErrInvalidHeader)
	}
	if err := json.Unmarshal(reqBytes, &ch.Request); err != nil {
		return nil, fmt.Errorf("%w: request json", ErrInvalidHeader)
	}
	if opaqueB64 := strings.TrimSpace(params["opaque"]); opaqueB64 != "" {
		opaqueRaw, err := base64.RawURLEncoding.DecodeString(opaqueB64)
		if err != nil {
			return nil, fmt.Errorf("%w: opaque base64url", ErrInvalidHeader)
		}
		var opaque map[string]string
		if err := json.Unmarshal(opaqueRaw, &opaque); err != nil {
			return nil, fmt.Errorf("%w: opaque json", ErrInvalidHeader)
		}
		ch.Opaque = opaque
	}
	return ch, nil
}

func (c Credential) EncodeAuthorization() (string, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return AuthScheme + " " + base64.RawURLEncoding.EncodeToString(raw), nil
}

func DecodeAuthorization(rawAuth string) (*Credential, error) {
	rawAuth = strings.TrimSpace(rawAuth)
	if rawAuth == "" {
		return nil, ErrInvalidHeader
	}
	if !strings.HasPrefix(strings.ToLower(rawAuth), strings.ToLower(AuthScheme)+" ") {
		return nil, ErrInvalidHeader
	}
	token := strings.TrimSpace(rawAuth[len(AuthScheme):])
	if token == "" {
		return nil, ErrInvalidHeader
	}
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("%w: credential base64url", ErrInvalidHeader)
	}
	var c Credential
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%w: credential json", ErrInvalidHeader)
	}
	if err := c.Payload.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func WritePaymentRequired(w http.ResponseWriter, challenge Challenge) error {
	v, err := challenge.WWWAuthenticateValue()
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("WWW-Authenticate", v)
	w.WriteHeader(http.StatusPaymentRequired)
	return nil
}

func WritePaymentReceipt(h http.Header, method, reference string, ts time.Time) error {
	body := map[string]string{
		"status":    "success",
		"method":    method,
		"timestamp": ts.UTC().Format(time.RFC3339),
		"reference": reference,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	h.Set("Payment-Receipt", base64.RawURLEncoding.EncodeToString(raw))
	return nil
}

func CanonicalRequestB64(req PaymentRequest) (string, error) {
	raw, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func BuildCredential(ch Challenge, payload ProofPayload, source string) (Credential, error) {
	reqB64, err := CanonicalRequestB64(ch.Request)
	if err != nil {
		return Credential{}, err
	}
	var opaqueB64 string
	if len(ch.Opaque) > 0 {
		opaqueRaw, err := json.Marshal(ch.Opaque)
		if err != nil {
			return Credential{}, err
		}
		opaqueB64 = base64.RawURLEncoding.EncodeToString(opaqueRaw)
	}
	return Credential{
		Challenge: ChallengeFields{
			ID:      ch.ID,
			Realm:   ch.Realm,
			Method:  ch.Method,
			Intent:  ch.Intent,
			Request: reqB64,
			Expires: ch.Expires,
			Description: ch.Description,
			Opaque:      opaqueB64,
			Digest:      ch.Digest,
		},
		Payload: payload,
		Source:  source,
	}, nil
}

func (h *ProofPayload) EncodeHTTP() (string, error) {
	if err := h.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

func DecodeHTTP(raw string) (*ProofPayload, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, ErrInvalidHeader
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: base64", ErrInvalidHeader)
	}
	var h ProofPayload
	if err := json.Unmarshal(b, &h); err != nil {
		return nil, fmt.Errorf("%w: json", ErrInvalidHeader)
	}
	if err := h.Validate(); err != nil {
		return nil, err
	}
	return &h, nil
}

func parseAuthParams(raw string) (map[string]string, error) {
	res := map[string]string{}
	parts := splitAuthParams(raw)
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		eq := strings.IndexByte(p, '=')
		if eq <= 0 {
			return nil, ErrInvalidHeader
		}
		k := strings.ToLower(textproto.TrimString(p[:eq]))
		v := textproto.TrimString(p[eq+1:])
		if strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) && len(v) >= 2 {
			v = v[1 : len(v)-1]
		}
		res[k] = v
	}
	return res, nil
}

func splitAuthParams(s string) []string {
	var out []string
	var b strings.Builder
	inQuotes := false
	for _, r := range s {
		switch r {
		case '"':
			inQuotes = !inQuotes
			b.WriteRune(r)
		case ',':
			if inQuotes {
				b.WriteRune(r)
			} else {
				out = append(out, b.String())
				b.Reset()
			}
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

func CanonicalChallengeParams(fields ChallengeFields) string {
	ordered := []string{"id", "intent", "method", "realm", "request"}
	if strings.TrimSpace(fields.Expires) != "" {
		ordered = append(ordered, "expires")
	}
	if strings.TrimSpace(fields.Description) != "" {
		ordered = append(ordered, "description")
	}
	if strings.TrimSpace(fields.Opaque) != "" {
		ordered = append(ordered, "opaque")
	}
	if strings.TrimSpace(fields.Digest) != "" {
		ordered = append(ordered, "digest")
	}
	sort.Strings(ordered)
	var parts []string
	for _, k := range ordered {
		var v string
		switch k {
		case "id":
			v = fields.ID
		case "intent":
			v = fields.Intent
		case "method":
			v = fields.Method
		case "realm":
			v = fields.Realm
		case "request":
			v = fields.Request
		case "expires":
			v = fields.Expires
		case "description":
			v = fields.Description
		case "opaque":
			v = fields.Opaque
		case "digest":
			v = fields.Digest
		}
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, "&")
}
