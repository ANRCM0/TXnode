// Package credentialdelivery verifies the non-secret authorization shared by
// Core, the Provider and Node. It has no configuration or persistence authority.
package credentialdelivery

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ANRCM0/TX-Node/internal/panel"
)

const (
	ContractVersion = "credential-delivery/1"
	PolicyVersion   = "native-provider-authorization/v1"
	Audience        = "tx-node-native-authorization-v1"
	MaxMessageBytes = 1 << 20
	MaxSubjects     = 128
)

type Envelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type Trust struct {
	ProtocolVersion int    `json:"protocol_version"`
	CoreInstanceID  string `json:"core_instance_id"`
	KeyID           string `json:"key_id"`
	KeyEpoch        string `json:"key_epoch"`
	Algorithm       string `json:"algorithm"`
	PublicKey       string `json:"public_key"`
}

type ProviderBinding struct {
	InstallationID        string    `json:"installation_id"`
	ProviderID            string    `json:"provider_id"`
	ProviderInstanceEpoch string    `json:"provider_instance_epoch"`
	RecipientSHA256       string    `json:"recipient_sha256"`
	CredentialProfileID   string    `json:"credential_profile_id"`
	Subjects              []Subject `json:"subjects"`
}

type Subject struct {
	UserID               int    `json:"user_id"`
	AccessSubjectID      string `json:"access_subject_id"`
	SubscriptionID       string `json:"subscription_id"`
	TermsID              string `json:"terms_id"`
	ProviderSubjectRef   string `json:"provider_subject_ref"`
	CredentialRef        string `json:"credential_ref"`
	CredentialGeneration string `json:"credential_generation"`
	CredentialExpiresAt  int64  `json:"credential_expires_at"`
}

type Payload struct {
	ProtocolVersion int             `json:"protocol_version"`
	Audience        string          `json:"audience"`
	PolicyVersion   string          `json:"policy_version"`
	CoreInstanceID  string          `json:"core_instance_id"`
	NodeID          int             `json:"node_id"`
	MachineID       *int            `json:"machine_id"`
	Revision        string          `json:"revision"`
	KeyID           string          `json:"key_id"`
	KeyEpoch        string          `json:"key_epoch"`
	IssuedAt        int64           `json:"issued_at"`
	NotBefore       int64           `json:"not_before"`
	ExpiresAt       int64           `json:"expires_at"`
	Complete        bool            `json:"complete"`
	Users           []panel.User    `json:"users"`
	Provider        ProviderBinding `json:"provider"`
}

type Grant struct {
	Payload      Payload
	PayloadBytes []byte
	Digest       string
}

type MaterialRequest struct {
	ContractVersion string   `json:"contract_version"`
	RequestID       string   `json:"request_id"`
	Authorization   Envelope `json:"authorization"`
}

type MaterialCredential struct {
	AccessSubjectID      string `json:"access_subject_id"`
	CredentialRef        string `json:"credential_ref"`
	CredentialGeneration string `json:"credential_generation"`
	UUID                 string `json:"uuid"`
}

type MaterialResponse struct {
	ContractVersion     string               `json:"contract_version"`
	RequestID           string               `json:"request_id"`
	AuthorizationDigest string               `json:"authorization_digest"`
	Credentials         []MaterialCredential `json:"credentials"`
}

type MetadataSubject struct {
	InstallationID       string `json:"installation_id"`
	AccessSubjectID      string `json:"access_subject_id"`
	SubscriptionID       string `json:"subscription_id"`
	TermsID              string `json:"terms_id"`
	ProviderSubjectRef   string `json:"provider_subject_ref"`
	CredentialRef        string `json:"credential_ref"`
	CredentialGeneration string `json:"credential_generation"`
	CredentialProfileID  string `json:"credential_profile_id"`
}

type MetadataRequest struct {
	ContractVersion       string            `json:"contract_version"`
	RequestID             string            `json:"request_id"`
	ProviderID            string            `json:"provider_id"`
	ProviderInstanceEpoch string            `json:"provider_instance_epoch"`
	Subjects              []MetadataSubject `json:"subjects"`
}

type MetadataCredential struct {
	AccessSubjectID      string `json:"access_subject_id"`
	CredentialRef        string `json:"credential_ref"`
	CredentialGeneration string `json:"credential_generation"`
	CredentialSHA256     string `json:"credential_sha256"`
	CredentialExpiresAt  int64  `json:"credential_expires_at"`
}

type MetadataResponse struct {
	ContractVersion       string               `json:"contract_version"`
	RequestID             string               `json:"request_id"`
	ProviderID            string               `json:"provider_id"`
	ProviderInstanceEpoch string               `json:"provider_instance_epoch"`
	Credentials           []MetadataCredential `json:"credentials"`
}

var (
	decimalRE    = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
	uuidRE       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	uuidV4RE     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestRE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	keyRE        = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	providerRE   = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	subjectRE    = regexp.MustCompile(`^subject_[0-9a-f]{32}$`)
	credentialRE = regexp.MustCompile(`^credential_[0-9a-f]{32}$`)
	requestRE    = regexp.MustCompile(`^[A-Za-z0-9._~:-]{1,96}$`)
)

func refusal(code string) error { return errors.New("CREDENTIAL_DELIVERY_" + code) }

func PositiveDecimal(value string) bool {
	if !decimalRE.MatchString(value) {
		return false
	}
	_, err := strconv.ParseInt(value, 10, 64)
	return err == nil
}

func ValidRequestID(value string) bool { return requestRE.MatchString(value) }
func ValidUUID(value string) bool      { return uuidV4RE.MatchString(value) }
func ValidProfile(value string) bool {
	return value == "vless-uuid/v1" || value == "vmess-uuid/v1"
}

func decodeBase64(value string, max int) ([]byte, error) {
	if len(value) > base64.RawURLEncoding.EncodedLen(max) || strings.ContainsAny(value, "=\r\n") {
		return nil, refusal("INVALID")
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) > max || base64.RawURLEncoding.EncodeToString(raw) != value {
		return nil, refusal("INVALID")
	}
	return raw, nil
}

func ValidateTrust(trust Trust) error {
	key, err := decodeBase64(trust.PublicKey, ed25519.PublicKeySize)
	if err != nil || len(key) != ed25519.PublicKeySize || trust.ProtocolVersion != 1 ||
		trust.Algorithm != "Ed25519" || !uuidRE.MatchString(trust.CoreInstanceID) ||
		!keyRE.MatchString(trust.KeyID) || !PositiveDecimal(trust.KeyEpoch) {
		return refusal("TRUST_INVALID")
	}
	return nil
}

// VerifyGrant verifies the full signed policy. Callers additionally enforce
// their configured Node/Machine target and the authenticated TLS recipient.
func VerifyGrant(env Envelope, trust Trust, now time.Time, skew int) (*Grant, error) {
	if ValidateTrust(trust) != nil || skew < 0 || skew > 30 {
		return nil, refusal("TRUST_INVALID")
	}
	raw, err := decodeBase64(env.Payload, MaxMessageBytes)
	if err != nil || len(raw) == 0 {
		return nil, refusal("INVALID")
	}
	signature, err := decodeBase64(env.Signature, ed25519.SignatureSize)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, refusal("SIGNATURE_INVALID")
	}
	key, _ := decodeBase64(trust.PublicKey, ed25519.PublicKeySize)
	if !ed25519.Verify(ed25519.PublicKey(key), raw, signature) {
		return nil, refusal("SIGNATURE_INVALID")
	}
	var p Payload
	if DecodeStrict(raw, &p) != nil {
		return nil, refusal("INVALID")
	}
	if p.ProtocolVersion != 1 || p.Audience != Audience || p.PolicyVersion != PolicyVersion ||
		p.CoreInstanceID != trust.CoreInstanceID || p.KeyID != trust.KeyID || p.KeyEpoch != trust.KeyEpoch ||
		p.NodeID <= 0 || p.NodeID > 2147483647 ||
		(p.MachineID != nil && (*p.MachineID <= 0 || *p.MachineID > 2147483647)) ||
		!PositiveDecimal(p.Revision) || !p.Complete || p.Users == nil || len(p.Users) > MaxSubjects ||
		p.IssuedAt < 0 || p.NotBefore < 0 || p.NotBefore > p.IssuedAt ||
		p.NotBefore < p.IssuedAt-int64(skew) || p.ExpiresAt <= p.IssuedAt || p.ExpiresAt-p.IssuedAt > 120 {
		return nil, refusal("INVALID")
	}
	wall := now.Unix()
	if wall < 0 || p.IssuedAt > wall+int64(skew) || p.NotBefore > wall+int64(skew) || p.ExpiresAt <= wall {
		return nil, refusal("EXPIRED")
	}
	b := p.Provider
	if b.InstallationID != p.CoreInstanceID || !providerRE.MatchString(b.ProviderID) ||
		!PositiveDecimal(b.ProviderInstanceEpoch) || !digestRE.MatchString(b.RecipientSHA256) ||
		!ValidProfile(b.CredentialProfileID) || b.Subjects == nil || len(b.Subjects) != len(p.Users) {
		return nil, refusal("BINDING_INVALID")
	}
	seenSubjects, seenRefs, seenCredentials, seenHashes := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	previous := 0
	for i, u := range p.Users {
		s := b.Subjects[i]
		if u.ID <= previous || u.ID > 2147483647 || u.ID != s.UserID ||
			!strings.HasPrefix(u.UUID, "sha256:") || !digestRE.MatchString(strings.TrimPrefix(u.UUID, "sha256:")) ||
			seenHashes[u.UUID] || u.SpeedLimit < 0 || u.DeviceLimit < 0 ||
			u.SpeedLimit > 2147483647 || u.DeviceLimit > 2147483647 || len(u.TrafficPeriod) > 512 ||
			!PositiveDecimal(s.AccessSubjectID) || !PositiveDecimal(s.SubscriptionID) || !PositiveDecimal(s.TermsID) ||
			!subjectRE.MatchString(s.ProviderSubjectRef) || !credentialRE.MatchString(s.CredentialRef) ||
			!PositiveDecimal(s.CredentialGeneration) || s.CredentialExpiresAt < p.ExpiresAt ||
			seenSubjects[s.AccessSubjectID] || seenRefs[s.ProviderSubjectRef] || seenCredentials[s.CredentialRef] {
			return nil, refusal("SUBJECTS_INVALID")
		}
		previous = u.ID
		seenSubjects[s.AccessSubjectID], seenRefs[s.ProviderSubjectRef] = true, true
		seenCredentials[s.CredentialRef], seenHashes[u.UUID] = true, true
	}
	digest := sha256.Sum256(raw)
	return &Grant{Payload: p, PayloadBytes: append([]byte(nil), raw...), Digest: hex.EncodeToString(digest[:])}, nil
}

func ValidateMetadataRequest(req MetadataRequest) error {
	if req.ContractVersion != ContractVersion || !ValidRequestID(req.RequestID) ||
		!providerRE.MatchString(req.ProviderID) || !PositiveDecimal(req.ProviderInstanceEpoch) ||
		req.Subjects == nil || len(req.Subjects) > MaxSubjects {
		return refusal("INVALID")
	}
	seen := map[string]bool{}
	for _, s := range req.Subjects {
		if !uuidRE.MatchString(s.InstallationID) || !PositiveDecimal(s.AccessSubjectID) ||
			!PositiveDecimal(s.SubscriptionID) || !PositiveDecimal(s.TermsID) ||
			!subjectRE.MatchString(s.ProviderSubjectRef) || !credentialRE.MatchString(s.CredentialRef) ||
			!PositiveDecimal(s.CredentialGeneration) || !ValidProfile(s.CredentialProfileID) ||
			seen[s.ProviderSubjectRef] || seen[s.InstallationID+":"+s.AccessSubjectID] || seen[s.CredentialRef] {
			return refusal("INVALID")
		}
		seen[s.ProviderSubjectRef], seen[s.InstallationID+":"+s.AccessSubjectID], seen[s.CredentialRef] = true, true, true
	}
	return nil
}

// DecodeStrict rejects duplicate keys (including escaped aliases), unknown or
// missing fields, noncanonical integers and null collections before decoding.
// Optional DTO fields must have omitempty; pointer fields may be explicit null.
func DecodeStrict(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > MaxMessageBytes || !utf8.Valid(raw) || target == nil {
		return refusal("INVALID_JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := readJSON(decoder, 0)
	if err != nil {
		return refusal("INVALID_JSON")
	}
	if _, err = decoder.Token(); err != io.EOF {
		return refusal("INVALID_JSON")
	}
	typ := reflect.TypeOf(target)
	if typ.Kind() != reflect.Pointer || !shapeMatches(value, typ.Elem()) {
		return refusal("INVALID_JSON")
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return refusal("INVALID_JSON")
	}
	return nil
}

func readJSON(d *json.Decoder, depth int) (any, error) {
	if depth > 12 {
		return nil, refusal("INVALID_JSON")
	}
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	if number, ok := token.(json.Number); ok {
		n, err := strconv.ParseInt(string(number), 10, 64)
		if err != nil || strconv.FormatInt(n, 10) != string(number) {
			return nil, refusal("INVALID_JSON")
		}
		return number, nil
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delimiter {
	case '{':
		out := map[string]any{}
		for d.More() {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok {
				return nil, refusal("INVALID_JSON")
			}
			if _, exists := out[name]; exists {
				return nil, refusal("INVALID_JSON")
			}
			out[name], err = readJSON(d, depth+1)
			if err != nil {
				return nil, err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return nil, refusal("INVALID_JSON")
		}
		return out, nil
	case '[':
		out := []any{}
		for d.More() {
			value, err := readJSON(d, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, value)
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return nil, refusal("INVALID_JSON")
		}
		return out, nil
	default:
		return nil, refusal("INVALID_JSON")
	}
}

func shapeMatches(value any, typ reflect.Type) bool {
	if typ.Kind() == reflect.Pointer {
		return value == nil || shapeMatches(value, typ.Elem())
	}
	switch typ.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return false
		}
		known := map[string]bool{}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if !field.IsExported() {
				continue
			}
			tag := strings.Split(field.Tag.Get("json"), ",")
			if tag[0] == "-" {
				continue
			}
			name := tag[0]
			if name == "" {
				name = field.Name
			}
			known[name] = true
			actual, exists := object[name]
			optional := len(tag) > 1 && tag[1] == "omitempty"
			if !exists && !optional || exists && !shapeMatches(actual, field.Type) {
				return false
			}
		}
		for name := range object {
			if !known[name] {
				return false
			}
		}
		return true
	case reflect.Slice:
		array, ok := value.([]any)
		if !ok {
			return false
		}
		for _, item := range array {
			if !shapeMatches(item, typ.Elem()) {
				return false
			}
		}
		return true
	case reflect.String:
		_, ok := value.(string)
		return ok
	case reflect.Bool:
		_, ok := value.(bool)
		return ok
	case reflect.Int, reflect.Int64, reflect.Int32:
		_, ok := value.(json.Number)
		return ok
	default:
		return false
	}
}
