// Package providerproof provides an offline signature diagnostic for Core's
// synthetic Provider evidence. It cannot produce an admission or usage grant.
package providerproof

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maxBytes = 16384

var ErrInvalidProof = errors.New("PROVIDER_OFFLINE_SIGNATURE_INVALID")

// TrustedKey is operator-provisioned public trust, never a JWS-derived key.
type TrustedKey struct {
	ID         string `json:"kid"`
	Epoch      string `json:"epoch"`
	PublicPEM  string `json:"public_pem"`
	SPKISHA256 string `json:"spki_sha256"`
	NotBefore  int64  `json:"not_before"`
	NotAfter   int64  `json:"not_after"`
	Revoked    bool   `json:"revoked"`
}

type trusted struct {
	meta TrustedKey
	key  *rsa.PublicKey
}

// Verifier owns immutable, parsed public keys. Refresh means constructing a new
// verifier; there is no package-global trust cache or mutable clock state.
type Verifier struct{ keys map[string]trusted }

// Proof is a non-authorizing diagnostic. Nested business semantics and clocks
// are explicitly unevaluated, even when the signature verifies.
type Proof struct {
	SignatureVerified          bool   `json:"signature_verified"`
	KeyRevoked                 bool   `json:"key_revoked"`
	SnapshotRef                string `json:"snapshot_ref"`
	KeyID                      string `json:"key_id"`
	KeyEpoch                   string `json:"key_epoch"`
	PayloadSHA256              string `json:"payload_sha256"`
	SignedStatementSHA256      string `json:"signed_statement_sha256"`
	IssuedAt                   int64  `json:"issued_at"`
	LeaseExpiresAt             int64  `json:"lease_expires_at"`
	AdmissionGranted           bool   `json:"admission_granted"`
	BusinessEvidenceValidation string `json:"business_evidence_validation"`
	LiveCoreEligibility        string `json:"live_core_eligibility"`
	WindowValidation           string `json:"window_validation"`
}

var (
	kidPattern       = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	decimalPattern   = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
	refPattern       = regexp.MustCompile(`^asf_[a-f0-9]{32}$`)
	hashPattern      = regexp.MustCompile(`^[a-f0-9]{64}$`)
	providerPattern  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	candidatePattern = regexp.MustCompile(`^lc_[a-f0-9]{32}$`)
)

func decimal(s string) bool {
	if !decimalPattern.MatchString(s) {
		return false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return err == nil && n > 0
}

func validTime(n int64) bool { return n >= 0 && n <= 9007199254740991 }

func New(keys []TrustedKey) (*Verifier, error) {
	if len(keys) < 1 || len(keys) > 2 {
		return nil, ErrInvalidProof
	}
	v := &Verifier{keys: make(map[string]trusted, len(keys))}
	for _, meta := range keys {
		if !kidPattern.MatchString(meta.ID) || !decimal(meta.Epoch) || !hashPattern.MatchString(meta.SPKISHA256) ||
			!validTime(meta.NotBefore) || !validTime(meta.NotAfter) || meta.NotBefore >= meta.NotAfter || len(meta.PublicPEM) > 8192 {
			return nil, ErrInvalidProof
		}
		if _, exists := v.keys[meta.ID]; exists {
			return nil, ErrInvalidProof
		}
		block, rest := pem.Decode([]byte(meta.PublicPEM))
		if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(rest) != 0 ||
			!bytes.Equal(pem.EncodeToMemory(block), []byte(meta.PublicPEM)) {
			return nil, ErrInvalidProof
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, ErrInvalidProof
		}
		key, ok := parsed.(*rsa.PublicKey)
		if !ok || key.N.BitLen() != 3072 || key.E < 3 {
			return nil, ErrInvalidProof
		}
		digest := sha256.Sum256(block.Bytes)
		if hex.EncodeToString(digest[:]) != meta.SPKISHA256 {
			return nil, ErrInvalidProof
		}
		v.keys[meta.ID] = trusted{meta: meta, key: key}
	}
	return v, nil
}

func (v *Verifier) VerifySignature(token string) (Proof, error) {
	if v == nil || len(token) == 0 || len(token) > maxBytes {
		return Proof{}, ErrInvalidProof
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Proof{}, ErrInvalidProof
	}
	decoded := make([][]byte, 3)
	for i, part := range parts {
		b, err := base64.RawURLEncoding.Strict().DecodeString(part)
		if err != nil || len(b) == 0 || base64.RawURLEncoding.EncodeToString(b) != part {
			return Proof{}, ErrInvalidProof
		}
		decoded[i] = b
	}
	if len(decoded[2]) != 384 {
		return Proof{}, ErrInvalidProof
	}
	h, err := object(decoded[0])
	if err != nil || !exact(h, "alg typ kid") || text(h["alg"]) != "RS256" ||
		text(h["typ"]) != "txboard-fixture-authorization+jws" {
		return Proof{}, ErrInvalidProof
	}
	kid := text(h["kid"])
	key, exists := v.keys[kid]
	if !exists {
		return Proof{}, ErrInvalidProof
	}
	p, err := object(decoded[1])
	if err != nil || !exact(p, "v mode iss aud snapshot_ref provider_id access_subject_id actor_ref authorization_ref candidate_id candidate_ref candidate_request candidate_evidence candidate_evidence_hash binding_commit source policy issued_at lease_expires_at key_epoch key_spki_sha256 key_not_before key_not_after admission_granted delivery_status node_convergence") {
		return Proof{}, ErrInvalidProof
	}
	if text(p["v"]) != "credential-provider/local-authorization/1" || text(p["mode"]) != "local_synthetic_authorization_snapshot" ||
		text(p["iss"]) != "txboard:local-synthetic-authority" || text(p["aud"]) != "txboard:offline-fixture-verifier" ||
		!refPattern.MatchString(text(p["snapshot_ref"])) || !providerPattern.MatchString(text(p["provider_id"])) ||
		!decimal(text(p["access_subject_id"])) || !decimal(text(p["candidate_id"])) ||
		!candidatePattern.MatchString(text(p["candidate_ref"])) || !hashPattern.MatchString(text(p["candidate_evidence_hash"])) ||
		text(p["actor_ref"]) != "local-fixture-operator" || text(p["authorization_ref"]) != "local-fixture-grant/v1" ||
		string(p["admission_granted"]) != "false" || text(p["delivery_status"]) != "not_implemented" || text(p["node_convergence"]) != "not_implemented" ||
		text(p["key_epoch"]) != key.meta.Epoch || text(p["key_spki_sha256"]) != key.meta.SPKISHA256 {
		return Proof{}, ErrInvalidProof
	}
	for _, name := range []string{"candidate_request", "candidate_evidence", "binding_commit", "source", "policy"} {
		if _, err := object(p[name]); err != nil {
			return Proof{}, ErrInvalidProof
		}
	}
	issued, ok1 := timestamp(p["issued_at"])
	expires, ok2 := timestamp(p["lease_expires_at"])
	before, ok3 := timestamp(p["key_not_before"])
	after, ok4 := timestamp(p["key_not_after"])
	if !ok1 || !ok2 || !ok3 || !ok4 || before != key.meta.NotBefore || after != key.meta.NotAfter ||
		issued < before || expires <= issued || expires > after || expires-issued > 60 {
		return Proof{}, ErrInvalidProof
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key.key, crypto.SHA256, digest[:], decoded[2]) != nil {
		return Proof{}, ErrInvalidProof
	}
	payloadHash, signedHash := sha256.Sum256(decoded[1]), sha256.Sum256([]byte(token))
	return Proof{SignatureVerified: true, KeyRevoked: key.meta.Revoked, SnapshotRef: text(p["snapshot_ref"]),
		KeyID: kid, KeyEpoch: key.meta.Epoch, PayloadSHA256: hex.EncodeToString(payloadHash[:]),
		SignedStatementSHA256: hex.EncodeToString(signedHash[:]), IssuedAt: issued, LeaseExpiresAt: expires,
		AdmissionGranted: false, BusinessEvidenceValidation: "not_evaluated", LiveCoreEligibility: "not_evaluated", WindowValidation: "not_evaluated"}, nil
}

func exact(m map[string]json.RawMessage, fields string) bool {
	names := strings.Fields(fields)
	if len(m) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := m[name]; !ok {
			return false
		}
	}
	return true
}

func text(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

func timestamp(raw json.RawMessage) (int64, bool) {
	s := string(raw)
	if s == "" || s != "0" && !decimalPattern.MatchString(s) {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil && validTime(n)
}

func object(raw []byte) (map[string]json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > maxBytes || !utf8.Valid(raw) {
		return nil, ErrInvalidProof
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := scan(dec, 0); err != nil {
		return nil, ErrInvalidProof
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, ErrInvalidProof
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(raw, &result) != nil || result == nil {
		return nil, ErrInvalidProof
	}
	return result, nil
}

func scan(dec *json.Decoder, depth int) error {
	if depth > 32 {
		return ErrInvalidProof
	}
	token, err := dec.Token()
	if err != nil {
		return err
	}
	if s, ok := token.(string); ok && strings.ContainsRune(s, '\uFFFD') {
		return ErrInvalidProof
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] || strings.ContainsRune(name, '\uFFFD') {
				return ErrInvalidProof
			}
			seen[name] = true
			if err := scan(dec, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return ErrInvalidProof
		}
	case '[':
		for dec.More() {
			if err := scan(dec, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return ErrInvalidProof
		}
	default:
		return ErrInvalidProof
	}
	return nil
}
