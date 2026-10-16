package credentialprovider

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"time"
)

const ContractVersion = "credential-provider/1"
const MaxMessageBytes = 64 << 10

var (
	tokenPattern       = regexp.MustCompile(`^[A-Za-z0-9._~:-]+$`)
	providerPattern    = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	operationPattern   = regexp.MustCompile(`^cp_[0-9a-f]{32}$`)
	subjectPattern     = regexp.MustCompile(`^subject_[0-9a-f]{32}$`)
	credentialPattern  = regexp.MustCompile(`^credential_[0-9a-f]{32}$`)
	uuidPattern        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hashPattern        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	positivePattern    = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
	errInvalidEnvelope = errors.New("INVALID_REQUEST")
)

type Request struct {
	ContractVersion       string          `json:"contract_version"`
	Operation             string          `json:"operation"`
	RequestID             string          `json:"request_id"`
	OperationID           string          `json:"operation_id"`
	ProviderID            string          `json:"provider_id"`
	ProviderInstanceEpoch string          `json:"provider_instance_epoch"`
	IdempotencyKey        string          `json:"idempotency_key"`
	InputHash             string          `json:"input_hash"`
	DeadlineAt            int64           `json:"deadline_at"`
	Input                 json.RawMessage `json:"input"`
}

type IssueInput struct {
	InstallationID         string `json:"installation_id"`
	AccessSubjectID        string `json:"access_subject_id"`
	SubscriptionID         string `json:"subscription_id"`
	TermsID                string `json:"terms_id"`
	ProviderSubjectRef     string `json:"provider_subject_ref"`
	ExpectedSubjectVersion string `json:"expected_subject_version"`
	CredentialProfileID    string `json:"credential_profile_id"`
	NotBeforeAt            int64  `json:"not_before_at"`
	CredentialExpiresAt    int64  `json:"credential_expires_at"`
}

type RotateInput struct {
	InstallationID               string `json:"installation_id"`
	AccessSubjectID              string `json:"access_subject_id"`
	SubscriptionID               string `json:"subscription_id"`
	TermsID                      string `json:"terms_id"`
	ProviderSubjectRef           string `json:"provider_subject_ref"`
	ExpectedSubjectVersion       string `json:"expected_subject_version"`
	CredentialProfileID          string `json:"credential_profile_id"`
	CredentialRef                string `json:"credential_ref"`
	ExpectedCredentialGeneration string `json:"expected_credential_generation"`
	RotationMode                 string `json:"rotation_mode"`
	NotBeforeAt                  int64  `json:"not_before_at"`
	CredentialExpiresAt          int64  `json:"credential_expires_at"`
}

type RotateResult struct {
	AccessSubjectID       string `json:"access_subject_id"`
	ProviderSubjectRef    string `json:"provider_subject_ref"`
	CredentialProfileID   string `json:"credential_profile_id"`
	CredentialRef         string `json:"credential_ref"`
	CredentialGeneration  string `json:"credential_generation"`
	IssuedAt              int64  `json:"issued_at"`
	NotBeforeAt           int64  `json:"not_before_at"`
	CredentialExpiresAt   int64  `json:"credential_expires_at"`
	PreviousCredentialRef string `json:"previous_credential_ref"`
	PreviousGeneration    string `json:"previous_generation"`
	PreviousValidUntil    int64  `json:"previous_valid_until"`
	RotationMode          string `json:"rotation_mode"`
}

func (r RotateResult) current() IssueResult {
	return IssueResult{r.AccessSubjectID, r.ProviderSubjectRef, r.CredentialProfileID, r.CredentialRef,
		r.CredentialGeneration, r.IssuedAt, r.NotBeforeAt, r.CredentialExpiresAt}
}

type RevokeInput struct {
	InstallationID        string `json:"installation_id"`
	AccessSubjectID       string `json:"access_subject_id"`
	ProviderSubjectRef    string `json:"provider_subject_ref"`
	RevocationFactVersion string `json:"revocation_fact_version"`
	EffectiveAt           int64  `json:"effective_at"`
	ReasonCode            string `json:"reason_code"`
}

type IssueResult struct {
	AccessSubjectID      string `json:"access_subject_id"`
	ProviderSubjectRef   string `json:"provider_subject_ref"`
	CredentialProfileID  string `json:"credential_profile_id"`
	CredentialRef        string `json:"credential_ref"`
	CredentialGeneration string `json:"credential_generation"`
	IssuedAt             int64  `json:"issued_at"`
	NotBeforeAt          int64  `json:"not_before_at"`
	CredentialExpiresAt  int64  `json:"credential_expires_at"`
}

type RevokeResult struct {
	AccessSubjectID               string `json:"access_subject_id"`
	ProviderSubjectRef            string `json:"provider_subject_ref"`
	AcceptedRevocationFactVersion string `json:"accepted_revocation_fact_version"`
	ProviderRevokedAt             int64  `json:"provider_revoked_at"`
}

type WireError struct {
	Code      string `json:"code"`
	Retryable bool   `json:"retryable"`
}

type Response struct {
	ContractVersion       string          `json:"contract_version"`
	RequestID             string          `json:"request_id"`
	OperationID           string          `json:"operation_id"`
	ProviderID            string          `json:"provider_id"`
	ProviderInstanceEpoch string          `json:"provider_instance_epoch"`
	Status                string          `json:"status"`
	Result                json.RawMessage `json:"result"`
	Error                 *WireError      `json:"error"`
}

func responseFor(req Request, status, code string, retryable bool) Response {
	result := Response{
		ContractVersion: ContractVersion, RequestID: req.RequestID,
		OperationID: req.OperationID, ProviderID: req.ProviderID,
		ProviderInstanceEpoch: req.ProviderInstanceEpoch, Status: status,
	}
	if code != "" {
		result.Error = &WireError{Code: code, Retryable: retryable}
	}
	return result
}

func positiveDecimal(value string) bool {
	if !positivePattern.MatchString(value) {
		return false
	}
	_, err := strconv.ParseInt(value, 10, 64)
	return err == nil
}

// Decode before unmarshalling so duplicate keys and missing required fields
// cannot silently collapse into a valid Go struct.
func decodeObject(raw []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := readValue(decoder, 0)
	if err != nil {
		return nil, errInvalidEnvelope
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, errInvalidEnvelope
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errInvalidEnvelope
	}
	return object, nil
}

func readValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > 8 {
		return nil, errInvalidEnvelope
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if token != json.Delim('{') {
		switch token.(type) {
		case string, json.Number, bool, nil:
			return token, nil
		default:
			return nil, errInvalidEnvelope
		}
	}
	object := make(map[string]any)
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok {
			return nil, errInvalidEnvelope
		}
		if _, exists := object[name]; exists {
			return nil, errInvalidEnvelope
		}
		value, err := readValue(decoder, depth+1)
		if err != nil {
			return nil, err
		}
		object[name] = value
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
		return nil, errInvalidEnvelope
	}
	return object, nil
}

func exactFields(object map[string]any, fields ...string) bool {
	if len(object) != len(fields) {
		return false
	}
	for _, field := range fields {
		if _, ok := object[field]; !ok {
			return false
		}
	}
	return true
}

func integerField(object map[string]any, field string) bool {
	value, ok := object[field].(json.Number)
	if !ok {
		return false
	}
	parsed, err := strconv.ParseInt(string(value), 10, 64)
	return err == nil && strconv.FormatInt(parsed, 10) == string(value)
}

func parseRequest(raw []byte, now time.Time) (Request, error) {
	var req Request
	if len(raw) > MaxMessageBytes {
		return req, errInvalidEnvelope
	}
	object, err := decodeObject(raw)
	if err != nil || !exactFields(object, "contract_version", "operation", "request_id",
		"operation_id", "provider_id", "provider_instance_epoch", "idempotency_key",
		"input_hash", "deadline_at", "input") || !integerField(object, "deadline_at") {
		return req, errInvalidEnvelope
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return Request{}, errInvalidEnvelope
	}
	if req.ContractVersion != ContractVersion ||
		len(req.RequestID) < 1 || len(req.RequestID) > 96 || !tokenPattern.MatchString(req.RequestID) ||
		!operationPattern.MatchString(req.OperationID) || !providerPattern.MatchString(req.ProviderID) ||
		!positiveDecimal(req.ProviderInstanceEpoch) ||
		len(req.IdempotencyKey) < 1 || len(req.IdempotencyKey) > 128 || !tokenPattern.MatchString(req.IdempotencyKey) ||
		!hashPattern.MatchString(req.InputHash) {
		return Request{}, errInvalidEnvelope
	}
	input, ok := object["input"].(map[string]any)
	if !ok {
		return req, errInvalidEnvelope
	}
	switch req.Operation {
	case "rotate":
		var value RotateInput
		if !exactFields(input, "installation_id", "access_subject_id", "subscription_id", "terms_id", "provider_subject_ref",
			"expected_subject_version", "credential_profile_id", "credential_ref", "expected_credential_generation",
			"rotation_mode", "not_before_at", "credential_expires_at") ||
			!integerField(input, "not_before_at") || !integerField(input, "credential_expires_at") ||
			json.Unmarshal(req.Input, &value) != nil || !uuidPattern.MatchString(value.InstallationID) ||
			!positiveDecimal(value.AccessSubjectID) || !positiveDecimal(value.SubscriptionID) ||
			!positiveDecimal(value.TermsID) || !subjectPattern.MatchString(value.ProviderSubjectRef) ||
			!positiveDecimal(value.ExpectedSubjectVersion) || !credentialPattern.MatchString(value.CredentialRef) ||
			!positiveDecimal(value.ExpectedCredentialGeneration) || value.ExpectedCredentialGeneration == "9223372036854775807" ||
			value.RotationMode != "immediate" ||
			(value.CredentialProfileID != "vless-uuid/v1" && value.CredentialProfileID != "vmess-uuid/v1") ||
			value.NotBeforeAt < 0 || value.CredentialExpiresAt <= value.NotBeforeAt ||
			value.CredentialExpiresAt-value.NotBeforeAt > 31*24*60*60 {
			return req, errInvalidEnvelope
		}
	case "issue":
		var value IssueInput
		if !exactFields(input, "installation_id", "access_subject_id", "subscription_id",
			"terms_id", "provider_subject_ref", "expected_subject_version",
			"credential_profile_id", "not_before_at", "credential_expires_at") ||
			!integerField(input, "not_before_at") || !integerField(input, "credential_expires_at") ||
			json.Unmarshal(req.Input, &value) != nil ||
			!uuidPattern.MatchString(value.InstallationID) || !positiveDecimal(value.AccessSubjectID) ||
			!positiveDecimal(value.SubscriptionID) || !positiveDecimal(value.TermsID) ||
			!subjectPattern.MatchString(value.ProviderSubjectRef) || !positiveDecimal(value.ExpectedSubjectVersion) ||
			(value.CredentialProfileID != "vless-uuid/v1" && value.CredentialProfileID != "vmess-uuid/v1") ||
			value.NotBeforeAt < 0 || value.CredentialExpiresAt <= value.NotBeforeAt ||
			value.CredentialExpiresAt-value.NotBeforeAt > 31*24*60*60 {
			return req, errInvalidEnvelope
		}
	case "revoke":
		var value RevokeInput
		if !exactFields(input, "installation_id", "access_subject_id", "provider_subject_ref",
			"revocation_fact_version", "effective_at", "reason_code") ||
			!integerField(input, "effective_at") || json.Unmarshal(req.Input, &value) != nil ||
			!uuidPattern.MatchString(value.InstallationID) || !positiveDecimal(value.AccessSubjectID) ||
			!subjectPattern.MatchString(value.ProviderSubjectRef) || !positiveDecimal(value.RevocationFactVersion) ||
			value.EffectiveAt < 0 || (value.ReasonCode != "MANUAL" &&
			value.ReasonCode != "SUBSCRIPTION_CHANGED" && value.ReasonCode != "ACCOUNT_BANNED") {
			return req, errInvalidEnvelope
		}
	case "query":
		if !exactFields(input, "operation_id") || input["operation_id"] != req.OperationID {
			return req, errInvalidEnvelope
		}
	default:
		return req, errInvalidEnvelope
	}
	canonical, err := json.Marshal(map[string]any{
		"operation": req.Operation, "provider_id": req.ProviderID,
		"provider_instance_epoch": req.ProviderInstanceEpoch, "input": input,
	})
	if err != nil {
		return req, errInvalidEnvelope
	}
	hash := sha256.Sum256(canonical)
	if hex.EncodeToString(hash[:]) != req.InputHash {
		return req, errors.New("INPUT_HASH_MISMATCH")
	}
	if req.DeadlineAt <= now.Unix() || req.DeadlineAt > now.Unix()+30 {
		return req, errors.New("DEADLINE_REJECTED")
	}
	return req, nil
}
