package credentialprovider

import (
	"encoding/json"
	"errors"
	"strconv"
)

var errInvalidStoredReceipt = errors.New("INVALID_STORED_RECEIPT")

// Persisted JSON is private state, not a response DTO. Validate and reconstruct
// receipts so a corrupt record cannot turn replay into a material export.
func decodeStoredOperation(raw []byte) (storedOperation, error) {
	var record storedOperation
	if len(raw) > MaxMessageBytes {
		return record, errInvalidStoredReceipt
	}
	object, err := decodeObject(raw)
	if err != nil || !exactFields(object, "operation", "idempotency_key", "input_hash", "status", "result", "error") ||
		json.Unmarshal(raw, &record) != nil ||
		(record.Operation != "issue" && record.Operation != "rotate" && record.Operation != "revoke") ||
		len(record.IdempotencyKey) < 1 || len(record.IdempotencyKey) > 128 ||
		!tokenPattern.MatchString(record.IdempotencyKey) || !hashPattern.MatchString(record.InputHash) {
		return storedOperation{}, errInvalidStoredReceipt
	}
	switch record.Status {
	case "succeeded":
		result, ok := object["result"].(map[string]any)
		if !ok || object["error"] != nil {
			return storedOperation{}, errInvalidStoredReceipt
		}
		var reconstructed []byte
		if record.Operation == "rotate" {
			var receipt RotateResult
			if !exactFields(result, "access_subject_id", "provider_subject_ref", "credential_profile_id", "credential_ref",
				"credential_generation", "issued_at", "not_before_at", "credential_expires_at", "previous_credential_ref",
				"previous_generation", "previous_valid_until", "rotation_mode") ||
				!integerField(result, "issued_at") || !integerField(result, "not_before_at") ||
				!integerField(result, "credential_expires_at") || !integerField(result, "previous_valid_until") ||
				json.Unmarshal(record.Result, &receipt) != nil || !validCurrentReceipt(receipt.current()) ||
				!positiveDecimal(receipt.PreviousGeneration) || !credentialPattern.MatchString(receipt.PreviousCredentialRef) ||
				receipt.CredentialRef == receipt.PreviousCredentialRef || receipt.PreviousValidUntil != receipt.IssuedAt ||
				receipt.RotationMode != "immediate" {
				return storedOperation{}, errInvalidStoredReceipt
			}
			previous, _ := strconv.ParseInt(receipt.PreviousGeneration, 10, 64)
			if previous == 9223372036854775807 || receipt.CredentialGeneration != strconv.FormatInt(previous+1, 10) {
				return storedOperation{}, errInvalidStoredReceipt
			}
			reconstructed, err = json.Marshal(receipt)
		} else if record.Operation == "issue" {
			var receipt IssueResult
			if !exactFields(result, "access_subject_id", "provider_subject_ref", "credential_profile_id",
				"credential_ref", "credential_generation", "issued_at", "not_before_at", "credential_expires_at") ||
				!integerField(result, "issued_at") || !integerField(result, "not_before_at") ||
				!integerField(result, "credential_expires_at") || json.Unmarshal(record.Result, &receipt) != nil ||
				!positiveDecimal(receipt.AccessSubjectID) || !subjectPattern.MatchString(receipt.ProviderSubjectRef) ||
				(receipt.CredentialProfileID != "vless-uuid/v1" && receipt.CredentialProfileID != "vmess-uuid/v1") ||
				!credentialPattern.MatchString(receipt.CredentialRef) || receipt.CredentialGeneration != "1" ||
				receipt.IssuedAt < 0 || receipt.NotBeforeAt < 0 ||
				receipt.CredentialExpiresAt <= receipt.NotBeforeAt || receipt.CredentialExpiresAt <= receipt.IssuedAt ||
				receipt.CredentialExpiresAt-receipt.NotBeforeAt > 31*24*60*60 {
				return storedOperation{}, errInvalidStoredReceipt
			}
			reconstructed, err = json.Marshal(receipt)
		} else {
			var receipt RevokeResult
			if !exactFields(result, "access_subject_id", "provider_subject_ref",
				"accepted_revocation_fact_version", "provider_revoked_at") ||
				!integerField(result, "provider_revoked_at") || json.Unmarshal(record.Result, &receipt) != nil ||
				!positiveDecimal(receipt.AccessSubjectID) || !subjectPattern.MatchString(receipt.ProviderSubjectRef) ||
				!positiveDecimal(receipt.AcceptedRevocationFactVersion) || receipt.ProviderRevokedAt < 0 {
				return storedOperation{}, errInvalidStoredReceipt
			}
			reconstructed, err = json.Marshal(receipt)
		}
		if err != nil {
			return storedOperation{}, errInvalidStoredReceipt
		}
		record.Result, record.Error = reconstructed, nil
	case "rejected":
		detail, ok := object["error"].(map[string]any)
		if !ok || !exactFields(detail, "code", "retryable") || object["result"] != nil {
			return storedOperation{}, errInvalidStoredReceipt
		}
		retryable, boolean := detail["retryable"].(bool)
		if !boolean || retryable || record.Error == nil || !storedRejectionAllowed(record.Operation, record.Error.Code) {
			return storedOperation{}, errInvalidStoredReceipt
		}
		record.Result = nil
		record.Error = &WireError{Code: record.Error.Code, Retryable: false}
	default:
		return storedOperation{}, errInvalidStoredReceipt
	}
	return record, nil
}

func validCurrentReceipt(receipt IssueResult) bool {
	return positiveDecimal(receipt.AccessSubjectID) && subjectPattern.MatchString(receipt.ProviderSubjectRef) &&
		(receipt.CredentialProfileID == "vless-uuid/v1" || receipt.CredentialProfileID == "vmess-uuid/v1") &&
		credentialPattern.MatchString(receipt.CredentialRef) && positiveDecimal(receipt.CredentialGeneration) &&
		receipt.IssuedAt >= 0 && receipt.NotBeforeAt >= 0 &&
		receipt.CredentialExpiresAt > receipt.NotBeforeAt && receipt.CredentialExpiresAt > receipt.IssuedAt &&
		receipt.CredentialExpiresAt-receipt.NotBeforeAt <= 31*24*60*60
}

func storedRejectionAllowed(operation, code string) bool {
	if code == "SUBJECT_BINDING_CONFLICT" {
		return true
	}
	if operation == "issue" {
		switch code {
		case "SUBJECT_REVOKED", "SUBJECT_ALREADY_ISSUED", "CREDENTIAL_EXPIRED":
			return true
		}
	}
	if operation == "rotate" {
		switch code {
		case "SUBJECT_REVOKED", "SUBJECT_NOT_ISSUED", "GENERATION_CONFLICT", "CREDENTIAL_EXPIRED":
			return true
		}
	}
	return operation == "revoke" && code == "REVOCATION_FACT_CONFLICT"
}
