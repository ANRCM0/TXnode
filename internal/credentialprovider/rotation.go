package credentialprovider

import (
	"encoding/json"
	"strconv"
	"time"

	bolt "github.com/sagernet/bbolt"
)

type generationEvidence struct {
	OperationID         string          `json:"operation_id"`
	Input               json.RawMessage `json:"input"`
	RetiredAt           *int64          `json:"retired_at"`
	SuccessorGeneration *string         `json:"successor_generation"`
}

func evidenceKey(ref, generation string) []byte { return []byte(ref + ":" + generation) }

func saveGenerationEvidence(tx *bolt.Tx, ref, generation string, record generationEvidence) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return tx.Bucket(generationEvidenceBucket).Put(evidenceKey(ref, generation), raw)
}

func readGenerationEvidence(tx *bolt.Tx, ref, generation string) (generationEvidence, error) {
	raw := tx.Bucket(generationEvidenceBucket).Get(evidenceKey(ref, generation))
	var result generationEvidence
	object, err := decodeObject(raw)
	if len(raw) > MaxMessageBytes || err != nil ||
		!exactFields(object, "operation_id", "input", "retired_at", "successor_generation") ||
		json.Unmarshal(raw, &result) != nil || !operationPattern.MatchString(result.OperationID) {
		return result, errDeliveryState
	}
	if (result.RetiredAt == nil) != (result.SuccessorGeneration == nil) ||
		result.RetiredAt != nil && (*result.RetiredAt < 0 || !positiveDecimal(*result.SuccessorGeneration)) {
		return result, errDeliveryState
	}
	return result, nil
}

func upgradeGenerationEvidence(tx *bolt.Tx, providerID, epoch string) error {
	if marker := tx.Bucket(metadataBucket).Get([]byte("credential_evidence_version")); marker != nil {
		return errDeliveryState
	}
	if key, _ := tx.Bucket(generationEvidenceBucket).Cursor().First(); key != nil {
		return errDeliveryState
	}
	if err := tx.Bucket(issueEvidenceBucket).ForEach(func(ref, operationID []byte) error {
		subject, err := readDeliverySubject(tx, string(ref))
		record, recordErr := decodeStoredOperation(tx.Bucket(operationsBucket).Get(operationID))
		var receipt IssueResult
		if err != nil || recordErr != nil || json.Unmarshal(record.Result, &receipt) != nil ||
			string(tx.Bucket(keysBucket).Get([]byte(record.IdempotencyKey))) != string(operationID) ||
			verifyIssueEvidence(subject, record, receipt) != nil || record.Operation != "issue" ||
			!issueHashMatches(subject, record, receipt, providerID, epoch) {
			return errDeliveryState
		}
		input, _ := json.Marshal(IssueInput{subject.InstallationID, subject.AccessSubjectID, subject.SubscriptionID,
			subject.TermsID, subject.ProviderSubjectRef, subject.ExpectedVersion, subject.ProfileID, receipt.NotBeforeAt, receipt.CredentialExpiresAt})
		return saveGenerationEvidence(tx, string(ref), receipt.CredentialGeneration, generationEvidence{OperationID: string(operationID), Input: input})
	}); err != nil {
		return err
	}
	if err := tx.Bucket(subjectsBucket).ForEach(func(ref, _ []byte) error {
		subject, err := readDeliverySubject(tx, string(ref))
		if err != nil || subject.Issue != nil && tx.Bucket(issueEvidenceBucket).Get(ref) == nil {
			return errDeliveryState
		}
		return nil
	}); err != nil {
		return err
	}
	if err := tx.Bucket(operationsBucket).ForEach(func(operationID, raw []byte) error {
		record, err := decodeStoredOperation(raw)
		if err != nil || !operationPattern.Match(operationID) || record.Operation == "rotate" ||
			string(tx.Bucket(keysBucket).Get([]byte(record.IdempotencyKey))) != string(operationID) {
			return errDeliveryState
		}
		if record.Operation == "issue" && record.Status == "succeeded" {
			var receipt IssueResult
			if json.Unmarshal(record.Result, &receipt) != nil ||
				string(tx.Bucket(issueEvidenceBucket).Get([]byte(receipt.ProviderSubjectRef))) != string(operationID) {
				return errDeliveryState
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return tx.Bucket(metadataBucket).Put([]byte("credential_evidence_version"), []byte("1"))
}

func (s *Store) currentEvidence(tx *bolt.Tx, subject *privateSubject) error {
	if subject.Issue == nil {
		return errDeliveryState
	}
	evidence, err := readGenerationEvidence(tx, subject.ProviderSubjectRef, subject.Issue.CredentialGeneration)
	if err != nil || evidence.RetiredAt != nil ||
		string(tx.Bucket(issueEvidenceBucket).Get([]byte(subject.ProviderSubjectRef))) != evidence.OperationID {
		return errDeliveryState
	}
	record, err := decodeStoredOperation(tx.Bucket(operationsBucket).Get([]byte(evidence.OperationID)))
	if err != nil || string(tx.Bucket(keysBucket).Get([]byte(record.IdempotencyKey))) != evidence.OperationID ||
		(record.Operation != "issue" && record.Operation != "rotate") || record.Status != "succeeded" {
		return errDeliveryState
	}
	receipt := IssueResult{}
	if record.Operation == "rotate" {
		var rotated RotateResult
		if json.Unmarshal(record.Result, &rotated) != nil {
			return errDeliveryState
		}
		receipt = rotated.current()
	} else if json.Unmarshal(record.Result, &receipt) != nil {
		return errDeliveryState
	}
	if verifyIssueEvidence(subject, record, receipt) != nil {
		return errDeliveryState
	}
	req := Request{ContractVersion: ContractVersion, Operation: record.Operation, RequestID: "evidence-check",
		OperationID: evidence.OperationID, ProviderID: s.providerID, ProviderInstanceEpoch: s.epoch,
		IdempotencyKey: record.IdempotencyKey, InputHash: record.InputHash, DeadlineAt: time.Now().Unix() + 30, Input: evidence.Input}
	raw, _ := json.Marshal(req)
	if _, err := parseRequest(raw, time.Now()); err != nil {
		return errDeliveryState
	}
	input, err := decodeObject(evidence.Input)
	if err != nil || input["installation_id"] != subject.InstallationID || input["access_subject_id"] != subject.AccessSubjectID ||
		input["provider_subject_ref"] != subject.ProviderSubjectRef || input["subscription_id"] != subject.SubscriptionID ||
		input["terms_id"] != subject.TermsID || input["expected_subject_version"] != subject.ExpectedVersion ||
		input["credential_profile_id"] != subject.ProfileID ||
		input["not_before_at"] != json.Number(strconv.FormatInt(receipt.NotBeforeAt, 10)) ||
		input["credential_expires_at"] != json.Number(strconv.FormatInt(receipt.CredentialExpiresAt, 10)) {
		return errDeliveryState
	}
	if record.Operation == "rotate" {
		var rotated RotateResult
		_ = json.Unmarshal(record.Result, &rotated)
		if input["credential_ref"] != rotated.PreviousCredentialRef ||
			input["expected_credential_generation"] != rotated.PreviousGeneration ||
			input["rotation_mode"] != rotated.RotationMode {
			return errDeliveryState
		}
		previous, err := readGenerationEvidence(tx, subject.ProviderSubjectRef, rotated.PreviousGeneration)
		if err != nil || previous.RetiredAt == nil || *previous.RetiredAt != rotated.PreviousValidUntil ||
			previous.SuccessorGeneration == nil || *previous.SuccessorGeneration != receipt.CredentialGeneration {
			return errDeliveryState
		}
		previousRecord, err := decodeStoredOperation(tx.Bucket(operationsBucket).Get([]byte(previous.OperationID)))
		if err != nil || string(tx.Bucket(keysBucket).Get([]byte(previousRecord.IdempotencyKey))) != previous.OperationID {
			return errDeliveryState
		}
		var previousReceipt IssueResult
		if previousRecord.Operation == "rotate" {
			var value RotateResult
			if json.Unmarshal(previousRecord.Result, &value) != nil {
				return errDeliveryState
			}
			previousReceipt = value.current()
		} else if previousRecord.Operation != "issue" || json.Unmarshal(previousRecord.Result, &previousReceipt) != nil {
			return errDeliveryState
		}
		if previousRecord.Status != "succeeded" || previousReceipt.CredentialRef != rotated.PreviousCredentialRef ||
			previousReceipt.CredentialGeneration != rotated.PreviousGeneration ||
			previousReceipt.AccessSubjectID != subject.AccessSubjectID || previousReceipt.ProviderSubjectRef != subject.ProviderSubjectRef {
			return errDeliveryState
		}
	}
	return nil
}

func (s *Store) rotate(tx *bolt.Tx, req Request, now time.Time) (Response, error) {
	var input RotateInput
	if json.Unmarshal(req.Input, &input) != nil {
		return Response{}, errInvalidEnvelope
	}
	subject, code, err := readSubject(tx, input.InstallationID, input.AccessSubjectID, input.ProviderSubjectRef)
	if err != nil {
		return Response{}, err
	}
	if code != "" {
		return responseFor(req, "rejected", code, false), nil
	}
	if subject.RevocationFactVersion != "" {
		return responseFor(req, "rejected", "SUBJECT_REVOKED", false), nil
	}
	if subject.Issue == nil {
		return responseFor(req, "rejected", "SUBJECT_NOT_ISSUED", false), nil
	}
	subject, err = readDeliverySubject(tx, input.ProviderSubjectRef)
	if err != nil {
		return Response{}, err
	}
	if s.currentEvidence(tx, subject) != nil {
		return Response{}, errDeliveryState
	}
	if subject.SubscriptionID != input.SubscriptionID || subject.ProfileID != input.CredentialProfileID {
		return responseFor(req, "rejected", "SUBJECT_BINDING_CONFLICT", false), nil
	}
	if subject.Issue.CredentialRef != input.CredentialRef || subject.Issue.CredentialGeneration != input.ExpectedCredentialGeneration {
		return responseFor(req, "rejected", "GENERATION_CONFLICT", false), nil
	}
	if input.CredentialExpiresAt <= now.Unix() {
		return responseFor(req, "rejected", "CREDENTIAL_EXPIRED", false), nil
	}
	previous, _ := strconv.ParseInt(input.ExpectedCredentialGeneration, 10, 64)
	generation := strconv.FormatInt(previous+1, 10)
	secret, err := randomUUID()
	if err != nil {
		return Response{}, err
	}
	ref, err := randomHex()
	if err != nil {
		return Response{}, err
	}
	receipt := RotateResult{input.AccessSubjectID, input.ProviderSubjectRef, input.CredentialProfileID, "credential_" + ref, generation,
		now.Unix(), input.NotBeforeAt, input.CredentialExpiresAt, input.CredentialRef, input.ExpectedCredentialGeneration, now.Unix(), "immediate"}
	evidence, err := readGenerationEvidence(tx, subject.ProviderSubjectRef, input.ExpectedCredentialGeneration)
	if err != nil {
		return Response{}, err
	}
	retired := now.Unix()
	evidence.RetiredAt, evidence.SuccessorGeneration = &retired, &generation
	if err := saveGenerationEvidence(tx, subject.ProviderSubjectRef, input.ExpectedCredentialGeneration, evidence); err != nil {
		return Response{}, err
	}
	current := receipt.current()
	subject.Credential, subject.Issue = secret, &current
	subject.TermsID, subject.ExpectedVersion = input.TermsID, input.ExpectedSubjectVersion
	if err := saveSubject(tx, subject); err != nil {
		return Response{}, err
	}
	response := responseFor(req, "succeeded", "", false)
	response.Result, err = json.Marshal(receipt)
	return response, err
}
