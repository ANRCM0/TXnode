package credentialprovider

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/ANRCM0/TX-Node/internal/credentialdelivery"
	bolt "github.com/sagernet/bbolt"
)

var errDeliveryState = errors.New("CREDENTIAL_STATE_UNAVAILABLE")

// C1 did not persist a direct issuance index. Backfill only references to
// validated historical receipts, atomically, without changing private material.
func backfillIssueEvidence(tx *bolt.Tx, providerID, epoch string) error {
	metadata := tx.Bucket(metadataBucket)
	if marker := metadata.Get([]byte("issue_evidence_version")); marker != nil {
		if string(marker) != "1" {
			return errDeliveryState
		}
		return nil
	}
	index := tx.Bucket(issueEvidenceBucket)
	expected := map[string]string{}
	err := tx.Bucket(operationsBucket).ForEach(func(id, raw []byte) error {
		record, err := decodeStoredOperation(raw)
		if err != nil || !operationPattern.Match(id) ||
			string(tx.Bucket(keysBucket).Get([]byte(record.IdempotencyKey))) != string(id) {
			return errDeliveryState
		}
		if record.Operation != "issue" || record.Status != "succeeded" {
			return nil
		}
		var receipt IssueResult
		if json.Unmarshal(record.Result, &receipt) != nil || expected[receipt.ProviderSubjectRef] != "" {
			return errDeliveryState
		}
		subject, err := readDeliverySubject(tx, receipt.ProviderSubjectRef)
		if err != nil || verifyIssueEvidence(subject, record, receipt) != nil ||
			!issueHashMatches(subject, record, receipt, providerID, epoch) {
			return errDeliveryState
		}
		expected[receipt.ProviderSubjectRef] = string(id)
		return nil
	})
	if err != nil {
		return err
	}
	if err = index.ForEach(func(ref, op []byte) error {
		if expected[string(ref)] != string(op) {
			return errDeliveryState
		}
		return nil
	}); err != nil {
		return err
	}
	// An issued private record without its durable operation is damaged state.
	if err = tx.Bucket(subjectsBucket).ForEach(func(ref, raw []byte) error {
		var subject privateSubject
		if credentialdelivery.DecodeStrict(raw, &subject) != nil || subject.ProviderSubjectRef != string(ref) {
			return errDeliveryState
		}
		if subject.Issue != nil && expected[string(ref)] == "" {
			return errDeliveryState
		}
		return nil
	}); err != nil {
		return err
	}
	for ref, operation := range expected {
		if err := index.Put([]byte(ref), []byte(operation)); err != nil {
			return err
		}
	}
	return metadata.Put([]byte("issue_evidence_version"), []byte("1"))
}

func readDeliverySubject(tx *bolt.Tx, ref string) (*privateSubject, error) {
	raw := tx.Bucket(subjectsBucket).Get([]byte(ref))
	var subject privateSubject
	if len(raw) > MaxMessageBytes || credentialdelivery.DecodeStrict(raw, &subject) != nil ||
		subject.ProviderSubjectRef != ref || !subjectPattern.MatchString(ref) ||
		!uuidPattern.MatchString(subject.InstallationID) || !positiveDecimal(subject.AccessSubjectID) ||
		string(tx.Bucket(subjectIDsBucket).Get([]byte(subject.InstallationID+":"+subject.AccessSubjectID))) != ref {
		return nil, errDeliveryState
	}
	return &subject, nil
}

func verifyIssueEvidence(subject *privateSubject, record storedOperation, receipt IssueResult) error {
	if subject.Issue == nil || *subject.Issue != receipt ||
		(record.Operation != "issue" && record.Operation != "rotate") || record.Status != "succeeded" ||
		subject.AccessSubjectID != receipt.AccessSubjectID || subject.ProviderSubjectRef != receipt.ProviderSubjectRef ||
		subject.ProfileID != receipt.CredentialProfileID ||
		!positiveDecimal(subject.SubscriptionID) || !positiveDecimal(subject.TermsID) || !positiveDecimal(subject.ExpectedVersion) {
		return errDeliveryState
	}
	if subject.RevocationFactVersion == "" {
		if !credentialdelivery.ValidUUID(subject.Credential) || subject.RevokedAt != 0 ||
			subject.EffectiveAt != 0 || subject.ReasonCode != "" {
			return errDeliveryState
		}
	} else if !positiveDecimal(subject.RevocationFactVersion) || subject.Credential != "" ||
		subject.RevokedAt <= 0 || subject.EffectiveAt < 0 ||
		(subject.ReasonCode != "MANUAL" && subject.ReasonCode != "SUBSCRIPTION_CHANGED" && subject.ReasonCode != "ACCOUNT_BANNED") {
		return errDeliveryState
	}
	return nil
}

func issueHashMatches(subject *privateSubject, record storedOperation, receipt IssueResult, providerID, epoch string) bool {
	input, _ := json.Marshal(IssueInput{
		InstallationID: subject.InstallationID, AccessSubjectID: subject.AccessSubjectID,
		SubscriptionID: subject.SubscriptionID, TermsID: subject.TermsID,
		ProviderSubjectRef: subject.ProviderSubjectRef, ExpectedSubjectVersion: subject.ExpectedVersion,
		CredentialProfileID: subject.ProfileID, NotBeforeAt: receipt.NotBeforeAt,
		CredentialExpiresAt: receipt.CredentialExpiresAt,
	})
	object, err := decodeObject(input)
	canonical, marshalErr := json.Marshal(map[string]any{
		"operation": "issue", "provider_id": providerID,
		"provider_instance_epoch": epoch, "input": object,
	})
	hash := sha256.Sum256(canonical)
	return err == nil && marshalErr == nil && hex.EncodeToString(hash[:]) == record.InputHash
}

func (s *Store) liveCredential(tx *bolt.Tx, binding credentialdelivery.MetadataSubject, now time.Time) (*privateSubject, string, error) {
	subject, err := readDeliverySubject(tx, binding.ProviderSubjectRef)
	if err != nil || subject.InstallationID != binding.InstallationID ||
		subject.AccessSubjectID != binding.AccessSubjectID || subject.SubscriptionID != binding.SubscriptionID ||
		subject.TermsID != binding.TermsID || subject.ProfileID != binding.CredentialProfileID {
		return nil, "", errDeliveryState
	}
	if s.currentEvidence(tx, subject) != nil || subject.Issue.CredentialRef != binding.CredentialRef ||
		subject.Issue.CredentialGeneration != binding.CredentialGeneration {
		return nil, "", errDeliveryState
	}
	receipt := *subject.Issue
	// Bind private ownership and terms to the original canonical mutation hash.
	if subject.RevocationFactVersion != "" || receipt.NotBeforeAt > now.Unix() ||
		receipt.CredentialExpiresAt <= now.Unix() {
		return nil, "", errDeliveryState
	}
	commitment := sha256.Sum256([]byte(subject.Credential))
	return subject, hex.EncodeToString(commitment[:]), nil
}

func (s *Store) metadata(req credentialdelivery.MetadataRequest, now time.Time) (*credentialdelivery.MetadataResponse, error) {
	if credentialdelivery.ValidateMetadataRequest(req) != nil ||
		req.ProviderID != s.providerID || req.ProviderInstanceEpoch != s.epoch {
		return nil, errors.New("PROVIDER_BINDING_REJECTED")
	}
	result := &credentialdelivery.MetadataResponse{
		ContractVersion: credentialdelivery.ContractVersion, RequestID: req.RequestID,
		ProviderID: s.providerID, ProviderInstanceEpoch: s.epoch,
		Credentials: make([]credentialdelivery.MetadataCredential, 0, len(req.Subjects)),
	}
	err := s.db.View(func(tx *bolt.Tx) error {
		for _, binding := range req.Subjects {
			subject, commitment, err := s.liveCredential(tx, binding, now)
			if err != nil {
				return err
			}
			result.Credentials = append(result.Credentials, credentialdelivery.MetadataCredential{
				AccessSubjectID: binding.AccessSubjectID, CredentialRef: binding.CredentialRef,
				CredentialGeneration: binding.CredentialGeneration, CredentialSHA256: commitment,
				CredentialExpiresAt: subject.Issue.CredentialExpiresAt,
			})
		}
		return nil
	})
	if err != nil {
		return nil, errDeliveryState
	}
	return result, nil
}

func (s *Store) material(grant *credentialdelivery.Grant, requestID string, peer string, now time.Time) (*credentialdelivery.MaterialResponse, error) {
	binding := grant.Payload.Provider
	if binding.ProviderID != s.providerID || binding.ProviderInstanceEpoch != s.epoch ||
		binding.RecipientSHA256 != peer || grant.Payload.ExpiresAt <= now.Unix() {
		return nil, errors.New("PROVIDER_BINDING_REJECTED")
	}
	result := &credentialdelivery.MaterialResponse{
		ContractVersion: credentialdelivery.ContractVersion, RequestID: requestID,
		AuthorizationDigest: grant.Digest, Credentials: make([]credentialdelivery.MaterialCredential, 0, len(binding.Subjects)),
	}
	err := s.db.View(func(tx *bolt.Tx) error {
		for i, expected := range binding.Subjects {
			subject, commitment, err := s.liveCredential(tx, credentialdelivery.MetadataSubject{
				InstallationID: binding.InstallationID, AccessSubjectID: expected.AccessSubjectID,
				SubscriptionID: expected.SubscriptionID, TermsID: expected.TermsID,
				ProviderSubjectRef: expected.ProviderSubjectRef, CredentialRef: expected.CredentialRef,
				CredentialGeneration: expected.CredentialGeneration, CredentialProfileID: binding.CredentialProfileID,
			}, now)
			if err != nil || subject.Issue.CredentialExpiresAt != expected.CredentialExpiresAt ||
				grant.Payload.Users[i].UUID != "sha256:"+commitment {
				return errDeliveryState
			}
			result.Credentials = append(result.Credentials, credentialdelivery.MaterialCredential{
				AccessSubjectID: expected.AccessSubjectID, CredentialRef: expected.CredentialRef,
				CredentialGeneration: expected.CredentialGeneration, UUID: subject.Credential,
			})
		}
		return nil
	})
	if err != nil {
		return nil, errDeliveryState
	}
	return result, nil
}
