package credentialprovider

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"time"

	bolt "github.com/sagernet/bbolt"
)

var (
	metadataBucket   = []byte("metadata")
	operationsBucket = []byte("operations")
	keysBucket       = []byte("idempotency")
	subjectsBucket   = []byte("subjects")
	subjectIDsBucket = []byte("subject_ids")
)

type Store struct {
	db         *bolt.DB
	providerID string
	epoch      string
}

type storedOperation struct {
	Operation      string          `json:"operation"`
	IdempotencyKey string          `json:"idempotency_key"`
	InputHash      string          `json:"input_hash"`
	Status         string          `json:"status"`
	Result         json.RawMessage `json:"result"`
	Error          *WireError      `json:"error"`
}

// Private subject records must never be marshalled into a control response.
type privateSubject struct {
	InstallationID        string       `json:"installation_id"`
	AccessSubjectID       string       `json:"access_subject_id"`
	ProviderSubjectRef    string       `json:"provider_subject_ref"`
	SubscriptionID        string       `json:"subscription_id,omitempty"`
	TermsID               string       `json:"terms_id,omitempty"`
	ExpectedVersion       string       `json:"expected_version,omitempty"`
	ProfileID             string       `json:"profile_id,omitempty"`
	Credential            string       `json:"credential,omitempty"`
	Issue                 *IssueResult `json:"issue,omitempty"`
	RevocationFactVersion string       `json:"revocation_fact_version,omitempty"`
	RevokedAt             int64        `json:"revoked_at,omitempty"`
	EffectiveAt           int64        `json:"effective_at,omitempty"`
	ReasonCode            string       `json:"reason_code,omitempty"`
}

// OpenStore requires a private operator-owned directory and refuses symlinks
// and permissive existing state. bbolt holds its exclusive lock until Close.
func OpenStore(path, providerID, epoch string) (*Store, error) {
	if !filepath.IsAbs(path) || !providerPattern.MatchString(providerID) || !positiveDecimal(epoch) {
		return nil, errors.New("INVALID_STORE_CONFIG")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, errors.New("STORE_UNAVAILABLE")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, errors.New("STORE_DIRECTORY_NOT_PRIVATE")
	}
	if resolved, err := filepath.EvalSymlinks(dir); err != nil || resolved != filepath.Clean(dir) {
		return nil, errors.New("STORE_DIRECTORY_NOT_PRIVATE")
	}
	if info, err = os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return nil, errors.New("STORE_FILE_NOT_PRIVATE")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("STORE_UNAVAILABLE")
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, errors.New("STORE_UNAVAILABLE")
	}
	store := &Store{db: db, providerID: providerID, epoch: epoch}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{metadataBucket, operationsBucket, keysBucket, subjectsBucket, subjectIDsBucket} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		metadata := tx.Bucket(metadataBucket)
		expected := "native-provider-store/1:" + providerID + ":" + epoch
		if current := metadata.Get([]byte("identity")); current != nil {
			if string(current) != expected {
				return errors.New("STORE_IDENTITY_MISMATCH")
			}
			return nil
		}
		for _, name := range [][]byte{operationsBucket, keysBucket, subjectsBucket, subjectIDsBucket} {
			if key, _ := tx.Bucket(name).Cursor().First(); key != nil {
				return errors.New("STORE_IDENTITY_MISMATCH")
			}
		}
		return metadata.Put([]byte("identity"), []byte(expected))
	})
	if err != nil {
		_ = db.Close()
		if err.Error() == "STORE_IDENTITY_MISMATCH" {
			return nil, err
		}
		return nil, errors.New("STORE_UNAVAILABLE")
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func randomHex() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func randomUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	raw := hex.EncodeToString(value[:])
	return raw[:8] + "-" + raw[8:12] + "-" + raw[12:16] + "-" + raw[16:20] + "-" + raw[20:], nil
}

func (s *Store) execute(ctx context.Context, req Request, now time.Time) Response {
	if req.ProviderID != s.providerID || req.ProviderInstanceEpoch != s.epoch {
		return responseFor(req, "rejected", "PROVIDER_IDENTITY_MISMATCH", false)
	}
	result := responseFor(req, "unknown", "STORE_UNAVAILABLE", true)
	run := s.db.Update
	if req.Operation == "query" {
		run = s.db.View
	}
	err := run(func(tx *bolt.Tx) error {
		now = time.Now()
		if ctx.Err() != nil || time.Now().Unix() >= req.DeadlineAt {
			return errors.New("DEADLINE_REJECTED")
		}
		operations, keys := tx.Bucket(operationsBucket), tx.Bucket(keysBucket)
		keyOwner := keys.Get([]byte(req.IdempotencyKey))
		existing := operations.Get([]byte(req.OperationID))
		if keyOwner != nil {
			owner, err := decodeStoredOperation(operations.Get(keyOwner))
			if err != nil || owner.IdempotencyKey != req.IdempotencyKey {
				return errInvalidStoredReceipt
			}
			if string(keyOwner) != req.OperationID {
				result = responseFor(req, "rejected", "IDEMPOTENCY_CONFLICT", false)
				return nil
			}
		}
		if existing != nil {
			record, err := decodeStoredOperation(existing)
			if err != nil || string(keys.Get([]byte(record.IdempotencyKey))) != req.OperationID {
				return errInvalidStoredReceipt
			}
			if record.IdempotencyKey != req.IdempotencyKey ||
				(req.Operation != "query" && (record.Operation != req.Operation || record.InputHash != req.InputHash)) {
				result = responseFor(req, "rejected", "IDEMPOTENCY_CONFLICT", false)
				return nil
			}
			result = responseFor(req, record.Status, "", false)
			result.Result, result.Error = record.Result, record.Error
			if req.Operation == "query" && record.Status == "succeeded" {
				result.Result, _ = json.Marshal(struct {
					Operation string          `json:"operation"`
					InputHash string          `json:"input_hash"`
					Result    json.RawMessage `json:"result"`
				}{record.Operation, record.InputHash, record.Result})
			}
			return nil
		}
		if req.Operation == "query" {
			result = responseFor(req, "unknown", "OPERATION_UNKNOWN", true)
			return nil
		}
		var applyErr error
		switch req.Operation {
		case "issue":
			result, applyErr = issue(tx, req, now)
		case "revoke":
			result, applyErr = revoke(tx, req, now)
		default:
			return errInvalidEnvelope
		}
		if applyErr != nil {
			return applyErr
		}
		if ctx.Err() != nil || time.Now().Unix() >= req.DeadlineAt {
			return errors.New("DEADLINE_REJECTED")
		}
		record, err := json.Marshal(storedOperation{
			Operation: req.Operation, IdempotencyKey: req.IdempotencyKey,
			InputHash: req.InputHash, Status: result.Status, Result: result.Result, Error: result.Error,
		})
		if err != nil {
			return err
		}
		if err = operations.Put([]byte(req.OperationID), record); err != nil {
			return err
		}
		return keys.Put([]byte(req.IdempotencyKey), []byte(req.OperationID))
	})
	if err != nil {
		if err.Error() == "DEADLINE_REJECTED" {
			return responseFor(req, "rejected", "DEADLINE_REJECTED", true)
		}
		return responseFor(req, "unknown", "STORE_UNAVAILABLE", true)
	}
	return result
}

func readSubject(tx *bolt.Tx, installationID, accessSubjectID, ref string) (*privateSubject, string, error) {
	id := []byte(installationID + ":" + accessSubjectID)
	if owner := tx.Bucket(subjectIDsBucket).Get(id); owner != nil && string(owner) != ref {
		return nil, "SUBJECT_BINDING_CONFLICT", nil
	}
	var subject privateSubject
	raw := tx.Bucket(subjectsBucket).Get([]byte(ref))
	if raw == nil {
		return &privateSubject{InstallationID: installationID, AccessSubjectID: accessSubjectID, ProviderSubjectRef: ref}, "", nil
	}
	if err := json.Unmarshal(raw, &subject); err != nil {
		return nil, "", err
	}
	if subject.InstallationID != installationID || subject.AccessSubjectID != accessSubjectID {
		return nil, "SUBJECT_BINDING_CONFLICT", nil
	}
	return &subject, "", nil
}

func saveSubject(tx *bolt.Tx, subject *privateSubject) error {
	raw, err := json.Marshal(subject)
	if err != nil {
		return err
	}
	if err = tx.Bucket(subjectsBucket).Put([]byte(subject.ProviderSubjectRef), raw); err != nil {
		return err
	}
	return tx.Bucket(subjectIDsBucket).Put(
		[]byte(subject.InstallationID+":"+subject.AccessSubjectID), []byte(subject.ProviderSubjectRef))
}

func issue(tx *bolt.Tx, req Request, now time.Time) (Response, error) {
	var input IssueInput
	if err := json.Unmarshal(req.Input, &input); err != nil {
		return Response{}, err
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
	if subject.Issue != nil {
		return responseFor(req, "rejected", "SUBJECT_ALREADY_ISSUED", false), nil
	}
	if input.CredentialExpiresAt <= now.Unix() {
		return responseFor(req, "rejected", "CREDENTIAL_EXPIRED", false), nil
	}
	secret, err := randomUUID()
	if err != nil {
		return Response{}, err
	}
	ref, err := randomHex()
	if err != nil {
		return Response{}, err
	}
	receipt := IssueResult{
		AccessSubjectID: input.AccessSubjectID, ProviderSubjectRef: input.ProviderSubjectRef,
		CredentialProfileID: input.CredentialProfileID, CredentialRef: "credential_" + ref,
		CredentialGeneration: "1", IssuedAt: now.Unix(), NotBeforeAt: input.NotBeforeAt,
		CredentialExpiresAt: input.CredentialExpiresAt,
	}
	subject.SubscriptionID, subject.TermsID = input.SubscriptionID, input.TermsID
	subject.ExpectedVersion, subject.ProfileID = input.ExpectedSubjectVersion, input.CredentialProfileID
	subject.Credential, subject.Issue = secret, &receipt
	if err := saveSubject(tx, subject); err != nil {
		return Response{}, err
	}
	response := responseFor(req, "succeeded", "", false)
	response.Result, err = json.Marshal(receipt)
	return response, err
}

func revoke(tx *bolt.Tx, req Request, now time.Time) (Response, error) {
	var input RevokeInput
	if err := json.Unmarshal(req.Input, &input); err != nil {
		return Response{}, err
	}
	subject, code, err := readSubject(tx, input.InstallationID, input.AccessSubjectID, input.ProviderSubjectRef)
	if err != nil {
		return Response{}, err
	}
	if code != "" {
		return responseFor(req, "rejected", code, false), nil
	}
	current, _ := strconv.ParseInt(subject.RevocationFactVersion, 10, 64)
	requested, _ := strconv.ParseInt(input.RevocationFactVersion, 10, 64)
	if current == requested && (subject.EffectiveAt != input.EffectiveAt || subject.ReasonCode != input.ReasonCode) {
		return responseFor(req, "rejected", "REVOCATION_FACT_CONFLICT", false), nil
	}
	if requested > current {
		subject.RevocationFactVersion, subject.EffectiveAt, subject.ReasonCode =
			input.RevocationFactVersion, input.EffectiveAt, input.ReasonCode
		if subject.RevokedAt == 0 {
			subject.RevokedAt = now.Unix()
		}
		subject.Credential = ""
		if err := saveSubject(tx, subject); err != nil {
			return Response{}, err
		}
	}
	response := responseFor(req, "succeeded", "", false)
	response.Result, err = json.Marshal(RevokeResult{
		AccessSubjectID: input.AccessSubjectID, ProviderSubjectRef: input.ProviderSubjectRef,
		AcceptedRevocationFactVersion: subject.RevocationFactVersion, ProviderRevokedAt: subject.RevokedAt,
	})
	return response, err
}
