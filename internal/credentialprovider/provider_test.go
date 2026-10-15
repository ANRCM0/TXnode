package credentialprovider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	bolt "github.com/sagernet/bbolt"
)

func testStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private", "provider.db")
	store, err := OpenStore(path, "provider-a", "1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, path
}

func makeRequest(t *testing.T, operation string, number int, input any) Request {
	t.Helper()
	inputRaw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	req := Request{
		ContractVersion: ContractVersion, Operation: operation,
		RequestID: fmt.Sprintf("req-%d", number), OperationID: fmt.Sprintf("cp_%032x", number),
		ProviderID: "provider-a", ProviderInstanceEpoch: "1",
		IdempotencyKey: fmt.Sprintf("key-%d", number), DeadlineAt: time.Now().Unix() + 30,
		Input: inputRaw,
	}
	return rehash(t, req)
}

func rehash(t *testing.T, req Request) Request {
	t.Helper()
	input, err := decodeObject(req.Input)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(map[string]any{
		"operation": req.Operation, "provider_id": req.ProviderID,
		"provider_instance_epoch": req.ProviderInstanceEpoch, "input": input,
	})
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(canonical)
	req.InputHash = hex.EncodeToString(hash[:])
	return req
}

func issueInput() IssueInput {
	now := time.Now().Unix()
	return IssueInput{
		InstallationID:  "11111111-1111-4111-8111-111111111111",
		AccessSubjectID: "11", SubscriptionID: "12", TermsID: "13",
		ProviderSubjectRef:     "subject_11111111111111111111111111111111",
		ExpectedSubjectVersion: "1", CredentialProfileID: "vless-uuid/v1",
		NotBeforeAt: now, CredentialExpiresAt: now + 3600,
	}
}

func revokeInput() RevokeInput {
	issue := issueInput()
	return RevokeInput{
		InstallationID: issue.InstallationID, AccessSubjectID: issue.AccessSubjectID,
		ProviderSubjectRef: issue.ProviderSubjectRef, RevocationFactVersion: "2",
		EffectiveAt: time.Now().Unix(), ReasonCode: "MANUAL",
	}
}

func execute(t *testing.T, store *Store, req Request) Response {
	t.Helper()
	raw, _ := json.Marshal(req)
	parsed, err := parseRequest(raw, time.Now())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return store.execute(context.Background(), parsed, time.Now())
}

func assertCode(t *testing.T, response Response, code string) {
	t.Helper()
	if response.Error == nil || response.Error.Code != code {
		t.Fatalf("expected %s, got status %s, error %#v", code, response.Status, response.Error)
	}
}

func privateFor(t *testing.T, store *Store) privateSubject {
	t.Helper()
	var subject privateSubject
	err := store.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(subjectsBucket).Get([]byte(issueInput().ProviderSubjectRef))
		return json.Unmarshal(raw, &subject)
	})
	if err != nil {
		t.Fatal(err)
	}
	return subject
}

func queryRequest(t *testing.T, original Request) Request {
	req := makeRequest(t, "query", 1, map[string]string{"operation_id": original.OperationID})
	req.OperationID, req.IdempotencyKey = original.OperationID, original.IdempotencyKey
	return rehash(t, req)
}

func TestIssuePersistsPrivateUUIDAndIdempotentReceiptAcrossRestart(t *testing.T) {
	store, path := testStore(t)
	req := makeRequest(t, "issue", 1, issueInput())
	first := execute(t, store, req)
	if first.Status != "succeeded" {
		t.Fatalf("issue rejected: %#v", first.Error)
	}
	private := privateFor(t, store)
	if !uuidPattern.MatchString(private.Credential) || private.Credential[14] != '4' ||
		!strings.ContainsAny(private.Credential[19:20], "89ab") {
		t.Fatal("private store lacks a random RFC4122 UUIDv4")
	}
	body, _ := json.Marshal(first)
	if bytes.Contains(body, []byte(private.Credential)) || bytes.Contains(body, []byte(`"credential":`)) {
		t.Fatal("credential escaped private store")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(path, "provider-a", "1")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	req.RequestID = "retry-other-request-id"
	replay := execute(t, reopened, req)
	if !bytes.Equal(first.Result, replay.Result) || replay.RequestID != req.RequestID {
		t.Fatal("retry changed the original receipt")
	}
	query := execute(t, reopened, queryRequest(t, req))
	var queried struct {
		Operation string          `json:"operation"`
		InputHash string          `json:"input_hash"`
		Result    json.RawMessage `json:"result"`
	}
	if json.Unmarshal(query.Result, &queried) != nil || queried.Operation != "issue" ||
		queried.InputHash != req.InputHash || !bytes.Equal(queried.Result, first.Result) {
		t.Fatal("query did not recover original receipt")
	}
	if privateFor(t, reopened).Credential != private.Credential {
		t.Fatal("restart regenerated credential")
	}
}

func TestProviderStoreIdentityPermissionsAndExclusiveOwnership(t *testing.T) {
	store, path := testStore(t)
	for _, pair := range [][2]string{{"other-provider", "1"}, {"provider-a", "2"}} {
		if duplicate, err := OpenStore(path, pair[0], pair[1]); err == nil {
			duplicate.Close()
			t.Fatal("concurrent process acquired exclusive database")
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"other-provider", "1"}, {"provider-a", "2"}} {
		if wrong, err := OpenStore(path, pair[0], pair[1]); err == nil {
			wrong.Close()
			t.Fatal("identity change accepted")
		} else if err.Error() != "STORE_IDENTITY_MISMATCH" {
			t.Fatalf("unexpected identity failure %v", err)
		}
	}
	file, _ := os.Stat(path)
	dir, _ := os.Stat(filepath.Dir(path))
	if file.Mode().Perm() != 0600 || dir.Mode().Perm() != 0700 {
		t.Fatal("private permissions not enforced")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if wrong, err := OpenStore(path, "provider-a", "1"); err == nil {
		wrong.Close()
		t.Fatal("permissive store accepted")
	}
}

func TestStoreRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	private := filepath.Join(root, "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	if store, err := OpenStore(filepath.Join(link, "store.db"), "provider-a", "1"); err == nil {
		store.Close()
		t.Fatal("symlink directory accepted")
	}
}

func TestConcurrentIssueIsAtomicAndHasOneGeneration(t *testing.T) {
	store, _ := testStore(t)
	req := makeRequest(t, "issue", 1, issueInput())
	var group sync.WaitGroup
	results := make(chan Response, 12)
	for range 12 {
		group.Add(1)
		go func() {
			defer group.Done()
			results <- store.execute(context.Background(), req, time.Now())
		}()
	}
	group.Wait()
	close(results)
	var receipt json.RawMessage
	for result := range results {
		if result.Status != "succeeded" {
			t.Fatalf("concurrent issue rejected: %#v", result.Error)
		}
		if receipt == nil {
			receipt = result.Result
		}
		if !bytes.Equal(receipt, result.Result) {
			t.Fatal("duplicate issuance changed receipt")
		}
	}
	store.db.View(func(tx *bolt.Tx) error {
		for _, bucket := range [][]byte{subjectsBucket, operationsBucket, keysBucket, subjectIDsBucket} {
			if tx.Bucket(bucket).Stats().KeyN != 1 {
				t.Errorf("atomic operation has unexpected bucket count: %s", bucket)
			}
		}
		return nil
	})
	assertCode(t, execute(t, store, makeRequest(t, "issue", 2, issueInput())), "SUBJECT_ALREADY_ISSUED")
}

func TestOperationAndIdempotencyConflictsCannotReplaceState(t *testing.T) {
	store, _ := testStore(t)
	original := makeRequest(t, "issue", 1, issueInput())
	first := execute(t, store, original)
	input := issueInput()
	input.TermsID = "99"
	changed := makeRequest(t, "issue", 1, input)
	assertCode(t, execute(t, store, changed), "IDEMPOTENCY_CONFLICT")
	changed = makeRequest(t, "issue", 2, input)
	changed.IdempotencyKey = original.IdempotencyKey
	assertCode(t, execute(t, store, changed), "IDEMPOTENCY_CONFLICT")
	changed = original
	changed.IdempotencyKey = "different-key"
	assertCode(t, execute(t, store, changed), "IDEMPOTENCY_CONFLICT")
	query := queryRequest(t, original)
	query.IdempotencyKey = "different-key"
	assertCode(t, execute(t, store, query), "IDEMPOTENCY_CONFLICT")
	if !bytes.Equal(first.Result, execute(t, store, original).Result) {
		t.Fatal("conflict changed original receipt")
	}
}

func TestTombstoneBeforeIssueAndMonotonicRevocation(t *testing.T) {
	store, path := testStore(t)
	input := revokeInput()
	input.RevocationFactVersion = "7"
	first := execute(t, store, makeRequest(t, "revoke", 1, input))
	if first.Status != "succeeded" {
		t.Fatalf("unknown subject revoke failed: %#v", first.Error)
	}
	input.RevocationFactVersion = "3"
	older := execute(t, store, makeRequest(t, "revoke", 2, input))
	var receipt RevokeResult
	if json.Unmarshal(older.Result, &receipt) != nil || receipt.AcceptedRevocationFactVersion != "7" {
		t.Fatal("lower fact version replaced tombstone")
	}
	input.RevocationFactVersion, input.ReasonCode = "7", "ACCOUNT_BANNED"
	assertCode(t, execute(t, store, makeRequest(t, "revoke", 3, input)), "REVOCATION_FACT_CONFLICT")
	issueReq := makeRequest(t, "issue", 4, issueInput())
	assertCode(t, execute(t, store, issueReq), "SUBJECT_REVOKED")
	query := execute(t, store, queryRequest(t, issueReq))
	assertCode(t, query, "SUBJECT_REVOKED")
	if query.Status != "rejected" {
		t.Fatal("stored rejection did not survive query")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(path, "provider-a", "1")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	assertCode(t, execute(t, reopened, makeRequest(t, "issue", 5, issueInput())), "SUBJECT_REVOKED")
	if privateFor(t, reopened).Credential != "" {
		t.Fatal("tombstone retained a usable credential")
	}
}

func TestRevokeRemovesMaterialButKeepsHistoricalIssueReceipt(t *testing.T) {
	store, _ := testStore(t)
	req := makeRequest(t, "issue", 1, issueInput())
	first := execute(t, store, req)
	if execute(t, store, makeRequest(t, "revoke", 2, revokeInput())).Status != "succeeded" {
		t.Fatal("revoke failed")
	}
	if privateFor(t, store).Credential != "" {
		t.Fatal("revoked subject has live material")
	}
	if !bytes.Equal(first.Result, execute(t, store, req).Result) {
		t.Fatal("revoke rewrote immutable issue receipt")
	}
}

func TestSubjectBindingsCannotBeReassigned(t *testing.T) {
	store, _ := testStore(t)
	execute(t, store, makeRequest(t, "issue", 1, issueInput()))
	input := issueInput()
	input.ProviderSubjectRef = "subject_22222222222222222222222222222222"
	assertCode(t, execute(t, store, makeRequest(t, "issue", 2, input)), "SUBJECT_BINDING_CONFLICT")
	revoke := revokeInput()
	revoke.AccessSubjectID = "99"
	assertCode(t, execute(t, store, makeRequest(t, "revoke", 3, revoke)), "SUBJECT_BINDING_CONFLICT")
}

func TestQueryIsReadOnlyAndUnknownIsRecoverable(t *testing.T) {
	store, _ := testStore(t)
	req := queryRequest(t, makeRequest(t, "issue", 999, issueInput()))
	result := execute(t, store, req)
	assertCode(t, result, "OPERATION_UNKNOWN")
	if result.Status != "unknown" || !result.Error.Retryable {
		t.Fatal("unknown operation not recoverable")
	}
	store.db.View(func(tx *bolt.Tx) error {
		for _, bucket := range [][]byte{operationsBucket, keysBucket, subjectsBucket} {
			if tx.Bucket(bucket).Stats().KeyN != 0 {
				t.Errorf("query wrote to %s", bucket)
			}
		}
		return nil
	})
}

func assertCorruptReceiptRefused(t *testing.T, store *Store, original Request, secret string) {
	t.Helper()
	for _, req := range []Request{original, queryRequest(t, original)} {
		response := execute(t, store, req)
		assertCode(t, response, "STORE_UNAVAILABLE")
		raw, err := json.Marshal(response)
		if err != nil || response.Status != "unknown" || response.Result != nil ||
			bytes.Contains(raw, []byte(secret)) || bytes.Contains(raw, []byte(`"material"`)) ||
			bytes.Contains(raw, []byte(`"credential"`)) {
			t.Fatal("corrupt stored receipt escaped the private-store boundary")
		}
	}
}

func TestCorruptStoredSuccessReceiptCannotExportMaterial(t *testing.T) {
	secret := "private-material-must-not-escape"
	for _, operation := range []string{"issue", "revoke"} {
		for _, damage := range []string{"extra result field", "duplicate result field", "invalid scalar",
			"extra envelope field", "unknown status", "error on success"} {
			t.Run(operation+"/"+damage, func(t *testing.T) {
				store, _ := testStore(t)
				var input any = issueInput()
				if operation == "revoke" {
					input = revokeInput()
				}
				original := makeRequest(t, operation, 1, input)
				if execute(t, store, original).Status != "succeeded" {
					t.Fatal("initial receipt failed")
				}
				err := store.db.Update(func(tx *bolt.Tx) error {
					bucket := tx.Bucket(operationsBucket)
					raw := append([]byte(nil), bucket.Get([]byte(original.OperationID))...)
					switch damage {
					case "extra result field":
						raw = bytes.Replace(raw, []byte(`"result":{`), []byte(`"result":{"material":"`+secret+`",`), 1)
					case "duplicate result field":
						raw = bytes.Replace(raw, []byte(`"access_subject_id":"11"`),
							[]byte(`"access_subject_id":"11","access_subject_id":"11"`), 1)
					case "invalid scalar":
						raw = bytes.Replace(raw, []byte(`"access_subject_id":"11"`),
							[]byte(`"access_subject_id":"`+secret+`"`), 1)
					case "extra envelope field":
						raw = append([]byte(`{"credential":"`+secret+`",`), raw[1:]...)
					case "unknown status":
						raw = bytes.Replace(raw, []byte(`"status":"succeeded"`),
							[]byte(`"status":"`+secret+`"`), 1)
					case "error on success":
						raw = bytes.Replace(raw, []byte(`"error":null`),
							[]byte(`"error":{"code":"`+secret+`","retryable":false}`), 1)
					}
					return bucket.Put([]byte(original.OperationID), raw)
				})
				if err != nil {
					t.Fatal(err)
				}
				assertCorruptReceiptRefused(t, store, original, secret)
			})
		}
	}
}

func TestCorruptStoredRejectionCannotExportMaterial(t *testing.T) {
	secret := "PRIVATE_MATERIAL_MUST_NOT_ESCAPE"
	for _, damage := range []string{"extra error field", "unknown error code", "wrong retryable type", "result on rejection"} {
		t.Run(damage, func(t *testing.T) {
			store, _ := testStore(t)
			execute(t, store, makeRequest(t, "revoke", 1, revokeInput()))
			original := makeRequest(t, "issue", 2, issueInput())
			assertCode(t, execute(t, store, original), "SUBJECT_REVOKED")
			err := store.db.Update(func(tx *bolt.Tx) error {
				bucket := tx.Bucket(operationsBucket)
				raw := append([]byte(nil), bucket.Get([]byte(original.OperationID))...)
				switch damage {
				case "extra error field":
					raw = bytes.Replace(raw, []byte(`"error":{`), []byte(`"error":{"credential":"`+secret+`",`), 1)
				case "unknown error code":
					raw = bytes.Replace(raw, []byte(`"code":"SUBJECT_REVOKED"`), []byte(`"code":"`+secret+`"`), 1)
				case "wrong retryable type":
					raw = bytes.Replace(raw, []byte(`"retryable":false`), []byte(`"retryable":null`), 1)
				case "result on rejection":
					raw = bytes.Replace(raw, []byte(`"result":null`), []byte(`"result":{"material":"`+secret+`"}`), 1)
				}
				return bucket.Put([]byte(original.OperationID), raw)
			})
			if err != nil {
				t.Fatal(err)
			}
			assertCorruptReceiptRefused(t, store, original, secret)
		})
	}
}

func TestReceiptAndIdempotencyIndexMustRemainConsistent(t *testing.T) {
	for _, damage := range []string{"missing key", "missing operation", "wrong key owner", "wrong receipt key"} {
		t.Run(damage, func(t *testing.T) {
			store, _ := testStore(t)
			original := makeRequest(t, "issue", 1, issueInput())
			if execute(t, store, original).Status != "succeeded" {
				t.Fatal("initial receipt failed")
			}
			err := store.db.Update(func(tx *bolt.Tx) error {
				keys, operations := tx.Bucket(keysBucket), tx.Bucket(operationsBucket)
				switch damage {
				case "missing key":
					return keys.Delete([]byte(original.IdempotencyKey))
				case "missing operation":
					return operations.Delete([]byte(original.OperationID))
				case "wrong key owner":
					return keys.Put([]byte(original.IdempotencyKey), []byte("cp_99999999999999999999999999999999"))
				default:
					raw := bytes.Replace(operations.Get([]byte(original.OperationID)),
						[]byte(`"idempotency_key":"key-1"`), []byte(`"idempotency_key":"different-key"`), 1)
					return operations.Put([]byte(original.OperationID), raw)
				}
			})
			if err != nil {
				t.Fatal(err)
			}
			assertCorruptReceiptRefused(t, store, original, "must-not-escape")
		})
	}
}

func TestMalformedClosedWireRequestsAreRejected(t *testing.T) {
	valid, _ := json.Marshal(makeRequest(t, "issue", 1, issueInput()))
	cases := map[string][]byte{
		"duplicate envelope": bytes.Replace(valid, []byte(`"operation":"issue"`), []byte(`"operation":"issue","operation":"issue"`), 1),
		"duplicate input":    bytes.Replace(valid, []byte(`"terms_id":"13"`), []byte(`"terms_id":"13","terms_id":"13"`), 1),
		"unknown envelope":   append([]byte(`{"password":"must-not-leak",`), valid[1:]...),
		"unknown input":      bytes.Replace(valid, []byte(`"terms_id":"13"`), []byte(`"terms_id":"13","credential":"must-not-leak"`), 1),
		"noncanonical id":    bytes.Replace(valid, []byte(`"terms_id":"13"`), []byte(`"terms_id":"013"`), 1),
		"overflow id":        bytes.Replace(valid, []byte(`"terms_id":"13"`), []byte(`"terms_id":"9223372036854775808"`), 1),
		"number id":          bytes.Replace(valid, []byte(`"terms_id":"13"`), []byte(`"terms_id":13`), 1),
		"null field":         bytes.Replace(valid, []byte(`"terms_id":"13"`), []byte(`"terms_id":null`), 1),
		"wrong type":         bytes.Replace(valid, []byte(`"input":{`), []byte(`"input":[{`), 1),
		"escaped key":        bytes.Replace(valid, []byte(`"terms_id":"13"`), []byte(`"terms_id":"13","terms_\u0069d":"13"`), 1),
		"trailing value":     append(append([]byte{}, valid...), []byte(`{}`)...),
		"oversize":           bytes.Repeat([]byte(" "), MaxMessageBytes+1),
		"array":              []byte(`[]`),
		"empty":              []byte{},
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseRequest(raw, time.Now()); err == nil {
				t.Fatal("malformed request accepted")
			}
		})
	}
}

func TestLifetimeDeadlineHashIdentityAndCanceledRequestsFailClosed(t *testing.T) {
	store, _ := testStore(t)
	valid := makeRequest(t, "issue", 1, issueInput())
	for _, deadline := range []int64{time.Now().Unix(), time.Now().Unix() - 1, time.Now().Unix() + 31} {
		req := valid
		req.DeadlineAt = deadline
		raw, _ := json.Marshal(req)
		if _, err := parseRequest(raw, time.Now()); err == nil || err.Error() != "DEADLINE_REJECTED" {
			t.Fatal("invalid deadline accepted")
		}
	}
	req := valid
	req.InputHash = strings.Repeat("0", 64)
	raw, _ := json.Marshal(req)
	if _, err := parseRequest(raw, time.Now()); err == nil || err.Error() != "INPUT_HASH_MISMATCH" {
		t.Fatal("hash mismatch accepted")
	}
	req = valid
	req.ProviderInstanceEpoch = "2"
	assertCode(t, execute(t, store, rehash(t, req)), "PROVIDER_IDENTITY_MISMATCH")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assertCode(t, store.execute(ctx, valid, time.Now()), "DEADLINE_REJECTED")
	query := execute(t, store, queryRequest(t, valid))
	assertCode(t, query, "OPERATION_UNKNOWN")
	input := issueInput()
	input.CredentialExpiresAt = input.NotBeforeAt + 31*24*60*60 + 1
	raw, _ = json.Marshal(makeRequest(t, "issue", 2, input))
	if _, err := parseRequest(raw, time.Now()); err == nil {
		t.Fatal("overlong lifetime accepted")
	}
	input = issueInput()
	input.NotBeforeAt, input.CredentialExpiresAt = time.Now().Unix()-3600, time.Now().Unix()-1
	assertCode(t, execute(t, store, makeRequest(t, "issue", 3, input)), "CREDENTIAL_EXPIRED")
}

func TestQueuedWriteRechecksDeadlineAndCredentialExpiry(t *testing.T) {
	for _, scenario := range []string{"deadline", "credential expiry"} {
		t.Run(scenario, func(t *testing.T) {
			store, _ := testStore(t)
			boundary := time.Now().Unix() + 1
			input := issueInput()
			if scenario == "credential expiry" {
				input.CredentialExpiresAt = boundary
			}
			req := makeRequest(t, "issue", 1, input)
			if scenario == "deadline" {
				req.DeadlineAt = boundary
			}
			blocker, err := store.db.Begin(true)
			if err != nil {
				t.Fatal(err)
			}
			result := make(chan Response, 1)
			go func() { result <- store.execute(context.Background(), req, time.Now()) }()
			time.Sleep(time.Until(time.Unix(boundary, 0)) + 20*time.Millisecond)
			if err := blocker.Rollback(); err != nil {
				t.Fatal(err)
			}
			want := "CREDENTIAL_EXPIRED"
			if scenario == "deadline" {
				want = "DEADLINE_REJECTED"
			}
			assertCode(t, <-result, want)
			store.db.View(func(tx *bolt.Tx) error {
				if tx.Bucket(subjectsBucket).Stats().KeyN != 0 {
					t.Error("queued expired operation created credential state")
				}
				return nil
			})
		})
	}
}

type tlsFixture struct {
	config Config
	client *http.Client
	wrong  *http.Client
	noCert *http.Client
	tls12  *http.Client
}

func makeTLSFixture(t *testing.T) tlsFixture {
	t.Helper()
	dir := t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Provider test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	issueCertificate := func(name string, serial int64, usage x509.ExtKeyUsage) (tls.Certificate, string, string, string) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		certPath, keyPath := filepath.Join(dir, name+".pem"), filepath.Join(dir, name+".key")
		if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
			t.Fatal(err)
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(der)
		return cert, certPath, keyPath, hex.EncodeToString(digest[:])
	}
	_, serverCert, serverKey, _ := issueCertificate("provider", 2, x509.ExtKeyUsageServerAuth)
	clientCert, _, _, fingerprint := issueCertificate("core", 3, x509.ExtKeyUsageClientAuth)
	wrongCert, _, _, _ := issueCertificate("other-core", 4, x509.ExtKeyUsageClientAuth)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	client := func(certs []tls.Certificate, version uint16) *http.Client {
		transport := &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: roots, Certificates: certs, MinVersion: version, MaxVersion: version,
		}}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: 5 * time.Second}
	}
	return tlsFixture{
		config: Config{
			Listen: "127.0.0.1:0", StorePath: filepath.Join(dir, "private", "provider.db"),
			ProviderID: "provider-a", Epoch: "1", TLSCert: serverCert, TLSKey: serverKey,
			ClientCA: caPath, ClientFingerprints: []string{fingerprint},
		},
		client: client([]tls.Certificate{clientCert}, tls.VersionTLS13),
		wrong:  client([]tls.Certificate{wrongCert}, tls.VersionTLS13),
		noCert: client(nil, tls.VersionTLS13), tls12: client([]tls.Certificate{clientCert}, tls.VersionTLS12),
	}
}

func runServer(t *testing.T, fixture tlsFixture) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	address := make(chan string, 1)
	go func() {
		result <- Run(ctx, fixture.config, func(addr net.Addr) { address <- addr.String() })
	}()
	select {
	case err := <-result:
		cancel()
		t.Fatalf("start: %v", err)
	case addr := <-address:
		t.Cleanup(func() {
			cancel()
			if err := <-result; err != nil {
				t.Errorf("shutdown: %v", err)
			}
		})
		return "https://" + addr
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("provider startup timed out")
	}
	return ""
}

func TestRealTLSRequiresVerifiedAllowlistedCertificateAndTLS13(t *testing.T) {
	fixture := makeTLSFixture(t)
	endpoint := runServer(t, fixture) + "/operations"
	body, _ := json.Marshal(makeRequest(t, "issue", 1, issueInput()))
	for name, client := range map[string]*http.Client{
		"wrong fingerprint": fixture.wrong, "missing certificate": fixture.noCert, "tls12": fixture.tls12,
	} {
		t.Run(name, func(t *testing.T) {
			if response, err := client.Post(endpoint, "application/json", bytes.NewReader(body)); err == nil {
				response.Body.Close()
				t.Fatal("unauthorized TLS connection succeeded")
			}
		})
	}
	response, err := fixture.client.Post(endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result Response
	if json.NewDecoder(response.Body).Decode(&result) != nil || result.Status != "succeeded" {
		t.Fatal("authenticated provider request failed")
	}
}

func TestHTTPBoundsAndDiagnosticResponsesNeverEchoInput(t *testing.T) {
	fixture := makeTLSFixture(t)
	endpoint := runServer(t, fixture)
	valid, _ := json.Marshal(makeRequest(t, "issue", 1, issueInput()))
	for name, tc := range map[string]struct {
		path   string
		method string
		body   []byte
		status int
	}{
		"material route": {"/material", "POST", valid, 404},
		"query string":   {"/operations?credential=must-not-leak", "POST", valid, 404},
		"wrong method":   {"/operations", "GET", nil, 405},
		"malformed":      {"/operations", "POST", []byte(`{"password":"must-not-leak",`), 400},
		"duplicate":      {"/operations", "POST", bytes.Replace(valid, []byte(`"terms_id":"13"`), []byte(`"terms_id":"13","terms_id":"must-not-leak"`), 1), 400},
		"oversize":       {"/operations", "POST", bytes.Repeat([]byte("X"), MaxMessageBytes+1), 413},
	} {
		t.Run(name, func(t *testing.T) {
			req, _ := http.NewRequest(tc.method, endpoint+tc.path, bytes.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			response, err := fixture.client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, _ := io.ReadAll(response.Body)
			if response.StatusCode != tc.status || len(body) > MaxMessageBytes ||
				bytes.Contains(body, []byte("must-not-leak")) || bytes.Contains(body, []byte("password")) {
				t.Fatal("bounded rejection or diagnostic secrecy failed")
			}
		})
	}
}
