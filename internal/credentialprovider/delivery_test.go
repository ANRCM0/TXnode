package credentialprovider

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/credentialdelivery"
	"github.com/ANRCM0/TX-Node/internal/panel"
	bolt "github.com/sagernet/bbolt"
)

func metadataRequest(receipt IssueResult) credentialdelivery.MetadataRequest {
	input := issueInput()
	return credentialdelivery.MetadataRequest{
		ContractVersion: credentialdelivery.ContractVersion, RequestID: "metadata-1",
		ProviderID: "provider-a", ProviderInstanceEpoch: "1",
		Subjects: []credentialdelivery.MetadataSubject{{
			InstallationID: input.InstallationID, AccessSubjectID: input.AccessSubjectID,
			SubscriptionID: input.SubscriptionID, TermsID: input.TermsID, ProviderSubjectRef: input.ProviderSubjectRef,
			CredentialRef: receipt.CredentialRef, CredentialGeneration: receipt.CredentialGeneration,
			CredentialProfileID: input.CredentialProfileID,
		}},
	}
}

func deliveryKey(t *testing.T) (credentialdelivery.Trust, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return credentialdelivery.Trust{
		ProtocolVersion: 1, CoreInstanceID: issueInput().InstallationID,
		KeyID: "core-key", KeyEpoch: "1", Algorithm: "Ed25519",
		PublicKey: base64.RawURLEncoding.EncodeToString(public),
	}, private
}

func deliveryPayload(receipt IssueResult, commitment, recipient string, trust credentialdelivery.Trust) credentialdelivery.Payload {
	now := time.Now().Unix()
	input := issueInput()
	return credentialdelivery.Payload{
		ProtocolVersion: 1, Audience: credentialdelivery.Audience, PolicyVersion: credentialdelivery.PolicyVersion,
		CoreInstanceID: trust.CoreInstanceID, NodeID: 5, Revision: "1",
		KeyID: trust.KeyID, KeyEpoch: trust.KeyEpoch, IssuedAt: now, NotBefore: now, ExpiresAt: now + 60,
		Complete: true, Users: []panel.User{{ID: 9, UUID: "sha256:" + commitment}},
		Provider: credentialdelivery.ProviderBinding{
			InstallationID: input.InstallationID, ProviderID: "provider-a", ProviderInstanceEpoch: "1",
			RecipientSHA256: recipient, CredentialProfileID: input.CredentialProfileID,
			Subjects: []credentialdelivery.Subject{{
				UserID: 9, AccessSubjectID: input.AccessSubjectID, SubscriptionID: input.SubscriptionID, TermsID: input.TermsID,
				ProviderSubjectRef: input.ProviderSubjectRef, CredentialRef: receipt.CredentialRef,
				CredentialGeneration: receipt.CredentialGeneration, CredentialExpiresAt: receipt.CredentialExpiresAt,
			}},
		},
	}
}

func deliveryEnvelope(t *testing.T, payload credentialdelivery.Payload, key ed25519.PrivateKey) credentialdelivery.Envelope {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return credentialdelivery.Envelope{
		Payload:   base64.RawURLEncoding.EncodeToString(raw),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, raw)),
	}
}

func issueForDelivery(t *testing.T, store *Store) IssueResult {
	t.Helper()
	result := execute(t, store, makeRequest(t, "issue", 1, issueInput()))
	var receipt IssueResult
	if result.Status != "succeeded" || json.Unmarshal(result.Result, &receipt) != nil {
		t.Fatal("fixture issuance failed")
	}
	return receipt
}

func TestMetadataAndMaterialRequireCurrentIntactPrivateIssuance(t *testing.T) {
	store, _ := testStore(t)
	receipt := issueForDelivery(t, store)
	req := metadataRequest(receipt)
	metadata, err := store.metadata(req, time.Now())
	if err != nil || len(metadata.Credentials) != 1 {
		t.Fatalf("metadata rejected: %v", err)
	}
	private := privateFor(t, store)
	hash := sha256.Sum256([]byte(private.Credential))
	if metadata.Credentials[0].CredentialSHA256 != hex.EncodeToString(hash[:]) {
		t.Fatal("metadata commitment differs from actual private material")
	}
	raw, _ := json.Marshal(metadata)
	if bytes.Contains(raw, []byte(private.Credential)) {
		t.Fatal("metadata leaked UUID")
	}
	trust, key := deliveryKey(t)
	peer := strings.Repeat("a", 64)
	payload := deliveryPayload(receipt, metadata.Credentials[0].CredentialSHA256, peer, trust)
	grant, err := credentialdelivery.VerifyGrant(deliveryEnvelope(t, payload, key), trust, time.Now(), 0)
	if err != nil {
		t.Fatal(err)
	}
	material, err := store.material(grant, "request-1", peer, time.Now())
	if err != nil || material.Credentials[0].UUID != private.Credential || material.AuthorizationDigest != grant.Digest {
		t.Fatalf("material rejected or rebound: %v", err)
	}
	if _, err := store.material(grant, "request-1", strings.Repeat("b", 64), time.Now()); err == nil {
		t.Fatal("wrong TLS recipient accepted")
	}
	payload.Users[0].UUID = "sha256:" + strings.Repeat("c", 64)
	wrong, _ := credentialdelivery.VerifyGrant(deliveryEnvelope(t, payload, key), trust, time.Now(), 0)
	if _, err := store.material(wrong, "request-2", peer, time.Now()); err == nil {
		t.Fatal("wrong signed commitment accepted")
	}
	revoke := execute(t, store, makeRequest(t, "revoke", 2, revokeInput()))
	if revoke.Status != "succeeded" {
		t.Fatal("fixture revoke failed")
	}
	if result, err := store.metadata(req, time.Now()); err == nil || result != nil {
		t.Fatal("revoked metadata returned")
	}
	if result, err := store.material(grant, "request-1", peer, time.Now()); err == nil || result != nil {
		t.Fatal("valid old snapshot bypassed current tombstone")
	}
}

func TestMetadataAndMaterialRejectPartialAndExpiredBindings(t *testing.T) {
	store, _ := testStore(t)
	receipt := issueForDelivery(t, store)
	req := metadataRequest(receipt)
	req.Subjects = append(req.Subjects, req.Subjects[0])
	req.Subjects[1].AccessSubjectID, req.Subjects[1].ProviderSubjectRef = "22", "subject_"+strings.Repeat("2", 32)
	req.Subjects[1].CredentialRef = "credential_" + strings.Repeat("3", 32)
	if result, err := store.metadata(req, time.Now()); err == nil || result != nil {
		t.Fatal("partial metadata succeeded")
	}
	req.Subjects = req.Subjects[:1]
	if result, err := store.metadata(req, time.Unix(receipt.CredentialExpiresAt, 0)); err == nil || result != nil {
		t.Fatal("expired credential returned")
	}
	for name, modify := range map[string]func(*credentialdelivery.MetadataRequest){
		"wrong epoch":        func(r *credentialdelivery.MetadataRequest) { r.ProviderInstanceEpoch = "2" },
		"wrong terms":        func(r *credentialdelivery.MetadataRequest) { r.Subjects[0].TermsID = "14" },
		"wrong subscription": func(r *credentialdelivery.MetadataRequest) { r.Subjects[0].SubscriptionID = "14" },
		"wrong generation":   func(r *credentialdelivery.MetadataRequest) { r.Subjects[0].CredentialGeneration = "2" },
		"wrong profile":      func(r *credentialdelivery.MetadataRequest) { r.Subjects[0].CredentialProfileID = "vmess-uuid/v1" },
	} {
		t.Run(name, func(t *testing.T) {
			r := metadataRequest(receipt)
			modify(&r)
			if result, err := store.metadata(r, time.Now()); err == nil || result != nil {
				t.Fatal("mismatched metadata succeeded")
			}
		})
	}
}

func TestDeliveryRejectsCorruptPrivateStateAndReceiptsWithoutLeaking(t *testing.T) {
	for name, corrupt := range map[string]func(*bolt.Tx) error{
		"extra private field": func(tx *bolt.Tx) error {
			b := tx.Bucket(subjectsBucket)
			ref := []byte(issueInput().ProviderSubjectRef)
			raw := append([]byte{}, b.Get(ref)...)
			raw = append(raw[:len(raw)-1], []byte(`,"extra_secret":"must-not-leak"}`)...)
			return b.Put(ref, raw)
		},
		"extra receipt field": func(tx *bolt.Tx) error {
			b := tx.Bucket(operationsBucket)
			ref := []byte("cp_00000000000000000000000000000001")
			raw := bytes.Replace(b.Get(ref), []byte(`"credential_generation":"1"`), []byte(`"credential_generation":"1","secret":"must-not-leak"`), 1)
			return b.Put(ref, raw)
		},
		"missing evidence": func(tx *bolt.Tx) error {
			return tx.Bucket(issueEvidenceBucket).Delete([]byte(issueInput().ProviderSubjectRef))
		},
		"missing key index": func(tx *bolt.Tx) error { return tx.Bucket(keysBucket).Delete([]byte("key-1")) },
		"wrong subject index": func(tx *bolt.Tx) error {
			return tx.Bucket(subjectIDsBucket).Put([]byte(issueInput().InstallationID+":11"), []byte("subject_"+strings.Repeat("2", 32)))
		},
		"wrong original hash": func(tx *bolt.Tx) error {
			b := tx.Bucket(operationsBucket)
			ref := []byte("cp_00000000000000000000000000000001")
			var record storedOperation
			json.Unmarshal(b.Get(ref), &record)
			record.InputHash = strings.Repeat("a", 64)
			raw, _ := json.Marshal(record)
			return b.Put(ref, raw)
		},
		"non v4 material": func(tx *bolt.Tx) error {
			b := tx.Bucket(subjectsBucket)
			ref := []byte(issueInput().ProviderSubjectRef)
			var record privateSubject
			json.Unmarshal(b.Get(ref), &record)
			record.Credential = "11111111-1111-1111-8111-111111111111"
			raw, _ := json.Marshal(record)
			return b.Put(ref, raw)
		},
	} {
		t.Run(name, func(t *testing.T) {
			store, _ := testStore(t)
			receipt := issueForDelivery(t, store)
			if err := store.db.Update(corrupt); err != nil {
				t.Fatal(err)
			}
			if response, err := store.metadata(metadataRequest(receipt), time.Now()); err == nil || response != nil ||
				strings.Contains(err.Error(), "must-not-leak") {
				t.Fatal("corruption became metadata or a secret diagnostic")
			}
		})
	}
}

func TestC1StoreBackfillIsAtomicIdempotentAndPreservesRecords(t *testing.T) {
	store, path := testStore(t)
	receipt := issueForDelivery(t, store)
	var subjectBefore, operationBefore []byte
	if err := store.db.Update(func(tx *bolt.Tx) error {
		subjectBefore = append([]byte{}, tx.Bucket(subjectsBucket).Get([]byte(receipt.ProviderSubjectRef))...)
		operationBefore = append([]byte{}, tx.Bucket(operationsBucket).Get([]byte("cp_00000000000000000000000000000001"))...)
		if err := tx.DeleteBucket(issueEvidenceBucket); err != nil {
			return err
		}
		return tx.Bucket(metadataBucket).Delete([]byte("issue_evidence_version"))
	}); err != nil {
		t.Fatal(err)
	}
	store.Close()
	for i := 0; i < 2; i++ {
		upgraded, err := OpenStore(path, "provider-a", "1")
		if err != nil {
			t.Fatalf("C1 migration/restart refused: %v", err)
		}
		if _, err := upgraded.metadata(metadataRequest(receipt), time.Now()); err != nil {
			t.Fatal(err)
		}
		upgraded.db.View(func(tx *bolt.Tx) error {
			if !bytes.Equal(subjectBefore, tx.Bucket(subjectsBucket).Get([]byte(receipt.ProviderSubjectRef))) ||
				!bytes.Equal(operationBefore, tx.Bucket(operationsBucket).Get([]byte("cp_00000000000000000000000000000001"))) {
				t.Error("backfill changed private record or historical receipt")
			}
			return nil
		})
		upgraded.Close()
	}
}

func TestC1BackfillRejectsDamagedEvidenceWithoutPartialMigration(t *testing.T) {
	for _, scenario := range []string{"missing receipt", "conflicting receipt", "private terms changed"} {
		t.Run(scenario, func(t *testing.T) {
			store, path := testStore(t)
			receipt := issueForDelivery(t, store)
			err := store.db.Update(func(tx *bolt.Tx) error {
				if err := tx.DeleteBucket(issueEvidenceBucket); err != nil {
					return err
				}
				if err := tx.Bucket(metadataBucket).Delete([]byte("issue_evidence_version")); err != nil {
					return err
				}
				operations := tx.Bucket(operationsBucket)
				opID := []byte("cp_00000000000000000000000000000001")
				switch scenario {
				case "missing receipt":
					return operations.Delete(opID)
				case "conflicting receipt":
					var duplicate storedOperation
					json.Unmarshal(operations.Get(opID), &duplicate)
					duplicate.IdempotencyKey = "other-key"
					raw, _ := json.Marshal(duplicate)
					id := []byte("cp_00000000000000000000000000000002")
					if err := operations.Put(id, raw); err != nil {
						return err
					}
					return tx.Bucket(keysBucket).Put([]byte("other-key"), id)
				default:
					var subject privateSubject
					b := tx.Bucket(subjectsBucket)
					json.Unmarshal(b.Get([]byte(receipt.ProviderSubjectRef)), &subject)
					subject.TermsID = "99"
					raw, _ := json.Marshal(subject)
					return b.Put([]byte(receipt.ProviderSubjectRef), raw)
				}
			})
			if err != nil {
				t.Fatal(err)
			}
			store.Close()
			upgraded, err := OpenStore(path, "provider-a", "1")
			if err == nil {
				upgraded.Close()
				t.Fatal("damaged C1 evidence accepted")
			}
			db, err := bolt.Open(path, 0600, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			db.View(func(tx *bolt.Tx) error {
				if tx.Bucket(issueEvidenceBucket) != nil || tx.Bucket(metadataBucket).Get([]byte("issue_evidence_version")) != nil {
					t.Error("failed migration left partial index or marker")
				}
				return nil
			})
		})
	}
}

func TestRealTLSDeliverySeparatesRolesAndRejectsStaleGrant(t *testing.T) {
	fixture := makeTLSFixture(t)
	trust, private := deliveryKey(t)
	nodeCertificate := fixture.wrong.Transport.(*http.Transport).TLSClientConfig.Certificates[0].Certificate[0]
	hash := sha256.Sum256(nodeCertificate)
	nodeFingerprint := hex.EncodeToString(hash[:])
	fixture.config.NodeClientFingerprints = []string{nodeFingerprint}
	fixture.config.DeliveryTrust = filepath.Join(t.TempDir(), "trust.json")
	trustRaw, _ := json.Marshal(trust)
	if err := os.WriteFile(fixture.config.DeliveryTrust, trustRaw, 0600); err != nil {
		t.Fatal(err)
	}
	endpoint := runServer(t, fixture)
	post := func(client *http.Client, path string, value any, status int, target any) []byte {
		t.Helper()
		raw, _ := json.Marshal(value)
		response, err := client.Post(endpoint+path, "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != status || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("unexpected response %d, wanted %d", response.StatusCode, status)
		}
		if target != nil && credentialdelivery.DecodeStrict(body, target) != nil {
			t.Fatal("malformed delivery DTO")
		}
		if status != 200 && path != "/operations" {
			var failure struct {
				ErrorCode string `json:"error_code"`
			}
			if credentialdelivery.DecodeStrict(body, &failure) != nil || failure.ErrorCode == "" {
				t.Fatal("unbounded delivery error")
			}
		}
		return body
	}
	issue := makeRequest(t, "issue", 1, issueInput())
	issueBody := post(fixture.client, "/operations", issue, 200, nil)
	var response Response
	json.Unmarshal(issueBody, &response)
	var receipt IssueResult
	if json.Unmarshal(response.Result, &receipt) != nil {
		t.Fatal("real issue failed")
	}
	metadataReq := metadataRequest(receipt)
	var metadata credentialdelivery.MetadataResponse
	metadataBody := post(fixture.client, "/credential-metadata", metadataReq, 200, &metadata)
	post(fixture.wrong, "/credential-metadata", metadataReq, 403, nil)
	post(fixture.wrong, "/operations", issue, 403, nil)
	payload := deliveryPayload(receipt, metadata.Credentials[0].CredentialSHA256, nodeFingerprint, trust)
	payload.NotBefore = payload.IssuedAt - 5
	req := credentialdelivery.MaterialRequest{ContractVersion: credentialdelivery.ContractVersion, RequestID: "delivery-1",
		Authorization: deliveryEnvelope(t, payload, private)}
	post(fixture.client, "/credentials", req, 403, nil)
	var material credentialdelivery.MaterialResponse
	post(fixture.wrong, "/credentials", req, 200, &material)
	if len(material.Credentials) != 1 || !credentialdelivery.ValidUUID(material.Credentials[0].UUID) ||
		bytes.Contains(metadataBody, []byte(material.Credentials[0].UUID)) || bytes.Contains(issueBody, []byte(material.Credentials[0].UUID)) {
		t.Fatal("material invalid or exposed through Core endpoints")
	}
	commitment := sha256.Sum256([]byte(material.Credentials[0].UUID))
	if hex.EncodeToString(commitment[:]) != metadata.Credentials[0].CredentialSHA256 {
		t.Fatal("material and metadata commitments differ")
	}
	wrongRecipient := payload
	wrongRecipient.Provider.RecipientSHA256 = fixture.config.ClientFingerprints[0]
	wrongReq := req
	wrongReq.Authorization = deliveryEnvelope(t, wrongRecipient, private)
	post(fixture.wrong, "/credentials", wrongReq, 409, nil)
	post(fixture.client, "/operations", makeRequest(t, "revoke", 2, revokeInput()), 200, nil)
	denied := post(fixture.wrong, "/credentials", req, 409, nil)
	if bytes.Contains(denied, []byte(material.Credentials[0].UUID)) {
		t.Fatal("revocation error leaked material")
	}
	post(fixture.client, "/credential-metadata", metadataReq, 409, nil)
	payload.Users, payload.Provider.Subjects = []panel.User{}, []credentialdelivery.Subject{}
	req.Authorization = deliveryEnvelope(t, payload, private)
	var empty credentialdelivery.MaterialResponse
	post(fixture.wrong, "/credentials", req, 200, &empty)
	if empty.Credentials == nil || len(empty.Credentials) != 0 {
		t.Fatal("complete empty grant did not return an empty typed array")
	}
	for _, path := range []string{"/credential-metadata", "/credentials"} {
		client := fixture.client
		if path == "/credentials" {
			client = fixture.wrong
		}
		for name, body := range map[string][]byte{
			"oversize":                bytes.Repeat([]byte("X"), credentialdelivery.MaxMessageBytes+1),
			"malformed secret":        []byte(`{"password":"must-not-leak"}`),
			"duplicate request field": []byte(`{"request_id":"a","request_\u0069d":"b"}`),
		} {
			t.Run(path+name, func(t *testing.T) {
				response, err := client.Post(endpoint+path, "application/json", bytes.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				raw, _ := io.ReadAll(response.Body)
				want := http.StatusBadRequest
				if name == "oversize" {
					want = http.StatusRequestEntityTooLarge
				}
				var failure struct {
					ErrorCode string `json:"error_code"`
				}
				if response.StatusCode != want || credentialdelivery.DecodeStrict(raw, &failure) != nil ||
					bytes.Contains(raw, []byte("must-not-leak")) {
					t.Fatal("delivery body limit or bounded diagnostic failed")
				}
			})
		}
	}
}

func TestDeliveryConfigurationRefusesPartialOrOverlappingRoles(t *testing.T) {
	trust, _ := deliveryKey(t)
	store, _ := testStore(t)
	fingerprint := strings.Repeat("a", 64)
	if _, err := NewDeliveryHandler(store, []string{fingerprint}, []string{fingerprint}, trust); err == nil {
		t.Fatal("overlapping control and material identities accepted")
	}
	fixture := makeTLSFixture(t)
	fixture.config.DeliveryTrust = "/unused/public-trust.json"
	if _, err := LoadTLSConfig(fixture.config); err == nil {
		t.Fatal("delivery trust without Node identity accepted")
	}
	fixture.config.DeliveryTrust = ""
	fixture.config.NodeClientFingerprints = []string{strings.Repeat("b", 64)}
	if _, err := LoadTLSConfig(fixture.config); err == nil {
		t.Fatal("Node identity without delivery trust accepted")
	}
}

type deliveryBlockingWriter struct {
	header  http.Header
	writing chan struct{}
	release chan struct{}
}

func (w *deliveryBlockingWriter) Header() http.Header { return w.header }
func (w *deliveryBlockingWriter) WriteHeader(int)     {}
func (w *deliveryBlockingWriter) Write(raw []byte) (int, error) {
	close(w.writing)
	<-w.release
	return len(raw), nil
}

func TestMaterialReleaseSerializesWithLocalRevocation(t *testing.T) {
	store, _ := testStore(t)
	receipt := issueForDelivery(t, store)
	metadata, err := store.metadata(metadataRequest(receipt), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fixture := makeTLSFixture(t)
	der := fixture.wrong.Transport.(*http.Transport).TLSClientConfig.Certificates[0].Certificate[0]
	leaf, _ := x509.ParseCertificate(der)
	digest := sha256.Sum256(der)
	fingerprint := hex.EncodeToString(digest[:])
	trust, key := deliveryKey(t)
	handler, err := NewDeliveryHandler(store, fixture.config.ClientFingerprints, []string{fingerprint}, trust)
	if err != nil {
		t.Fatal(err)
	}
	payload := deliveryPayload(receipt, metadata.Credentials[0].CredentialSHA256, fingerprint, trust)
	wire := credentialdelivery.MaterialRequest{ContractVersion: credentialdelivery.ContractVersion, RequestID: "serialize-1",
		Authorization: deliveryEnvelope(t, payload, key)}
	raw, _ := json.Marshal(wire)
	request := httptest.NewRequest(http.MethodPost, "/credentials", bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains: [][]*x509.Certificate{{leaf}}}
	writer := &deliveryBlockingWriter{header: http.Header{}, writing: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(writer, request)
		close(done)
	}()
	select {
	case <-writer.writing:
	case <-time.After(3 * time.Second):
		t.Fatal("material did not reach release boundary")
	}
	revokeRequest := makeRequest(t, "revoke", 2, revokeInput())
	revoked := make(chan Response, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		revoked <- store.execute(request.Context(), revokeRequest, time.Now())
	}()
	<-started
	select {
	case <-revoked:
		t.Fatal("tombstone committed during an in-progress material release")
	case <-time.After(25 * time.Millisecond):
	}
	close(writer.release)
	<-done
	if result := <-revoked; result.Status != "succeeded" {
		t.Fatal("revocation failed after material release")
	}
	request = httptest.NewRequest(http.MethodPost, "/credentials", bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains: [][]*x509.Certificate{{leaf}}}
	record := httptest.NewRecorder()
	handler.ServeHTTP(record, request)
	if record.Code != http.StatusConflict {
		t.Fatal("material release after committed revocation succeeded")
	}
}
