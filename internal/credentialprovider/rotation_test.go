package credentialprovider

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	bolt "github.com/sagernet/bbolt"
)

func rotateInput(receipt IssueResult) RotateInput {
	input := issueInput()
	return RotateInput{InstallationID: input.InstallationID, AccessSubjectID: input.AccessSubjectID,
		SubscriptionID: input.SubscriptionID, TermsID: "14", ProviderSubjectRef: input.ProviderSubjectRef,
		ExpectedSubjectVersion: "3", CredentialProfileID: input.CredentialProfileID,
		CredentialRef: receipt.CredentialRef, ExpectedCredentialGeneration: receipt.CredentialGeneration,
		RotationMode: "immediate", NotBeforeAt: time.Now().Unix(), CredentialExpiresAt: time.Now().Unix() + 3600}
}

func TestRotatePreservesHistoricalReceiptsAndPermanentlyRetiresOldGeneration(t *testing.T) {
	store, path := testStore(t)
	issued := issueForDelivery(t, store)
	old := privateFor(t, store).Credential
	req := makeRequest(t, "rotate", 2, rotateInput(issued))
	response := execute(t, store, req)
	var rotated RotateResult
	if response.Status != "succeeded" || json.Unmarshal(response.Result, &rotated) != nil ||
		rotated.CredentialGeneration != "2" || rotated.PreviousGeneration != "1" ||
		rotated.PreviousCredentialRef != issued.CredentialRef || rotated.PreviousValidUntil != rotated.IssuedAt ||
		rotated.CredentialRef == issued.CredentialRef {
		t.Fatal("rotation did not produce an exact successor")
	}
	current := privateFor(t, store)
	if current.Credential == old || current.TermsID != "14" {
		t.Fatal("rotation retained old material or terms")
	}
	if result, err := store.metadata(metadataRequest(issued), time.Now()); err == nil || result != nil {
		t.Fatal("old generation still delivered")
	}
	metadataReq := metadataRequest(rotated.current())
	metadataReq.Subjects[0].TermsID = "14"
	if _, err := store.metadata(metadataReq, time.Now()); err != nil {
		t.Fatal("current generation unavailable")
	}
	replay := execute(t, store, req)
	if !bytes.Equal(replay.Result, response.Result) || privateFor(t, store).Credential != current.Credential {
		t.Fatal("retry rotated again")
	}
	query := execute(t, store, queryRequest(t, req))
	if query.Status != "succeeded" || bytes.Contains(query.Result, []byte(current.Credential)) {
		t.Fatal("query lost receipt or leaked material")
	}
	if err := store.db.View(func(tx *bolt.Tx) error {
		evidence, err := readGenerationEvidence(tx, issued.ProviderSubjectRef, "1")
		if err != nil || evidence.RetiredAt == nil || evidence.SuccessorGeneration == nil || *evidence.SuccessorGeneration != "2" {
			t.Error("old generation lacks durable retirement")
		}
		if string(tx.Bucket(metadataBucket).Get([]byte("identity"))) != "native-provider-store/2:provider-a:1" {
			t.Error("old writer could open new schema")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	store.Close()
	reopened, err := OpenStore(path, "provider-a", "1")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.metadata(metadataReq, time.Now()); err != nil {
		t.Fatal("rotation evidence lost across restart")
	}
	nextInput := rotateInput(rotated.current())
	nextInput.ExpectedSubjectVersion = "5"
	next := execute(t, reopened, makeRequest(t, "rotate", 3, nextInput))
	if next.Status != "succeeded" {
		t.Fatal("second rotation failed")
	}
	oldReplay := execute(t, reopened, req)
	if !bytes.Equal(oldReplay.Result, response.Result) {
		t.Fatal("historical rotation receipt changed")
	}
	if result, err := reopened.metadata(metadataReq, time.Now()); err == nil || result != nil {
		t.Fatal("second rotation revived predecessor")
	}
	stale := execute(t, reopened, makeRequest(t, "rotate", 4, rotateInput(issued)))
	assertCode(t, stale, "GENERATION_CONFLICT")
	if execute(t, reopened, makeRequest(t, "revoke", 5, revokeInput())).Status != "succeeded" {
		t.Fatal("revoke failed")
	}
	assertCode(t, execute(t, reopened, makeRequest(t, "rotate", 6, nextInput)), "SUBJECT_REVOKED")
}

func TestRotateCanReplaceAnExpiredCredentialWithoutRevivingOldMaterial(t *testing.T) {
	store, _ := testStore(t)
	input := issueInput()
	input.CredentialExpiresAt = time.Now().Unix() + 2
	response := execute(t, store, makeRequest(t, "issue", 1, input))
	var issued IssueResult
	if response.Status != "succeeded" || json.Unmarshal(response.Result, &issued) != nil {
		t.Fatal("fixture issue failed")
	}
	time.Sleep(time.Until(time.Unix(input.CredentialExpiresAt, 0)) + 10*time.Millisecond)
	if _, err := store.metadata(metadataRequest(issued), time.Now()); err == nil {
		t.Fatal("expired generation was delivered")
	}
	response = execute(t, store, makeRequest(t, "rotate", 2, rotateInput(issued)))
	if response.Status != "succeeded" {
		t.Fatal("control rotation of expired credential refused")
	}
}
