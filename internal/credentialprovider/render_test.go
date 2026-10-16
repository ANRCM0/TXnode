package credentialprovider

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/credentialdelivery"
)

func TestRealPublicRenderListenerRequiresClientProofAndNeverExposesControlRoutes(t *testing.T) {
	fixture := makeTLSFixture(t)
	trust, core := deliveryKey(t)
	nodeDER := fixture.wrong.Transport.(*http.Transport).TLSClientConfig.Certificates[0].Certificate[0]
	nodeHash := sha256.Sum256(nodeDER)
	fixture.config.NodeClientFingerprints = []string{hex.EncodeToString(nodeHash[:])}
	fixture.config.DeliveryTrust = filepath.Join(t.TempDir(), "trust.json")
	trustRaw, _ := json.Marshal(trust)
	if err := os.WriteFile(fixture.config.DeliveryTrust, trustRaw, 0600); err != nil {
		t.Fatal(err)
	}
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture.config.SubscriptionListen = reservation.Addr().String()
	reservation.Close()
	fixture.config.SubscriptionTLSCert, fixture.config.SubscriptionTLSKey = fixture.config.TLSCert, fixture.config.TLSKey
	controlURL := runServer(t, fixture)
	publicURL := "https://" + fixture.config.SubscriptionListen
	post := func(client *http.Client, url string, value any, status int, target any) []byte {
		t.Helper()
		raw, _ := json.Marshal(value)
		response, err := client.Post(url, "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != status || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("unexpected render/control status %d (wanted %d)", response.StatusCode, status)
		}
		if target != nil && json.Unmarshal(body, target) != nil {
			t.Fatal("invalid response DTO")
		}
		return body
	}
	capabilityRequest := CapabilityRequest{CapabilitiesContractVersion, "render-capability-1", "provider-a", "1"}
	var capabilities CapabilityResponse
	post(fixture.client, controlURL+"/capabilities", capabilityRequest, 200, &capabilities)
	if !capabilities.NodeDelivery || !capabilities.SubscriptionRender || capabilities.StoreVersion != 2 {
		t.Fatal("capability flags do not describe the enabled public listener")
	}
	post(fixture.wrong, controlURL+"/capabilities", capabilityRequest, 403, nil)
	post(fixture.noCert, publicURL+"/capabilities", capabilityRequest, 404, nil)
	var issued Response
	post(fixture.client, controlURL+"/operations", makeRequest(t, "issue", 1, issueInput()), 200, &issued)
	var receipt IssueResult
	if json.Unmarshal(issued.Result, &receipt) != nil {
		t.Fatal("issue failed")
	}
	var metadata credentialdelivery.MetadataResponse
	post(fixture.client, controlURL+"/credential-metadata", metadataRequest(receipt), 200, &metadata)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	payload := credentialdelivery.RenderPayload{ProtocolVersion: 1, PolicyVersion: credentialdelivery.RenderPolicyVersion,
		Audience: credentialdelivery.RenderAudience, CoreInstanceID: trust.CoreInstanceID, KeyID: trust.KeyID, KeyEpoch: trust.KeyEpoch,
		IssuedAt: now, NotBefore: now - 5, ExpiresAt: now + 30, GrantID: "render_" + strings.Repeat("1", 32),
		ProviderID: "provider-a", ProviderInstanceEpoch: "1", RecipientPublicKey: base64.RawURLEncoding.EncodeToString(public),
		FormatID: credentialdelivery.RenderFormat, UserID: "9", Subject: metadataRequest(receipt).Subjects[0],
		CredentialSHA256: metadata.Credentials[0].CredentialSHA256, CredentialExpiresAt: receipt.CredentialExpiresAt,
		Nodes: []credentialdelivery.ConnectionNode{{NodeID: "5", Name: "test connection", Protocol: "vless", Host: "127.0.0.1", Port: 443, Transport: "tcp"}}}
	raw, _ := json.Marshal(payload)
	hash := sha256.Sum256(raw)
	request := credentialdelivery.RenderRequest{ContractVersion: credentialdelivery.RenderContractVersion, RequestID: "render-request-1",
		Authorization: credentialdelivery.Envelope{Payload: base64.RawURLEncoding.EncodeToString(raw),
			Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(core, raw))}}
	request.Proof = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private,
		credentialdelivery.RenderProofMessage(request.RequestID, hex.EncodeToString(hash[:]))))
	var delivered credentialdelivery.RenderResponse
	post(fixture.noCert, publicURL+"/subscription-render", request, 200, &delivered)
	if len(delivered.Connections) != 1 || !credentialdelivery.ValidUUID(delivered.Connections[0].UUID) ||
		delivered.AuthorizationDigest != hex.EncodeToString(hash[:]) {
		t.Fatal("typed connection bundle invalid")
	}
	gotHash := sha256.Sum256([]byte(delivered.Connections[0].UUID))
	if hex.EncodeToString(gotHash[:]) != payload.CredentialSHA256 {
		t.Fatal("rendered material is not committed credential")
	}
	withoutProof := request
	withoutProof.Proof = ""
	post(fixture.noCert, publicURL+"/subscription-render", withoutProof, 403, nil)
	post(fixture.client, controlURL+"/subscription-render", request, 404, nil)
	post(fixture.noCert, publicURL+"/operations", request, 404, nil)
	post(fixture.noCert, publicURL+"/credentials", request, 404, nil)
	post(fixture.client, controlURL+"/operations", makeRequest(t, "rotate", 2, rotateInput(receipt)), 200, nil)
	body := post(fixture.noCert, publicURL+"/subscription-render", request, 409, nil)
	if bytes.Contains(body, []byte(delivered.Connections[0].UUID)) {
		t.Fatal("retired generation leaked")
	}
}
