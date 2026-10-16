package credentialdeliveryclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/credentialdelivery"
	"github.com/ANRCM0/TX-Node/internal/panel"
)

const testUUID = "00112233-4455-4677-8899-aabbccddeeff"

type tlsFixture struct {
	cfg       config.AuthorizationProviderConfig
	env       credentialdelivery.Envelope
	grant     *credentialdelivery.Grant
	server    *httptest.Server
	recipient string
}

func deliveryTLSFixture(t *testing.T, handler http.Handler) tlsFixture {
	t.Helper()
	root := t.TempDir()
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, IsCA: true, BasicConstraintsValid: true}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	cert := func(serial int64, client bool) (tls.Certificate, []byte, []byte) {
		t.Helper()
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "fixture-leaf"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if client {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		} else {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, public, caKey)
		if err != nil {
			t.Fatal(err)
		}
		key, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return pair, certPEM, keyPEM
	}
	serverCert, _, _ := cert(2, false)
	clientCert, clientPEM, keyPEM := cert(3, true)
	hash := sha256.Sum256(clientCert.Certificate[0])
	recipient := hex.EncodeToString(hash[:])
	cfg := config.AuthorizationProviderConfig{ProviderID: "primary-provider", ProviderInstanceEpoch: "1", CAFile: filepath.Join(root, "ca.pem"), ClientCert: filepath.Join(root, "client.pem"), ClientKey: filepath.Join(root, "client.key")}
	for path, data := range map[string][]byte{cfg.CAFile: caPEM, cfg.ClientCert: clientPEM, cfg.ClientKey: keyPEM} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
	server.StartTLS()
	t.Cleanup(server.Close)
	cfg.Endpoint = server.URL
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	trust := credentialdelivery.Trust{ProtocolVersion: 1, CoreInstanceID: "1b32d316-8cb8-4b46-8d49-e281c28d5169", KeyID: "native-key", KeyEpoch: "1", Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}
	material := sha256.Sum256([]byte(testUUID))
	p := credentialdelivery.Payload{ProtocolVersion: 1, Audience: credentialdelivery.Audience, PolicyVersion: credentialdelivery.PolicyVersion, CoreInstanceID: trust.CoreInstanceID, NodeID: 42, Revision: "5", KeyID: trust.KeyID, KeyEpoch: trust.KeyEpoch, IssuedAt: now.Unix(), NotBefore: now.Unix() - 5, ExpiresAt: now.Unix() + 60, Complete: true,
		Users:    []panel.User{{ID: 7, UUID: "sha256:" + hex.EncodeToString(material[:]), SpeedLimit: 23, DeviceLimit: 2, TrafficPeriod: "period-7"}},
		Provider: credentialdelivery.ProviderBinding{InstallationID: trust.CoreInstanceID, ProviderID: cfg.ProviderID, ProviderInstanceEpoch: cfg.ProviderInstanceEpoch, RecipientSHA256: recipient, CredentialProfileID: "vless-uuid/v1", Subjects: []credentialdelivery.Subject{{UserID: 7, AccessSubjectID: "10", SubscriptionID: "11", TermsID: "12", ProviderSubjectRef: "subject_" + strings.Repeat("a", 32), CredentialRef: "credential_" + strings.Repeat("b", 32), CredentialGeneration: "1", CredentialExpiresAt: now.Unix() + 3600}}}}
	raw, _ := json.Marshal(p)
	env := credentialdelivery.Envelope{Payload: base64.RawURLEncoding.EncodeToString(raw), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, raw))}
	grant, err := credentialdelivery.VerifyGrant(env, trust, now, 5)
	if err != nil {
		t.Fatal(err)
	}
	return tlsFixture{cfg: cfg, env: env, grant: grant, server: server, recipient: recipient}
}

func TestDirectMTLSDeliveryValidatesEveryBindingWithoutPolicyChanges(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("https_proxy", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")
	for _, mode := range []string{"valid", "request_id", "digest", "subject", "reference", "generation", "uuid", "non_v4", "uppercase_uuid", "extra", "duplicate", "missing_field", "partial", "oversize", "no_store", "content_type", "secret_error", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			var fixture tlsFixture
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodPost || r.URL.Path != "/credentials" || r.Header.Get("Authorization") != "" || r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.PeerCertificates) != 1 {
					t.Error("unexpected authority or transport")
				}
				if mode == "redirect" {
					http.Redirect(w, r, "/leak", http.StatusTemporaryRedirect)
					return
				}
				if mode == "secret_error" {
					w.WriteHeader(http.StatusConflict)
					io.WriteString(w, testUUID+" private certificate diagnostic")
					return
				}
				raw, _ := io.ReadAll(r.Body)
				var request credentialdelivery.MaterialRequest
				if credentialdelivery.DecodeStrict(raw, &request) != nil || request.Authorization != fixture.env || !credentialdelivery.ValidRequestID(request.RequestID) || request.ContractVersion != credentialdelivery.ContractVersion {
					t.Error("invalid delivery request")
				}
				response := credentialdelivery.MaterialResponse{ContractVersion: credentialdelivery.ContractVersion, RequestID: request.RequestID, AuthorizationDigest: fixture.grant.Digest, Credentials: []credentialdelivery.MaterialCredential{{AccessSubjectID: "10", CredentialRef: "credential_" + strings.Repeat("b", 32), CredentialGeneration: "1", UUID: testUUID}}}
				switch mode {
				case "request_id":
					response.RequestID = "different"
				case "digest":
					response.AuthorizationDigest = strings.Repeat("c", 64)
				case "subject":
					response.Credentials[0].AccessSubjectID = "11"
				case "reference":
					response.Credentials[0].CredentialRef = "credential_" + strings.Repeat("c", 32)
				case "generation":
					response.Credentials[0].CredentialGeneration = "2"
				case "uuid":
					response.Credentials[0].UUID = "10112233-4455-4677-8899-aabbccddeeff"
				case "non_v4":
					response.Credentials[0].UUID = "00112233-4455-6677-8899-aabbccddeeff"
				case "uppercase_uuid":
					response.Credentials[0].UUID = strings.ToUpper(testUUID)
				case "partial":
					response.Credentials = nil
				}
				body, _ := json.Marshal(response)
				switch mode {
				case "extra":
					body = []byte(strings.TrimSuffix(string(body), "}") + `,"secret":"bad"}`)
				case "duplicate":
					body = []byte(strings.Replace(string(body), `"contract_version":`, `"contract_version":"credential-delivery/1","contract_version":`, 1))
				case "missing_field":
					body = []byte(strings.Replace(string(body), `"credential_generation":"1",`, "", 1))
				case "oversize":
					body = []byte(strings.Repeat("x", credentialdelivery.MaxMessageBytes+1))
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				if mode == "no_store" {
					w.Header().Set("Cache-Control", "public")
				}
				if mode == "content_type" {
					w.Header().Set("Content-Type", "text/plain")
				}
				w.Write(body)
			})
			fixture = deliveryTLSFixture(t, handler)
			client, err := New(fixture.cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			users, err := client.Resolve(context.Background(), fixture.env, fixture.grant)
			if mode == "valid" {
				if err != nil || len(users) != 1 || users[0].UUID != testUUID || users[0].SpeedLimit != 23 || users[0].DeviceLimit != 2 || users[0].TrafficPeriod != "period-7" || !strings.HasPrefix(fixture.grant.Payload.Users[0].UUID, "sha256:") {
					t.Fatal("material changed signed policy or failed delivery", err)
				}
			} else if err == nil || users != nil || !strings.HasPrefix(err.Error(), "NODE_CREDENTIAL_DELIVERY_") || strings.Contains(err.Error(), testUUID) {
				t.Fatal("invalid material or secret diagnostic escaped")
			}
			if calls.Load() != 1 {
				t.Fatal("redirect or unexpected Provider retry", calls.Load())
			}
		})
	}
}

func TestDeliveryPinsClientCertificateProviderAndGrantBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	fixture := deliveryTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	client, err := New(fixture.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, mode := range []string{"recipient", "provider", "epoch", "digest", "payload", "expired"} {
		t.Run(mode, func(t *testing.T) {
			grant := *fixture.grant
			envelope := fixture.env
			switch mode {
			case "recipient":
				grant.Payload.Provider.RecipientSHA256 = strings.Repeat("c", 64)
			case "provider":
				grant.Payload.Provider.ProviderID = "another-provider"
			case "epoch":
				grant.Payload.Provider.ProviderInstanceEpoch = "2"
			case "digest":
				grant.Digest = strings.Repeat("c", 64)
			case "payload":
				envelope.Payload = base64.RawURLEncoding.EncodeToString([]byte("{}"))
			case "expired":
				grant.Payload.ExpiresAt = time.Now().Unix()
			}
			if users, err := client.Resolve(context.Background(), envelope, &grant); err == nil || users != nil {
				t.Fatal("invalid grant fetched material")
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("preflight refusal called Provider")
	}
}

func TestDeliveryRejectsUntrustedServerAndInvalidTLSIdentityWithoutRawErrors(t *testing.T) {
	var calls atomic.Int32
	fixture := deliveryTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	other := deliveryTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	cfg := fixture.cfg
	cfg.CAFile = other.cfg.CAFile
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if users, err := client.Resolve(context.Background(), fixture.env, fixture.grant); err == nil || users != nil || err.Error() != "NODE_CREDENTIAL_DELIVERY_TRANSPORT_UNAVAILABLE" {
		t.Fatal("untrusted TLS server accepted or raw error leaked", err)
	}
	cfg = fixture.cfg
	cfg.ClientKey = other.cfg.ClientKey
	if _, err := New(cfg); err == nil || strings.Contains(err.Error(), cfg.ClientKey) {
		t.Fatal("mismatched key accepted or path leaked")
	}
	if calls.Load() != 0 {
		t.Fatal("untrusted TLS request reached application")
	}
}
