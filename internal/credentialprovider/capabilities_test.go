package credentialprovider

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/ANRCM0/TX-Node/internal/credentialdelivery"
)

func TestCapabilitiesAreClosedCoreOnlyAndReportActualEnabledHandlers(t *testing.T) {
	store, _ := testStore(t)
	fixture := makeTLSFixture(t)
	clientState := func(client *http.Client) *tls.ConnectionState {
		der := client.Transport.(*http.Transport).TLSClientConfig.Certificates[0].Certificate[0]
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{leaf},
			VerifiedChains: [][]*x509.Certificate{{leaf}}}
	}
	core, node := clientState(fixture.client), clientState(fixture.wrong)
	nodeHash := sha256.Sum256(node.PeerCertificates[0].Raw)
	nodeFingerprint := hex.EncodeToString(nodeHash[:])
	base, err := NewHandler(store, fixture.config.ClientFingerprints)
	if err != nil {
		t.Fatal(err)
	}
	trust, _ := deliveryKey(t)
	delivery, err := NewDeliveryHandler(store, fixture.config.ClientFingerprints, []string{nodeFingerprint}, trust)
	if err != nil {
		t.Fatal(err)
	}
	request := CapabilityRequest{CapabilitiesContractVersion, "capability-1", "provider-a", "1"}
	valid, _ := json.Marshal(request)
	post := func(handler http.Handler, state *tls.ConnectionState, path string, raw []byte) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = state
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("capability response permits caching")
		}
		return response
	}
	for _, test := range []struct {
		name     string
		handler  http.Handler
		delivery bool
	}{{"control only", base, false}, {"node delivery", delivery, true}} {
		t.Run(test.name, func(t *testing.T) {
			result := post(test.handler, core, "/capabilities", valid)
			var response CapabilityResponse
			if result.Code != http.StatusOK || credentialdelivery.DecodeStrict(result.Body.Bytes(), &response) != nil ||
				response.ContractVersion != request.ContractVersion || response.RequestID != request.RequestID ||
				response.ProviderID != request.ProviderID || response.ProviderInstanceEpoch != request.ProviderInstanceEpoch ||
				response.StoreVersion != 2 || response.NodeDelivery != test.delivery || response.SubscriptionRender ||
				!reflect.DeepEqual(response.Operations, []string{"issue", "query", "revoke", "rotate"}) ||
				!reflect.DeepEqual(response.Profiles, []string{"vless-uuid/v1", "vmess-uuid/v1"}) {
				t.Fatal("capability response differs from runtime configuration")
			}
			for _, state := range []*tls.ConnectionState{nil, node} {
				if post(test.handler, state, "/capabilities", valid).Code != http.StatusForbidden {
					t.Fatal("capability access accepted without Core role")
				}
			}
		})
	}
	for _, raw := range [][]byte{
		[]byte(`{"contract_version":"credential-provider-capabilities/1","request_id":"capability-1","provider_id":"provider-a"}`),
		[]byte(strings.TrimSuffix(string(valid), "}") + `,"secret":"must-not-leak"}`),
		[]byte(strings.TrimSuffix(string(valid), "}") + `,"request_\u0069d":"duplicate"}`),
		bytes.Repeat([]byte("x"), MaxMessageBytes+1),
	} {
		result := post(delivery, core, "/capabilities", raw)
		var failure struct {
			ErrorCode string `json:"error_code"`
		}
		if result.Code < 400 || credentialdelivery.DecodeStrict(result.Body.Bytes(), &failure) != nil ||
			bytes.Contains(result.Body.Bytes(), []byte("must-not-leak")) {
			t.Fatal("malformed capabilities request was not bounded")
		}
	}
	request.ProviderInstanceEpoch = "2"
	wrongIdentity, _ := json.Marshal(request)
	if post(delivery, core, "/capabilities", wrongIdentity).Code != http.StatusConflict ||
		post(delivery, core, "/capabilities?grant=none", valid).Code != http.StatusNotFound {
		t.Fatal("capability target or URL binding was ignored")
	}
}
