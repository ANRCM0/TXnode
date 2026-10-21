package credentialprovider

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"

	"github.com/ANRCM0/TX-Node/internal/credentialdelivery"
)

const CapabilitiesContractVersion = "credential-provider-capabilities/1"

type CapabilityRequest struct {
	ContractVersion       string `json:"contract_version"`
	RequestID             string `json:"request_id"`
	ProviderID            string `json:"provider_id"`
	ProviderInstanceEpoch string `json:"provider_instance_epoch"`
}

type CapabilityResponse struct {
	ContractVersion            string   `json:"contract_version"`
	RequestID                  string   `json:"request_id"`
	ProviderID                 string   `json:"provider_id"`
	ProviderInstanceEpoch      string   `json:"provider_instance_epoch"`
	StoreVersion               int      `json:"store_version"`
	Operations                 []string `json:"operations"`
	NodeDelivery               bool     `json:"node_delivery"`
	SubscriptionRender         bool     `json:"subscription_render"`
	Profiles                   []string `json:"profiles"`
	SubscriptionTemplateEngine string   `json:"subscription_template_engine,omitempty"`
}

func withCapabilities(base http.Handler, store *Store, fingerprints []string, nodeDelivery, subscriptionRender bool) http.Handler {
	allowed, _ := fingerprintSet(fingerprints)
	templateAdmission := make(chan struct{}, 8)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/template-validate" {
			select {
			case templateAdmission <- struct{}{}:
				defer func() { <-templateAdmission }()
			default:
				w.Header().Set("Cache-Control", "no-store")
				writeDeliveryError(w, http.StatusServiceUnavailable, "REQUEST_CAPACITY_EXCEEDED")
				return
			}
			validateTemplateRequest(w, r, store, allowed, subscriptionRender)
			return
		}
		if r.URL.Path != "/capabilities" {
			base.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !peerAllowed(r.TLS, allowed) {
			writeDeliveryError(w, http.StatusForbidden, "CLIENT_IDENTITY_REJECTED")
			return
		}
		if r.URL.RawPath != "" || r.URL.RawQuery != "" {
			writeDeliveryError(w, http.StatusNotFound, "ENDPOINT_NOT_FOUND")
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeDeliveryError(w, http.StatusMethodNotAllowed, "METHOD_REJECTED")
			return
		}
		content, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || content != "application/json" || r.Header.Get("Content-Encoding") != "" {
			writeDeliveryError(w, http.StatusUnsupportedMediaType, "CONTENT_TYPE_REJECTED")
			return
		}
		if r.ContentLength > MaxMessageBytes {
			writeDeliveryError(w, http.StatusRequestEntityTooLarge, "MESSAGE_TOO_LARGE")
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, MaxMessageBytes+1))
		if len(raw) > MaxMessageBytes {
			writeDeliveryError(w, http.StatusRequestEntityTooLarge, "MESSAGE_TOO_LARGE")
			return
		}
		var request CapabilityRequest
		if err != nil || credentialdelivery.DecodeStrict(raw, &request) != nil ||
			request.ContractVersion != CapabilitiesContractVersion || !credentialdelivery.ValidRequestID(request.RequestID) {
			writeDeliveryError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		if request.ProviderID != store.providerID || request.ProviderInstanceEpoch != store.epoch {
			writeDeliveryError(w, http.StatusConflict, "PROVIDER_BINDING_REJECTED")
			return
		}
		engine := ""
		if subscriptionRender {
			engine = credentialdelivery.ClientTemplateEngine
		}
		response := CapabilityResponse{CapabilitiesContractVersion, request.RequestID, store.providerID, store.epoch, 2,
			[]string{"issue", "query", "revoke", "rotate"}, nodeDelivery, subscriptionRender, []string{"vless-uuid/v1", "vmess-uuid/v1"}, engine}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	})
}
