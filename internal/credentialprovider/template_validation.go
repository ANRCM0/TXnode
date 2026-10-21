package credentialprovider

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"net/http"

	"github.com/ANRCM0/TX-Node/internal/credentialdelivery"
)

type templateValidationRequest struct {
	ContractVersion       string `json:"contract_version"`
	RequestID             string `json:"request_id"`
	ProviderID            string `json:"provider_id"`
	ProviderInstanceEpoch string `json:"provider_instance_epoch"`
	FormatID              string `json:"format_id"`
	Source                string `json:"source"`
	SHA256                string `json:"sha256"`
}

func validateTemplateRequest(w http.ResponseWriter, r *http.Request, store *Store, allowed map[string]bool, enabled bool) {
	w.Header().Set("Cache-Control", "no-store")
	if !enabled || r.URL.RawPath != "" || r.URL.RawQuery != "" {
		writeDeliveryError(w, 404, "ENDPOINT_NOT_FOUND")
		return
	}
	if !peerAllowed(r.TLS, allowed) {
		writeDeliveryError(w, 403, "CLIENT_IDENTITY_REJECTED")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if r.Method != http.MethodPost || err != nil || media != "application/json" || r.Header.Get("Content-Encoding") != "" {
		writeDeliveryError(w, 400, "INVALID_REQUEST")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, credentialdelivery.MaxMessageBytes+1))
	var input templateValidationRequest
	if err != nil || len(raw) > credentialdelivery.MaxMessageBytes || credentialdelivery.DecodeStrict(raw, &input) != nil || input.ContractVersion != credentialdelivery.ClientTemplateEngine ||
		!credentialdelivery.ValidRequestID(input.RequestID) || input.ProviderID != store.providerID || input.ProviderInstanceEpoch != store.epoch {
		writeDeliveryError(w, 400, "INVALID_REQUEST")
		return
	}
	hash := sha256.Sum256([]byte(input.Source))
	version := hex.EncodeToString(hash[:])
	if input.SHA256 != version || !credentialdelivery.ValidClientTemplate(&credentialdelivery.ClientTemplate{Engine: credentialdelivery.ClientTemplateEngine, FormatID: input.FormatID, Version: version, SHA256: version, Source: input.Source}, input.FormatID) {
		writeDeliveryError(w, 422, "CLIENT_TEMPLATE_INVALID")
		return
	}
	protocol := "vless"
	if input.FormatID == credentialdelivery.RenderClash || input.FormatID == credentialdelivery.RenderSurgeIOS || input.FormatID == credentialdelivery.RenderSurgeMac || input.FormatID == credentialdelivery.RenderSurfboard {
		protocol = "vmess"
	}
	sample := []credentialdelivery.RenderConnection{{UUID: "11111111-1111-4111-8111-111111111111", Node: credentialdelivery.ConnectionNode{NodeID: "1", Name: "Template sample", Host: "example.invalid", Port: 443, Protocol: protocol, Transport: "tcp"}}}
	_, validationErr := renderTemplateDocument(input.FormatID, input.Source, sample)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"contract_version": input.ContractVersion, "request_id": input.RequestID, "provider_id": store.providerID, "provider_instance_epoch": store.epoch, "format_id": input.FormatID, "sha256": version, "valid": validationErr == nil})
}
