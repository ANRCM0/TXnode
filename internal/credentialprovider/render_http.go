package credentialprovider

import (
	"crypto/tls"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/ANRCM0/TX-Node/internal/credentialdelivery"
	bolt "github.com/sagernet/bbolt"
)

// NewRenderHandler belongs only on the separate public TLS listener. It exposes
// no control or Node endpoint and requires the subscriber's private-key proof.
func NewRenderHandler(store *Store, trust credentialdelivery.Trust) (http.Handler, error) {
	if store == nil || credentialdelivery.ValidateTrust(trust) != nil {
		return nil, errors.New("RENDER_CONFIG_INVALID")
	}
	admission := make(chan struct{}, 32)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		select {
		case admission <- struct{}{}:
			defer func() { <-admission }()
		default:
			writeDeliveryError(w, http.StatusServiceUnavailable, "REQUEST_CAPACITY_EXCEEDED")
			return
		}
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 {
			writeDeliveryError(w, http.StatusForbidden, "TLS_REQUIRED")
			return
		}
		if r.URL.Path != "/subscription-render" || r.URL.RawPath != "" || r.URL.RawQuery != "" {
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
		if r.ContentLength > credentialdelivery.MaxMessageBytes {
			writeDeliveryError(w, http.StatusRequestEntityTooLarge, "MESSAGE_TOO_LARGE")
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, credentialdelivery.MaxMessageBytes+1))
		if len(raw) > credentialdelivery.MaxMessageBytes {
			writeDeliveryError(w, http.StatusRequestEntityTooLarge, "MESSAGE_TOO_LARGE")
			return
		}
		var request credentialdelivery.RenderRequest
		if err != nil || credentialdelivery.DecodeStrict(raw, &request) != nil {
			writeDeliveryError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		grant, err := credentialdelivery.VerifyRenderRequest(request, trust, time.Now())
		if err != nil {
			writeDeliveryError(w, http.StatusForbidden, "AUTHORIZATION_REJECTED")
			return
		}
		if grant.Payload.ProviderID != store.providerID || grant.Payload.ProviderInstanceEpoch != store.epoch {
			writeDeliveryError(w, http.StatusForbidden, "PROVIDER_BINDING_REJECTED")
			return
		}
		store.deliveryMu.RLock()
		defer store.deliveryMu.RUnlock()
		result := credentialdelivery.RenderResponse{ContractVersion: credentialdelivery.RenderContractVersion,
			RequestID: request.RequestID, AuthorizationDigest: grant.Digest, FormatID: credentialdelivery.RenderFormat,
			Connections: make([]credentialdelivery.RenderConnection, 0, len(grant.Payload.Nodes))}
		err = store.db.View(func(tx *bolt.Tx) error {
			subject, hash, err := store.liveCredential(tx, grant.Payload.Subject, time.Now())
			if err != nil || hash != grant.Payload.CredentialSHA256 ||
				subject.Issue.CredentialExpiresAt != grant.Payload.CredentialExpiresAt {
				return errDeliveryState
			}
			for _, node := range grant.Payload.Nodes {
				result.Connections = append(result.Connections, credentialdelivery.RenderConnection{
					Node: node, AccessSubjectID: subject.AccessSubjectID, CredentialRef: subject.Issue.CredentialRef,
					CredentialGeneration: subject.Issue.CredentialGeneration, UUID: subject.Credential})
			}
			return nil
		})
		if err != nil {
			writeDeliveryError(w, http.StatusConflict, "CREDENTIAL_STATE_UNAVAILABLE")
			return
		}
		if r.Context().Err() != nil {
			writeDeliveryError(w, http.StatusRequestTimeout, "REQUEST_EXPIRED")
			return
		}
		writeDeliveryResponse(w, result, grant.Payload.ExpiresAt)
	}), nil
}
