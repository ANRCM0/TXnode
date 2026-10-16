package credentialprovider

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/ANRCM0/TX-Node/internal/credentialdelivery"
)

func loadDeliveryTrust(path string) (credentialdelivery.Trust, error) {
	var trust credentialdelivery.Trust
	if !filepath.IsAbs(path) {
		return trust, errors.New("DELIVERY_TRUST_INVALID")
	}
	file, err := os.Open(path)
	if err != nil {
		return trust, errors.New("DELIVERY_TRUST_INVALID")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil || len(raw) > 8192 || credentialdelivery.DecodeStrict(raw, &trust) != nil ||
		credentialdelivery.ValidateTrust(trust) != nil {
		return trust, errors.New("DELIVERY_TRUST_INVALID")
	}
	return trust, nil
}

func NewDeliveryHandler(store *Store, controlFingerprints, nodeFingerprints []string, trust credentialdelivery.Trust) (http.Handler, error) {
	control, err := fingerprintSet(controlFingerprints)
	if err != nil {
		return nil, err
	}
	nodes, err := fingerprintSet(nodeFingerprints)
	if err != nil {
		return nil, err
	}
	for value := range nodes {
		if control[value] {
			return nil, errors.New("CLIENT_ROLE_OVERLAP")
		}
	}
	if credentialdelivery.ValidateTrust(trust) != nil {
		return nil, errors.New("DELIVERY_TRUST_INVALID")
	}
	operations, err := NewHandler(store, controlFingerprints)
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/credential-metadata" && r.URL.Path != "/credentials" {
			operations.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		allowed := control
		if r.URL.Path == "/credentials" {
			allowed = nodes
		}
		if !peerAllowed(r.TLS, allowed) {
			writeDeliveryError(w, http.StatusForbidden, "CLIENT_IDENTITY_REJECTED")
			return
		}
		if r.URL.RawQuery != "" || r.URL.RawPath != "" {
			writeDeliveryError(w, http.StatusNotFound, "ENDPOINT_NOT_FOUND")
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeDeliveryError(w, http.StatusMethodNotAllowed, "METHOD_REJECTED")
			return
		}
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" || r.Header.Get("Content-Encoding") != "" {
			writeDeliveryError(w, http.StatusUnsupportedMediaType, "CONTENT_TYPE_REJECTED")
			return
		}
		if r.ContentLength > credentialdelivery.MaxMessageBytes {
			writeDeliveryError(w, http.StatusRequestEntityTooLarge, "MESSAGE_TOO_LARGE")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, credentialdelivery.MaxMessageBytes+1))
		if len(body) > credentialdelivery.MaxMessageBytes {
			writeDeliveryError(w, http.StatusRequestEntityTooLarge, "MESSAGE_TOO_LARGE")
			return
		}
		if err != nil || r.Context().Err() != nil {
			writeDeliveryError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		if r.URL.Path == "/credential-metadata" {
			var req credentialdelivery.MetadataRequest
			if credentialdelivery.DecodeStrict(body, &req) != nil || credentialdelivery.ValidateMetadataRequest(req) != nil {
				writeDeliveryError(w, http.StatusBadRequest, "INVALID_REQUEST")
				return
			}
			result, err := store.metadata(req, time.Now())
			if err != nil {
				writeDeliveryError(w, http.StatusConflict, "CREDENTIAL_STATE_UNAVAILABLE")
				return
			}
			for _, credential := range result.Credentials {
				if credential.CredentialExpiresAt <= time.Now().Unix() {
					writeDeliveryError(w, http.StatusConflict, "CREDENTIAL_STATE_UNAVAILABLE")
					return
				}
			}
			writeDeliveryResponse(w, result, 0)
			return
		}
		var req credentialdelivery.MaterialRequest
		if credentialdelivery.DecodeStrict(body, &req) != nil ||
			req.ContractVersion != credentialdelivery.ContractVersion || !credentialdelivery.ValidRequestID(req.RequestID) {
			writeDeliveryError(w, http.StatusBadRequest, "INVALID_REQUEST")
			return
		}
		// Core backdates not_before within the existing 30-second skew bound.
		// Expiry is always checked against the current time without any grace.
		grant, err := credentialdelivery.VerifyGrant(req.Authorization, trust, time.Now(), 30)
		if err != nil {
			writeDeliveryError(w, http.StatusForbidden, "AUTHORIZATION_REJECTED")
			return
		}
		peerHash := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
		// Serialize release with local mutations so a committed tombstone cannot
		// race a material response. Server write deadlines bound this read lock.
		store.deliveryMu.RLock()
		defer store.deliveryMu.RUnlock()
		result, err := store.material(grant, req.RequestID, hex.EncodeToString(peerHash[:]), time.Now())
		if err != nil {
			writeDeliveryError(w, http.StatusConflict, "CREDENTIAL_STATE_UNAVAILABLE")
			return
		}
		if grant.Payload.ExpiresAt <= time.Now().Unix() || r.Context().Err() != nil {
			writeDeliveryError(w, http.StatusForbidden, "AUTHORIZATION_REJECTED")
			return
		}
		writeDeliveryResponse(w, result, grant.Payload.ExpiresAt)
	}), nil
}

func writeDeliveryResponse(w http.ResponseWriter, response any, expiresAt int64) {
	raw, err := json.Marshal(response)
	if err != nil || len(raw) > credentialdelivery.MaxMessageBytes {
		writeDeliveryError(w, http.StatusInternalServerError, "RESPONSE_UNAVAILABLE")
		return
	}
	if expiresAt != 0 && expiresAt <= time.Now().Unix() {
		writeDeliveryError(w, http.StatusForbidden, "AUTHORIZATION_REJECTED")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func writeDeliveryError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	// Call sites supply fixed, non-secret codes only.
	_ = json.NewEncoder(w).Encode(struct {
		ErrorCode string `json:"error_code"`
	}{code})
}
