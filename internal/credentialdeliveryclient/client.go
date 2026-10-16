// Package credentialdeliveryclient retrieves short-lived native UUID material
// directly from an operator-pinned Provider after Core authorization checks.
package credentialdeliveryclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/credentialdelivery"
	"github.com/ANRCM0/TX-Node/internal/panel"
)

type Client struct {
	cfg       config.AuthorizationProviderConfig
	recipient string
	http      *http.Client
}

func New(cfg config.AuthorizationProviderConfig) (*Client, error) {
	if err := (config.AuthorizationConfig{PolicyVersion: config.NativeProviderAuthorizationPolicyVersion, Provider: cfg}).ValidateProvider(); err != nil {
		return nil, failure("CONFIGURATION_INVALID")
	}
	ca, err := readTLSFile(cfg.CAFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, failure("TLS_CONFIGURATION_INVALID")
	}
	certPEM, err := readTLSFile(cfg.ClientCert)
	if err != nil {
		return nil, err
	}
	keyPEM, err := readTLSFile(cfg.ClientKey)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, failure("TLS_CONFIGURATION_INVALID")
	}
	if _, err := x509.ParseCertificate(certificate.Certificate[0]); err != nil {
		return nil, failure("TLS_CONFIGURATION_INVALID")
	}
	recipient := sha256.Sum256(certificate.Certificate[0])
	transport := &http.Transport{
		Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{certificate}},
		DisableKeepAlives: true, TLSHandshakeTimeout: 10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second, MaxResponseHeaderBytes: 64 << 10,
	}
	return &Client{cfg: cfg, recipient: hex.EncodeToString(recipient[:]), http: &http.Client{
		Transport: transport, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func (c *Client) Close() { c.http.CloseIdleConnections() }

// Resolve returns a new user slice with only UUID fields replaced. It never
// persists response bodies, credentials, certificates or private keys.
func (c *Client) Resolve(ctx context.Context, envelope credentialdelivery.Envelope, grant *credentialdelivery.Grant) ([]panel.User, error) {
	if grant == nil || grant.Payload.Provider.ProviderID != c.cfg.ProviderID || grant.Payload.Provider.ProviderInstanceEpoch != c.cfg.ProviderInstanceEpoch || grant.Payload.Provider.RecipientSHA256 != c.recipient || grant.Payload.ExpiresAt <= time.Now().Unix() {
		return nil, failure("BINDING_MISMATCH")
	}
	raw, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil || !bytes.Equal(raw, grant.PayloadBytes) {
		return nil, failure("GRANT_INVALID")
	}
	digest := sha256.Sum256(raw)
	if grant.Digest != hex.EncodeToString(digest[:]) || len(grant.Payload.Users) != len(grant.Payload.Provider.Subjects) || len(grant.Payload.Users) > credentialdelivery.MaxSubjects {
		return nil, failure("GRANT_INVALID")
	}
	requestID := make([]byte, 16)
	if _, err := rand.Read(requestID); err != nil {
		return nil, failure("REQUEST_UNAVAILABLE")
	}
	id := hex.EncodeToString(requestID)
	body, err := json.Marshal(credentialdelivery.MaterialRequest{ContractVersion: credentialdelivery.ContractVersion, RequestID: id, Authorization: envelope})
	if err != nil || len(body) > credentialdelivery.MaxMessageBytes {
		return nil, failure("REQUEST_INVALID")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.cfg.Endpoint, "/")+"/credentials", bytes.NewReader(body))
	if err != nil {
		return nil, failure("REQUEST_INVALID")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, failure("TRANSPORT_UNAVAILABLE")
	}
	defer resp.Body.Close()
	// Error responses are intentionally not interpreted as authorization or
	// copied into diagnostics; the previous finite lease is never extended.
	if resp.StatusCode != http.StatusOK {
		return nil, failure("PROVIDER_REJECTED")
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || !hasNoStore(resp.Header.Values("Cache-Control")) {
		return nil, failure("RESPONSE_INVALID")
	}
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, credentialdelivery.MaxMessageBytes+1))
	if err != nil || len(responseBody) > credentialdelivery.MaxMessageBytes {
		return nil, failure("RESPONSE_INVALID")
	}
	var response credentialdelivery.MaterialResponse
	if err := credentialdelivery.DecodeStrict(responseBody, &response); err != nil || response.ContractVersion != credentialdelivery.ContractVersion || response.RequestID != id || response.AuthorizationDigest != grant.Digest || response.Credentials == nil || len(response.Credentials) != len(grant.Payload.Provider.Subjects) {
		return nil, failure("RESPONSE_INVALID")
	}
	users := append([]panel.User{}, grant.Payload.Users...)
	for i, value := range response.Credentials {
		binding := grant.Payload.Provider.Subjects[i]
		hash := sha256.Sum256([]byte(value.UUID))
		if value.AccessSubjectID != binding.AccessSubjectID || value.CredentialRef != binding.CredentialRef || value.CredentialGeneration != binding.CredentialGeneration || !credentialdelivery.ValidUUID(value.UUID) || grant.Payload.Users[i].UUID != "sha256:"+hex.EncodeToString(hash[:]) {
			return nil, failure("RESPONSE_INVALID")
		}
		users[i].UUID = value.UUID
	}
	if grant.Payload.ExpiresAt <= time.Now().Unix() {
		return nil, failure("GRANT_EXPIRED")
	}
	return users, nil
}

func readTLSFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, failure("TLS_CONFIGURATION_UNAVAILABLE")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, failure("TLS_CONFIGURATION_INVALID")
	}
	data, err := io.ReadAll(io.LimitReader(f, credentialdelivery.MaxMessageBytes+1))
	if err != nil || len(data) == 0 || len(data) > credentialdelivery.MaxMessageBytes {
		return nil, failure("TLS_CONFIGURATION_INVALID")
	}
	return data, nil
}

func hasNoStore(values []string) bool {
	for _, value := range values {
		for _, directive := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(directive), "no-store") {
				return true
			}
		}
	}
	return false
}

func failure(code string) error { return errors.New("NODE_CREDENTIAL_DELIVERY_" + code) }
