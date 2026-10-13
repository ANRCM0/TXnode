package txboard

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/ANRCM0/TX-Node/internal/usagev2"
)

// PrepareIsolatedUsageV2TLS runs once before bootstrap, never during request
// handling. Credentials remain in the native client, and trust is explicit.
func (c *Client) PrepareIsolatedUsageV2TLS(caFile string) error {
	if c == nil {
		return errors.New("USAGE_V2_NATIVE_HTTP_REQUIRED")
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if caFile != "" {
		info, err := os.Lstat(caFile)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 65536 {
			return errors.New("USAGE_V2_TRUST_INVALID")
		}
		pem, err := os.ReadFile(caFile)
		if err != nil || !roots.AppendCertsFromPEM(pem) {
			return errors.New("USAGE_V2_TRUST_INVALID")
		}
	}
	c.http = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return nil
}

func (c *Client) ServiceUsageV2(hs *Handshake) (*usagev2.Session, usagev2.Transport, error) {
	if hs == nil || hs.ProtocolVersion != 1 || hs.WebSocket.Enabled || c == nil || c.machineID != 0 || len(hs.UsageV2) == 0 {
		return nil, nil, errors.New("USAGE_V2_NATIVE_HTTP_REQUIRED")
	}
	var session usagev2.Session
	if usagev2.StrictDecode(hs.UsageV2, &session, usagev2.MaxPayloadBytes) != nil || session.Validate() != nil || session.NodeID != strconv.Itoa(c.nodeID) {
		return nil, nil, errors.New("USAGE_V2_CAPABILITY_INVALID")
	}
	transport, err := usagev2.NewHTTPTransport(c.baseURL, c.token, session.NodeID, 0, c.http)
	if err != nil {
		return nil, nil, errors.New("USAGE_V2_TRANSPORT_INVALID")
	}
	return &session, transport, nil
}
