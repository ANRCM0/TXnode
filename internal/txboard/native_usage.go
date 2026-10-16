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

// PrepareNativeUsageTLS runs once before bootstrap, never during request
// handling. Credentials remain in the native client, and trust is explicit.
func (c *Client) PrepareNativeUsageTLS(caFile string) error {
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

func (c *Client) NativeUsageTransport(session *usagev2.Session) (usagev2.Transport, error) {
	if c == nil || session == nil || session.Validate() != nil || session.NodeID != strconv.Itoa(c.nodeID) {
		return nil, errors.New("NATIVE_USAGE_SESSION_INVALID")
	}
	return usagev2.NewHTTPTransport(c.baseURL, c.token, session.NodeID, c.machineID, c.http)
}
