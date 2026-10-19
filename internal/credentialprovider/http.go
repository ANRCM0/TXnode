package credentialprovider

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type Config struct {
	Listen                 string
	StorePath              string
	ProviderID             string
	Epoch                  string
	TLSCert                string
	TLSKey                 string
	ClientCA               string
	ClientFingerprints     []string
	DeliveryTrust          string
	NodeClientFingerprints []string
	SubscriptionListen     string
	SubscriptionTLSCert    string
	SubscriptionTLSKey     string
	SubscriptionOrigins    []string
}

func fingerprintSet(values []string) (map[string]bool, error) {
	if len(values) == 0 {
		return nil, errors.New("CLIENT_IDENTITY_REQUIRED")
	}
	allowed := make(map[string]bool, len(values))
	for _, value := range values {
		if !hashPattern.MatchString(value) {
			return nil, errors.New("INVALID_CLIENT_FINGERPRINT")
		}
		allowed[value] = true
	}
	return allowed, nil
}

func peerAllowed(state *tls.ConnectionState, allowed map[string]bool) bool {
	if state == nil || state.Version != tls.VersionTLS13 ||
		len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return false
	}
	digest := sha256.Sum256(state.PeerCertificates[0].Raw)
	return allowed[hex.EncodeToString(digest[:])]
}

func LoadTLSConfig(config Config) (*tls.Config, error) {
	allowed, err := fingerprintSet(config.ClientFingerprints)
	if err != nil {
		return nil, err
	}
	if (config.DeliveryTrust == "") != (len(config.NodeClientFingerprints) == 0) {
		return nil, errors.New("DELIVERY_CONFIG_INVALID")
	}
	if config.DeliveryTrust != "" {
		nodes, err := fingerprintSet(config.NodeClientFingerprints)
		if err != nil {
			return nil, err
		}
		for fingerprint := range nodes {
			if allowed[fingerprint] {
				return nil, errors.New("CLIENT_ROLE_OVERLAP")
			}
			allowed[fingerprint] = true
		}
	}
	certificate, err := tls.LoadX509KeyPair(config.TLSCert, config.TLSKey)
	if err != nil {
		return nil, errors.New("TLS_CONFIG_INVALID")
	}
	caPEM, err := os.ReadFile(config.ClientCA)
	if err != nil {
		return nil, errors.New("TLS_CONFIG_INVALID")
	}
	ca := x509.NewCertPool()
	if !ca.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("TLS_CONFIG_INVALID")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: ca,
		VerifyConnection: func(state tls.ConnectionState) error {
			if !peerAllowed(&state, allowed) {
				return errors.New("CLIENT_IDENTITY_REJECTED")
			}
			return nil
		},
	}, nil
}

func NewHandler(store *Store, fingerprints []string) (http.Handler, error) {
	if store == nil {
		return nil, errors.New("STORE_UNAVAILABLE")
	}
	allowed, err := fingerprintSet(fingerprints)
	if err != nil {
		return nil, err
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !peerAllowed(r.TLS, allowed) {
			writeResponse(w, http.StatusForbidden, responseFor(Request{}, "rejected", "CLIENT_IDENTITY_REJECTED", false))
			return
		}
		if r.URL.Path != "/operations" || r.URL.RawQuery != "" || r.URL.RawPath != "" {
			writeResponse(w, http.StatusNotFound, responseFor(Request{}, "rejected", "ENDPOINT_NOT_FOUND", false))
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeResponse(w, http.StatusMethodNotAllowed, responseFor(Request{}, "rejected", "METHOD_REJECTED", false))
			return
		}
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" || r.Header.Get("Content-Encoding") != "" {
			writeResponse(w, http.StatusUnsupportedMediaType, responseFor(Request{}, "rejected", "CONTENT_TYPE_REJECTED", false))
			return
		}
		if r.ContentLength > MaxMessageBytes {
			writeResponse(w, http.StatusRequestEntityTooLarge, responseFor(Request{}, "rejected", "MESSAGE_TOO_LARGE", false))
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, MaxMessageBytes+1))
		if len(body) > MaxMessageBytes {
			writeResponse(w, http.StatusRequestEntityTooLarge, responseFor(Request{}, "rejected", "MESSAGE_TOO_LARGE", false))
			return
		}
		if err != nil {
			writeResponse(w, http.StatusBadRequest, responseFor(Request{}, "rejected", "INVALID_REQUEST", false))
			return
		}
		req, err := parseRequest(body, time.Now())
		if err != nil {
			// Only allow-listed, validated envelope fields can reach diagnostics.
			if err == errInvalidEnvelope {
				req = Request{}
			}
			writeResponse(w, http.StatusBadRequest, responseFor(req, "rejected", err.Error(), false))
			return
		}
		ctx, cancel := context.WithDeadline(r.Context(), time.Unix(req.DeadlineAt, 0))
		defer cancel()
		writeResponse(w, http.StatusOK, store.execute(ctx, req, time.Now()))
	})
	return withCapabilities(handler, store, fingerprints, false, false), nil
}

func writeResponse(w http.ResponseWriter, status int, response Response) {
	encoded, err := json.Marshal(response)
	if err != nil || len(encoded) > MaxMessageBytes {
		encoded = []byte(`{"contract_version":"credential-provider/1","request_id":"","operation_id":"","provider_id":"","provider_instance_epoch":"","status":"unknown","result":null,"error":{"code":"RESPONSE_UNAVAILABLE","retryable":true}}`)
		status = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
}

// Run never logs request bodies, TLS errors, certificate paths or private state.
// The optional ready callback receives only the bound listener address.
func Run(ctx context.Context, config Config, ready func(net.Addr)) error {
	if _, err := newRenderCORS(config.SubscriptionOrigins); err != nil {
		return err
	}
	if len(config.SubscriptionOrigins) > 0 && config.SubscriptionListen == "" {
		return errors.New("RENDER_CONFIG_INVALID")
	}
	if strings.TrimSpace(config.Listen) == "" {
		return errors.New("LISTEN_CONFIG_INVALID")
	}
	tlsConfig, err := LoadTLSConfig(config)
	if err != nil {
		return err
	}
	store, err := OpenStore(config.StorePath, config.ProviderID, config.Epoch)
	if err != nil {
		return err
	}
	defer store.Close()
	handler, err := NewHandler(store, config.ClientFingerprints)
	if err != nil {
		return err
	}
	if config.DeliveryTrust != "" {
		trust, err := loadDeliveryTrust(config.DeliveryTrust)
		if err != nil {
			return err
		}
		handler, err = NewDeliveryHandler(store, config.ClientFingerprints, config.NodeClientFingerprints, trust)
		if err != nil {
			return err
		}
	}
	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		return errors.New("LISTEN_UNAVAILABLE")
	}
	defer listener.Close()
	listeners := []net.Listener{listener}
	server := &http.Server{
		Handler: handler, TLSConfig: tlsConfig,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 35 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 8 << 10,
		// net/http's default TLS diagnostics include peer certificate details.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	servers := []*http.Server{server}
	if config.SubscriptionListen != "" || config.SubscriptionTLSCert != "" || config.SubscriptionTLSKey != "" {
		if config.SubscriptionListen == "" || config.SubscriptionTLSCert == "" || config.SubscriptionTLSKey == "" || config.DeliveryTrust == "" {
			return errors.New("RENDER_CONFIG_INVALID")
		}
		cert, err := tls.LoadX509KeyPair(config.SubscriptionTLSCert, config.SubscriptionTLSKey)
		if err != nil {
			return errors.New("RENDER_CONFIG_INVALID")
		}
		trust, err := loadDeliveryTrust(config.DeliveryTrust)
		if err != nil {
			return err
		}
		renderHandler, err := NewBrowserRenderHandler(store, trust, config.SubscriptionOrigins)
		if err != nil {
			return err
		}
		renderListener, err := net.Listen("tcp", config.SubscriptionListen)
		if err != nil {
			return errors.New("RENDER_LISTEN_UNAVAILABLE")
		}
		defer renderListener.Close()
		listeners = append(listeners, renderListener)
		servers = append(servers, &http.Server{Handler: renderHandler,
			TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}},
			ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 35 * time.Second,
			IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10, ErrorLog: log.New(io.Discard, "", 0)})
	}
	serveResult := make(chan error, len(servers))
	server.Handler = withCapabilities(handler, store, config.ClientFingerprints, config.DeliveryTrust != "", len(servers) > 1)
	for i, current := range servers {
		bound := listeners[i]
		go func() { serveResult <- current.ServeTLS(bound, "", "") }()
	}
	if ready != nil {
		ready(listener.Addr())
	}
	select {
	case err := <-serveResult:
		for _, current := range servers {
			_ = current.Close()
		}
		for i := 1; i < len(servers); i++ {
			<-serveResult
		}
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("SERVER_UNAVAILABLE")
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, current := range servers {
			if err := current.Shutdown(shutdown); err != nil {
				_ = current.Close()
			}
		}
		for range servers {
			<-serveResult
		}
		return nil
	}
}
