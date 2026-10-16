// Package txboard implements the native TXBoard node/v1 wire protocol.
// It intentionally does not reuse the Xboard query/body-token transport.
package txboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/ANRCM0/TX-Node/internal/authorization"
	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlerror"
	"github.com/ANRCM0/TX-Node/internal/credentialdelivery"
	"github.com/ANRCM0/TX-Node/internal/credentialdeliveryclient"
	"github.com/ANRCM0/TX-Node/internal/panel"
)

const prefix = "/txapi/node/v1"
const maxResponse = 4 << 20
const maxAuthorityError = 8 << 10

type Handshake struct {
	ProtocolVersion int            `json:"protocol_version"`
	NodeID          *int           `json:"node_id"`
	Mode            string         `json:"mode"`
	Settings        panel.Settings `json:"settings"`
	WebSocket       struct {
		Enabled bool   `json:"enabled"`
		Path    string `json:"path"`
	} `json:"websocket"`
	// Optional capability; the explicit v2 reporter validates it. Service remains v1.
	UsageV2            json.RawMessage           `json:"usage_v2,omitempty"`
	AuthorizationTrust *panel.AuthorizationTrust `json:"authorization_trust,omitempty"`
}
type NodeList struct {
	Nodes      []panel.MachineNode     `json:"nodes"`
	BaseConfig panel.MachineBaseConfig `json:"base_config"`
}
type Client struct {
	baseURL, token                    string
	nodeID, machineID                 int
	http                              *http.Client
	mu                                sync.Mutex
	configETag, usersETag             string
	cachedConfig                      *panel.NodeConfig
	cachedUsers                       []panel.User
	configGeneration, usersGeneration uint64
	configReadMu, usersReadMu         sync.Mutex
	success, failure                  atomic.Uint64
}

func NewClient(cfg config.PanelConfig) *Client {
	return &Client{baseURL: strings.TrimRight(cfg.URL, "/"), token: cfg.Token,
		nodeID: cfg.NodeID, machineID: cfg.MachineID, http: &http.Client{Timeout: 30 * time.Second}}
}
func (c *Client) ForNode(id int) *Client {
	return &Client{baseURL: c.baseURL, token: c.token, nodeID: id, machineID: c.machineID, http: c.http}
}

// ResetConfigETag also removes its matching body; an in-flight read cannot
// repopulate the invalidated generation after a reconnect/reset.
func (c *Client) ResetConfigETag() {
	c.mu.Lock()
	c.configETag = ""
	c.cachedConfig = nil
	c.configGeneration++
	c.mu.Unlock()
}
func (c *Client) ResetETags() {
	c.mu.Lock()
	c.configETag, c.usersETag = "", ""
	c.cachedConfig, c.cachedUsers = nil, nil
	c.configGeneration++
	c.usersGeneration++
	c.mu.Unlock()
}
func (c *Client) Metrics() (uint64, uint64) { return c.success.Load(), c.failure.Load() }
func (c *Client) NodeID() int               { return c.nodeID }
func (c *Client) MachineID() int            { return c.machineID }
func (c *Client) Token() string             { return c.token }
func (c *Client) BaseURL() string           { return c.baseURL }

// WSSURL accepts only the versioned route advertised by native handshake.
func (c *Client) WSSURL(path string) (string, error) {
	if path != prefix+"/ws" {
		return "", errors.New("unexpected native websocket path")
	}
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return "", errors.New("invalid panel URL")
	}
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else if u.Scheme == "http" {
		u.Scheme = "ws"
	} else {
		return "", errors.New("unsupported panel scheme")
	}
	u.Path = path
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}
func (c *Client) request(method, path string, body any, etag string) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, errors.New("invalid TXBoard request body")
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.baseURL+prefix+path, reader)
	if err != nil {
		return nil, errors.New("invalid TXBoard request")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	if c.machineID > 0 {
		req.Header.Set("X-TX-Machine-ID", strconv.Itoa(c.machineID))
	}
	if c.nodeID > 0 {
		req.Header.Set("X-TX-Node-ID", strconv.Itoa(c.nodeID))
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	// The configured TLS transport and cookie jar are retained; redirect policy
	// is per request and never mutates a shared client used by sibling nodes.
	nativeHTTP := *c.http
	nativeHTTP.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := nativeHTTP.Do(req)
	if err != nil {
		c.failure.Add(1)
		if errors.Is(err, context.Canceled) {
			return nil, fmt.Errorf("TXBoard HTTP request failed: %w", context.Canceled)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("TXBoard HTTP request failed: %w", context.DeadlineExceeded)
		}
		return nil, errors.New("TXBoard HTTP request failed")
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		c.success.Add(1)
	} else {
		c.failure.Add(1)
	}
	if denial := c.authorityDenial(resp, method, path); denial != nil {
		resp.Body.Close()
		return nil, denial
	}
	return resp, nil
}

// authorityDenial recognizes only completed, bounded native read/handshake
// rejections. Identity and scope come from this request, never the response.
func (c *Client) authorityDenial(resp *http.Response, method, path string) *controlerror.AuthorityDenial {
	allowed := method == "POST" && path == "/handshake" || method == "GET" && ((path == "/config" || path == "/users") && c.nodeID > 0 || path == "/machine/nodes" && c.machineID > 0)
	if !allowed || c.token == "" || (c.nodeID <= 0 && c.machineID <= 0) || (resp.StatusCode != 401 && resp.StatusCode != 404) {
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAuthorityError+1))
	if err != nil || len(body) > maxAuthorityError || !utf8.Valid(body) {
		return nil
	}
	code, valid := authorityErrorCode(body)
	if !valid {
		return nil
	}
	denial := &controlerror.AuthorityDenial{NodeID: c.nodeID, MachineID: c.machineID, Code: code, HTTPStatus: resp.StatusCode}
	if resp.StatusCode == 401 && code == "NODE_UNAUTHORIZED" {
		if c.machineID > 0 {
			denial.Scope = controlerror.MachineScope
		} else {
			denial.Scope = controlerror.NodeScope
		}
		return denial
	}
	if resp.StatusCode == 404 && code == "NODE_NOT_FOUND" && c.nodeID > 0 && path != "/machine/nodes" {
		denial.Scope = controlerror.NodeScope
		return denial
	}
	return nil
}

func authorityErrorCode(body []byte) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	value, err := uniqueJSONValue(dec, 0)
	if err != nil {
		return "", false
	}
	if _, err = dec.Token(); err != io.EOF {
		return "", false
	}
	envelope, ok := value.(map[string]any)
	if !ok {
		return "", false
	}
	if _, exists := envelope["data"]; exists {
		return "", false
	}
	requestID, ok := envelope["request_id"].(string)
	if !ok || len(requestID) > 256 || strings.TrimSpace(requestID) == "" {
		return "", false
	}
	details, ok := envelope["error"].(map[string]any)
	if !ok {
		return "", false
	}
	code, ok := details["code"].(string)
	if !ok {
		return "", false
	}
	if _, ok := details["message"].(string); !ok {
		return "", false
	}
	return code, true
}

// JSON's default last-key-wins behavior is unsuitable for authority decisions.
// Walk every object (including optional fields) to reject duplicate keys.
func uniqueJSONValue(dec *json.Decoder, depth int) (any, error) {
	if depth > 128 {
		return nil, errors.New("native error nesting limit")
	}
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := make(map[string]any)
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("invalid native error key")
			}
			if _, exists := object[key]; exists {
				return nil, errors.New("duplicate native error key")
			}
			value, err := uniqueJSONValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		closing, err := dec.Token()
		if err != nil || closing != json.Delim('}') {
			return nil, errors.New("invalid native error object")
		}
		return object, nil
	case '[':
		var array []any
		for dec.More() {
			value, err := uniqueJSONValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		closing, err := dec.Token()
		if err != nil || closing != json.Delim(']') {
			return nil, errors.New("invalid native error array")
		}
		return array, nil
	default:
		return nil, errors.New("invalid native error delimiter")
	}
}

func decode(resp *http.Response, dest any, allowed ...int) error {
	defer resp.Body.Close()
	ok := false
	for _, code := range allowed {
		if resp.StatusCode == code {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("TXBoard HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return errors.New("read TXAPI response failed")
	}
	if len(b) > maxResponse {
		return errors.New("TXBoard response too large")
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(b, &envelope); err != nil {
		return errors.New("invalid TXAPI envelope")
	}
	if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return errors.New("missing TXAPI data")
	}
	if err := json.Unmarshal(envelope.Data, dest); err != nil {
		return errors.New("invalid TXAPI data")
	}
	return nil
}
func (c *Client) Handshake() (*Handshake, error) {
	resp, err := c.request("POST", "/handshake", nil, "")
	if err != nil {
		return nil, err
	}
	var hs Handshake
	if err := decode(resp, &hs, 200); err != nil {
		return nil, err
	}
	if hs.ProtocolVersion != 1 {
		return nil, fmt.Errorf("unsupported TXBoard protocol version %d", hs.ProtocolVersion)
	}
	if c.nodeID > 0 && hs.NodeID != nil && *hs.NodeID != c.nodeID {
		return nil, errors.New("handshake node mismatch")
	}
	return &hs, nil
}

// GetConfig preserves the original nil=304 transport interface.
func (c *Client) GetConfig() (*panel.NodeConfig, error) { return c.readConfig(false) }

// ConfigSnapshot returns an independent complete desired body, including on304.
// An uncached304 forces one unconditional request and then fails explicitly.
func (c *Client) ConfigSnapshot() (*panel.NodeConfig, error) { return c.readConfig(true) }

func (c *Client) readConfig(complete bool) (*panel.NodeConfig, error) {
	c.configReadMu.Lock()
	defer c.configReadMu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		c.mu.Lock()
		etag, generation := c.configETag, c.configGeneration
		c.mu.Unlock()
		resp, err := c.request("GET", "/config", nil, etag)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusNotModified {
			resp.Body.Close()
			c.mu.Lock()
			if generation != c.configGeneration {
				c.mu.Unlock()
				return nil, errors.New("TXBoard config cache invalidated during read")
			}
			if !complete {
				c.mu.Unlock()
				return nil, nil
			}
			if c.cachedConfig != nil {
				cached, err := cloneConfigSnapshot(c.cachedConfig)
				c.mu.Unlock()
				return cached, err
			}
			c.configETag = ""
			c.mu.Unlock()
			if attempt == 0 {
				continue
			}
			return nil, errors.New("TXBoard config304 without matching snapshot")
		}
		var data struct {
			ProtocolVersion int              `json:"protocol_version"`
			NodeID          int              `json:"node_id"`
			Config          panel.NodeConfig `json:"config"`
		}
		if err := decode(resp, &data, 200); err != nil {
			return nil, err
		}
		if data.ProtocolVersion != 1 || data.NodeID != c.nodeID || data.Config.Protocol == "" {
			return nil, errors.New("invalid TXBoard config snapshot")
		}
		cached, err := cloneConfigSnapshot(&data.Config)
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		if generation != c.configGeneration {
			c.mu.Unlock()
			return nil, errors.New("TXBoard config cache invalidated during read")
		}
		c.cachedConfig, c.configETag = cached, resp.Header.Get("ETag")
		c.mu.Unlock()
		return &data.Config, nil
	}
	return nil, errors.New("TXBoard config snapshot unavailable")
}

func cloneConfigSnapshot(cfg *panel.NodeConfig) (*panel.NodeConfig, error) {
	body, err := json.Marshal(cfg)
	if err != nil {
		return nil, errors.New("cannot clone TXBoard config snapshot")
	}
	var cloned panel.NodeConfig
	if err := json.Unmarshal(body, &cloned); err != nil {
		return nil, errors.New("cannot clone TXBoard config snapshot")
	}
	return &cloned, nil
}

// A nil slice means304; an allocated empty slice means a valid empty user set.
func (c *Client) GetUsers() ([]panel.User, error) { return c.readUsers(false) }

// UsersSnapshot returns an independent complete desired user set. A legitimate
// empty set remains allocated; missing cached content is never invented empty.
func (c *Client) UsersSnapshot() ([]panel.User, error) { return c.readUsers(true) }

// AuthorizedUsersSnapshot fetches a complete signed users snapshot. It never
// uses ETag/304 because a cached unsigned body cannot renew finite authority.
func (c *Client) AuthorizedUsersSnapshot(m *authorization.Manager) ([]panel.User, *authorization.Snapshot, error) {
	if m == nil {
		return nil, nil, errors.New("NODE_AUTHORIZATION_MANAGER_REQUIRED")
	}
	endpoint, err := url.Parse(c.baseURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil {
		return nil, nil, errors.New("NODE_AUTHORIZATION_HTTPS_REQUIRED")
	}
	resp, err := c.request("GET", "/users", nil, "")
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotModified {
			return nil, nil, errors.New("NODE_AUTHORIZATION_304_NOT_RENEWAL")
		}
		return nil, nil, fmt.Errorf("TXBoard HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, nil, errors.New("read TXAPI authorized response failed")
	}
	if len(raw) > maxResponse {
		return nil, nil, errors.New("NODE_AUTHORIZATION_RESPONSE_TOO_LARGE")
	}
	var response struct {
		Data      json.RawMessage `json:"data"`
		RequestID json.RawMessage `json:"request_id,omitempty"`
	}
	if err := authorization.ValidateJSON(raw, &response); err != nil {
		return nil, nil, errors.New("NODE_AUTHORIZATION_RESPONSE_INVALID")
	}
	var data struct {
		ProtocolVersion int                               `json:"protocol_version"`
		NodeID          int                               `json:"node_id"`
		Users           []panel.User                      `json:"users"`
		Authorization   panel.SignedAuthorizationEnvelope `json:"authorization"`
	}
	if err := authorization.ValidateJSON(response.Data, &data); err != nil {
		return nil, nil, errors.New("NODE_AUTHORIZATION_RESPONSE_INVALID")
	}
	if data.ProtocolVersion != 1 || data.NodeID != c.nodeID || data.Users == nil {
		return nil, nil, errors.New("NODE_AUTHORIZATION_RESPONSE_INVALID")
	}
	envelope := authorization.Envelope{Payload: data.Authorization.Payload, Signature: data.Authorization.Signature}
	users := data.Users
	if config.ProviderAuthorizationPolicy(m.Config().PolicyVersion) {
		grant, err := m.VerifyProviderGrant(envelope, users, time.Now())
		if err != nil {
			return nil, nil, err
		}
		if len(users) > 0 {
			delivery, err := credentialdeliveryclient.New(m.Config().Provider)
			if err != nil {
				return nil, nil, err
			}
			defer delivery.Close()
			users, err = delivery.Resolve(context.Background(), credentialdelivery.Envelope{Payload: envelope.Payload, Signature: envelope.Signature}, grant)
			if err != nil {
				return nil, nil, err
			}
		}
	}
	snap, err := m.Verify(envelope, users, time.Now())
	if err != nil {
		return nil, nil, err
	}
	return cloneUsersSnapshot(snap.Users), snap, nil
}

func (c *Client) readUsers(complete bool) ([]panel.User, error) {
	c.usersReadMu.Lock()
	defer c.usersReadMu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		c.mu.Lock()
		etag, generation := c.usersETag, c.usersGeneration
		c.mu.Unlock()
		resp, err := c.request("GET", "/users", nil, etag)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusNotModified {
			resp.Body.Close()
			c.mu.Lock()
			if generation != c.usersGeneration {
				c.mu.Unlock()
				return nil, errors.New("TXBoard users cache invalidated during read")
			}
			if !complete {
				c.mu.Unlock()
				return nil, nil
			}
			if c.cachedUsers != nil {
				users := cloneUsersSnapshot(c.cachedUsers)
				c.mu.Unlock()
				return users, nil
			}
			c.usersETag = ""
			c.mu.Unlock()
			if attempt == 0 {
				continue
			}
			return nil, errors.New("TXBoard users304 without matching snapshot")
		}
		var data struct {
			ProtocolVersion int          `json:"protocol_version"`
			NodeID          int          `json:"node_id"`
			Users           []panel.User `json:"users"`
		}
		if err := decode(resp, &data, 200); err != nil {
			return nil, err
		}
		if data.ProtocolVersion != 1 || data.NodeID != c.nodeID || data.Users == nil {
			return nil, errors.New("invalid TXBoard users snapshot")
		}
		cached := cloneUsersSnapshot(data.Users)
		c.mu.Lock()
		if generation != c.usersGeneration {
			c.mu.Unlock()
			return nil, errors.New("TXBoard users cache invalidated during read")
		}
		c.cachedUsers, c.usersETag = cached, resp.Header.Get("ETag")
		c.mu.Unlock()
		return data.Users, nil
	}
	return nil, errors.New("TXBoard users snapshot unavailable")
}

func cloneUsersSnapshot(users []panel.User) []panel.User {
	cloned := make([]panel.User, len(users))
	copy(cloned, users)
	return cloned
}
func (c *Client) GetMachineNodes() (*NodeList, error) {
	resp, err := c.request("GET", "/machine/nodes", nil, "")
	if err != nil {
		return nil, err
	}
	var data struct {
		ProtocolVersion int                     `json:"protocol_version"`
		Nodes           []panel.MachineNode     `json:"nodes"`
		BaseConfig      panel.MachineBaseConfig `json:"base_config"`
	}
	if err := decode(resp, &data, 200); err != nil {
		return nil, err
	}
	if data.ProtocolVersion != 1 || data.Nodes == nil {
		return nil, errors.New("invalid machine node list")
	}
	seen := make(map[int]struct{}, len(data.Nodes))
	for _, node := range data.Nodes {
		if node.ID <= 0 {
			return nil, errors.New("invalid machine node list")
		}
		if _, duplicate := seen[node.ID]; duplicate {
			return nil, errors.New("invalid machine node list")
		}
		seen[node.ID] = struct{}{}
	}
	return &NodeList{Nodes: data.Nodes, BaseConfig: data.BaseConfig}, nil
}
func (c *Client) PostReport(body map[string]any) error {
	body["protocol_version"] = 1
	resp, err := c.request("POST", "/report", body, "")
	if err != nil {
		return err
	}
	var ack struct {
		ProtocolVersion int    `json:"protocol_version"`
		Accepted        bool   `json:"accepted"`
		BatchID         string `json:"traffic_batch_id"`
		Settlement      string `json:"settlement"`
		ReceiptStatus   string `json:"receipt_status"`
		ReceiptID       string `json:"receipt_id"`
	}
	if err := decode(resp, &ack, 202); err != nil {
		return err
	}
	if ack.ProtocolVersion != 1 || !ack.Accepted {
		return errors.New("TXBoard rejected report")
	}
	if traffic, ok := body["traffic"]; ok && traffic != nil {
		if id, ok := body["traffic_batch_id"].(string); ok && id != "" && (ack.BatchID != id || ack.Settlement != "queued") {
			return errors.New("invalid TXBoard report ACK")
		}
	}
	if segments, present := body["traffic_segments"]; present && segments != nil {
		receipt, err := strconv.ParseUint(ack.ReceiptID, 10, 64)
		if ack.ReceiptStatus != "persisted" || err != nil || receipt == 0 || len(ack.ReceiptID) > 20 || ack.ReceiptID[0] == '0' {
			return errors.New("invalid durable TXBoard report ACK")
		}
	}
	return nil
}
func (c *Client) ReportMachineStatus(body map[string]any) error {
	body["protocol_version"] = 1
	resp, err := c.request("POST", "/machine/status", body, "")
	if err != nil {
		return err
	}
	var ack struct {
		ProtocolVersion int  `json:"protocol_version"`
		Accepted        bool `json:"accepted"`
	}
	if err := decode(resp, &ack, 200); err != nil {
		return err
	}
	if ack.ProtocolVersion != 1 || !ack.Accepted {
		return errors.New("TXBoard rejected machine status")
	}
	return nil
}
