package usagev2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const HTTPPrefix = "/txapi/node/v2/usage"

var ErrTransportUnavailable = errors.New("usage v2 transport unavailable; retain original batch")
var errorCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

type HTTPTransport struct {
	baseURL, token string
	nodeID         string
	machineID      int
	client         *http.Client
}

type HTTPError struct {
	Status int
	Code   string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("usage v2 HTTP %d (%s)", e.Status, e.Code) }
func (e *HTTPError) Unwrap() error {
	if e.Code == "BATCH_PAYLOAD_CONFLICT" {
		return ErrPayloadConflict
	}
	return nil
}

func NewHTTPTransport(baseURL, token, nodeID string, machineID int, client *http.Client) (*HTTPTransport, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("usage v2 requires authenticated HTTPS base URL")
	}
	if token == "" {
		return nil, errors.New("usage v2 requires Native bearer credentials")
	}
	if err := Decimal(nodeID, false); err != nil {
		return nil, err
	}
	if machineID < 0 {
		return nil, errors.New("invalid usage machine scope")
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &HTTPTransport{strings.TrimRight(baseURL, "/"), token, nodeID, machineID, &copyClient}, nil
}

func (t *HTTPTransport) Submit(ctx context.Context, s Submission) (Receipt, error) {
	if err := s.Validate(); err != nil {
		return Receipt{}, err
	}
	if s.Payload.NodeID != t.nodeID {
		return Receipt{}, ErrReceiptMismatch
	}
	r, _, err := t.request(ctx, "/submit", s, false)
	return r, err
}

func (t *HTTPTransport) Get(ctx context.Context, q Query) (Receipt, bool, error) {
	if q.ProtocolVersion != 2 || q.NodeID != t.nodeID || !identifier.MatchString(q.BatchID) || !digestPattern.MatchString(q.PayloadDigest) {
		return Receipt{}, false, ErrReceiptMismatch
	}
	if err := Decimal(q.SourceEpoch, false); err != nil {
		return Receipt{}, false, err
	}
	return t.request(ctx, "/batch/get", q, true)
}

func (t *HTTPTransport) request(ctx context.Context, path string, body any, query bool) (Receipt, bool, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return Receipt{}, false, err
	}
	if len(b) > MaxPayloadBytes {
		return Receipt{}, false, errors.New("usage request exceeds byte limit")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.baseURL+HTTPPrefix+path, bytes.NewReader(b))
	if err != nil {
		return Receipt{}, false, err
	}
	req.Header.Set("Authorization", "Bearer "+t.token)
	req.Header.Set("X-TX-Node-ID", t.nodeID)
	if t.machineID > 0 {
		req.Header.Set("X-TX-Machine-ID", strconv.Itoa(t.machineID))
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	response, err := t.client.Do(req)
	if err != nil {
		return Receipt{}, false, ErrTransportUnavailable
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxPayloadBytes+1))
	if err != nil {
		return Receipt{}, false, ErrTransportUnavailable
	}
	var envelope struct {
		Data      json.RawMessage `json:"data,omitempty"`
		RequestID string          `json:"request_id,omitempty"`
		Meta      json.RawMessage `json:"meta,omitempty"`
		Error     *struct {
			Code    string          `json:"code"`
			Message string          `json:"message,omitempty"`
			Details json.RawMessage `json:"details,omitempty"`
		} `json:"error,omitempty"`
	}
	if err := StrictDecode(data, &envelope, MaxPayloadBytes); err != nil {
		return Receipt{}, false, err
	}
	if response.StatusCode != 200 && response.StatusCode != 201 {
		code := "UNEXPECTED_RESPONSE"
		if envelope.Error != nil {
			code = envelope.Error.Code
		}
		if len(code) > 80 || !errorCodePattern.MatchString(code) {
			code = "INVALID_ERROR_CODE"
		}
		if query && response.StatusCode == 404 && code == "BATCH_NOT_FOUND" {
			return Receipt{}, false, nil
		}
		return Receipt{}, false, &HTTPError{response.StatusCode, code}
	}
	if envelope.Error != nil {
		return Receipt{}, false, errors.New("usage v2 success envelope contains error")
	}
	var receipt Receipt
	if err := StrictDecode(envelope.Data, &receipt, MaxPayloadBytes); err != nil {
		return receipt, false, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(envelope.Data, &fields); err != nil {
		return receipt, false, err
	}
	for _, field := range []string{"protocol_version", "core_instance_id", "receipt_generation", "node_id", "source_epoch", "batch_id", "payload_digest", "receipt_status", "settlement_status", "accepted_at", "receipt_id"} {
		if value, ok := fields[field]; !ok || string(value) == "null" {
			return receipt, false, errors.New("usage v2 complete durable receipt required")
		}
	}
	var q Query
	switch value := body.(type) {
	case Submission:
		q = value.Query()
	case Query:
		q = value
	default:
		return Receipt{}, false, errors.New("invalid usage operation")
	}
	if !identifier.MatchString(receipt.CoreInstanceID) {
		return receipt, false, ErrReceiptMismatch
	}
	if err := Decimal(receipt.ReceiptGeneration, false); err != nil {
		return receipt, false, err
	}
	expected := Submission{Payload: Payload{NodeID: q.NodeID, SourceEpoch: q.SourceEpoch, BatchID: q.BatchID}, PayloadDigest: q.PayloadDigest}
	if err := receipt.Validate(Session{CoreInstanceID: receipt.CoreInstanceID, ReceiptGeneration: receipt.ReceiptGeneration}, expected); err != nil {
		return receipt, false, err
	}
	return receipt, true, nil
}
