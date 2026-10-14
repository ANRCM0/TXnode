// Package authorization verifies finite Core-signed native users snapshots.
// It does not issue credentials, change traffic ownership or activate Usage v2.
package authorization

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/panel"
)

const Audience = "tx-node-native-authorization-v1"
const maxPayloadBytes = 1 << 20

type Envelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}
type Trust struct {
	ProtocolVersion int    `json:"protocol_version"`
	CoreInstanceID  string `json:"core_instance_id"`
	KeyID           string `json:"key_id"`
	KeyEpoch        string `json:"key_epoch"`
	Algorithm       string `json:"algorithm"`
	PublicKey       string `json:"public_key"`
}
type Target struct {
	NodeID    int
	MachineID *int
}
type Payload struct {
	ProtocolVersion int          `json:"protocol_version"`
	Audience        string       `json:"audience"`
	PolicyVersion   string       `json:"policy_version"`
	CoreInstanceID  string       `json:"core_instance_id"`
	NodeID          int          `json:"node_id"`
	MachineID       *int         `json:"machine_id"`
	Revision        string       `json:"revision"`
	KeyID           string       `json:"key_id"`
	KeyEpoch        string       `json:"key_epoch"`
	IssuedAt        int64        `json:"issued_at"`
	NotBefore       int64        `json:"not_before"`
	ExpiresAt       int64        `json:"expires_at"`
	Complete        bool         `json:"complete"`
	Users           []panel.User `json:"users"`
}

// Snapshot metadata is copied at acceptance. The verified envelope remains
// private, so a caller cannot manufacture authorization via an exported DTO.
type Snapshot struct {
	Payload      Payload
	Users        []panel.User
	PayloadBytes []byte
	Digest       string
	envelope     Envelope
}

type State struct {
	Version        int    `json:"version"`
	CoreInstanceID string `json:"core_instance_id"`
	PolicyVersion  string `json:"policy_version"`
	NodeID         int    `json:"node_id"`
	MachineID      *int   `json:"machine_id"`
	KeyID          string `json:"key_id"`
	PublicKey      string `json:"public_key"`
	KeyEpoch       string `json:"key_epoch"`
	Revision       string `json:"revision"`
	IssuedAt       int64  `json:"issued_at"`
	ExpiresAt      int64  `json:"expires_at"`
	LastObservedAt int64  `json:"last_observed_at"`
	PayloadDigest  string `json:"payload_digest"`
}

type Manager struct {
	mu       sync.Mutex
	cfg      config.AuthorizationConfig
	target   Target
	trust    Trust
	state    State
	hasState bool
	snapshot *Snapshot
	deadline time.Time
	lastWall int64
	failed   bool
	lock     *os.File
}

var positiveDecimalRE = regexp.MustCompile(`\A[1-9][0-9]{0,18}\z`)
var digestRE = regexp.MustCompile(`\A[a-f0-9]{64}\z`)
var keyIDRE = regexp.MustCompile(`\A[A-Za-z0-9_-]{1,64}\z`)
var instanceRE = regexp.MustCompile(`\A[A-Za-z0-9:_-]{8,80}\z`)

func NewManager(cfg config.AuthorizationConfig, target Target) (*Manager, error) {
	if target.NodeID <= 0 || target.MachineID != nil && *target.MachineID <= 0 || cfg.StateDir == "" || !filepath.IsAbs(cfg.StateDir) || !instanceRE.MatchString(cfg.CoreInstanceID) || !keyIDRE.MatchString(cfg.KeyID) || !positiveDecimal(cfg.KeyEpoch) || cfg.PolicyVersion != config.NativeAuthorizationPolicyVersion || cfg.MaxClockSkew < 0 || cfg.MaxClockSkew > 30 {
		return nil, refuse("CONFIGURATION_INVALID")
	}
	if _, err := decodeKey(cfg.PublicKey); err != nil {
		return nil, err
	}
	lock, err := openStore(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	m := &Manager{cfg: cfg, target: Target{NodeID: target.NodeID, MachineID: cloneInt(target.MachineID)}, lock: lock}
	st, ok, err := loadState(cfg.StateDir)
	if err == nil && ok {
		if st.Version != 1 || st.CoreInstanceID != cfg.CoreInstanceID || st.PolicyVersion != cfg.PolicyVersion || st.NodeID != target.NodeID || !sameMachine(st.MachineID, target.MachineID) || !positiveDecimal(st.Revision) || !positiveDecimal(st.KeyEpoch) || !keyIDRE.MatchString(st.KeyID) || st.IssuedAt < 0 || st.ExpiresAt <= st.IssuedAt || st.ExpiresAt-st.IssuedAt > 120 || st.LastObservedAt < 0 || !digestRE.MatchString(st.PayloadDigest) || compareDecimal(cfg.KeyEpoch, st.KeyEpoch) < 0 || cfg.KeyEpoch == st.KeyEpoch && (cfg.KeyID != st.KeyID || cfg.PublicKey != st.PublicKey) {
			err = refuse("STATE_CORRUPT_OR_TRUST_ROLLBACK")
		}
		if err == nil {
			m.state, m.hasState = st, true
		}
	}
	if err != nil {
		lock.Close()
		return nil, err
	}
	return m, nil
}
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failed = true
	if m.lock == nil {
		return nil
	}
	err := m.lock.Close()
	m.lock = nil
	return err
}
func (m *Manager) Config() config.AuthorizationConfig { return m.cfg }
func (m *Manager) Trust() Trust                       { m.mu.Lock(); defer m.mu.Unlock(); return m.trust }
func (m *Manager) Expiry() time.Time                  { m.mu.Lock(); defer m.mu.Unlock(); return m.deadline }
func (m *Manager) Current() *Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return cloneSnapshot(m.snapshot)
}
func (m *Manager) Check(now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed || m.lock == nil || m.snapshot == nil || !now.Before(m.deadline) || now.UnixNano() < m.lastWall {
		m.failed = true
		return refuse("EXPIRED_OR_CLOCK_ROLLBACK")
	}
	m.lastWall = now.UnixNano()
	return nil
}
func (m *Manager) SetTrust(t Trust) error {
	if t.ProtocolVersion != 1 || t.Algorithm != "Ed25519" || t.CoreInstanceID != m.cfg.CoreInstanceID || t.KeyID != m.cfg.KeyID || t.KeyEpoch != m.cfg.KeyEpoch || t.PublicKey != m.cfg.PublicKey {
		return refuse("TRUST_MISMATCH")
	}
	if _, err := decodeKey(t.PublicKey); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed || m.lock == nil {
		return refuse("MANAGER_CLOSED")
	}
	m.trust = t
	return nil
}
func (m *Manager) Verify(env Envelope, users []panel.User, now time.Time) (*Snapshot, error) {
	m.mu.Lock()
	trust := m.trust
	m.mu.Unlock()
	if trust.PublicKey == "" {
		return nil, refuse("TRUST_UNAVAILABLE")
	}
	snap, err := Verify(env, users, trust, m.target, m.cfg.PolicyVersion, now, m.cfg.MaxClockSkew)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkHighWater(snap, now, false); err != nil {
		return nil, err
	}
	return snap, nil
}
func (m *Manager) Accept(env Envelope, users []panel.User, now time.Time) (*Snapshot, error) {
	snap, err := m.Verify(env, users, now)
	if err != nil {
		return nil, err
	}
	return m.AcceptVerified(snap, now)
}
func (m *Manager) checkHighWater(snap *Snapshot, now time.Time, applying bool) error {
	if m.failed || m.lock == nil {
		return refuse("MANAGER_CLOSED")
	}
	if snap == nil || snap.Payload.ExpiresAt <= now.Unix() {
		return refuse("EXPIRED")
	}
	if applying && m.snapshot != nil && now.UnixNano() < m.lastWall || (applying || m.snapshot == nil) && m.hasState && now.Unix() < m.state.LastObservedAt {
		return refuse("CLOCK_ROLLBACK")
	}
	if m.hasState {
		rev := compareDecimal(snap.Payload.Revision, m.state.Revision)
		if compareDecimal(snap.Payload.KeyEpoch, m.state.KeyEpoch) < 0 || rev < 0 || snap.Payload.IssuedAt < m.state.IssuedAt {
			return refuse("ROLLBACK")
		}
		if rev == 0 {
			if snap.Digest != m.state.PayloadDigest {
				return refuse("REVISION_CONFLICT")
			}
			if m.snapshot == nil {
				return refuse("RESTART_FRESH_SNAPSHOT_REQUIRED")
			}
		}
	}
	return nil
}
func (m *Manager) AcceptVerified(candidate *Snapshot, now time.Time) (*Snapshot, error) {
	if candidate == nil {
		return nil, refuse("SNAPSHOT_REQUIRED")
	}
	// Always reverify the private envelope and exported consumer rows at the
	// application boundary; a background response cannot renew stale authority.
	snap, err := m.Verify(candidate.envelope, candidate.Users, now)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkHighWater(snap, now, true); err != nil {
		return nil, err
	}
	if m.hasState && snap.Payload.Revision == m.state.Revision {
		return cloneSnapshot(snap), nil
	}
	st := State{Version: 1, CoreInstanceID: m.cfg.CoreInstanceID, PolicyVersion: m.cfg.PolicyVersion, NodeID: m.target.NodeID, MachineID: cloneInt(m.target.MachineID), KeyID: snap.Payload.KeyID, PublicKey: m.cfg.PublicKey, KeyEpoch: snap.Payload.KeyEpoch, Revision: snap.Payload.Revision, IssuedAt: snap.Payload.IssuedAt, ExpiresAt: snap.Payload.ExpiresAt, LastObservedAt: now.Unix(), PayloadDigest: snap.Digest}
	if err := saveState(m.cfg.StateDir, st); err != nil {
		m.failed = true
		return nil, err
	}
	remaining := time.Unix(snap.Payload.ExpiresAt, 0).Sub(now)
	if remaining > 120*time.Second {
		remaining = 120 * time.Second
	}
	if remaining <= 0 {
		m.failed = true
		return nil, refuse("EXPIRED")
	}
	m.state, m.hasState, m.snapshot = st, true, cloneSnapshot(snap)
	m.lastWall = now.UnixNano()
	m.deadline = now.Add(remaining)
	return cloneSnapshot(snap), nil
}

func Verify(env Envelope, outerUsers []panel.User, trust Trust, target Target, policy string, now time.Time, skew int) (*Snapshot, error) {
	if policy != config.NativeAuthorizationPolicyVersion || skew < 0 || skew > 30 || target.NodeID <= 0 || trust.ProtocolVersion != 1 || trust.Algorithm != "Ed25519" {
		return nil, refuse("INVALID")
	}
	raw, err := decodeBase64(env.Payload, maxPayloadBytes)
	if err != nil || len(raw) == 0 || !utf8.Valid(raw) {
		return nil, refuse("INVALID")
	}
	sig, err := decodeBase64(env.Signature, ed25519.SignatureSize)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, refuse("INVALID")
	}
	key, err := decodeKey(trust.PublicKey)
	if err != nil || !ed25519.Verify(key, raw, sig) {
		return nil, refuse("SIGNATURE_INVALID")
	}
	var fields map[string]json.RawMessage
	if err := strictJSON(raw, &fields); err != nil {
		return nil, refuse("INVALID")
	}
	required := []string{"audience", "complete", "core_instance_id", "expires_at", "issued_at", "key_epoch", "key_id", "machine_id", "node_id", "not_before", "policy_version", "protocol_version", "revision", "users"}
	if len(fields) != len(required) {
		return nil, refuse("FIELDS_INVALID")
	}
	for _, k := range required {
		if _, ok := fields[k]; !ok {
			return nil, refuse("FIELDS_INVALID")
		}
	}
	var p Payload
	if err := strictJSON(raw, &p); err != nil {
		return nil, refuse("INVALID")
	}
	if p.ProtocolVersion != 1 || p.Audience != Audience || p.PolicyVersion != policy || p.CoreInstanceID != trust.CoreInstanceID || p.NodeID != target.NodeID || !sameMachine(p.MachineID, target.MachineID) || p.KeyID != trust.KeyID || p.KeyEpoch != trust.KeyEpoch || !p.Complete || p.Users == nil || !positiveDecimal(p.Revision) || !positiveDecimal(p.KeyEpoch) || p.IssuedAt < 0 || p.NotBefore < 0 || p.ExpiresAt <= p.IssuedAt || p.NotBefore > p.IssuedAt || p.ExpiresAt-p.IssuedAt > 120 || p.NotBefore < p.IssuedAt-int64(skew) {
		return nil, refuse("INVALID")
	}
	wall := now.Unix()
	if wall < 0 || p.IssuedAt > wall+int64(skew) || p.NotBefore > wall+int64(skew) || p.ExpiresAt <= wall {
		return nil, refuse("EXPIRED")
	}
	if len(p.Users) > 10000 || outerUsers == nil {
		return nil, refuse("USERS_INVALID")
	}
	canonical, _ := json.Marshal(p.Users)
	outer, _ := json.Marshal(outerUsers)
	if !bytes.Equal(canonical, outer) {
		return nil, refuse("USERS_MISMATCH")
	}
	prevID := 0
	uuids := map[string]bool{}
	for _, u := range p.Users {
		if u.ID <= prevID || u.ID > 2147483647 || len(u.UUID) == 0 || len(u.UUID) > 255 || uuids[u.UUID] || u.SpeedLimit < 0 || u.DeviceLimit < 0 {
			return nil, refuse("USERS_INVALID")
		}
		prevID = u.ID
		uuids[u.UUID] = true
	}
	digest := sha256.Sum256(raw)
	return &Snapshot{Payload: p, Users: cloneUsers(p.Users), PayloadBytes: append([]byte(nil), raw...), Digest: hex.EncodeToString(digest[:]), envelope: env}, nil
}

// ValidateJSON checks strict signed-mode transport DTOs before decoding.
func ValidateJSON(raw []byte, v any) error {
	if !utf8.Valid(raw) {
		return refuse("INVALID_JSON")
	}
	return strictJSON(raw, v)
}

func IsRefusal(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), "NODE_AUTHORIZATION_")
}
func refuse(code string) error { return errors.New("NODE_AUTHORIZATION_" + code) }
func decodeBase64(s string, max int) ([]byte, error) {
	if len(s) > base64.RawURLEncoding.EncodedLen(max) || strings.ContainsAny(s, "=\r\n") {
		return nil, refuse("INVALID")
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) > max || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, refuse("INVALID")
	}
	return b, nil
}
func decodeKey(s string) (ed25519.PublicKey, error) {
	b, err := decodeBase64(s, ed25519.PublicKeySize)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, refuse("PUBLIC_KEY_INVALID")
	}
	return ed25519.PublicKey(b), nil
}
func positiveDecimal(s string) bool {
	if !positiveDecimalRE.MatchString(s) {
		return false
	}
	_, err := strconv.ParseInt(s, 10, 64)
	return err == nil
}
func sameMachine(a, b *int) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
func cloneInt(v *int) *int {
	if v == nil {
		return nil
	}
	x := *v
	return &x
}
func cloneUsers(users []panel.User) []panel.User {
	if users == nil {
		return nil
	}
	out := make([]panel.User, len(users))
	copy(out, users)
	return out
}
func cloneSnapshot(s *Snapshot) *Snapshot {
	if s == nil {
		return nil
	}
	out := *s
	out.Users = cloneUsers(s.Users)
	out.Payload.Users = cloneUsers(s.Payload.Users)
	out.Payload.MachineID = cloneInt(s.Payload.MachineID)
	out.PayloadBytes = append([]byte(nil), s.PayloadBytes...)
	return &out
}
func compareDecimal(a, b string) int {
	aa, _ := strconv.ParseInt(a, 10, 64)
	bb, _ := strconv.ParseInt(b, 10, 64)
	if aa < bb {
		return -1
	}
	if aa > bb {
		return 1
	}
	return 0
}
func statePath(dir string) string { return filepath.Join(dir, "state.json") }
func loadState(dir string) (State, bool, error) {
	p := statePath(dir)
	info, err := os.Lstat(p)
	if os.IsNotExist(err) {
		return State{}, false, nil
	}
	if err != nil {
		return State{}, false, refuse("STATE_UNAVAILABLE")
	}
	if !info.Mode().IsRegular() || !privateOwner(info) {
		return State{}, false, refuse("STATE_CORRUPT")
	}
	f, err := openPrivateFile(p, os.O_RDONLY, 0)
	if err != nil {
		return State{}, false, refuse("STATE_UNAVAILABLE")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil || len(raw) > 8192 {
		return State{}, false, refuse("STATE_CORRUPT")
	}
	var stored struct {
		State  State  `json:"state"`
		Digest string `json:"digest"`
	}
	if err := strictJSON(raw, &stored); err != nil {
		return State{}, false, refuse("STATE_CORRUPT")
	}
	data, _ := json.Marshal(stored.State)
	sum := sha256.Sum256(data)
	if stored.Digest != hex.EncodeToString(sum[:]) {
		return State{}, false, refuse("STATE_CORRUPT")
	}
	return stored.State, true, nil
}
func saveState(dir string, st State) error {
	if err := verifyDirectory(dir); err != nil {
		return err
	}
	p := statePath(dir)
	if info, err := os.Lstat(p); err == nil && (!info.Mode().IsRegular() || !privateOwner(info)) {
		return refuse("STATE_CORRUPT")
	}
	raw, _ := json.Marshal(st)
	sum := sha256.Sum256(raw)
	record, _ := json.Marshal(struct {
		State  State  `json:"state"`
		Digest string `json:"digest"`
	}{st, hex.EncodeToString(sum[:])})
	f, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return refuse("STATE_PERSISTENCE_FAILED")
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(record)
	}
	if err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return refuse("STATE_PERSISTENCE_FAILED")
	}
	if err = os.Rename(tmp, p); err != nil {
		return refuse("STATE_PERSISTENCE_FAILED")
	}
	if err := syncDirectory(dir); err != nil {
		return refuse("STATE_PERSISTENCE_FAILED")
	}
	return nil
}

// strictJSON rejects duplicate properties, multiple values, unknown fields and
// excessive nested collections; signatures are verified over the original bytes.
func strictJSON(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := walkJSON(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return refuse("INVALID_JSON")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return refuse("INVALID_JSON")
	}
	return nil
}
func walkJSON(d *json.Decoder, depth int) error {
	if depth > 16 {
		return refuse("INVALID_JSON")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	delimiter, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		keys := map[string]bool{}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := k.(string)
			if !ok || keys[name] {
				return refuse("INVALID_JSON")
			}
			keys[name] = true
			if err := walkJSON(d, depth+1); err != nil {
				return err
			}
		}
		t, err = d.Token()
		if err != nil || t != json.Delim('}') {
			return refuse("INVALID_JSON")
		}
	case '[':
		for d.More() {
			if err := walkJSON(d, depth+1); err != nil {
				return err
			}
		}
		t, err = d.Token()
		if err != nil || t != json.Delim(']') {
			return refuse("INVALID_JSON")
		}
	default:
		return refuse("INVALID_JSON")
	}
	return nil
}
