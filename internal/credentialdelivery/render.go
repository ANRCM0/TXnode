package credentialdelivery

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	RenderContractVersion = "credential-render/1"
	RenderPolicyVersion   = "native-provider-subscription/v1"
	RenderAudience        = "tx-subscription-client-v1"
	RenderFormat          = "native-connection-bundle/v1"
)

type ConnectionTLS struct {
	ServerName string   `json:"server_name"`
	ALPN       []string `json:"alpn"`
}

type ConnectionNode struct {
	NodeID    string         `json:"node_id"`
	MachineID *string        `json:"machine_id"`
	Name      string         `json:"name"`
	Protocol  string         `json:"protocol"`
	Host      string         `json:"host"`
	Port      int            `json:"port"`
	Transport string         `json:"transport"`
	TLS       *ConnectionTLS `json:"tls"`
}

type RenderPayload struct {
	ProtocolVersion       int              `json:"protocol_version"`
	PolicyVersion         string           `json:"policy_version"`
	Audience              string           `json:"audience"`
	CoreInstanceID        string           `json:"core_instance_id"`
	KeyID                 string           `json:"key_id"`
	KeyEpoch              string           `json:"key_epoch"`
	IssuedAt              int64            `json:"issued_at"`
	NotBefore             int64            `json:"not_before"`
	ExpiresAt             int64            `json:"expires_at"`
	GrantID               string           `json:"grant_id"`
	ProviderID            string           `json:"provider_id"`
	ProviderInstanceEpoch string           `json:"provider_instance_epoch"`
	RecipientPublicKey    string           `json:"recipient_public_key"`
	FormatID              string           `json:"format_id"`
	UserID                string           `json:"user_id"`
	Subject               MetadataSubject  `json:"subject"`
	CredentialSHA256      string           `json:"credential_sha256"`
	CredentialExpiresAt   int64            `json:"credential_expires_at"`
	Nodes                 []ConnectionNode `json:"nodes"`
}

type RenderGrant struct {
	Payload      RenderPayload
	PayloadBytes []byte
	Digest       string
}

type RenderRequest struct {
	ContractVersion string   `json:"contract_version"`
	RequestID       string   `json:"request_id"`
	Authorization   Envelope `json:"authorization"`
	Proof           string   `json:"proof"`
}

type RenderConnection struct {
	Node                 ConnectionNode `json:"node"`
	AccessSubjectID      string         `json:"access_subject_id"`
	CredentialRef        string         `json:"credential_ref"`
	CredentialGeneration string         `json:"credential_generation"`
	UUID                 string         `json:"uuid"`
}

type RenderResponse struct {
	ContractVersion     string             `json:"contract_version"`
	RequestID           string             `json:"request_id"`
	AuthorizationDigest string             `json:"authorization_digest"`
	FormatID            string             `json:"format_id"`
	Connections         []RenderConnection `json:"connections"`
}

var renderIDRE = regexp.MustCompile(`^render_[0-9a-f]{32}$`)
var dnsLabelRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func validHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) < 1 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !dnsLabelRE.MatchString(label) {
			return false
		}
	}
	return true
}

func validNode(node ConnectionNode, profile string) bool {
	if !PositiveDecimal(node.NodeID) || node.MachineID != nil && !PositiveDecimal(*node.MachineID) ||
		len(node.Name) < 1 || len(node.Name) > 128 || !utf8.ValidString(node.Name) ||
		strings.IndexFunc(node.Name, unicode.IsControl) >= 0 || !validHost(node.Host) ||
		node.Port < 1 || node.Port > 65535 || node.Transport != "tcp" ||
		(node.Protocol != "vless" && node.Protocol != "vmess") || node.Protocol+"-uuid/v1" != profile {
		return false
	}
	if node.TLS != nil {
		if !validHost(node.TLS.ServerName) || node.TLS.ALPN == nil || len(node.TLS.ALPN) > 2 {
			return false
		}
		seen := map[string]bool{}
		for _, alpn := range node.TLS.ALPN {
			if (alpn != "h2" && alpn != "http/1.1") || seen[alpn] {
				return false
			}
			seen[alpn] = true
		}
	}
	return true
}

func RenderProofMessage(requestID, digest string) []byte {
	return []byte("native-provider-subscription-request/v1\n" + requestID + "\n" + digest + "\n")
}

func VerifyRenderGrant(envelope Envelope, trust Trust, now time.Time) (*RenderGrant, error) {
	if ValidateTrust(trust) != nil {
		return nil, refusal("TRUST_INVALID")
	}
	raw, err := decodeBase64(envelope.Payload, MaxMessageBytes)
	signature, sigErr := decodeBase64(envelope.Signature, ed25519.SignatureSize)
	key, _ := decodeBase64(trust.PublicKey, ed25519.PublicKeySize)
	if err != nil || sigErr != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(ed25519.PublicKey(key), raw, signature) {
		return nil, refusal("SIGNATURE_INVALID")
	}
	var p RenderPayload
	if DecodeStrict(raw, &p) != nil || p.ProtocolVersion != 1 ||
		p.PolicyVersion != RenderPolicyVersion || p.Audience != RenderAudience ||
		p.CoreInstanceID != trust.CoreInstanceID || p.KeyID != trust.KeyID || p.KeyEpoch != trust.KeyEpoch ||
		p.Subject.InstallationID != p.CoreInstanceID || !renderIDRE.MatchString(p.GrantID) ||
		p.FormatID != RenderFormat || !PositiveDecimal(p.UserID) ||
		!digestRE.MatchString(p.CredentialSHA256) || p.CredentialExpiresAt < p.ExpiresAt ||
		p.IssuedAt < 0 || p.NotBefore < 0 || p.NotBefore > p.IssuedAt || p.NotBefore < p.IssuedAt-30 ||
		p.ExpiresAt <= p.IssuedAt || p.ExpiresAt-p.IssuedAt > 30 ||
		p.IssuedAt > now.Unix()+30 || p.NotBefore > now.Unix()+30 || p.ExpiresAt <= now.Unix() ||
		p.Nodes == nil || len(p.Nodes) == 0 || len(p.Nodes) > MaxSubjects {
		return nil, refusal("RENDER_INVALID")
	}
	recipient, err := decodeBase64(p.RecipientPublicKey, ed25519.PublicKeySize)
	if err != nil || len(recipient) != ed25519.PublicKeySize ||
		ValidateMetadataRequest(MetadataRequest{ContractVersion, "render-validation", p.ProviderID, p.ProviderInstanceEpoch, []MetadataSubject{p.Subject}}) != nil {
		return nil, refusal("RENDER_INVALID")
	}
	var previous int64
	for _, node := range p.Nodes {
		id, err := strconv.ParseInt(node.NodeID, 10, 64)
		if err != nil || id <= previous || !validNode(node, p.Subject.CredentialProfileID) {
			return nil, refusal("RENDER_TARGET_INVALID")
		}
		previous = id
	}
	digest := sha256.Sum256(raw)
	return &RenderGrant{Payload: p, PayloadBytes: append([]byte(nil), raw...), Digest: hex.EncodeToString(digest[:])}, nil
}

func VerifyRenderRequest(request RenderRequest, trust Trust, now time.Time) (*RenderGrant, error) {
	if request.ContractVersion != RenderContractVersion || !ValidRequestID(request.RequestID) {
		return nil, refusal("RENDER_INVALID")
	}
	grant, err := VerifyRenderGrant(request.Authorization, trust, now)
	if err != nil {
		return nil, err
	}
	key, _ := decodeBase64(grant.Payload.RecipientPublicKey, ed25519.PublicKeySize)
	proof, err := decodeBase64(request.Proof, ed25519.SignatureSize)
	if err != nil || len(proof) != ed25519.SignatureSize ||
		!ed25519.Verify(ed25519.PublicKey(key), RenderProofMessage(request.RequestID, grant.Digest), proof) {
		return nil, refusal("RECIPIENT_PROOF_INVALID")
	}
	return grant, nil
}
