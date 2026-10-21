package credentialdelivery

import (
	"crypto/sha256"
	"encoding/hex"
	"unicode/utf8"
)

const ClientTemplateEngine = "tx-template/v1"
const MaxTemplateBytes = 65536

// The Core signature binds the entire source; the provider never loads a URL.
type ClientTemplate struct {
	Engine   string `json:"engine"`
	FormatID string `json:"format_id"`
	Version  string `json:"version"`
	SHA256   string `json:"sha256"`
	Source   string `json:"source"`
}

func ValidClientTemplate(t *ClientTemplate, format string) bool {
	if t == nil {
		return true
	}
	if format == RenderFormat || t.FormatID != format || t.Engine != ClientTemplateEngine || !digestRE.MatchString(t.Version) ||
		!digestRE.MatchString(t.SHA256) || len(t.Source) < 1 || len(t.Source) > MaxTemplateBytes || !utf8.ValidString(t.Source) {
		return false
	}
	hash := sha256.Sum256([]byte(t.Source))
	return hex.EncodeToString(hash[:]) == t.SHA256
}
