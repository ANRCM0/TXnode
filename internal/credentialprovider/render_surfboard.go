package credentialprovider

import (
	"errors"
	"strconv"
	"strings"
	"unicode"

	"github.com/ANRCM0/TX-Node/internal/credentialdelivery"
)

// Surfboard's documented VMess subset uses a separate signed client target.
func renderSurfboardDocument(connections []credentialdelivery.RenderConnection) (renderedDocument, error) {
	if len(connections) == 0 || len(connections) > credentialdelivery.MaxSubjects {
		return renderedDocument{}, errors.New("RENDER_CONNECTIONS_INVALID")
	}
	names, lines := make([]string, 0, len(connections)), make([]string, 0, len(connections))
	for _, c := range connections {
		n := c.Node
		if !credentialdelivery.CompatibleRenderNode(credentialdelivery.RenderSurfboard, n) || !uuidPattern.MatchString(c.UUID) {
			return renderedDocument{}, errors.New("RENDER_PROTOCOL_UNSUPPORTED")
		}
		label := strings.Map(func(r rune) rune {
			if unicode.IsLetter(r) || unicode.IsNumber(r) || strings.ContainsRune(" ._-", r) {
				return r
			}
			return ' '
		}, n.Name)
		name := strings.TrimSpace("TX-" + n.NodeID + " " + strings.Join(strings.Fields(label), " "))
		fields := []string{name + " = vmess", n.Host, strconv.Itoa(n.Port), "username=" + c.UUID, "vmess-aead=true", "tfo=true"}
		if n.TLS != nil {
			fields = append(fields, "tls=true", "skip-cert-verify=false", "sni="+n.TLS.ServerName)
		}
		names = append(names, name)
		lines = append(lines, strings.Join(fields, ", "))
	}
	body := []byte("[General]\n\n[Proxy]\n" + strings.Join(lines, "\n") + "\n\n[Proxy Group]\nTXBoard = select, " + strings.Join(names, ", ") + "\n\n[Rule]\nFINAL,TXBoard\n")
	return renderedDocument{body, "text/plain; charset=utf-8", "txboard-surfboard.conf"}, nil
}
