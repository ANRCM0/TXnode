package credentialprovider

import (
	"errors"
	"strconv"
	"strings"
	"unicode"

	"github.com/ANRCM0/TX-Node/internal/credentialdelivery"
)

// VMess field mapping adapted from Xboard app/Protocols/Surge.php (MIT).
// Copyright (c) 2019 Tokumeikoi. Full notice: licenses/Xboard-MIT.txt.
func renderSurgeDocument(format string, connections []credentialdelivery.RenderConnection) (renderedDocument, error) {
	if len(connections) == 0 || len(connections) > credentialdelivery.MaxSubjects ||
		(format != credentialdelivery.RenderSurgeIOS && format != credentialdelivery.RenderSurgeMac) {
		return renderedDocument{}, errors.New("RENDER_FORMAT_UNSUPPORTED")
	}
	names, lines := make([]string, 0, len(connections)), make([]string, 0, len(connections))
	for _, connection := range connections {
		node := connection.Node
		if !credentialdelivery.CompatibleRenderNode(format, node) || !uuidPattern.MatchString(connection.UUID) {
			return renderedDocument{}, errors.New("RENDER_PROTOCOL_UNSUPPORTED")
		}
		// Prefix immutable IDs; remove INI delimiters and comment syntax from display labels.
		label := strings.Map(func(value rune) rune {
			if unicode.IsLetter(value) || unicode.IsNumber(value) || strings.ContainsRune(" ._-", value) {
				return value
			}
			return ' '
		}, node.Name)
		name := strings.TrimSpace("TX-" + node.NodeID + " " + strings.Join(strings.Fields(label), " "))
		fields := []string{name + " = vmess", node.Host, strconv.Itoa(node.Port), "username=" + connection.UUID,
			"vmess-aead=true", "encrypt-method=aes-128-gcm", "tfo=true"}
		if node.TLS != nil {
			fields = append(fields, "tls=true", "skip-cert-verify=false", "sni="+node.TLS.ServerName)
			if len(node.TLS.ALPN) > 0 {
				fields = append(fields, "alpn="+strconv.Quote(strings.Join(node.TLS.ALPN, ",")))
			}
		}
		names, lines = append(names, name), append(lines, strings.Join(fields, ", "))
	}
	body := []byte("[General]\nloglevel = notify\n\n[Proxy]\n" + strings.Join(lines, "\n") +
		"\n\n[Proxy Group]\nTXBoard = select, " + strings.Join(names, ", ") + "\n\n[Rule]\nFINAL,TXBoard\n")
	if format == credentialdelivery.RenderSurgeIOS {
		return renderedDocument{body, "text/plain; charset=utf-8", "txboard-surge-ios.conf"}, nil
	}
	return renderedDocument{body, "text/plain; charset=utf-8", "txboard-surge-mac.conf"}, nil
}
