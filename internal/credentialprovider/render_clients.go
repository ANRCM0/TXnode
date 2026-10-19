package credentialprovider

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/ANRCM0/TX-Node/internal/credentialdelivery"
	"gopkg.in/yaml.v3"
)

// Only the Provider calls this, after signature, recipient proof and live-state
// admission. Client formats never export credential references or owner rows.
type renderedDocument struct {
	body        []byte
	contentType string
	filename    string
}

func renderClientDocument(format string, connections []credentialdelivery.RenderConnection) (renderedDocument, error) {
	if len(connections) == 0 || len(connections) > credentialdelivery.MaxSubjects {
		return renderedDocument{}, errors.New("RENDER_CONNECTIONS_INVALID")
	}
	if format == credentialdelivery.RenderSurgeIOS || format == credentialdelivery.RenderSurgeMac {
		return renderSurgeDocument(format, connections)
	}
	names := make([]string, 0, len(connections))
	entries := make([]map[string]any, 0, len(connections))
	for _, connection := range connections {
		node := connection.Node
		name := node.Name + " [" + node.NodeID + "]"
		names = append(names, name)
		if !credentialdelivery.CompatibleRenderNode(format, node) || !uuidPattern.MatchString(connection.UUID) {
			return renderedDocument{}, errors.New("RENDER_PROTOCOL_UNSUPPORTED")
		}
		switch format {
		case "clash/v1", "clash-meta/v1":
			entry := map[string]any{"name": name, "type": node.Protocol, "server": node.Host,
				"port": node.Port, "uuid": connection.UUID, "network": "tcp", "udp": true}
			if node.Protocol == "vmess" {
				entry["alterId"] = 0
				entry["cipher"] = "auto"
			}
			if node.TLS != nil {
				entry["tls"] = true
				entry["servername"] = node.TLS.ServerName
				entry["skip-cert-verify"] = false
				if len(node.TLS.ALPN) > 0 {
					entry["alpn"] = node.TLS.ALPN
				}
			}
			entries = append(entries, entry)
		case "sing-box/v1":
			entry := map[string]any{"tag": name, "type": node.Protocol, "server": node.Host,
				"server_port": node.Port, "uuid": connection.UUID}
			if node.Protocol == "vmess" {
				entry["security"] = "auto"
				entry["alter_id"] = 0
			}
			if node.TLS != nil {
				tls := map[string]any{"enabled": true, "server_name": node.TLS.ServerName, "insecure": false}
				if len(node.TLS.ALPN) > 0 {
					tls["alpn"] = node.TLS.ALPN
				}
				entry["tls"] = tls
			}
			entries = append(entries, entry)
		case "shadowrocket/v1":
			// Serialized below; URI components are encoded rather than interpolated.
		default:
			return renderedDocument{}, errors.New("RENDER_FORMAT_UNSUPPORTED")
		}
	}
	switch format {
	case "clash/v1", "clash-meta/v1":
		config := map[string]any{"mode": "rule", "proxies": entries,
			"proxy-groups": []any{map[string]any{"name": "TXBoard", "type": "select", "proxies": names}},
			"rules":        []string{"MATCH,TXBoard"}}
		body, err := yaml.Marshal(config)
		if format == credentialdelivery.RenderClash {
			return renderedDocument{body, "application/yaml", "txboard-clash-classic.yaml"}, err
		}
		return renderedDocument{body, "application/yaml", "txboard-clash.yaml"}, err
	case "sing-box/v1":
		outbounds := append([]map[string]any{{"type": "selector", "tag": "TXBoard", "outbounds": names}}, entries...)
		body, err := json.MarshalIndent(map[string]any{"outbounds": outbounds,
			"route": map[string]any{"final": "TXBoard"}}, "", "  ")
		return renderedDocument{append(body, '\n'), "application/json", "txboard-sing-box.json"}, err
	default:
		lines := make([]string, 0, len(connections))
		for index, connection := range connections {
			node := connection.Node
			if node.Protocol == "vless" {
				query := url.Values{"encryption": {"none"}, "type": {"tcp"}, "security": {"none"}}
				if node.TLS != nil {
					query.Set("security", "tls")
					query.Set("sni", node.TLS.ServerName)
					if len(node.TLS.ALPN) > 0 {
						query.Set("alpn", strings.Join(node.TLS.ALPN, ","))
					}
				}
				link := url.URL{Scheme: "vless", User: url.User(connection.UUID),
					Host: net.JoinHostPort(node.Host, strconv.Itoa(node.Port)), RawQuery: query.Encode(), Fragment: names[index]}
				lines = append(lines, link.String())
			} else {
				entry := map[string]any{"v": "2", "ps": names[index], "add": node.Host,
					"port": strconv.Itoa(node.Port), "id": connection.UUID, "aid": "0", "scy": "auto",
					"net": "tcp", "type": "none", "host": "", "path": "", "tls": ""}
				if node.TLS != nil {
					entry["tls"] = "tls"
					entry["sni"] = node.TLS.ServerName
					if len(node.TLS.ALPN) > 0 {
						entry["alpn"] = strings.Join(node.TLS.ALPN, ",")
					}
				}
				body, err := json.Marshal(entry)
				if err != nil {
					return renderedDocument{}, errors.New("RENDER_SERIALIZATION_FAILED")
				}
				lines = append(lines, "vmess://"+base64.StdEncoding.EncodeToString(body))
			}
		}
		body := base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n") + "\n"))
		return renderedDocument{[]byte(body + "\n"), "text/plain; charset=utf-8", "txboard-shadowrocket.txt"}, nil
	}
}
