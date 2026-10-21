package credentialprovider

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"text/template"
	"text/template/parse"
	"unicode/utf8"

	"github.com/ANRCM0/TX-Node/internal/credentialdelivery"
	"gopkg.in/yaml.v3"
)

var errTemplate = errors.New("CLIENT_TEMPLATE_INVALID")

type templateConnection struct {
	Name string
	Node credentialdelivery.ConnectionNode
	UUID string
}

type templateData struct {
	Format      string
	Connections []templateConnection
	Default     string
}

type templateWriter struct{ bytes.Buffer }

func (w *templateWriter) Write(p []byte) (int, error) {
	if len(p) > credentialdelivery.MaxMessageBytes-w.Len() {
		return 0, errTemplate
	}
	return w.Buffer.Write(p)
}

// Only inert values and bounded encoders are exposed. Recursive invocation,
// nested ranges and integer/channel iteration are rejected before execution.
func parseClientTemplate(source string) (*template.Template, error) {
	if len(source) < 1 || len(source) > credentialdelivery.MaxTemplateBytes || !utf8.ValidString(source) || strings.ContainsRune(source, 0) {
		return nil, errTemplate
	}
	encodeJSON := func(v any) (string, error) {
		p, e := json.Marshal(v)
		if len(p) > credentialdelivery.MaxMessageBytes {
			return "", errTemplate
		}
		return string(p), e
	}
	encodeYAML := func(v any) (string, error) {
		p, e := yaml.Marshal(v)
		if len(p) > credentialdelivery.MaxMessageBytes {
			return "", errTemplate
		}
		return string(p), e
	}
	t, err := template.New("client").Option("missingkey=error").Funcs(template.FuncMap{
		"json": encodeJSON, "yaml": encodeYAML, "quote": func(v string) (string, error) { return encodeJSON(v) },
		"urlquery": func(v string) (string, error) {
			if len(v) > credentialdelivery.MaxMessageBytes {
				return "", errTemplate
			}
			escaped := url.QueryEscape(v)
			if len(escaped) > credentialdelivery.MaxMessageBytes {
				return "", errTemplate
			}
			return escaped, nil
		},
		"base64": func(v string) (string, error) {
			if base64.StdEncoding.EncodedLen(len(v)) > credentialdelivery.MaxMessageBytes {
				return "", errTemplate
			}
			return base64.StdEncoding.EncodeToString([]byte(v)), nil
		},
	}).Parse(source)
	if err != nil || len(t.Templates()) != 1 {
		return nil, errTemplate
	}
	count := 0
	var visit func(parse.Node, int) bool
	visit = func(n parse.Node, ranges int) bool {
		if n == nil {
			return true
		}
		count++
		if count > 1024 {
			return false
		}
		switch x := n.(type) {
		case *parse.ListNode:
			if x == nil {
				return true
			}
			for _, v := range x.Nodes {
				if !visit(v, ranges) {
					return false
				}
			}
		case *parse.ActionNode:
			return visit(x.Pipe, ranges)
		case *parse.PipeNode:
			for _, v := range x.Cmds {
				if !visit(v, ranges) {
					return false
				}
			}
		case *parse.CommandNode:
			for _, v := range x.Args {
				if !visit(v, ranges) {
					return false
				}
			}
		case *parse.IdentifierNode:
			switch x.Ident {
			case "json", "yaml", "quote", "urlquery", "base64", "eq", "ne", "lt", "le", "gt", "ge", "and", "or", "not", "len":
			default:
				return false
			}
		case *parse.IfNode:
			return visit(x.Pipe, ranges) && visit(x.List, ranges) && visit(x.ElseList, ranges)
		case *parse.WithNode:
			return visit(x.Pipe, ranges) && visit(x.List, ranges) && visit(x.ElseList, ranges)
		case *parse.RangeNode:
			if ranges > 0 || len(x.Pipe.Cmds) != 1 || len(x.Pipe.Cmds[0].Args) != 1 {
				return false
			}
			field, ok := x.Pipe.Cmds[0].Args[0].(*parse.FieldNode)
			if !ok || len(field.Ident) != 1 || field.Ident[0] != "Connections" {
				return false
			}
			return visit(x.Pipe, ranges+1) && visit(x.List, ranges+1) && visit(x.ElseList, ranges+1)
		case *parse.TemplateNode, *parse.ChainNode:
			return false
		}
		return true
	}
	if !visit(t.Tree.Root, 0) {
		return nil, errTemplate
	}
	return t, nil
}

func renderTemplateDocument(format, source string, connections []credentialdelivery.RenderConnection) (renderedDocument, error) {
	builtin, err := renderClientDocument(format, connections)
	if err != nil {
		return renderedDocument{}, err
	}
	t, err := parseClientTemplate(source)
	if err != nil {
		return renderedDocument{}, err
	}
	data := templateData{Format: format, Default: string(builtin.body), Connections: make([]templateConnection, 0, len(connections))}
	for _, c := range connections {
		data.Connections = append(data.Connections, templateConnection{c.Node.Name + " [" + c.Node.NodeID + "]", c.Node, c.UUID})
	}
	var w templateWriter
	if t.Execute(&w, data) != nil || w.Len() == 0 || !utf8.Valid(w.Bytes()) || bytes.IndexByte(w.Bytes(), 0) >= 0 {
		return renderedDocument{}, errTemplate
	}
	switch format {
	case credentialdelivery.RenderClash, credentialdelivery.RenderClashMeta, credentialdelivery.RenderStash:
		var document map[string]any
		decoder := yaml.NewDecoder(bytes.NewReader(w.Bytes()))
		if decoder.Decode(&document) != nil || document == nil {
			return renderedDocument{}, errTemplate
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			return renderedDocument{}, errTemplate
		}
	case credentialdelivery.RenderSingBox:
		var document map[string]any
		if json.Unmarshal(w.Bytes(), &document) != nil || document == nil {
			return renderedDocument{}, errTemplate
		}
	case credentialdelivery.RenderSurgeIOS, credentialdelivery.RenderSurgeMac, credentialdelivery.RenderSurfboard:
		section := ""
		for _, line := range strings.Split(w.String(), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			if strings.HasPrefix(line, "[") {
				if !strings.HasSuffix(line, "]") || len(line) < 3 || strings.ContainsAny(line[1:len(line)-1], "[]") {
					return renderedDocument{}, errTemplate
				}
				section = line[1 : len(line)-1]
				continue
			}
			if section == "" {
				return renderedDocument{}, errTemplate
			}
			if section == "Rule" {
				if !strings.Contains(line, ",") {
					return renderedDocument{}, errTemplate
				}
			} else if key, _, ok := strings.Cut(line, "="); !ok || strings.TrimSpace(key) == "" {
				return renderedDocument{}, errTemplate
			}
		}
		if section == "" {
			return renderedDocument{}, errTemplate
		}
	case credentialdelivery.RenderShadowrocket:
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(w.String()))
		if err != nil || len(decoded) == 0 {
			return renderedDocument{}, errTemplate
		}
		for _, line := range strings.Split(strings.TrimSpace(string(decoded)), "\n") {
			if strings.HasPrefix(line, "vless://") {
				link, err := url.Parse(line)
				if err != nil || link.User == nil || !credentialdelivery.ValidUUID(link.User.Username()) || link.Hostname() == "" || link.Port() == "" {
					return renderedDocument{}, errTemplate
				}
			} else if strings.HasPrefix(line, "vmess://") {
				raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "vmess://"))
				var link map[string]any
				if err != nil || json.Unmarshal(raw, &link) != nil || link["id"] == nil || link["add"] == nil {
					return renderedDocument{}, errTemplate
				}
			} else {
				return renderedDocument{}, errTemplate
			}
		}
	}
	builtin.body = append([]byte(nil), w.Bytes()...)
	return builtin, nil
}
