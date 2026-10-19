package credentialprovider

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type renderCORS map[string]bool

func newRenderCORS(origins []string) (renderCORS, error) {
	if len(origins) > 16 {
		return nil, errors.New("RENDER_CONFIG_INVALID")
	}
	allowed := make(renderCORS, len(origins))
	for _, origin := range origins {
		if !canonicalBrowserOrigin(origin) || allowed[origin] {
			return nil, errors.New("RENDER_CONFIG_INVALID")
		}
		allowed[origin] = true
	}
	return allowed, nil
}

func canonicalBrowserOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Host == "" ||
		u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		u.RawFragment != "" || strings.ContainsAny(origin, " \t\r\n,#?*\\") {
		return false
	}
	host := u.Hostname()
	canonicalHost := host
	if ip := net.ParseIP(host); ip != nil {
		canonicalHost = ip.String()
		if strings.Contains(canonicalHost, ":") {
			canonicalHost = "[" + canonicalHost + "]"
		}
	} else {
		if len(host) > 253 || host != strings.ToLower(host) {
			return false
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return false
			}
			for _, character := range label {
				if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
					return false
				}
			}
		}
		// Numeric dotted hosts must be canonical IP literals, not browser-specific
		// abbreviated, octal or integer address spellings.
		last := host[strings.LastIndex(host, ".")+1:]
		if strings.Trim(last, "0123456789") == "" || strings.HasPrefix(last, "0x") {
			return false
		}
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || n == 443 || strconv.Itoa(n) != port {
			return false
		}
		canonicalHost += ":" + port
	}
	return origin == "https://"+canonicalHost
}

// handle completes rejected requests and preflights without reading a grant or
// credential. It runs only after the public listener's TLS and path guards.
func (allowed renderCORS) handle(w http.ResponseWriter, r *http.Request) bool {
	origins, present := r.Header["Origin"]
	if !present {
		return false
	}
	w.Header().Add("Vary", "Origin")
	if r.Method == http.MethodOptions {
		w.Header().Add("Vary", "Access-Control-Request-Method")
		w.Header().Add("Vary", "Access-Control-Request-Headers")
	}
	deny := func() bool {
		writeDeliveryError(w, http.StatusForbidden, "REQUEST_REJECTED")
		return true
	}
	if len(origins) != 1 || !allowed[origins[0]] || !canonicalBrowserOrigin(origins[0]) {
		return deny()
	}
	for _, name := range []string{"Cookie", "Authorization", "Proxy-Authorization"} {
		if _, exists := r.Header[name]; exists {
			return deny()
		}
	}
	if r.Method == http.MethodOptions {
		methods := r.Header.Values("Access-Control-Request-Method")
		headers := r.Header.Values("Access-Control-Request-Headers")
		if len(methods) != 1 || methods[0] != http.MethodPost || len(headers) != 1 || headers[0] == "" {
			return deny()
		}
		seen := map[string]bool{}
		for _, value := range strings.Split(headers[0], ",") {
			name := strings.ToLower(strings.TrimSpace(value))
			if (name != "content-type" && name != "accept") || seen[name] {
				return deny()
			}
			seen[name] = true
		}
		if !seen["content-type"] {
			return deny()
		}
		w.Header().Set("Access-Control-Allow-Origin", origins[0])
		w.Header().Set("Access-Control-Allow-Methods", http.MethodPost)
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept")
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	w.Header().Set("Access-Control-Allow-Origin", origins[0])
	w.Header().Set("Access-Control-Expose-Headers", "Content-Type, Content-Disposition, Content-Encoding, X-TXBoard-Format, X-TXBoard-Authorization-Digest")
	return false
}
