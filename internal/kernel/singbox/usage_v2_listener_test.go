package singbox

import (
	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/model"
	"testing"
)

func TestBoundedListenerScopePreservesNativeDefault(t *testing.T) {
	for _, protocol := range []string{"vless", "vmess"} {
		t.Run(protocol, func(t *testing.T) {
			native := buildConfig(config.KernelConfig{LogLevel: "error"}, &model.NodeSpec{Protocol: protocol, ServerPort: 12345}, nil, kernel.TLSCert{})
			if native["inbounds"].([]M)[0]["listen"] != "::" {
				t.Fatal("native default changed")
			}
			isolated := buildConfig(config.KernelConfig{LogLevel: "error"}, &model.NodeSpec{Protocol: protocol, ServerPort: 12345}, nil, kernel.TLSCert{})
			if err := isolateBoundedListeners(isolated); err != nil {
				t.Fatal(err)
			}
			if isolated["inbounds"].([]M)[0]["listen"] != "127.0.0.1" {
				t.Fatal("bounded listener escaped loopback")
			}
			if native["inbounds"].([]M)[0]["listen"] != "::" {
				t.Fatal("isolated mutation affected native config")
			}
		})
	}
}
func TestBoundedListenerScopeRejectsWholeMalformedSet(t *testing.T) {
	cases := []M{{}, {"inbounds": []M{}}, {"inbounds": []any{M{"type": "vless", "listen": "::", "listen_port": 12345}}}, {"inbounds": []M{{"type": "", "listen": "::", "listen_port": 12345}}}, {"inbounds": []M{{"type": "vless", "listen": "::", "listen_port": 0}}}, {"inbounds": []M{{"type": "vless", "listen": "::", "listen_port": 65536}}}, {"inbounds": []M{{"type": "vless", "listen": "::", "listen_port": 12345}, {"type": "vmess", "listen": "::", "listen_port": "12345"}}}}
	for _, cfg := range cases {
		if isolateBoundedListeners(cfg) == nil {
			t.Fatal("malformed generated inbound admitted", cfg)
		}
	}
	last := cases[len(cases)-1]["inbounds"].([]M)
	if last[0]["listen"] != "::" {
		t.Fatal("partial inbound set mutated before validation")
	}
}
