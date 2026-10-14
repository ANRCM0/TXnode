package singbox

import (
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/model"
)

// ErrFullRestartRequired is returned before mutating a running construction.
// Service must stop the old instance before starting the complete desired one.
var ErrFullRestartRequired = errors.New("FULL_RESTART_REQUIRED")

func runtimeConstructionHash(cfg config.KernelConfig, node *model.NodeSpec, tls kernel.TLSCert) ([32]byte, error) {
	if node == nil {
		return [32]byte{}, errors.New("KERNEL_CONFIG_INVALID")
	}
	// Fail visibly instead of allowing buildConfig's optional custom-config
	// loader to discard a malformed source and silently keep old runtime effects.
	if _, err := kernel.LoadCustomConfig(cfg.CustomConfig); err != nil {
		return [32]byte{}, errors.New("KERNEL_CUSTOM_CONFIG_INVALID")
	}
	// A fixed representative identity removes credentials/count/order from this
	// comparison while retaining per-user construction fields such as VLESS Flow.
	// Only the private digest is retained; raw config or its digest is never logged.
	representative := []model.UserSpec{{ID: 1, UUID: "00000000-0000-0000-0000-000000000001"}}
	body, err := json.Marshal(buildConfig(cfg, node, representative, tls))
	if err != nil {
		return [32]byte{}, errors.New("KERNEL_CONFIG_ENCODE_FAILED")
	}
	if err := validateConstructionReferences(body); err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(body), nil
}

// validateConstructionReferences checks references after local/panel settings
// have been merged. Raw rules bypass the structured model's target validation;
// sing-box can accept their options yet defer a missing outbound until traffic.
func validateConstructionReferences(body []byte) error {
	var construction map[string]any
	if err := json.Unmarshal(body, &construction); err != nil {
		return errors.New("KERNEL_CONFIG_PARSE_FAILED")
	}
	tags := make(map[string]bool)
	// Endpoints such as WireGuard participate in the routing outbound namespace.
	for _, key := range []string{"outbounds", "endpoints"} {
		entries, _ := construction[key].([]any)
		for _, entry := range entries {
			object, ok := entry.(map[string]any)
			if !ok {
				return errors.New("KERNEL_CONFIG_INVALID")
			}
			tag, ok := object["tag"].(string)
			if !ok || tag == "" {
				continue
			} // unnamed upstream entries are legal but cannot be referenced
			if tags[tag] {
				return errors.New("KERNEL_OUTBOUND_TAG_DUPLICATE")
			}
			tags[tag] = true
		}
	}
	check := func(value any) error {
		if value == nil {
			return nil
		}
		name, ok := value.(string)
		if !ok {
			return errors.New("KERNEL_CONFIG_INVALID")
		}
		if name != "" && !tags[name] {
			return errors.New("KERNEL_ROUTE_OUTBOUND_UNKNOWN")
		}
		return nil
	}
	var checkRules func(any) error
	checkRules = func(value any) error {
		if value == nil {
			return nil
		}
		rules, ok := value.([]any)
		if !ok {
			return errors.New("KERNEL_CONFIG_INVALID")
		}
		for _, rule := range rules {
			object, ok := rule.(map[string]any)
			if !ok {
				return errors.New("KERNEL_CONFIG_INVALID")
			}
			// Empty/default action means route. Reject/direct/sniff actions have no
			// outbound reference; a malformed field is left to option shape validation.
			action, _ := object["action"].(string)
			if action == "" || action == "route" || action == "bypass" {
				if err := check(object["outbound"]); err != nil {
					return err
				}
			}
			if nested, exists := object["rules"]; exists {
				if err := checkRules(nested); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if route, ok := construction["route"].(map[string]any); ok {
		if err := check(route["final"]); err != nil {
			return err
		}
		if err := checkRules(route["rules"]); err != nil {
			return err
		}
	}
	for _, key := range []string{"outbounds", "endpoints"} {
		entries, _ := construction[key].([]any)
		for _, entry := range entries {
			object := entry.(map[string]any)
			for _, key := range []string{"detour", "proxy_tag"} {
				if err := check(object[key]); err != nil {
					return err
				}
			}
			kind, _ := object["type"].(string)
			if kind == "selector" || kind == "urltest" {
				if members, exists := object["outbounds"]; exists {
					names, ok := members.([]any)
					if !ok {
						return errors.New("KERNEL_CONFIG_INVALID")
					}
					for _, name := range names {
						if err := check(name); err != nil {
							return err
						}
					}
				}
				if kind == "selector" {
					if err := check(object["default"]); err != nil {
						return err
					}
				}
			}
		}
	}
	if dns, ok := construction["dns"].(map[string]any); ok {
		servers, _ := dns["servers"].([]any)
		for _, server := range servers {
			if object, ok := server.(map[string]any); ok {
				if err := check(object["detour"]); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
