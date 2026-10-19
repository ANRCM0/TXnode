package txnode

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ANRCM0/TX-Node/internal/dataplane/core"
	"github.com/ANRCM0/TX-Node/internal/dataplane/opt"
	"github.com/ANRCM0/TX-Node/internal/dataplane/outbound"
	"github.com/ANRCM0/TX-Node/internal/model"
)

// compileRouter turns the panel's routes and custom outbounds into the data
// plane router. It is the native replacement for the sing-box/xray JSON
// compilers: the rule vocabulary is core.Rule's ("kind:value" tokens) and the
// outbounds are built with outbound.New.
func compileRouter(nc *model.NodeSpec, rt RuntimeConfig, log *slog.Logger) (*core.Router, error) {
	loadGeo(rt.GeoDataDir, log)

	r := core.NewRouter()
	r.BlockBitTorrent = rt.ForbiddenBitTorrent
	r.BlockPrivate = rt.ForbiddenPrivateIP

	if err := addCustomOutbounds(r, nc.CustomOutbounds, log); err != nil {
		return nil, err
	}
	for _, pr := range nc.Routes {
		if err := addPanelRoute(r, pr, rt, log); err != nil {
			return nil, err
		}
	}
	for _, cr := range nc.CustomRouteRules {
		if err := addCustomRoute(r, cr, log); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(rt.ForbiddenPorts) != "" {
		rule := core.NewRule("forbidden_ports", core.ActionBlock)
		if err := rule.AddMatch("port:" + rt.ForbiddenPorts); err != nil {
			log.Warn("forbidden_ports ignored", "err", err)
		} else {
			r.Rules = append(r.Rules, rule)
		}
	}
	return r, nil
}

func loadGeo(dir string, log *slog.Logger) {
	if strings.TrimSpace(dir) == "" {
		return
	}
	for _, name := range []string{"geosite.dat", "geoip.dat"} {
		path := filepath.Join(dir, name)
		if _, err := core.LoadGeo(path); err != nil {
			if !os.IsNotExist(err) {
				log.Warn("geo data", "path", path, "err", err)
			}
		}
	}
}

func addCustomOutbounds(r *core.Router, list []model.OutboundConfig, log *slog.Logger) error {
	if len(list) == 0 {
		return nil
	}
	tagOf := func(o model.OutboundConfig) string {
		if t := strings.TrimSpace(o.Tag); t != "" {
			return t
		}
		return strings.ToLower(strings.TrimSpace(o.Protocol))
	}
	// Two passes: later outbounds may chain through earlier ones regardless of
	// their order in the panel payload.
	pending := make([]model.OutboundConfig, 0, len(list))
	for _, ob := range list {
		if strings.TrimSpace(ob.ProxyTag) != "" {
			pending = append(pending, ob)
			continue
		}
		if err := buildOne(r, ob, nil, log); err != nil {
			return err
		}
	}
	for _, ob := range pending {
		tag := tagOf(ob)
		up, ok := r.Outbounds[strings.TrimSpace(ob.ProxyTag)]
		if !ok {
			return fmt.Errorf("custom_outbounds[%s]: proxy_tag %q is not defined", tag, ob.ProxyTag)
		}
		if err := buildOne(r, ob, []core.Outbound{up}, log); err != nil {
			return err
		}
	}
	return nil
}

func buildOne(r *core.Router, ob model.OutboundConfig, via []core.Outbound, log *slog.Logger) error {
	tag := strings.TrimSpace(ob.Tag)
	if tag == "" {
		tag = strings.ToLower(strings.TrimSpace(ob.Protocol))
	}
	o := opt.Opt{}
	for k, v := range ob.Settings {
		o[k] = v
	}
	if len(via) > 0 {
		o["_kaze_via"] = via
	}
	built, err := outbound.New(strings.ToLower(strings.TrimSpace(ob.Protocol)), o)
	if err != nil {
		return fmt.Errorf("custom_outbounds[%s]: %w", tag, err)
	}
	r.SetOutbound(tag, built)
	log.Debug("custom outbound", "tag", tag, "protocol", ob.Protocol)
	return nil
}

// addPanelRoute compiles one panel route. Domains keep sing-box's domain_suffix
// semantics ("domain:" in the rule vocabulary); CIDRs become "ip:".
func addPanelRoute(r *core.Router, pr model.RouteRule, rt RuntimeConfig, log *slog.Logger) error {
	if len(pr.Match) == 0 {
		return nil
	}
	name := fmt.Sprintf("panel#%d", pr.ID)
	action := strings.ToLower(strings.TrimSpace(pr.Action))
	value := strings.TrimSpace(pr.ActionValue)

	switch action {
	case "default_out":
		tag, proto, settings, err := resolveActionOutbound(value, r)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if tag == "" && proto == "" {
			// direct
			r.SetDefault("")
			return nil
		}
		if proto != "" {
			tag = name
			if err := buildInlineOutbound(r, tag, proto, settings); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
		r.SetDefault(tag)
		return nil
	}

	var domains, cidrs []string
	for _, item := range pr.Match {
		item = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(item), "*."))
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			cidrs = append(cidrs, item)
			continue
		}
		if strings.Contains(item, ":") {
			// Already a kind:value token ("domain:x", "port:443", ...).
			domains = append(domains, item)
			continue
		}
		domains = append(domains, "domain:"+item)
	}

	mk := func(matches []string, suffix string) (*core.Rule, error) {
		rule := core.NewRule(name+suffix, core.ActionBlock)
		used := false
		for _, m := range matches {
			if err := rule.AddMatch(m); err != nil {
				log.Warn("panel rule match ignored", "rule", name, "match", m, "err", err)
				continue
			}
			used = true
		}
		if !used {
			return nil, nil
		}
		switch action {
		case "", "block", "reject", "blackhole":
			rule.Action = core.ActionBlock
		case "direct", "freedom":
			rule.Action = core.ActionDirect
		case "dns":
			server := value
			if server == "" {
				rule.Action = core.ActionDirect
				break
			}
			res, err := core.NewResolver(server, rt.DNSStrategy, rt.DNSCacheTTL)
			if err != nil {
				return nil, fmt.Errorf("%s: dns %q: %w", name, server, err)
			}
			rule.Action = core.ActionDNS
			rule.Resolver = res
		case "proxy", "route", "route_ip":
			tag := value
			if tag == "" {
				rule.Action = core.ActionBlock
				break
			}
			if _, ok := r.Outbounds[tag]; !ok {
				return nil, fmt.Errorf("%s: outbound %q is not defined", name, tag)
			}
			rule.Action = core.ActionProxy
			rule.Outbound = tag
		default:
			return nil, fmt.Errorf("%s: action %q is not supported", name, pr.Action)
		}
		return rule, nil
	}

	if len(domains) > 0 {
		rule, err := mk(domains, "")
		if err != nil {
			return err
		}
		if rule != nil {
			r.Rules = append(r.Rules, rule)
		}
	}
	if len(cidrs) > 0 {
		prefixed := make([]string, 0, len(cidrs))
		for _, c := range cidrs {
			prefixed = append(prefixed, "ip:"+c)
		}
		rule, err := mk(prefixed, "#ip")
		if err != nil {
			return err
		}
		if rule != nil {
			r.Rules = append(r.Rules, rule)
		}
	}
	return nil
}

// addCustomRoute compiles one structured custom route rule. Each match family
// becomes its own rule so the panel's "any of these matchers" semantics survive
// (core.Rule ANDs the families inside one rule).
func addCustomRoute(r *core.Router, cr model.CustomRouteRule, log *slog.Logger) error {
	if cr.Disabled {
		return nil
	}
	name := strings.TrimSpace(cr.Name)
	if name == "" {
		name = "custom"
	}
	if len(cr.Match.SourceCIDRs) > 0 || len(cr.Match.SourcePorts) > 0 {
		return fmt.Errorf("custom_route_rules[%s]: source_cidrs/source_ports are not supported by kernel \"txnode\"", name)
	}

	action := strings.ToLower(strings.TrimSpace(cr.Action.Type))
	target := strings.TrimSpace(cr.Action.Target)

	groups := [][]string{}
	if len(cr.Match.Domains) > 0 {
		items := make([]string, 0, len(cr.Match.Domains))
		for _, d := range cr.Match.Domains {
			items = append(items, "full:"+d)
		}
		groups = append(groups, items)
	}
	if len(cr.Match.DomainSuffixes) > 0 {
		items := make([]string, 0, len(cr.Match.DomainSuffixes))
		for _, d := range cr.Match.DomainSuffixes {
			items = append(items, "domain:"+d)
		}
		groups = append(groups, items)
	}
	if len(cr.Match.IPCIDRs) > 0 {
		items := make([]string, 0, len(cr.Match.IPCIDRs))
		for _, c := range cr.Match.IPCIDRs {
			items = append(items, "ip:"+c)
		}
		groups = append(groups, items)
	}
	if len(cr.Match.Ports) > 0 {
		items := make([]string, 0, len(cr.Match.Ports))
		for _, p := range cr.Match.Ports {
			items = append(items, "port:"+p)
		}
		groups = append(groups, items)
	}
	if len(cr.Match.Networks) > 0 {
		items := make([]string, 0, len(cr.Match.Networks))
		for _, n := range cr.Match.Networks {
			items = append(items, "network:"+n)
		}
		groups = append(groups, items)
	}
	if len(groups) == 0 {
		return nil
	}

	for i, matches := range groups {
		rule := core.NewRule(fmt.Sprintf("custom#%s#%d", name, i), core.ActionBlock)
		used := false
		for _, m := range matches {
			if err := rule.AddMatch(m); err != nil {
				log.Warn("custom route match ignored", "rule", name, "match", m, "err", err)
				continue
			}
			used = true
		}
		if !used {
			continue
		}
		switch action {
		case "direct":
			rule.Action = core.ActionDirect
		case "route", "proxy":
			if target == "" {
				rule.Action = core.ActionBlock
				break
			}
			if _, ok := r.Outbounds[target]; !ok {
				return fmt.Errorf("custom_route_rules[%s]: outbound %q is not defined", name, target)
			}
			rule.Action = core.ActionProxy
			rule.Outbound = target
		default:
			rule.Action = core.ActionBlock
		}
		r.Rules = append(r.Rules, rule)
	}
	return nil
}

// resolveActionOutbound accepts either a bare outbound tag or the panel's
// JSON-in-a-string outbound object (the shape the production panel sends for
// default_out / route actions).
func resolveActionOutbound(value string, r *core.Router) (tag, protocol string, settings map[string]any, err error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", nil, nil
	}
	if !strings.HasPrefix(value, "{") {
		if _, ok := r.Outbounds[value]; !ok {
			return "", "", nil, fmt.Errorf("outbound %q is not defined", value)
		}
		return value, "", nil, nil
	}
	var parsed struct {
		Tag      string         `json:"tag"`
		Protocol string         `json:"protocol"`
		Settings map[string]any `json:"settings"`
	}
	if err := json.Unmarshal([]byte(value), &parsed); err != nil {
		return "", "", nil, fmt.Errorf("outbound specification: %w", err)
	}
	proto := strings.ToLower(strings.TrimSpace(parsed.Protocol))
	switch proto {
	case "", "direct", "freedom":
		return "", "", nil, nil
	case "block", "reject", "blackhole":
		return "block", "", nil, nil
	}
	return strings.TrimSpace(parsed.Tag), proto, parsed.Settings, nil
}

func buildInlineOutbound(r *core.Router, tag, protocol string, settings map[string]any) error {
	o := opt.Opt{}
	for k, v := range settings {
		o[k] = v
	}
	built, err := outbound.New(protocol, o)
	if err != nil {
		return err
	}
	r.SetOutbound(tag, built)
	return nil
}

// dnsCacheDefault is exported for tests that need the same default the service
// uses when a panel omits the cache time.
const dnsCacheDefault = time.Minute
