package listener

import (
	"net"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	proxyproto "github.com/pires/go-proxyproto"
)

func wrapProxyProtocolListener(base net.Listener, listenOptions option.ListenOptions) (net.Listener, error) {
	if !listenOptions.ProxyProtocol && !listenOptions.ProxyProtocolAcceptNoHeader {
		return base, nil
	}

	var trustedCIDRs []string
	if listenOptions.ProxyProtocolTrustedCIDRs != nil {
		trustedCIDRs = *listenOptions.ProxyProtocolTrustedCIDRs
	}
	policy, err := newProxyProtocolPolicy(trustedCIDRs, listenOptions.ProxyProtocolAcceptNoHeader)
	if err != nil {
		return nil, err
	}

	return &proxyproto.Listener{
		Listener: base,
		Policy:   policy,
	}, nil
}

func newProxyProtocolPolicy(trustedCIDRs []string, acceptNoHeader bool) (proxyproto.PolicyFunc, error) {
	trusted, err := parseProxyProtocolTrustedCIDRs(trustedCIDRs)
	if err != nil {
		return nil, err
	}
	if len(trusted) == 0 {
		return nil, E.New("proxy protocol requires at least one trusted upstream IP or CIDR")
	}

	return func(upstream net.Addr) (proxyproto.Policy, error) {
		host, _, err := net.SplitHostPort(upstream.String())
		if err != nil {
			return proxyproto.REJECT, proxyproto.ErrInvalidUpstream
		}
		if zoneIndex := strings.LastIndexByte(host, '%'); zoneIndex > 0 {
			host = host[:zoneIndex]
		}
		upstreamIP := net.ParseIP(host)
		if upstreamIP == nil {
			return proxyproto.REJECT, proxyproto.ErrInvalidUpstream
		}

		for _, trustedRange := range trusted {
			if trustedRange.Contains(upstreamIP) {
				if acceptNoHeader {
					return proxyproto.USE, nil
				}
				return proxyproto.REQUIRE, nil
			}
		}

		// Returning ErrInvalidUpstream makes proxyproto.Listener close this
		// connection and continue accepting, instead of exposing the raw socket.
		return proxyproto.REJECT, proxyproto.ErrInvalidUpstream
	}, nil
}

func parseProxyProtocolTrustedCIDRs(values []string) ([]*net.IPNet, error) {
	trusted := make([]*net.IPNet, 0, len(values))
	for _, rawValue := range values {
		value := strings.TrimSpace(rawValue)
		if value == "" {
			continue
		}

		if strings.Contains(value, "/") {
			_, network, err := net.ParseCIDR(value)
			if err != nil {
				return nil, E.Cause(err, "invalid proxy protocol trusted CIDR ", value)
			}
			trusted = append(trusted, network)
			continue
		}

		ip := net.ParseIP(value)
		if ip == nil {
			return nil, E.New("invalid proxy protocol trusted IP ", value)
		}
		if ipv4 := ip.To4(); ipv4 != nil {
			trusted = append(trusted, &net.IPNet{IP: ipv4, Mask: net.CIDRMask(32, 32)})
		} else {
			trusted = append(trusted, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
		}
	}
	return trusted, nil
}
