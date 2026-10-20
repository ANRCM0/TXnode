package service

import (
	"time"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/kernel"
	"github.com/ANRCM0/TX-Node/internal/kernel/txnode"
)

// newKernel builds the node data plane. TX-Node ships exactly one kernel; the
// sing-box and Xray backends were removed with the native rework.
func newKernel(cfg *config.Config) kernel.Kernel {
	return txnode.New(txnodeRuntime(cfg))
}

func txnodeRuntime(cfg *config.Config) txnode.RuntimeConfig {
	if cfg == nil {
		return txnode.RuntimeConfig{}
	}
	dp := cfg.Dataplane
	return txnode.RuntimeConfig{
		TrustedProxies:       dp.TrustedProxies,
		ProxyProtocol:        dp.ProxyProtocol,
		RequireProxyProtocol: dp.RequireProxyProtocol,
		AutoOutIP:            dp.AutoOutIP,
		StrictALPN:           dp.StrictALPN,
		MaxFresh:             dp.MaxFresh,
		HandshakeTimeout:     seconds(dp.HandshakeTimeout),
		TCPTimeout:           seconds(dp.TCPTimeout),
		UDPTimeout:           seconds(dp.UDPTimeout),
		DrainTimeout:         seconds(dp.DrainTimeout),
		ForbiddenPrivateIP:   dp.ForbiddenPrivateIP,
		ForbiddenBitTorrent:  dp.ForbiddenBitTorrent,
		ForbiddenPorts:       dp.ForbiddenPorts,
		UserTCPLimit:         dp.UserTCPLimit,
		DeviceLimit:          dp.DeviceLimit,
		DeviceIPv6Prefix:     dp.DeviceIPv6Prefix,

		InvalidAccessEnable:    dp.InvalidAccessEnable,
		InvalidAccessCount:     dp.InvalidAccessCount,
		InvalidAccessDuration:  dp.InvalidAccessDuration,
		InvalidAccessForbidden: dp.InvalidAccessForbiddenTime,

		GeoDataDir: cfg.Kernel.GeoDataDir,
	}
}

func seconds(v int) time.Duration {
	if v <= 0 {
		return 0
	}
	return time.Duration(v) * time.Second
}
