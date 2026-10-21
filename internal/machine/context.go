package machine

import "context"

// Native transport accepts the lifetime owned by the Machine/child. Legacy
// adapters retain their existing optional transport contract.
type machineContextControlPlane interface {
	GetMachineNodesContext(context.Context) (*machineDiscovery, error)
	HandshakeContext(context.Context) (*machineHandshake, error)
	ReportMachineStatusContext(context.Context, float64, [2]uint64, [2]uint64, [2]uint64, float64, float64, *machineRuntimeStatus) error
}

func machineNodesContext(ctx context.Context, plane machineControlPlane) (*machineDiscovery, error) {
	if native, ok := plane.(machineContextControlPlane); ok {
		return native.GetMachineNodesContext(ctx)
	}
	return plane.GetMachineNodes()
}

func machineHandshakeContext(ctx context.Context, plane machineControlPlane) (*machineHandshake, error) {
	if native, ok := plane.(machineContextControlPlane); ok {
		return native.HandshakeContext(ctx)
	}
	return plane.Handshake()
}

func machineConfigContext(ctx context.Context, client machineNodeClient) (*machineNodeConfig, error) {
	if native, ok := client.(interface {
		GetConfigContext(context.Context) (*machineNodeConfig, error)
	}); ok {
		return native.GetConfigContext(ctx)
	}
	return client.GetConfig()
}

var _ machineContextControlPlane = (*txboardMachineControlPlane)(nil)
