package machine

import (
	"context"
	"encoding/json"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/controlplane"
	"github.com/ANRCM0/TX-Node/internal/txboard"
)

type txboardMachineControlPlane struct{ client *txboard.Client }
type txboardMachineNodeClient struct{ client *txboard.Client }

func (x *txboardMachineNodeClient) GetConfig() (*machineNodeConfig, error) {
	return x.GetConfigContext(context.Background())
}
func (x *txboardMachineNodeClient) GetConfigContext(ctx context.Context) (*machineNodeConfig, error) {
	cfg, err := x.client.GetConfigContext(ctx)
	if err != nil || cfg == nil {
		return nil, err
	}
	return &machineNodeConfig{Network: cfg.Network}, nil
}
func (x *txboardMachineNodeClient) ResetConfigETag() { x.client.ResetConfigETag() }
func (x *txboardMachineNodeClient) ControlPlane(k config.KernelConfig, push controlplane.PushClient, register func(chan<- controlplane.StatusChange) *controlplane.NodeMailbox) controlplane.ControlPlane {
	return controlplane.NewMachineTXBoardControlPlane(x.client, k, push, register)
}
func (x *txboardMachineControlPlane) ForNode(id int) machineNodeClient {
	return &txboardMachineNodeClient{client: x.client.ForNode(id)}
}
func (x *txboardMachineControlPlane) GetMachineNodes() (*machineDiscovery, error) {
	return x.GetMachineNodesContext(context.Background())
}
func (x *txboardMachineControlPlane) GetMachineNodesContext(ctx context.Context) (*machineDiscovery, error) {
	nodes, err := x.client.GetMachineNodesContext(ctx)
	if err != nil {
		return nil, err
	}
	result := &machineDiscovery{BaseConfig: machineIntervals{PullInterval: nodes.BaseConfig.PullInterval, PushInterval: nodes.BaseConfig.PushInterval}}
	for _, n := range nodes.Nodes {
		result.Nodes = append(result.Nodes, machineNode{ID: n.ID, Type: n.Type, Name: n.Name})
	}
	return result, nil
}
func (x *txboardMachineControlPlane) Handshake() (*machineHandshake, error) {
	return x.HandshakeContext(context.Background())
}
func (x *txboardMachineControlPlane) HandshakeContext(ctx context.Context) (*machineHandshake, error) {
	hs, err := x.client.HandshakeContext(ctx)
	if err != nil {
		return nil, err
	}
	result := &machineHandshake{Enabled: hs.WebSocket.Enabled}
	if result.Enabled {
		result.URL, err = x.client.WSSURL(hs.WebSocket.Path)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}
func (x *txboardMachineControlPlane) NewMachineSocket(url, token string, machineID int, ws config.WSConfig, k config.KernelConfig, onEvent func(machineEvent), onStatus func(bool)) machineSocket {
	socket := txboard.NewSocket(url, token, 0, machineID, ws, func(raw txboard.Event) {
		e := machineEvent{Kind: machineEventNode, NodeID: raw.NodeID}
		switch raw.Name {
		case "sync.nodes":
			e.Kind = machineEventSyncNodes
		case "ops.machine.runtime.update":
			e.Kind = machineEventRuntimeUpdate
			var data machineRuntimeUpdate
			e.Err = json.Unmarshal(raw.Data, &data)
			if e.Err == nil {
				e.RuntimeUpdate = &data
			}
		default:
			e.NodeEvent, e.Err = controlplane.TranslateTXBoardEvent(raw, k)
			if e.NodeEvent.Type == "" && e.Err == nil {
				return
			}
		}
		onEvent(e)
	}, onStatus)
	return &txboardMachineSocket{Socket: socket}
}
func (x *txboardMachineControlPlane) ReportMachineStatus(cpu float64, mem, swap, disk [2]uint64, netIn, netOut float64, status *machineRuntimeStatus) error {
	return x.ReportMachineStatusContext(context.Background(), cpu, mem, swap, disk, netIn, netOut, status)
}
func (x *txboardMachineControlPlane) ReportMachineStatusContext(ctx context.Context, cpu float64, mem, swap, disk [2]uint64, netIn, netOut float64, status *machineRuntimeStatus) error {
	body := map[string]any{
		"cpu": cpu, "mem": map[string]any{"total": mem[0], "used": mem[1]},
		"swap": map[string]any{"total": swap[0], "used": swap[1]},
		"disk": map[string]any{"total": disk[0], "used": disk[1]},
	}
	if netIn >= 0 && netOut >= 0 {
		body["net"] = map[string]any{"in_speed": netIn, "out_speed": netOut}
	}
	if status != nil {
		runtime := map[string]any{"version": status.Version, "build_time": status.BuildTime, "deployment": status.Deployment, "updater_available": status.UpdaterAvailable, "update_targets": status.UpdateTargets}
		if status.Update != nil {
			u := status.Update
			runtime["update"] = map[string]any{"request_id": u.RequestID, "target": u.Target, "status": u.Status, "updated_at": u.UpdatedAt, "message": u.Message}
		}
		body["runtime"] = runtime
	}
	return x.client.ReportMachineStatusContext(ctx, body)
}

type txboardMachineSocket struct{ *txboard.Socket }

func (s *txboardMachineSocket) SendDeviceReport(_ json.RawMessage) {} // Native device state uses HTTP alive snapshots.
func (s *txboardMachineSocket) SendOpsResult(data json.RawMessage) {
	var body map[string]any
	if err := json.Unmarshal(data, &body); err != nil {
		return
	}
	s.Socket.Send("ops.result", body)
}

var _ machineSocket = (*txboardMachineSocket)(nil)
var _ machineControlPlane = (*txboardMachineControlPlane)(nil)
var _ machineNodeClient = (*txboardMachineNodeClient)(nil)
