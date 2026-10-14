package controlplane

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/ANRCM0/TX-Node/internal/config"
	"github.com/ANRCM0/TX-Node/internal/model"
	"github.com/ANRCM0/TX-Node/internal/nlog"
	"github.com/ANRCM0/TX-Node/internal/panel"
	"github.com/ANRCM0/TX-Node/internal/txboard"
	"github.com/ANRCM0/TX-Node/internal/usagev2"
)

// TXBoardControlPlane speaks the native node/v1 protocol. Xboard transport
// stays independent so existing deployments retain their wire contract.
type TXBoardControlPlane struct {
	client          *txboard.Client
	kernel          config.KernelConfig
	ws              config.WSConfig
	machine         bool
	sharedPush      PushClient
	register        func(chan<- StatusChange) *NodeMailbox
	isolatedUsageV2 bool
}

func NewTXBoardControlPlane(p config.PanelConfig, ws config.WSConfig, kernel config.KernelConfig) *TXBoardControlPlane {
	return &TXBoardControlPlane{client: txboard.NewClient(p), ws: ws, kernel: kernel}
}
func NewMachineTXBoardControlPlane(c *txboard.Client, k config.KernelConfig, push PushClient, register func(chan<- StatusChange) *NodeMailbox) *TXBoardControlPlane {
	return &TXBoardControlPlane{client: c, kernel: k, machine: true, sharedPush: push, register: register}
}

var _ ControlPlane = (*TXBoardControlPlane)(nil)

// AuditTarget activates the existing sing-box reporter using native Bearer
// credentials. In Machine mode the per-node client retains the Machine ID.
func (p *TXBoardControlPlane) AuditTarget() (AuditTarget, bool) {
	if p == nil || p.client == nil || p.client.NodeID() <= 0 || p.client.Token() == "" {
		return AuditTarget{}, false
	}
	return AuditTarget{Protocol: "txboard", BaseURL: p.client.BaseURL(), Token: p.client.Token(), NodeID: p.client.NodeID(), MachineID: p.client.MachineID()}, true
}

func (p *TXBoardControlPlane) SupportsPolling() bool       { return true }
func (p *TXBoardControlPlane) SupportsDiscovery() bool     { return !p.machine }
func (p *TXBoardControlPlane) SupportsReporting() bool     { return true }
func (p *TXBoardControlPlane) SupportsDeviceReports() bool { return false }
func (p *TXBoardControlPlane) Metrics() APIMetrics {
	a, b := p.client.Metrics()
	return APIMetrics{Success: a, Failure: b}
}

// ResetSnapshotCache is an optional native hook for runtime reconnect/drop
// reconciliation; it leaves other providers' transport contracts unchanged.
func (p *TXBoardControlPlane) ResetSnapshotCache() {
	if p != nil && p.client != nil {
		p.client.ResetETags()
	}
}

func (p *TXBoardControlPlane) snapshot(ctx context.Context) (Snapshot, error) {
	cfg, err := p.client.ConfigSnapshot()
	if err != nil {
		return Snapshot{}, err
	}
	users, err := p.client.UsersSnapshot()
	if err != nil {
		return Snapshot{}, err
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	var spec *model.NodeSpec
	if cfg != nil {
		spec, err = model.NodeSpecFromPanelValidated(cfg, p.kernel)
		if err != nil {
			return Snapshot{}, err
		}
	}
	return Snapshot{Config: spec, Users: model.UserSpecsFromPanel(users)}, nil
}
func (p *TXBoardControlPlane) Initial(ctx context.Context, metricsFn func() map[string]interface{}, events chan<- Event, statuses chan<- StatusChange) (Bootstrap, error) {
	p.client.ResetETags()
	hs, err := p.client.Handshake()
	if err != nil {
		return Bootstrap{}, err
	}
	snapshot, err := p.snapshot(ctx)
	if err != nil {
		return Bootstrap{}, err
	}
	if snapshot.Config == nil {
		return Bootstrap{}, errors.New("TXBoard initial config not available")
	}
	b := Bootstrap{PushInterval: hs.Settings.PushInterval, PullInterval: hs.Settings.PullInterval, Config: snapshot.Config, Users: snapshot.Users}
	if p.isolatedUsageV2 {
		session, transport, err := p.client.ServiceUsageV2(hs)
		if err != nil {
			return Bootstrap{}, err
		}
		b.UsageV2Session = session
		b.UsageV2Transport = transport
		b.UsageV2NativeHTTP = true
	}
	if p.machine {
		b.Push = p.sharedPush
		if p.sharedPush != nil && p.register != nil {
			b.Mailbox = p.register(statuses)
		}
	} else if hs.WebSocket.Enabled {
		b.Push, err = p.makePush(hs.WebSocket.Path, events, statuses)
		if err != nil {
			return Bootstrap{}, err
		}
	}
	return b, nil
}
func (p *TXBoardControlPlane) Poll(ctx context.Context) (Snapshot, error) { return p.snapshot(ctx) }
func (p *TXBoardControlPlane) Discover(ctx context.Context, _ func() map[string]interface{}, events chan<- Event, statuses chan<- StatusChange) (PushClient, error) {
	if p.machine {
		return nil, nil
	}
	hs, err := p.client.Handshake()
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !hs.WebSocket.Enabled {
		return nil, nil
	}
	return p.makePush(hs.WebSocket.Path, events, statuses)
}
func (p *TXBoardControlPlane) makePush(path string, events chan<- Event, statuses chan<- StatusChange) (PushClient, error) {
	u, err := p.client.WSSURL(path)
	if err != nil {
		return nil, err
	}
	socket := txboard.NewSocket(u, p.client.Token(), p.client.NodeID(), 0, p.ws, func(raw txboard.Event) {
		translated, err := TranslateTXBoardEvent(raw, p.kernel)
		if err != nil {
			nlog.Core().Warn("native WS event rejected", "event", raw.Name, "error", err)
			select {
			case statuses <- StatusChange{Connected: true, NeedsResync: true}:
			default:
			}
			return
		}
		if translated.Type == "" {
			return
		}
		select {
		case events <- translated:
		default:
			select {
			case statuses <- StatusChange{Connected: true, NeedsResync: true}:
			default:
			}
		}
	}, func(connected bool) {
		select {
		case statuses <- StatusChange{Connected: connected, NeedsResync: connected}:
		default:
		}
	})
	return &txboardNodePush{socket: socket}, nil
}

type txboardNodePush struct{ socket *txboard.Socket }

func (p *txboardNodePush) Run(ctx context.Context)           { p.socket.Run(ctx) }
func (p *txboardNodePush) IsConnected() bool                 { return p.socket.IsConnected() }
func (p *txboardNodePush) SendDeviceReport(map[int][]string) {} // Native reports carry alive state via HTTP.
func (p *TXBoardControlPlane) Report(payload ReportPayload) error {
	body := map[string]any{
		"status": map[string]any{"cpu": payload.CPU, "mem": map[string]any{"total": payload.Mem[0], "used": payload.Mem[1]},
			"swap": map[string]any{"total": payload.Swap[0], "used": payload.Swap[1]},
			"disk": map[string]any{"total": payload.Disk[0], "used": payload.Disk[1]}},
		"metrics": payload.Metrics,
	}
	if len(payload.Traffic) > 0 {
		if payload.BatchID == "" {
			return errors.New("native traffic requires durable batch ID")
		}
		body["traffic_batch_id"] = payload.BatchID
		body["traffic"] = payload.Traffic
	}
	if len(payload.Alive) > 0 {
		body["alive"] = payload.Alive
	}
	if len(payload.Online) > 0 {
		body["online"] = payload.Online
	}
	return p.client.PostReport(body)
}
func (p *TXBoardControlPlane) ReportDevices(_ PushClient, _ map[int][]string) {}

// UsageV2Reporter negotiates a fresh authenticated handshake explicitly for a
// bounded v2 collector. It never changes the existing v1 Service report path.
func (p *TXBoardControlPlane) UsageV2Reporter(spoolDir, legacyPendingPath string, countersEmpty bool) (*usagev2.Reporter, error) {
	hs, err := p.client.Handshake()
	if err != nil {
		return nil, err
	}
	return p.client.NewUsageV2Reporter(hs, spoolDir, legacyPendingPath, countersEmpty)
}

// TranslateTXBoardEvent turns native frame data into the runtime's provider-neutral model.
func TranslateTXBoardEvent(raw txboard.Event, k config.KernelConfig) (Event, error) {
	var event Event
	switch raw.Name {
	case "sync.config":
		var data struct {
			Config panel.NodeConfig `json:"config"`
		}
		if err := json.Unmarshal(raw.Data, &data); err != nil {
			return event, err
		}
		spec, err := model.NodeSpecFromPanelValidated(&data.Config, k)
		if err != nil {
			return event, err
		}
		event = Event{Type: EventSyncConfig, Config: spec}
	case "sync.users":
		var data struct {
			Users []panel.User `json:"users"`
		}
		if err := json.Unmarshal(raw.Data, &data); err != nil {
			return event, err
		}
		if data.Users == nil {
			data.Users = make([]panel.User, 0)
		}
		event = Event{Type: EventSyncUsers, Users: model.UserSpecsFromPanel(data.Users)}
	case "sync.user.delta":
		var data struct {
			Action string       `json:"action"`
			Users  []panel.User `json:"users"`
		}
		if err := json.Unmarshal(raw.Data, &data); err != nil {
			return event, err
		}
		if data.Action != "add" && data.Action != "remove" {
			return event, errors.New("invalid user delta action")
		}
		event = Event{Type: EventSyncUserDelta, DeltaAction: data.Action, DeltaUsers: model.UserSpecsFromPanel(data.Users)}
	case "sync.devices":
		var data struct {
			Users map[int][]string `json:"users"`
		}
		if err := json.Unmarshal(raw.Data, &data); err != nil {
			return event, err
		}
		event = Event{Type: EventSyncDevices, DeviceUsers: data.Users}
	default:
		if len(raw.Name) > 4 && raw.Name[:4] == "ops." {
			return event, errors.New("retired node operation")
		}
	}
	return event, nil
}

func (p *TXBoardControlPlane) PrepareIsolatedUsageV2(caFile string) error {
	if p == nil || p.machine || p.client == nil {
		return errors.New("USAGE_V2_NATIVE_HTTP_REQUIRED")
	}
	if err := p.client.PrepareIsolatedUsageV2TLS(caFile); err != nil {
		return err
	}
	p.isolatedUsageV2 = true
	return nil
}
