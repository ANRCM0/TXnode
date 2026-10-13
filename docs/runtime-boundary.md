# TX-Node Runtime Boundary

Status: **active architecture baseline**

TX-Node is a dedicated Agent / Data Plane runtime for TXBoard and compatible control planes. It is not a second control plane and it is not a general-purpose host management agent.

The runtime design principle is:

> Keep TX-Node small enough that its core responsibility can be stated as: receive bounded control-plane intent, run proxy nodes, enforce user/runtime policy, and report bounded runtime state.

## 1. Core runtime

The following responsibilities belong in TX-Node Core:

- ControlPlane adapter boundary and protocol translation;
- Machine orchestration and per-node runtime ownership;
- Node configuration/user synchronization;
- kernel lifecycle through the kernel interface;
- user, traffic, device and speed-limit enforcement;
- runtime status/traffic/device reporting;
- bounded typed Node Ops;
- Machine runtime update **delegation** to TXBoard-Deploy's Node installer;
- runtime-safe configuration validation needed before applying data-plane state.

These responsibilities are data-plane facts or actions. They must not depend on TXBoard database internals or host deployment implementation.

## 2. Authoritative runtimes outside TX-Node

TX-Node must delegate rather than duplicate specialized runtimes.

### TXBoard

TXBoard owns:

- authentication and authorization;
- User / Plan / Subscription / Order;
- Node / Machine / Group / Route facts;
- approval and audit policy;
- Agent Ops orchestration;
- module/plugin/theme lifecycle.

TX-Node never becomes a second source of truth for those domains.

### TXBoard-Deploy

TXBoard-Deploy's `node/` installer owns:

- install;
- upgrade;
- rollback;
- uninstall;
- Docker Compose generation;
- host service units;
- multi-instance deployment layout;
- host backup/restore.

TX-Node may request a bounded deployment action through a typed bridge, but must not gain Docker socket, SSH or arbitrary shell access.

### Proxy kernels

sing-box / Xray adapters own protocol-specific packet/runtime implementation. TX-Node orchestrates them through the kernel interface instead of reimplementing protocol engines.

## 3. Supported adapters and backends

The following remain supported, but they do not expand the Core domain:

- TXBoard native Node/Machine ControlPlane adapter;
- Xboard-compatible Node/Machine ControlPlane adapter;
- Local/Standalone ControlPlane adapter;
- sing-box backend;
- Xray backend.

Protocol-specific behavior should stay behind adapters. New panel-specific branches should not leak into Service or kernel-independent runtime code.

## 4. Compatibility surfaces

The following have distinct compatibility obligations; historical deployment paths are **frozen for feature expansion**:

- Local / standalone ControlPlane;
- remote single-node mode (supported, though TXBoard Machine mode is preferred for new managed deployments);
- legacy native/systemd layout as an Installer migration source;
- legacy `/etc/xboard-node` host paths as Installer migration input;
- legacy container `/etc/xboard-node/config.yml` only as a bounded startup fallback for already-generated Compose files.

The canonical container config path is `/etc/txnode/config.yml`. When that
canonical path is explicitly requested but absent, TX-Node may fall back to
`/etc/xboard-node/config.yml` so an old Compose file can pull a new image
without becoming unbootable. Custom `-c` paths never participate in this
fallback.

The TX-Node v2 mainline no longer builds or publishes the historical
`xboard-node` binary alias or `xbctl`. Host migration/cleanup responsibility
belongs to TXBoard-Deploy's Node installer.

Frozen-for-expansion means:

- bug fixes and security fixes are allowed;
- compatibility regressions are fixed;
- new product features should not target these surfaces first;
- removal requires an explicit breaking release and migration plan.

The canonical product path is Machine mode managed by TXBoard, deployed through TXBoard-Deploy.

## 5. Optional capabilities

Optional capabilities must not quietly grow into core orchestration.

Current optional capabilities include:

- Xboard-compatible AccessAudit reporter/client (not provided by TXBoard native Node API);
- certificate automation;
- DNS-provider integrations used by ACME;
- custom geo/routing assets.

Rules:

1. optional capability failure must not redefine core node truth;
2. optional capability code should remain isolated from Service orchestration;
3. adding a new third-party provider requires an explicit reason rather than default inclusion;
4. where TXBoard Plugin/Integration or host tooling can own the lifecycle, prefer delegation;
5. compatibility is preserved before any optional capability is removed.

Certificate consumption by the kernel remains a runtime need. Owning an ever-growing external DNS-provider catalog is not automatically a TX-Node Core responsibility.

## 6. Retired Agent operations

Agent/MCP and the per-node AI operation executor were removed under the2026-10-13 product decision. No operation queue or runtime diagnostic executor is retained. Config/user synchronization, local kernel lifecycle and usage observers remain authoritative for normal service work. Machine installer updates remain a separate lifecycle capability.

## 7. New feature gate

Before adding a new TX-Node feature, answer these questions in order:

1. Is this Control Plane orchestration or a business fact?  
   If yes, it belongs in TXBoard.

2. Is this install/upgrade/rollback/host lifecycle?  
   If yes, it belongs in TXBoard-Deploy.

3. Is this proxy protocol/runtime behavior?  
   If yes, prefer the kernel adapter/runtime.

4. Is this an optional external integration?  
   If yes, prefer TXBoard Plugin/Integration or an isolated optional adapter.

5. Does TX-Node need this to safely execute or observe the Data Plane?  
   Only then should it enter TX-Node Core.

A feature being useful on a server is not sufficient reason to add it to TX-Node.

## 8. Current controller and runtime ownership

```text
TXBoard native / Xboard compatible / Local
    -> internal/controlplane  (Source + Sink, native models)
    -> internal/service       (orchestration and validation)
         -> nodesync          (REST snapshot polling, retry and hashing)
         -> pushsync          (WS status/event lifecycle)
         -> userstate         (desired users / limiter indexes)
         -> reporting         (durable batch delivery, retry and replay)
         -> kernellifecycle   (applied runtime, Start/Reload/Stop)
         -> certcoord         (TLS normalization and certificate coordination)
         -> auditcoord        (optional Xboard-only AccessAudit attachment)
         -> geoassets        (optional geo/routing asset provisioning)
    -> internal/kernel        (sing-box or Xray)
```

Machine mode owns node discovery and a shared provider-specific push transport. Each discovered node has isolated runtime state and mailbox; rediscovery and retry must be bounded and must not propagate one node's transient failure into other nodes.

### State, reporting and optional integrations

- **Desired vs applied:** user-state and the kernel's successfully applied snapshot are separate; failed changes must not falsely update the applied-state truth.
- **Durable reporting:** `traffic_batch_id` remains stable across timeout/restart replay, backed by writable persistent `kernel.config_dir`. Native TXBoard HTTP 202 confirms queue acceptance, not MySQL settlement. Follow [durable traffic reporting](./traffic-durable-replay.md).
- **AccessAudit:** the embedded reporter uses the legacy Xboard plugin protocol. The native TXBoard adapter intentionally does not expose `AuditTargetProvider`; `audit.enabled` should remain off for native deployments until a dedicated contract exists.
- **Certificates/geo assets:** existing ACME DNS-provider compatibility is managed behind `certcoord`, and geo acquisition behind `geoassets`; kernel adapters execute proxy routing. Integrations must not turn into an unrestricted host-management runtime.

### Release and deployment

The TX-Node repository builds and tests runtime binaries and multi-arch images; the Installer owns host configuration, Docker Compose, state volumes, upgrades and rollback. Each `main` push runs CI and builds the development `:dev` image plus an immutable SHA tag; pull requests validate without publishing. Only strict stable `vX.Y.Z` tags update production `:latest` and produce GitHub Releases. Preview/RC tags and the manual `:test` channel are retired. Existing running nodes upgrade only through explicit Installer actions.

## 9. Compatibility and non-goals

- Keep Xboard protocol support independent of native TXBoard support; do not implement panel-name conditionals inside the kernel.
- Keep legacy config-path fallback bounded to old Compose startup and old native/systemd detection confined to Installer migration/cleanup.
- Do not restore retired `xbctl` or `xboard-node` build artifacts.
- Do not grant TX-Node arbitrary shell, Docker socket, SSH, filesystem control, or access to TXBoard business database internals.
- Do not treat the optional audit reporter, Xray, standalone, or certificate backends as disposable leftovers: changing a supported capability requires an explicit contract and migration review.

The canonical compatibility classifications and migration safeguards are in [compatibility inventory](./legacy-compatibility-inventory.md). Control-plane adapter semantics are in [controlplane.md](./controlplane.md).
