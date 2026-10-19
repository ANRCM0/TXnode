# TX-Node 内核改造方案 v3：txnode 数据面替换 sing-box / Xray

> 状态：**P1 + P3 已实施**（txnode 成为唯一内核，`go build ./...` / `go vet` / `go test ./...` 全绿；
> usage_v2 的 per-IO 计量已落地）。
> 决策已锁定（v3）：不保留 sing-box 与 Xray，彻底替换；kaze 内核更名为 txnode；
> 开发阶段不做兼容/迁移映射。
>
> 已落地：`internal/kernel/txnode`（spec/build/bind/router/meter/kernel/native_meter）、
> `internal/dataplane` 的限速/准入/chunk 钩子补丁、配置/模型/服务接线、旧内核与依赖删除。
>
> 测试：数据面临速与设备闸、适配层 spec/route、socks 端到端、本地事件计量、
> 授权到期/拒绝的真实流关闭与精确尾部、usage_v2 授权生命周期全部恢复并通过；
> 仍依赖旧内核内部类型的 8 个文件保留在 `docs/removed-tests/`。
>
> 性能（本机回环，SOCKS5 上传，32 KiB 写）：splice 路径 **1504.85 MB/s**；
> 启用 chunk 计量（usage_v2/本地事件，禁用 splice）**767.75 MB/s**。
>
> 互通实测（Xray 26.3.27 / Mihomo v1.19.32，客户端仅作测试工具）：VLESS(tcp/ws)、
> Trojan+TLS、Shadowsocks、REALITY（Xray/Mihomo）通过；VMess、Hysteria2 为已知缺口（见 `docs/INTEROP.md`）。
> 依据：本仓 `HEAD`（`b0f6a06`）实测 + `/workspace/Node/kaze` 复刻工程（v0.5.18 行为级复刻）
> + `kazecore/REPORT.md`。本文不含原始二进制、专有代码或密钥。

---

## 0. 相对 v1 的修订（先看这一节）

| # | v1 的说法 | 实测 / 结论 | v2 处理 |
|---|---|---|---|
| 1 | P1「搬运 122 文件 + 适配层 ~6 文件」 | 数据面已搬运（`b0f6a06`，122 文件 / 30,589 行，可独立编译）；但**适配层不是 6 个文件**——kaze 的 `internal/node` 自身就是 1,100+ 行（`apply.go` 582 / `router.go` 520 / `node.go` 420），承担 spec→handler→监听→路由的全部翻译 | 适配层按「移植 kaze node 层」立项（§3），P1 拆成 1.1/1.2/1.3 |
| 2 | P1 验收「`go build ./...` 通过」 | 当前全仓编译**只有 1 个错误**：`sing-box/transport/v2rayhttp.ResetTransport: relocation target golang.org/x/net/http2.(*Transport).connPool not defined`（x/net 升级到 0.56 后 sing-box 的 linkname 失效） | 「删旧内核」成为 P1 的**收尾条件**而不是 P3；先让 txnode 顶替，再删依赖 |
| 3 | P3「`compatibility/renderers.v1.json` 重新生成」 | **与内核无关**：该 fixture 只跟踪 `internal/credential*/render*.go` 六个文件与 Core 的 renderer 契约（`scripts/check-renderer-compatibility.py`） | v2 明确**不动** renderers；只评审 `core.v1.json`（`node-usage/v2` 是否仍成立，见 §6.3） |
| 4 | 未提 usage_v2 的类型耦合 | `service/native_usage_adapter.go:24` 的 `nativeUsageKernel` 断言**具体类型** `*singbox.ConnTracker`；`SetNativeUsageTracker` 移除旧 `singbox` 包即断 | v2 先接口化，再给数据面 per-IO 钩子补丁（§4.2） |
| 5 | 未提本地事件计量 | `usagebucket.Coordinator` 通过 `SetLocalEventConsumer` 接管 `*ConnTracker` 的事件桶；`usageobserver` 另有采样 | v2 纳入 P4，与 usage_v2 共用一个 chunk 钩子 |
| 6 | 未提 model 层内核矩阵 | `custom_outbound_support.go:5,22` / `custom_route_support.go:5,17` / `validate.go:71 normalizeKernelType` / `validate.go:63 ResolveKernelForTransport` 全是 `xray|singbox` 二元 | v2 列为 §5 必改项（含 machine 模式自动切内核） |
| 7 | 限速只写「接 limiter」 | TX-Node `limiter.SpeedTracker` 用 `rate.Limiter`（burst = max(bytes/s, 64 KiB)）；数据面 `core.Limiter` 固定 burst = 0.25×rate | v3 给出逐项差异与决定（§3.5） |
| 8 | 无数据面补丁清单 | 数据面缺 4 个 TX-Node 必需的能力：审计钩子、连接 ID、准入开关、per-IO 计量 | v2 给文件级补丁清单（§4） |

### v3 变更（决策落定后）

1. **D1 无兼容**：直接删除旧内核与内核原生配置键，不做 `kernel.type` 迁移映射、不保留别名；
2. **D2 接受**：审计与协议能力按「等价子集」交付，差异写进能力矩阵与 README；
3. **D3 硬门禁**：usage_v2 未对齐前不得发布 txnode 版本（`core.v1.json` 不降级）；
4. **D4 限速**：执行引擎用数据面，速率/burst/上下行语义按 TX-Node 对齐，并补 UDP 限速（§3.5）；
5. **D5 配置**：结构化子集翻译；`kernel.custom_*` 原生键删除，加载期检测到即报错（防静默忽略）。

---

## 1. 现状快照（可复现）

```
$ git -C TXnode log --oneline -1
b0f6a06 P1: 搬运数据面到 internal/dataplane 并对齐 quic-go 版本

$ find internal/dataplane -name '*.go' | wc -l ; find internal/dataplane -name '*.go' -exec cat {} + | wc -l
122
30589

$ go build ./internal/dataplane/...        # 通过（本机缓存可写；受限环境可用 GOMODCACHE 指向可写目录）
$ go build ./...
# github.com/ANRCM0/TX-Node/cmd/tx-node
github.com/sagernet/sing-box/transport/v2rayhttp.ResetTransport:
    relocation target golang.org/x/net/http2.(*Transport).connPool not defined
```

| 事实 | 值 |
|---|---|
| 数据面子包 | `core proto/{12 协议,xudp} transport ctransport mux qstream outbound wgout tlsbuf pool udperr opt socks congestion/bbr`（14 个目录） |
| 数据面外部依赖 | **零** `sagernet/*` / `xtls/*`（仅注释提及协议名） |
| 旧内核仍在 | `internal/kernel/singbox`（7 非测试文件）、`internal/kernel/xray`（3 非测试文件）、`internal/deps/sing-box` 5.0 MB、`internal/deps/sing-vmess` 228 KB |
| `go.mod` | 已按 kaze 对齐 `apernet/quic-go v0.63.1-…`、`utls v1.8.3-0.2026…`、`x/crypto v0.54.0`、`x/net v0.56.0`；仍保留 `replace sing-box/sing-vmess/Xray-core` |
| 分支/标签 | `feat/txnode-kernel`；**无 `pre-txnode` tag**（v1 的 P0 没做） |
| `kernel/txnode` | **不存在** |
| 绑定旧内核的测试 | 5 个测试文件 import `kernel/singbox`（`usagebucket/store_io_test.go`、`service/usage_{observer,event_store}_adapter_test.go`、`service/native_usage_linux_test.go`、`service/traffic_period_packet_test.go`） |
| 数据面已验证能力 | `core.Server`（15 阶段 handle）、`Tracker`（用户/设备/限速/在线 IP）、12 协议 handler、9 类传输、REALITY、路由/DNS/geo(.dat)、splice 零拷贝 |

**结论：P1 的「搬运」已完成，缺的是适配层、服务接线、以及数据面 4 个缺口。** 当前 HEAD 是不可编译的中间态，任何基线测试都要在 P1.4 之后才可跑。

---

## 2. 目标架构

```
cmd/tx-node ─► internal/service ─► internal/kernel.Kernel（接口不变）
                     │                    │
                     │                    └─ internal/kernel/txnode/        适配层（新增）
                     │                         spec.go       NodeSpec → spec（面板语义）
                     │                         build.go      协议 handler / 传输 / TLS / REALITY
                     │                         bind.go       监听器（TCP/UDP/QUIC）
                     │                         router.go     custom_outbounds / routes / geo
                     │                         meter.go      计数、连接表、审计、限速桥
                     │                                │
                     │                                └─ internal/dataplane/*   协议引擎（已存在）
                     ├─ panel（txboard/xboard/…）       不变
                     ├─ tracker / reporting / usage*    不变（计费权威）
                     └─ authorization / credentialprovider  不变（独立进程）
```

数据流（不变的部分略）：

```
panel pull → model.NodeSpec → service → txnode.Start
                                     ├─ spec.Build()      协议 + 传输 + TLS/REALITY
                                     ├─ router.Compile()  → dataplane core.Router / outbound
                                     └─ core.NewServer(ServerOptions{Handler,Tracker,Router,…})
客户端 → 监听 → core.Server.handle（15 阶段）→ Handler.Handle → ServeSession
                                                 → Tracker.Acquire（设备门控）
                                                 → relay（限速 / splice / 计数）
                                                 → tracker（TX-Node）→ reporting → panel
```

**边界原则**

1. 计费/上报权威仍在 TX-Node 的 `tracker`/`reporting`；数据面只提供原子计数与门控。
2. 适配层只做「翻译」，不复制 TX-Node 的授权、面板、证书、日志策略。
3. 需要改数据面的地方**必须**是通用能力（钩子/注册表），不允许为 TX-Node 特化协议逻辑。

---

## 3. 适配层设计（`internal/kernel/txnode`）

### 3.1 不复用的东西

kaze 中**不迁移**：`internal/{panel,conf,certs,licclient,license,logfile,memlimit,timefloor,hop,dnscert}`。
理由：面板/配置/证书/授权/运维面全部由 TX-Node 既有包承担；`hop` 在 v0.5.18 是死代码；`dnscert` 未被数据面引用。

### 3.2 `spec.go`：NodeSpec → 内部 `spec`

TX-Node 的面板语义是 `model.NodeSpec`（`internal/model/types.go:9`），而数据面 handler 需要 kaze
`panel.NodeConfig` 那一组**已归一化**的字段。中间层 `spec` 避免把面板键名散进 handler 工厂。

| `spec` 字段 | 来源（`model.NodeSpec`） | 备注 |
|---|---|---|
| `Protocol` | `Protocol`，经 `normalizeProtocol` | 见下表别名 |
| `Port/ListenIP` | `ServerPort` / `ListenIP` | |
| `Network` | `Network`（空→`tcp`） | 传输名 |
| `Path` | `NetworkSettings["path"]` | WS/HTTPUpgrade/XHTTP/gRPC 共用 |
| `Host` | `NetworkSettings["host"]` 或 `ServerName` | |
| `ServiceName` | `NetworkSettings["serviceName"]` / `["service_name"]` | gRPC |
| `Mode/Extra/Headers` | `NetworkSettings["mode"/"extra"/"headers"]` | XHTTP |
| `EarlyData*` | `NetworkSettings["max_early_data"/"early_data_header_name"]` | WS；**数据面暂不支持**（§6） |
| `TLS` | `TLS`（0/1/2） | 2=REALITY |
| `ServerName` | `ServerName` | |
| `RealityPrivateKey` | `TLSSettings["private_key"]` | |
| `RealityShortIDs` | `TLSSettings["short_id"]`（数组或单值） | |
| `RealityDest/ServerNames/MaxTimeDiff` | `TLSSettings["dest"/"server_name"/…]` | |
| `ALPN` | `TLSSettings["alpn"]` | |
| `Flow/Decryption/Cipher/ServerKey` | 同名字段 | VLESS/VMess/SS |
| `Version` | 同名字段；`hysteria2` ⇒ 强制 2 | |
| `Obfs/ObfsPassword` | 同名字段 | 与 `Plugin` 二选一，冲突报错 |
| `Mieru*` | `Transport`/`TrafficPattern` | `traffic_pattern` 数据面未实现（§6） |
| `Congestion/UpMbps/DownMbps` | `CongestionControl`/`UpMbps`/`DownMbps` | Hysteria2/TUIC |
| `Brutal*` | `Multiplex.Brutal` | |
| `PaddingScheme` | `PaddingScheme` | AnyTLS |
| `Multiplex` | `Multiplex` | Mux 出站/入站 |
| `AcceptProxyProtocol` | `AcceptProxyProtocol` | |

协议别名（面板名 → 数据面工厂）：

| 面板 | 工厂 |
|---|---|
| `vless` / `vmess` / `trojan` / `anytls` / `naive` / `mieru` / `snell` / `tuic` | 同名 |
| `shadowsocks` | `shadowsocks`（必须带 `Cipher`；空值即在构建期报错） |
| `hysteria` / `hysteria2` | `hysteria`，`Version=2`；面板 `hysteria` 且 `Version!=2` ⇒ 明确报错 |
| `socks` / `socks5` | `socks5`（`NoAuth` 由本地/面板语义决定） |
| `http` | `httpproxy` |

`Protocols()` 返回**面板侧名称**（`hysteria2` 等），与 `validateNodeRuntime`
（`internal/service/service.go:715`）使用的名称同一套，避免「支持但被拒」。

### 3.3 `build.go`：协议 + 传输 + TLS

直接移植 kaze `internal/node/apply.go` 的 `buildProtocolHandler` / `security` / `bind` 结构：

- handler 选项必须与现网一致：VLESS `AllowVision: Flow != ""`、`MuxPackets: xudp.New`；
- REALITY：`transport.NewReality{PrivateKey, ShortIDs, Dest, ServerNames, MaxTimeDiff, Mirror}`；
  网络限制保持 kaze 的「REALITY 只允许 tcp/grpc/h2/xhttp」；
- TLS：**不启用数据面/`certs` 的 ACME**。TX-Node 已把证书归一化成 PEM
  （`kernel.TLSCert`），适配层用 `tls.X509KeyPair(CertPEM, KeyPEM)` 直接构造；
- 传输：`transport.Inbound{Network,Path,Host,ServiceName,TLS,TLSConfig,Reality,XHTTP}`
  的 `WrapListener` + `WrapHandler`，与原实现同一条路径；
- QUIC：`hysteria.NewServer` / `tuic.NewServer` 的 `Relay` 指向
  `srv.ServeSession`（`dataplane/core/session.go:29`）；
- UDP：需要 `PacketHandler` 的协议把 `net.ListenPacket` 交给 handler。

骨架（签名已对齐现有数据面 API）：

```go
package txnode

type Kernel struct {
    mu       sync.Mutex
    rt       RuntimeConfig        // 见 §5.2
    tracker  *core.Tracker        // 跨 Reload 复用（计数不丢）
    spec     *spec
    srv      *core.Server
    ln       net.Listener
    closers  []io.Closer
    users    map[int]model.UserSpec
    limitFn  func(uuid string) *rate.Limiter
    deviceFn func(uuid string) (int, bool)
    meter    *meter
}

func (k *Kernel) Start(nc *model.NodeSpec, users []model.UserSpec, tls kernel.TLSCert) error {
    sp, err := buildSpec(nc)                      // §3.2
    if err != nil { return err }
    h, err := buildHandler(sp, coreUsers(users), k.rt)
    if err != nil { return err }
    r, err := compileRouter(nc, k.rt)             // §3.8
    if err != nil { return err }
    tlsCfg, re, err := security(tls, sp)          // §3.3
    if err != nil { return err }
    srv := core.NewServer(core.ServerOptions{
        Handler: h, Tracker: k.tracker,
        Router: func() *core.Router { return r },
        Trust:  trustOf(k.rt.TrustedProxies),
        Guard:  guardOf(k.rt),
        HandshakeTimeout: k.rt.HandshakeTimeout, TCPTimeout: k.rt.TCPTimeout,
        UDPTimeout: k.rt.UDPTimeout, MaxFresh: k.rt.MaxFresh,
        ProxyProtocol: sp.ProxyProtocol, RequireProxyProtocol: sp.RequireProxyProtocol,
        BindLocal: k.rt.AutoOutIP, NodeID: nc.NodeID,
        OnTraffic: k.meter.traffic,                    // 现有字段
        Hooks:     k.meter.hooks(),                    // 新增，见 §4.2
        OnAudit:   k.meter.audit,                      // 新增，见 §4.4
        Admission: k.meter.admit,                      // 新增，见 §4.3
    })
    ...
}
```

### 3.4 生命周期语义（对齐 `kernel.Kernel` 的注释契约）

| 方法 | 实现 | 语义 |
|---|---|---|
| `Start` | 建新 `Tracker`（首启）→ build → bind → 发布 | 失败不留半成品；`Stop` 后再 `Start` 允许 |
| `Stop` | 关监听 → `Server.Close`（等在途，`drainTimeout`）→ 结束 | 与 sing-box 的「先关 listen 再 drain」一致 |
| `Reload` | **同一 Tracker**、新建 Server/监听 → 原子交换 → 关旧 | 沿用 kaze `apply()` 的「先建后换、失败即弃」；计数与在线表不丢 |
| `Add/Remove/UpdateUsers` | `Tracker.SetUsers`（保留同 ID 计数）+ 差集计数 | 不重启监听；被删用户的连接由 `Tracker.CloseUserConns` 关闭 |
| `IsRunning` | `srv != nil && !srv.closed` | |

### 3.5 限速与设备门控（D4）

**两套实现的实际差别**（代码为证，不是文档猜测）：

| 维度 | TX-Node 现状（`internal/limiter` + sing-box `ConnTracker`） | kaze / dataplane（`core.Limiter`） |
|---|---|---|
| 桶实现 | `golang.org/x/time/rate`：`AllowN` 快路径 + `ReserveN` 等待 | 自研 token bucket：`Reserve` 返回等待时长，`Wait` sleep |
| 单位换算 | `SpeedLimit * 1_000_000 / 8`（十进制；100 Mbps = 12,500,000 B/s） | `mbps * 1024 * 1024 / 8`（二进制；100 Mbps = 13,107,200 B/s，**高 4.86%**） |
| burst | `clamp(bytesPerSec, 64 KiB, 4×bytesPerSec)`，初始**满桶** | `0.25 × rate`（250 ms 带宽），初始 0.25×rate |
| 上下行 | **共用一个桶**：`GetLimiter(uuid)` 同一个 `*rate.Limiter` 同时挂在读、写包装上 | **上下行各一个桶**，另有可选节点级桶；所有桶都必须放行（等效取最小） |
| 挂点 | 连接包装：`trackedConn.Read/Write`（`conntracker.go:645/681`）与 `trackedPacketConn`（`:907` 起）——TCP/UDP 都限 | 中继循环：`copyDirection` 每 32 KiB 读块前 `Wait`（`pipe.go:122`）；**UDP 中继 `relayUDP` 没有限速** |
| 与零拷贝 | 无 splice 路径 | 有限速时自动关闭 splice（`activeLimiters` 为空才走 `splicePipe`） |
| 写缓冲 | `Write` 前按 burst 截断 `b`：单次 `Write` 大于 burst 会短写且不报错（`conntracker.go:645-651`） | 按块等待，不截断 |
| 其他 | 只有 per-user；节点级 Mbps 仅用于 Hysteria/TUIC brutal（`singbox/config.go:667`） | 另有全局/节点级限速、动态限速（阈值触发 + 时段） |

**决定（D4）**：执行引擎用数据面，语义参数按 TX-Node 对齐。

1. `mbpsToBytes` 改为 `×1_000_000/8`（面板口径），避免速率悄悄 +4.86%；
2. `core.Limiter` 增加 `SetBurst`，适配层传入 `clamp(rate, 64 KiB, 4×rate)`；
3. 保留上下行分离（面板语义本就是上行/下行各自上限；共享桶会让两个方向互相抢配额）；
4. 数据面补 **UDP 限速**（现网 TCP/UDP 都限，这条不能丢，见 §4.5）；
5. 节点级/动态限速保留为能力但默认关闭（TX-Node 当前没有对应配置）；
6. TX-Node 的「按 burst 截断写」**不继承**，随旧内核一起删除（属缺陷，不是语义）。

设备门控：数据面 `Tracker.Acquire`（`core/tracker.go:250`）已有 per-user/全局设备上限与
「others」在线计数；适配层把 `UserSpec.DeviceLimit` 写入 `core.User`，并在 `Acquire` 时调用
`SetDeviceLimitFunc` 提供的 fn（需 §4.5 的钩子），保持 TX-Node 侧「移除用户即拒绝」的语义。

### 3.6 计数、在线 IP、连接注册表

| Kernel API | 数据面来源 | 结论 |
|---|---|---|
| `GetUserTraffic` | `Tracker.Snapshot()`（`tracker.go:352`）、`Alive()`（`:376`）、`Connections()`（`:363`）+ `totalSessions` | 直通 |
| `UpdateGlobalDevices` | `Tracker.SetGlobalAlive(map[int]int)`（`:397`），入参 `len([]string)` | 直通（语义：仅计数） |
| `ClearGlobalDevices` | `SetGlobalAlive(nil)` | 直通 |
| `CloseUserConnections(uuid)` | `Tracker.CloseUserConns(userID)`（**新增**，`userState.conns` 已存在） | 需 §4.6 |
| `CloseConnection(connID)` | 数据面 `Server.conns map[net.Conn]struct{}` **无 ID** | 需 §4.6（当前 service 无调用点，可降级为 P3） |

### 3.7 授权、审计、usage_v2、本地事件

| 能力 | 现状 | txnode 方案 |
|---|---|---|
| `StopAuthorization()`（`authorization_adapter.go:224`） | sing-box 关 listener + 关 `authorizationIO` 句柄 | `Server.SetAdmission(false)` + 关监听（§4.3），无需特化句柄 |
| `SetAuditor(*audit.Reporter)`（`auditcoord`） | sing-box adapter 回调 | 数据面 `OnAudit` 钩子 → `Reporter.ObserveWithTargetIP`（§4.4）；口径为「每会话一次」，与 sing-box 的 inbound 级回调**等价子集** |
| `usage_v2` | `nativeUsageKernel` 断言具体 `*singbox.ConnTracker`；绑定后拒绝重启 | 接口化 + per-IO 钩子（§4.2）；**启用时关闭 splice**（见风险 R6） |
| 本地事件（`usagebucket`） | `ConnTracker` 的 `eventBuckets` + `Meter.Bind/Session.Begin/Complete` | 与 usage_v2 共用 chunk 钩子；mux/UDP 需要 `Path` 区分 |
| `usageobserver` | service 侧 `Sample(traffic)`/`Boundary` | 无需内核改动（走 `GetUserTraffic`） |

### 3.8 路由 / 出站 / geo

- 移植 kaze `internal/node/router.go`：`prepareRouter` + `addRoute` + `buildOutbound` + `resolveVia`；
- **删除** `internal/kernel/customcfg.go`、`custom_route_compile.go`（生成 sing-box/xray JSON 的路径）；
- geo 只保留 v2ray `.dat`：数据面 `core/geo.go` 已实现 `geoip.dat`/`geosite.dat` 解析；
  `internal/kernel/geodata` 中 sing-box `geoip.db` 分支删除，`geoassets` 增加 `PrepareTxnode`；
- `KernelConfig.custom_outbound/custom_route/custom_config`（内核原生对象/文件）在 txnode 下**无对应物**：
  只有 `model.CustomOutbounds/CustomRoutes` 的结构化子集被翻译；其余在启动期**明确报错**
  （`custom_config is not supported by kernel "txnode"`），不静默忽略。

### 3.9 限流（准入层）：三层防线怎么分工

「限流」在节点里有三种不同含义，不能混在一层做：

| 层 | TX-Node 现状（sing-box 路径） | dataplane 现状 | txnode 方案 |
|---|---|---|---|
| ① 带宽限速 | `SpeedTracker` 共享桶，TCP+UDP 都限 | 上下行分离 + 节点级，**仅 TCP** | §3.5：用数据面引擎，参数按 TX-Node 对齐，补 UDP |
| ② 设备上限（反共享） | `ConnTracker.checkDeviceGate`：本机 IP 集合 **合并面板全局 IP 集**，全局状态 60 s 过期后退化为只看本机，超限时按字典序确定性取舍（`conntracker.go:433-510`） | `Tracker.Acquire` **只看本机 IP**；面板上报只进 `userState.others`，仅用于 `Online()` 上报，不参与准入（`tracker.go:397-430`） | **必须移植合并逻辑**：新增 `DeviceGate` 钩子（§4.7），由适配层实现，否则多节点反共享失效 |
| ③ 每用户连接数 | 无（面板只下发 SpeedLimit/DeviceLimit） | `Tracker.SetConnLimit`（user_tcp_limit）在 `Acquire` 生效 | 接入为新能力，默认 0（不改变现网） |
| ④ 未认证并发闸 | 无（sing-box 内部机制） | `Fresh/MaxFresh`：满即丢，保护握手阶段 | 配置化，默认 4096 |
| ⑤ 爆破闸 | 无 | `Guard`（invalid_access_*：30 次/60 s → 封 600 s，IPv6 按 /64 聚合） | 接入，默认关闭（与 kaze 默认一致） |
| ⑥ 配额准入 | `usage_v2` 的 `BeginIO`（授权窗口 + grants + 请求字节数） | 无 | §4.2 chunk 钩子补齐（D3 门禁） |

其它准入细节：

- **删除用户即断连**：TX-Node `limiter.UpdateUsers` 返回被删 ID，`RemoveUsers` 后必须调
  `Tracker.CloseUserConns`，否则旧会话继续跑（现网 sing-box 路径就是关连接的）；
- **拒绝原因可诊断**：数据面 `refuseReason` 给出 `connection limit reached` /
  `device limit reached`，与现网日志口径一致，适配层直接复用；
- **多节点设备态**：面板 `/alivelist` 的 IP 列表要保留到适配层的设备表里，
  **不能只转成计数**（v2 的 `UpdateGlobalDevices → SetGlobalAlive(len)` 是错的，v3 已改）。

结论：**准入骨架用数据面（Tracker + Fresh + Guard），业务语义用 TX-Node（全局设备合并 + 配额准入）**。

---

## 4. 数据面补丁清单（`internal/dataplane`，通用能力）

> 原则：只加钩子/注册表，不改协议语义。每个补丁都要带自己的单测。

### 4.1 会话/连接标识

`core/server.go`：`handle()` 第 1 阶段给连接分配 `uint64` 自增 ID，登记到
`connIDs map[uint64]net.Conn`；`Session`（`core/types.go:97`）增加 `ConnID uint64`。
提供 `Server.CloseConnection(id) bool`。关闭路径同时清 `Tracker` 的 `userState.conns`。

### 4.2 per-IO 计量钩子（usage_v2 / 本地事件）

```go
type Direction int // DirUp / DirDown

type Chunk struct {
    ConnID uint64
    UserID int
    Dir    Direction
    Path   string // "conn" | "mux" | "udp"
    N      int64
}

type ChunkHook interface {
    Begin(Chunk) error    // 可拒绝本次 IO（配额/授权）
    Complete(Chunk, error)
}

// ServerOptions 新增 Hooks ChunkHook
```

挂点：`core/pipe.go` 的 `copyDirection`（`relay.go:176` 取桶之后）与 UDP 计数路径。
`splice` 快路径无法「先准入后拷贝」，**启用 Hooks 时 `trySplice` 返回 false**，退回
`io.Copy`+限速路径；这是可接受的显式降级（原生 usage 模式本就不追求零拷贝）。

### 4.3 准入开关（授权到期）

`ServerOptions.Admission func() bool`，在 `handle()` 第 3 阶段（fresh 之后）与 QUIC
`ServeSession` 入口检查；返回 false 直接关闭连接并计入拒绝原因。

### 4.4 审计钩子

`ServerOptions.OnAudit func(userID int, target, targetIP, sourceIP string)`：
在 `relay.go` 路由决策后调用一次（域名优先，IP 兜底）。适配层映射到
`audit.Reporter.ObserveWithTargetIP`。

### 4.5 限速/设备门控扩展（D4）

- `core.Limiter` 增加 `SetBurst(n int64)`（默认仍为 0.25×rate，不改变无配置时的行为）；
- `Tracker.SetUserLimit(userID int, upBps, downBps int64, burst int)`——适配层用 TX-Node 的
  `clamp(rate, 64 KiB, 4×rate)` 传入；
- `mbpsToBytes` 的换算改为 `×1_000_000/8`（当前 `core/limiter.go` 末尾是 `×1024×1024/8`）；
- **UDP 限速**：`relayUDP`（`core/relay.go`）补 `s.limiters(o, user)` + 每数据报 `Wait`，
  与 TCP 同一对桶；否则 UDP 用户可绕过面板限速（现网 sing-box 路径对 `trackedPacketConn`
  是限速的，见 §3.5）；
- `Tracker.SetDeviceLimitFunc(fn func(userID int) (int, bool))`，在 `Acquire` 内调用（热路径一次函数调用）。

### 4.6 按用户关闭连接

`Tracker.CloseUserConns(userID int) int`（遍历 `userState.conns` 关闭并计数）。
`CloseConnection(connID)` 以 §4.1 的注册表实现。

**规模估计：约 250–350 行改动 + 单测。**

---

### 4.7 设备闸钩子（多节点反共享）

```go
// DeviceGate 替代 Tracker 内建的「只看本机 IP」判定。
type DeviceGate interface {
    // local: 本机在线地址 → 连接数；返回 false 拒绝本次会话。
    Allow(userID int, src netip.Addr, local map[string]int) bool
}

func (t *Tracker) SetDeviceGate(g DeviceGate)
```

`Acquire` 在设置 `DeviceGate` 时改调它，否则走内建上限。适配层实现按
`singbox/conntracker.go:433-510` 的语义移植：本机已知 IP 直接放行；全局状态
超过 60 s 视为过期、退化为只看本机；否则取本地∪全局并集，超限时按字典序保留前 N 个
（确定性，避免同一 IP 反复抖动）。

### 4.8 与新能力相关的默认值

- `user_tcp_limit` 默认 0（不限）；
- `invalid_access_enable` 默认 false（与现网一致）；
- `max_fresh` 默认 4096；
- 设备上限：panel 下发的 `device_limit` 与节点 `device_limit` 取小，沿用现网规则。

## 5. 服务层 / 配置 / 模型改造清单

### 5.1 代码接线（按文件）

| 文件 | 改动 |
|---|---|
| `internal/service/service.go:125-132` | 工厂：`case "txnode": k = txnode.New(cfg.Kernel)`；删掉 `singbox`/`xray` 分支（无迁移映射） |
| `internal/service/service.go:359-360` | 限速/设备钩子改由 txnode 适配层消费（签名不变） |
| `internal/service/kernel_adapter.go` | 无需改动（只依赖 `kernel.Kernel`） |
| `internal/service/native_usage_adapter.go:24,138` | `nativeUsageKernel` 改为中性接口（§5.3） |
| `internal/service/usage_event_store_adapter.go:19` | `localEventKernel` 接口保持不变，txnode 实现之 |
| `internal/service/authorization_adapter.go:224` | txnode 实现 `StopAuthorization()` |
| `internal/auditcoord/coordinator.go:27` | txnode 实现 `SetAuditor(*audit.Reporter)` |
| `internal/config/config.go:151,627,802` | 注释/默认值/校验：只接受 `txnode`（空值默认 `txnode`）；其他值直接拒绝，不提供迁移提示 |
| `internal/model/validate.go:71` | `normalizeKernelType` 只保留 `txnode`；`singboxUnsupportedTransports` 对 txnode 不生效（xhttp 反而支持） |
| `internal/model/validate.go:63` | `ResolveKernelForTransport`：txnode 不需要按传输切内核，直接返回自身 |
| `internal/model/custom_outbound_support.go:5,22` | 新增 `"txnode"` 条目（协议子集 = 数据面 outbound：vmess/vless/trojan/shadowsocks/socks/http/wireguard/tuic/hysteria2/anytls/naive/mieru） |
| `internal/model/custom_route_support.go:5,17` | 新增 `"txnode"` 条目 |
| `internal/geoassets/coordinator.go:55` | 增加 `PrepareTxnode`（只 .dat） |
| `internal/kernel/geo.go` | `NeedsGeoIP/NeedsGeoSite` 可复用 |
| `docs/`、`config.yml.example`、`README.md` | 内核名与能力矩阵 |

### 5.2 新增运行配置（数据面需要，TX-Node 现在没有）

`KernelConfig` 现有字段是「内核原生 JSON」语义，txnode 需要的是**行为参数**。建议加
`internal/config/dataplane.go`：

```yaml
dataplane:
  trusted_proxies: [private, cloudflare]   # core.ParseTrust
  proxy_protocol: false
  require_proxy_protocol: false
  auto_out_ip: false
  max_fresh: 4096
  handshake_timeout: 10s
  tcp_timeout: 300s          # 0 = 不限
  udp_timeout: 60s
  forbidden_private_ip: false
  forbidden_bittorrent: true
  forbidden_ports: ""
  block_list_file: ""
  white_list_file: ""
  routes_file: ""
  dns_rules_file: ""

  # 准入（限流）——新增能力，默认值保持现网行为
  user_tcp_limit: 0              # 每用户并发连接上限，0=不限（现网无此限制）
  device_limit: 0                # 节点级设备上限，与 panel 的 device_limit 取小
  device_ipv6_prefix: 64
  invalid_access_enable: false   # 爆破闸，默认关闭
  invalid_access_count: 30
  invalid_access_duration: 60
  invalid_access_forbidden_time: 600
```

**默认值必须与现网 sing-box 行为一致**（例如私网默认不阻断、连接数不限、爆破闸关闭），
否则面板侧无感知地改变准入语义。

### 5.3 usage_v2 接口化

在 `internal/usageinterval`（或新 `internal/kernel/usage`）定义：

```go
type NativeMeter interface {
    EnableEnforcingBounded() bool
    FlushBoundedUsage() (*usagev2.Submission, error)
    CheckBoundedUsage() error
    StopBoundedUsageTraffic()
}
```

`nativeUsageKernel` 改为 `SetNativeUsageTracker(NativeMeter) bool`；
`nativeUsageRuntime.active` 从 `*singbox.ConnTracker` 改为 `NativeMeter`。
singbox 与 txnode 各自实现，service 不再 import 具体内核。

---

## 6. 能力矩阵与降级

### 6.1 协议

| 协议 | 现网 sing-box | txnode（数据面） | 结论 |
|---|---|---|---|
| vmess / vless / trojan / shadowsocks / anytls / naive / socks / http / mieru | ✅ | ✅ | 对等 |
| hysteria2 | ✅ | ✅（`hysteria` v2） | **Mihomo 互通未通过（HY2-1）** |
| tuic | ✅ | ✅ | 对等（0-RTT 双方都没有/未验证） |
| snell | ❌（sing-box 入站不支持） | ✅ | **能力新增**，需在能力矩阵标注 |
| VLESS Encryption（客户端侧） | 部分 | 仅服务端自洽实现 | 互通未证（R1） |
| VMess（AEAD） | ✅ | 自互通通过 | **Xray 互通失败（VMESS-1）** |

### 6.2 传输

tcp / tls / reality / ws / grpc / h2 / httpupgrade / xhttp / shadowtls / obfs-http / mux(h2) 全支持；
**xhttp 从「只有 xray 能用」变成 txnode 原生支持**，`ResolveKernelForTransport` 的
自动切内核逻辑因此可以退休。

### 6.3 明确降级（必须在文档标注）

| 项 | 现网 | txnode | 影响 |
|---|---|---|---|
| WS `permessage-deflate` / early-data | 有 | 无 | 少数客户端协商失败 |
| Mieru `traffic_pattern` / 低熵编码 | 有 | 无 | 流量整形能力缺失 |
| Snell `reuse` / 12 槽印记 | 有 | 无 | 高频短连接性能差异 |
| REALITY `mirror` 字节回放 | 真实回放 | 仅时延整形 | 探测指纹细节不同 |
| 审计口径 | inbound 回调（含协议/路由细节） | 每会话一次（目标/来源） | 审计字段子集 |
| `node-usage/v2` | 完整 | 需 §4.2 落地后才算 | **兼容性契约项**：未落地前 `core.v1.json` 必须记录降级 |

> `compatibility/core.v1.json` 声明了 `node-usage/v2`，属于 Node↔Core 契约。
> usage_v2 未对齐前不能声称兼容，只能显式评审降级。

---

## 7. 分阶段实施

### P0 基线（0.25 人日，可立即做）

1. `git tag pre-txnode`（当前 HEAD 无 tag，v1 遗留项）；
2. 记录可复现构建方式：本机 `/root/.cache/go-build`、`/root/go/pkg/mod` 已可写，
   `go build ./...` 可离线/在线复现；记录当前唯一编译错误（§1）；
3. 记录 `kaze` 侧基准（`kaze/BENCHMARKS.md`：897.9 MB/s、CPU 0.96 s/GiB、RSS 14.4 MB）作为对照。

### P1 适配层与编译闭环（4–5 人日）

| 步骤 | 产出 | 验收 |
|---|---|---|
| P1.1 `meter.go` + `Tracker` 补丁 | txnode 计数/在线 IP/设备门控/限速桥；`usagebucket` 可接 | `go test ./internal/dataplane/... ./internal/kernel/txnode/...` |
| P1.2 `spec.go` + `build.go` | 12 协议 × 传输 × TLS/REALITY 构建 | 表驱动单测：每个 `NodeSpec` fixture 产出期望 handler/监听 |
| P1.3 `router.go` | custom_outbounds/routes/geo(.dat) | 与 kaze `node/router` 行为对齐的单测 |
| P1.4 删旧内核（**无兼容，直接删**） | 删除 `kernel/{singbox,xray}`、`deps/*`、`sagernet/*`/`xtls/*` 依赖与 replace；`KernelConfig` 原生字段下线；`kernel.type` 只保留 `txnode`，空值默认 `txnode`，其他值由校验直接拒绝（**无迁移提示、无别名**） | `go build ./...` 通过（**此时才可能**）；`grep -r "sagernet\|xtls" --include=*.go` 为 0 |
| P1.5 service/config/model 接线 | §5.1 全表 | `kernel.type: txnode` 起 socks 节点，本地 `curl` 通 |

> 顺序很重要：**先让 txnode 顶替，再删 sing-box**。反过来会同时失去编译与运行能力。
> 删除 sing-box 会打断 5 个测试文件的 `*ConnTracker` 引用，因此 P1.1 必须先于 P1.4。

### P2 能力对齐（3–4 人日）

1. `Reload` 不断流（同 Tracker、先建后换）；
2. `CloseConnection`/`CloseUserConnections`；`StopAuthorization`；`Admission`；
3. 审计钩子 + `auditcoord` 接线；
4. 限速/设备门控与 TX-Node `limiter` 对拍（含 burst 差异）；
5. geo 只 .dat；`custom_config` 明确报错；
6. **验收**：与 sing-box 时期逐项行为对照表（用户增删 / 计数 / 限速 / 设备上限 / 关连接 / Reload / 授权到期）。

### P3 usage_v2 与本地事件（2–3 人日）

1. `NativeMeter` 接口化（§5.3）；
2. 数据面 chunk 钩子（§4.2）→ `usageinterval.NativeCollector.BeginIO/CompleteIO`；
3. `usagebucket.Meter.Bind/Session.Begin/Complete` 接入（含 mux/UDP 的 `Path`）；
4. 与 sing-box 时期的 `usagev2` 会话/日志**对拍**（同配额、同窗口、同截断点）；
5. **验收**：`node-usage/v2` 行为等价；`core.v1.json` 保持不降级。

### P4 测试、e2e、发布（3–4 人日）

- 移植 kaze `e2e/`：`protocols_test.go`（12 协议）、`listeners_test.go`、`limits_test.go`、
  `reality_mirror_test.go`、`transport_test.go`、`fakepanel/`；
- TX-Node 侧 e2e：假面板 + `kernel.type=txnode` 全链路（拉配置 → 监听 → 上报 → 用户同步 → Reload）；
- `-race`、30 分钟 soak、1000 并发（kaze 未做的部分，纳入本阶段）；
- 第三方客户端互通（Xray/mihomo/v2rayN 等**仅作测试客户端**，不进入依赖；VLESS/VMess/Trojan/SS 优先）；
- `scripts/bench-ab.sh` 移植：txnode vs 旧 sing-box 快照镜像，吞吐/CPU 不劣于基线 5%；
- 文档：`README`、`config.yml.example`、能力矩阵、迁移说明。

---

## 8. 风险登记册

| # | 风险 | 证据 | 对策 |
|---|---|---|---|
| R1 | **互通实测结果**：VLESS(tcp/ws)、Trojan+TLS、SS 通过；**VMess / REALITY / Hysteria2 未通过**（详见 `docs/INTEROP.md`），VLESS Encryption 仍无客户端侧 | 本轮 Xray 26.3.27 / Mihomo v1.19.32 实测 | 三项缺口按 HY2→VMess→REALITY 顺序修；修复前对应协议标「实验性」，不得宣称全互通 |
| R2 | **REALITY 已互通**：鉴权与证书按 `xtls/reality` 对齐并改用参考 TLS 栈，Xray/Mihomo 均通过；限制是借用站点握手记录需 ≤8 KiB，首次握手等待 post-handshake 学习（≤8 s） | `docs/INTEROP.md` | 保留参考栈依赖；mirror 字节回放仍待补 |
| R3 | **usage_v2 语义**：区间计量要求 per-IO 准入，数据面需关 splice | 本仓 `native_usage_adapter.go:24`；`core/pipe.go` splice 路径 | P3 单独立项；原生模式与普通模式分开压测 |
| R4 | **依赖版本**：TX-Node 已对齐 quic-go 0.63/utls 1.8.3；后续升级需双向验证 | `go.mod` | 锁版本 + CI 双跑 |
| R5 | **linkname 类冲突**：sing-box 的 `v2rayhttp.ResetTransport` 已因 x/net 升级失效 | 本次实测编译错误 | 删除 `internal/deps/sing-box` 是根治；不要试图用 `-checklinkname=0` 掩盖 |
| R6 | **性能回归**：splice 在 Hooks 模式关闭；REALITY/QUIC 路径与 sing-box 实现不同 | kaze 基准仅回环 | 分模式基准：普通模式必须 ≥ 基线；usage_v2 模式单独给基线 |
| R7 | **配置语义漂移**：数据面默认值（私网/BT/超时/设备上限）与 sing-box 不同 | §5.2 | 默认值逐项对齐 + 启动时打印生效值 |
| R8 | **可回滚性**：大量删除 | 无 tag | `pre-txnode` tag + 删除类提交单独 commit |
| R9 | **清洁室声明**：数据面来自行为复刻 | kaze §四 | `internal/dataplane/NOTICE.md` 记录来源与清洁室声明 |

---

## 9. 工作量

| 阶段 | 内容 | 人日 |
|---|---|---|
| P0 | tag + 构建基线 | 0.25 |
| P1 | 适配层（spec/build/router/meter）+ Tracker 补丁 + 删旧内核 + 接线 | 4–5 |
| P2 | 生命周期/审计/授权/限速/geo 对齐 | 3–4 |
| P3 | usage_v2 + 本地事件 | 2–3 |
| P4 | e2e/互通/压测/文档/基准 | 3–4 |
| **合计** | | **12.25–16.25** |

可并行：P1.2（协议构建）与 P1.3（路由）互不依赖；P3 可与 P4 的测试框架并行启动。

---

## 10. 验收标准（可执行）

1. `grep -rn "sagernet\|xtls\|kernel/singbox\|kernel/xray" --include=*.go .` 为 **0**；
2. `go build ./... && go vet ./... && make test` 全绿；`go test -race ./...` 无报告；
3. `kernel.type: txnode` 起节点：面板用户同步、流量上报、限速、设备上限、Reload、授权到期全部生效；
4. `bench-ab`：普通模式吞吐/CPU 不劣于旧内核 5%；usage_v2 模式单独基线；
5. 12 协议 × 传输子集 e2e 通过；互通清单按 `docs/INTEROP.md` 执行：VLESS/Trojan/SS 已通过，VMess/REALITY/Hysteria2 修复前不算通过；
6. `core.v1.json` 若发生能力变化，必须有显式评审记录（不允许静默降级）。

---

## 11. 决策台账（已确认，2026-10-20）

| # | 问题 | 决定 | 落地位置 |
|---|---|---|---|
| D1 | `kernel.type: singbox/xray` 旧配置 | **直接彻底清理**：节点在开发阶段，无兼容需要。删旧内核、删内核原生配置键；`kernel.type` 只接受 `txnode`，其他值直接报错，不做自动映射/别名/迁移提示 | §5.1、P1.4 |
| D2 | 审计与部分协议只能「等价子集」 | **接受**，差异写进能力矩阵与 README；审计字段子集在 `auditcoord` 注释与文档中标注 | §6.3、P2 |
| D3 | usage_v2 未对齐前能否发版 | **不允许**。`node-usage/v2` 是 `core.v1.json` 的 Core 契约项；P3 完成并通过对拍前不得发布 txnode 版本，也不得修改 `core.v1.json` 降级 | P3、§10 第 3/6 条 |
| D4 | txnode 与 kaze 的限速差异 | 见 §3.5。结论：**引擎用数据面，参数按 TX-Node 对齐**（十进制 Mbps、burst=clamp(rate,64 KiB,4×rate)、上下行分离、补 UDP 限速、不继承 burst 截断写） | §3.5、§4.5 |
| D5 | `KernelConfig.custom_outbound/custom_route/custom_config` | 按建议：结构化子集翻译；内核原生键**删除**；加载期若出现已删除键则报错（防止静默忽略，属防护而非兼容）；CHANGELOG 记为破坏性变更 | §5.1、§5.2 |
| D6 | 限速与限流的分层归属 | 带宽 = 数据面引擎 + TX-Node 参数（§3.5）；准入 = 数据面骨架（Tracker/Fresh/Guard）+ TX-Node 业务语义（全局设备合并、配额准入，§3.9/§4.7）；每用户连接数与爆破闸作为新增能力，默认关闭 | §3.9、§4.5–§4.8 |

> 环境：构建缓存已可写（`/root/.cache/go-build`、`/root/go/pkg/mod`），
> 本机实测 `go build ./...` 仍只有 §1 记录的 sing-box linkname 单点错误，删旧内核即消除。
