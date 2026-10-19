# TX-Node 数据面改造方案：用自研 txnode 内核彻底替换 sing-box / Xray

> 状态：方案稿（待实施）
> 决策来源：用户确认——**不保留 sing-box 与 Xray**，彻底替换；**kaze 内核更名为 txnode 内核**，便于后续自研。
> 本文只描述改造方案，不含原始闭源样本、专有代码或密钥。

---

## 1. 目标与原则

| 原则 | 含义 |
|---|---|
| **以 TX-Node 为主** | 进程模型、YAML 配置、面板 provider、计费/用量、Credential Provider、CI/镜像、兼容性契约全部保留在 TX-Node；数据面换掉即可 |
| **彻底替换** | 删除 `internal/kernel/{singbox,xray}`、`internal/deps/{sing-box,sing-vmess}` 与 `sagernet/*`、`xtls/*` 依赖；`kernel.type` 只接受 `txnode` |
| **单一权威** | 计费/上报以 TX-Node 的 `tracker`/`reporting` 为唯一权威；内核只提供原始计数与门控能力 |
| **内核可自研** | 新内核命名 `txnode`，接口边界（`kernel.Kernel`）保持不变；协议引擎放在 `internal/dataplane/`，与适配层解耦，便于后续替换/演进 |
| **可回滚** | 改造在独立分支进行，旧内核代码在首个提交前打 tag，便于对照与回退 |

命名约定：

- 内核标识：`kernel.type: txnode`（旧值 `singbox`/`xray` 给出明确迁移错误，不静默回退）
- 内核实现包：`internal/kernel/txnode`
- 协议引擎：`internal/dataplane/{core,proto/*,transport,ctransport,mux,qstream,outbound,wgout,tlsbuf,pool,udperr,opt,socks,congestion/bbr}`

---

## 2. 目标架构

```
cmd/tx-node ──► internal/service ──► internal/kernel.Kernel 接口
                     │                      │
                     │                      └─ internal/kernel/txnode   （适配层：NodeSpec↔数据面）
                     │                                │
                     │                                └─ internal/dataplane/*（协议引擎）
                     │                                        core（监听/中继/路由/DNS/限速/splice）
                     │                                        proto/*（12 协议 + xudp）
                     │                                        transport/ctransport/mux/outbound/wgout
                     ├─ panel（provider：txboard/xboard/…）      ← 不变
                     ├─ tracker / reporting / usage / audit    ← 不变（计费权威）
                     └─ authorization / credentialprovider     ← 不变（独立进程）
```

数据流（一次会话）：

```
panel pull ─► model.NodeSpec ─► service ─► kernel.Start
                                        └─ txnode：NodeSpec → dataplane 配置
                                              ├─ 协议 handler（12 选 1）
                                              ├─ 传输（tcp/tls/reality/ws/grpc/h2/xhttp）
                                              └─ core.Server（握手/审计/限速/中继/splice）
客户端 ─► 监听 ─► core.Server ─► tracker（TX-Node）取限速与设备限额
                                └─ GetUserTraffic → tracker/usage → reporting → panel
```

---

## 3. 包与命名映射

| 现状 | 改造后 | 动作 |
|---|---|---|
| `internal/kernel/singbox`（17 文件） | — | **删除** |
| `internal/kernel/xray`（6 文件） | — | **删除** |
| `internal/deps/sing-box`（5 MB）、`internal/deps/sing-vmess` | — | **删除**（含 `licenses/` 中对应上游声明） |
| — | `internal/kernel/txnode` | **新增**：实现 `kernel.Kernel` |
| — | `internal/dataplane/*`（122 文件） | **新增**：由 kaze 数据面搬运并重命名 |
| `internal/kernel/geodata`（sing-box `geoip.db`/xray `.dat` 双格式） | 仅 `.dat` | 改写：只下载/校验 v2ray `geoip.dat`/`geosite.dat` |
| `internal/kernel/customcfg.go`、`custom_route_compile.go` | `txnode` 路由/出站编译器 | 改写：输出 dataplane 的 `Router`/`outbound.New`，不再生成 sing-box/xray JSON |
| `internal/service/native_usage_adapter.go`（依赖 `singbox.NewNativeUsageTracker`） | `txnode` 原生用量采集 | 改写：用 dataplane 的 per-user 计数 + 连接表实现 `NativeCollector` |
| `compatibility/renderers.v1.json` | 重新生成 | 指纹改为 txnode 渲染器；`core.v1.json` 重新评审 |
| `go.mod` | 去掉 `sagernet/*`、`xtls/*`；加入 `apernet/quic-go`、`refraction-networking/utls`、`golang.zx2c4.com/wireguard`、`lukechampine.com/blake3`、`xtaci/smux`、`hashicorp/yamux`、`zeebo/blake3` 等 | 依赖重排 |

---

## 4. TX-Node 依赖的内核能力 → txnode 如何满足

| `kernel.Kernel` 能力 | 现状（sing-box/Xray） | txnode 实现 |
|---|---|---|
| `Name/Protocols/Capabilities` | 各自声明 | `"txnode"`；12 协议；5 项能力全 `true` |
| `Start(NodeSpec, users, TLSCert)` | 生成内核 JSON/YAML 并启动 | `NodeSpec` → dataplane 配置；`TLSCert` 直接注入 `tls.Config`（**不启用** dataplane 自带的 ACME） |
| `Stop` | 关闭内核 | 关闭 TCP/UDP/QUIC 监听，等待在途会话 |
| `Reload` | 重建内核 | 先建新监听→原子交换→失败即弃（沿用 dataplane 的 apply 语义） |
| `AddUsers/RemoveUsers/UpdateUsers` | 内核用户表 | `tracker.SetUsers` + 差集计数；不重启监听 |
| `GetUserTraffic` | 内核内部原子计数 | `tracker.Snapshot()/Alive()/Connections()` |
| `CloseConnection(connID)` | 连接表 | dataplane 需新增**连接注册表**：connID→conn、userID |
| `CloseUserConnections(uuid)` | 按 UUID 关闭 | 注册表按 UUID 索引批量关闭 |
| `SetSpeedLimitFunc(uuid) *rate.Limiter` | 内核限速钩子 | dataplane 增加 `ServerOptions.LimitFunc`；中继按块 `WaitN`（与 TX-Node 语义一致） |
| `SetDeviceLimitFunc(uuid) (int,bool)` | 内核设备门控 | dataplane 增加 `Tracker.DeviceLimitFunc`，`Acquire` 时调用 |
| `UpdateGlobalDevices(map[int][]string)` | 内核全局设备表 | 转为计数后 `tracker.SetGlobalAlive` |
| `ClearGlobalDevices` | 清空 | `tracker.SetGlobalAlive(nil)` |
| 审计（`SetAuditor`） | 仅 sing-box 实现 | txnode 实现同名钩子：用 dataplane 的嗅探审计（私网/BT/端口）映射到 `audit.Reporter`；能力矩阵标注等价子集 |
| 原生用量 v2（`usage_v2`） | 需 `kernel.type == singbox` | 改为 `kernel.type == txnode`；采集器基于 dataplane 计数 |

---

## 5. 分阶段实施

### P0 准备（0.5 天）
- 从 `main` 拉分支 `feat/txnode-kernel`，打 tag `pre-txnode`；
- 记录当前 `make test` 基线（通过数/耗时），作为回归对照。

### P1 搬运与适配骨架（2–3 天）
1. `internal/dataplane/*`：搬运 kaze 数据面（core/12 proto/transport/ctransport/mux/qstream/outbound/wgout/tlsbuf/pool/udperr/opt/socks/congestion），改写 import，删除随包测试；
2. `internal/kernel/txnode`：实现 `Kernel` 接口（Start/Stop/IsRunning/用户增删/流量/关连接/限速与设备钩子）；
3. `internal/config`：`kernel.type` 只接受 `txnode`（旧值报错并提示迁移）；默认值改为 `txnode`；
4. `internal/service`：工厂 switch 改为 `txnode`；协议支持表换成 12 协议；
5. 移除 `internal/kernel/{singbox,xray}`、`internal/deps/*` 与相关 import；
6. **验收**：`go build ./...` 通过；`kernel.type=txnode` 能起一个 socks 节点，本地 curl 通。

### P2 能力对齐（3–4 天）
1. `Reload` 热替换；`CloseConnection`/`CloseUserConnections`（连接注册表）；
2. 限速/设备限制钩子接 TX-Node 的 `limiter`；
3. `usage_v2` / `native_usage_adapter` 改为基于 txnode；
4. `geo` 只保留 `.dat`；`custom_outbound`/`custom_route` 编译到 dataplane 路由；
5. 审计钩子（`SetAuditor`）等价实现；
6. **验收**：与 sing-box 时期的行为对照表逐项通过（用户增删、流量计数、限速、设备限制、关连接、Reload 不断流）。

### P3 删除与清理（1 天）
- 删除 `internal/deps/*`、`sagernet/*`/`xtls/*` 依赖、旧内核测试；
- `go mod tidy`；`Dockerfile`/`Makefile`/CI 调整；
- `compatibility/renderers.v1.json` 重新生成，`core.v1.json` 重新评审；
- **验收**：`go vet`、`make build`、`make test`、`-race` 全绿；镜像可构建。

### P4 集成与发布（2 天）
- e2e：假面板 + `kernel.type=txnode` 全链路（拉配置→起监听→流量上报→用户同步→Reload）；
- 文档：`README`、`config.yml.example` 增补 `txnode`；能力矩阵与降级说明；
- 可选：`txnode` 内核的协议/传输矩阵公开测试（12 协议 × 9 传输的子集）。

---

## 6. 风险与对策

| # | 风险 | 影响 | 对策 |
|---|---|---|---|
| 1 | **依赖版本冲突**：TX-Node 锁 `x/crypto v0.49`、`quic-go v0.59`、`utls v1.8.3-0.x`；数据面按 `v0.57/v0.63/v1.8.2` 写的 | 编译失败或 API 差异 | 以 TX-Node 版本为准，逐项适配（重点 quic-go/utls 少量 API） |
| 2 | **协议覆盖差异**：sing-box/Xray 支持的协议比 dataplane 多（如 TUIC 0-RTT、部分 obfs） | 面板下发某些配置会失败 | `Capabilities()` + `Protocols()` 显式声明；不支持时返回明确错误，并在能力矩阵标注 |
| 3 | **审计语义**：TX-Node 审计依赖 sing-box 的 listener 钩子 | 审计功能降级 | 用 dataplane 嗅探审计实现等价子集（私网/BT/端口/域名规则），差异写入文档 |
| 4 | **用量 v2 语义**：原生订阅用量依赖 sing-box 的区间采集 | 计费精度变化 | 用 dataplane 的 per-user 原子计数 + 连接表重建采集器，并用 TX-Node 的 `usagev2` 会话/日志做对拍 |
| 5 | **性能回归**：新内核与原 sing-box 的实现差异 | 吞吐/延迟变化 | 用 `scripts/bench-ab.sh` 做 txnode 内核 vs 旧内核的配对基准（不需要原样本） |
| 6 | **可回滚性**：大量删除 | 出错难恢复 | 分支 + `pre-txnode` tag；删除类提交单独成一个 commit |
| 7 | **合规与溯源**：数据面来自对闭源样本的行为复刻 | 许可风险 | `internal/dataplane/NOTICE.md` 记录来源与清洁室声明；不引入原始二进制/密钥 |

---

## 7. 工作量估算

| 阶段 | 文件改动（估） | 人日（单人） |
|---|---|---|
| P0 | 0 | 0.5 |
| P1 | +122（数据面）+ ~6（适配层）+ 8 处接线 −23（旧内核） | 2–3 |
| P2 | ~15 文件改写 | 3–4 |
| P3 | 删除 + 依赖整理 + CI | 1 |
| P4 | e2e + 文档 | 2 |
| **合计** | **~170 文件** | **8–10 人日** |

（并行度高：数据面搬运、适配层、配置接线可拆给 2–3 人/代理同时做；适配层是关键路径。）

---

## 8. 验收标准（可执行）

1. `grep -r "sagernet\|xtls\|kernel/singbox\|kernel/xray" --include=*.go .` 为 **0**；
2. `go build ./... && go vet ./... && make test` 全绿，`go test -race` 无报告；
3. `kernel.type: txnode` 起节点后：面板能拉到用户、上报能到面板、限速与设备限制生效、Reload 不断流；
4. `scripts/bench-ab.sh`（txnode 内核 vs 旧内核快照二进制）吞吐与 CPU 不劣于基线 5%；
5. 文档与示例同步：`README` / `config.yml.example` / `compatibility/renderers.v1.json`。

---

## 9. 待你确认的 3 个细节

| # | 问题 | 建议 |
|---|---|---|
| 1 | 旧配置里的 `kernel.type: singbox/xray` 是**报错**还是**自动映射到 txnode**？ | 报错并给出迁移提示（避免静默行为变化） |
| 2 | 审计与原生用量 v2 若无法完全等价，是否接受「等价子集 + 文档标注」？ | 接受（这是唯一可行的路径） |
| 3 | 数据面目录名用 `internal/dataplane` 还是 `internal/txnode`？ | `internal/dataplane`（适配层叫 `kernel/txnode`，避免同名混淆） |
