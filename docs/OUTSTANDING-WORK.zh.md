# 剩余事项报告（txnode 数据面）

> 基线：`feat/txnode-kernel` @ `a6d0e96`（2026-10-20）
> 互通实测：Xray 26.3.27 / Mihomo v1.19.32 / sing-box 1.14.3 / curl 8.5 / 官方 mieru 3.38.1
> 结论：**29 个互通用例通过、0 失败、6 跳过**；本文只记录尚未完成或尚不能验证的事项。

本文与 `docs/INTEROP.md` 的分工：INTEROP 记录「已实测通过什么、怎么复现」，本文记录
「还差什么、差在哪一步、下一步怎么做」。每条都带实测证据或代码位置，避免下一个人重复摸索。

---

## 0. 总览

| # | 事项 | 类型 | 影响 | 优先级 |
|---|---|---|---|---|
| 1 | mieru v2 UDP 承载（`Transport=udp`） | 协议能力 | 用 UDP 承载的 mieru 节点不可用 | P1 |
| 2 | 地址头 mux 的 UDP（smux/yamux `FlagUDP`） | 协议能力 | 开 mux 且走 UDP 的 sing-box 客户端不可用 | P2 |
| 3 | mieru `traffic_pattern` 与低熵编码（type 10/11） | 协议能力 | 缺少流量整形；官方默认关闭 | P3 |
| 4 | Mihomo TUIC 客户端差异 | 上游差异 | 仅 Mihomo 版 TUIC 不可用 | P3 |
| 5 | 部分用例依赖外部条件 | 测试覆盖 | 本机/CI 不稳定可见 | P2 |
| 6 | `usageinterval` 故障注入用例在慢盘上偶发失败 | 测试基建 | 整套 `go test` 偶发红 | P1 |

---

## 1. mieru v2 UDP 承载（未实现）

**现状**：TCP 承载已互通（含 1 MiB 双向、空闲复用、拨号失败），`Transport=udp` 未通过。

**已确证的协议差异**（`internal/dataplane/proto/mieru/v2_udp.go` 实验分支已回滚，结论保留）：

1. 每包自带 nonce：`[nonce 24][metadata 32+tag][payload+tag][padding]`，没有流状态；
2. **同一包内 metadata 与 payload 共用同一个 nonce**（流传输才逐记录 +1）。这条是实测出来的：
   用 `nonce+1` 解 payload 失败、用 `nonce` 成功；
3. 首包 payload 是 SOCKS5 CONNECT 请求，可解出目标地址；
4. 我们回 `openSessionResponse` 后，客户端日志显示 `ATTACHED => ESTABLISHED`，
   但随后**持续重传 open 请求**（tcCount 1→2→3，退避 2s/4s/6s），只回
   `ackServerToClient` 不足以让它进入数据阶段，最终会话超时、SOCKS 建连失败。

**卡点**：包传输的确认语义未对齐——需要确定「哪些 seq 由 ACK 覆盖」「open 请求何时被视为已确认」，
以及服务端回包该用哪个 seq。

**下一步（可执行）**：

1. 以官方 `github.com/enfein/mieru/v3@v3.38.1` 的 `pkg/protocol/underlay_packet.go` 为准，
   读 `sendBuf` 的删除条件（`unAckSeq` 比较）与 `session.runOutputLoop` 的退避逻辑；
2. 用官方客户端 + 本仓 `TXNODE_INTEROP_MIERU` 做逐包抓包（本仓已有 `tap` 思路：TCP/UDP 中继打印首字节），
   对比「Xray 无法作参考（不支持 mieru）」，参考实现只能是官方 server；
3. 更省事的对照：直接跑官方 mieru server 与官方 client 抓同一场景的字节序列，再复刻 ack/open 时序。

**相关代码**：`internal/dataplane/proto/mieru/{v2.go,handler.go,udp.go}`；
原生 v1 UDP 路径在 `udp.go`（`ListenUDP`/`handleDatagram`），可复用其 peer/sweep 结构。

---

## 2. 地址头 mux 的 UDP（明确关闭）

**现状**：`internal/dataplane/mux` 的 `Packets`（`FlagUDP` 流）已实现，但内核层
`serveMux` 只把 TCP 流转给 relay；UDP 流在 Mux.Cool/地址头 mux 中不承载。

**已确证的事实**：用 sing-box 1.14.3 + mux(smux) 发 UDP，抓包得到流内 packet 头：

```
03 | 目标地址(IPv4:port) | 源地址(IPv4:port) | LEN(2) | 数据
```

把它指向 **Xray 26.3.27 参考服务端**时，服务端同样只回了 mux 头的 `0000`，
**没有回任何数据**，客户端 8s 超时（`docs/INTEROP.md` 记录为此用例的 skip 原因）。

**卡点**：没有可对齐的参考行为，无法判断服务端应答格式（是否带地址、是否带源地址回显）。

**下一步**：等 sing-box 侧文档/新版本，或读 `sing-mux` 的 packet-stream 实现后按实现写；
在此之前保持「收到 UDP 流即回 `End`」，保证不串流、不静默错发。

**相关代码**：`internal/dataplane/mux/packets.go`（`[LEN][socks addr][payload]`）、
`internal/dataplane/muxcool/{muxcool.go,xudp.go}`（Mux.Cool 侧已完成 UDP）。

---

## 3. mieru `traffic_pattern` 与低熵编码（未实现）

**现状**：`mieru.Options.TrafficPattern` 已被面板透传（`internal/kernel/txnode/spec.go`），
但数据面**没有任何整形逻辑**，低熵编码（协议 type 10/11）也未实现。

**影响**：默认关闭，普通部署不受影响；开了 `traffic_pattern` 的节点行为与参考实现不一致
（padding/分片策略不同，抗审查强度下降）。

**下一步**：
1. 实现 `traffic_pattern` 的 padding 上下限与分片策略（参考 `docs/protocol.md` 的
   `padding 0/1/2` 与 `mtu` 语义）；
2. 低熵编码按文档的 4 种模式（32/40/48/56 位）实现 8 字节块打包与掩码旋转，
   注意 `payload length` 含填充、`extracted payload length` 才是真实长度；
3. 用例需要显式夹具（官方客户端默认关闭该功能）。

**相关代码**：`internal/dataplane/proto/mieru/{v2.go,segment.go}`；
面板字段见 `internal/kernel/txnode/spec.go:51`。

---

## 4. Mihomo TUIC 客户端差异（上游）

**现状**：sing-box 的 TUIC（TCP/UDP）通过；**Mihomo v1.19.32 的 TUIC 在 QUIC 建连后不发 v5 认证帧**，
服务端没有任何认证记录，用例记为 `TUIC-mihomo` / `TUIC-1` 并 skip。

**判断**：属于客户端实现差异（同参数下 sing-box 正常），不是服务端缺陷；但未经抓包逐帧确认。

**下一步**：抓 Mihomo 的 QUIC 流，确认它是否使用了不同的 ALPN / 认证流布局；
若确认为客户端 bug，则在本仓文档标注版本区间并保持 skip。

---

## 5. 依赖外部条件的用例（覆盖度缺口）

| 用例 | 跳过原因 | 补齐方式 |
|---|---|---|
| `TestInteropMihomoVLESSReality` | 需要 `TXNODE_INTEROP_REALITY_PUB` 才能构造 Mihomo 侧公钥 | CI 里生成固定 REALITY 密钥对并注入环境变量 |
| `TestInteropSingBoxMieru` | sing-box 1.14.3 发布二进制没有 mieru outbound | 等上游支持，或改用官方 mieru 客户端（已覆盖） |
| `TestInteropSingBoxNaive` | sing-box 的 naive outbound 依赖 Chromium cronet，发布二进制不带 | 用 curl（已覆盖 h2 CONNECT） |
| `TestInteropXrayVLESSH2Removed` | Xray 26 已移除独立 h2 传输 | 无需补齐（上游移除） |

另外**互通矩阵目前只在 nightly / dispatch / tag 跑**（`.github/workflows/ci-node.yml` 的 `interop` job），
PR 门禁不跑。若希望 PR 即拦截协议回归，需要评估 30 分钟级耗时是否可接受。

---

## 6. `usageinterval` 故障注入用例在慢盘上偶发失败（测试基建）

**现象**：`TestBoundedIntervalSIGKILLRetainsOriginalSealedJournalAndNeverResumesTail`
在整套 `go test ./internal/...` 运行时偶发失败（约 10s 超时类断言），单独运行稳定通过。

**已做**：`TestNativePendingReadKeepsCompletedWritesBoundedUntilOriginalSessionDrain`
此前因同一类问题（60s 租约在 1024 次持久化写入中途过期）加了「按实测吞吐判定环境不足则带诊断 skip」。

**下一步**：给 SIGKILL 用例同样加环境判定（或把故障注入的等待改成事件驱动而非固定超时），
避免在慢盘/高负载 CI 上误报。

**相关代码**：`internal/usageinterval/{native_linux_test.go,crash_linux_test.go}`。

---

## 7. 复现与验证入口

```bash
# 拉取固定版本客户端（版本 + SHA-256）
scripts/fetch-interop-clients.sh .clients

# 全量互通矩阵（29 通过 / 6 跳过）
TXNODE_INTEROP_XRAY=$PWD/../.clients/xray/xray \
TXNODE_INTEROP_MIHOMO=$PWD/../.clients/mihomo/mihomo \
TXNODE_INTEROP_SINGBOX=$PWD/../.clients/singbox/sing-box \
TXNODE_INTEROP_MIERU=$PWD/../.clients/mieru/mieru \
go test ./internal/kernel/txnode/ -run TestInterop -v -timeout 900s

# 单元测试
go test ./internal/... -count=1
```

诊断工具约定（本轮用过、可复用）：

- 在客户端与服务端之间插一个 TCP 中继，打印前几个字节的 hex，用于确认线上格式
  （Mux.Cool 的 port-then-address、XUDP 的「一帧一分块」都是这样定位的）；
- 客户端 `loggingLevel: TRACE`（mieru）/ `log.level: debug`（sing-box、Xray）可直接看到
  段级收发，比读代码快。
