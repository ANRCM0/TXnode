# Mieru v2 承载、显式 traffic_pattern 与验收入口

状态：已编写候选源码与测试；本地只执行格式、静态诊断和交叉编译。中间候选已有
官方 UDP、TCP 复用与显式整形执行记录，最终源码仍须完整 Actions 验收；具体候选
状态见 `OUTSTANDING-WORK.zh.md`，不能据此宣告可发布。

## 固定参考与兼容入口

协议参考固定为官方 `enfein/mieru v3.38.1`，annotated tag 对象
`f8611fa049aec119af6e525691f2d8971bc2094e`，解析后的 commit 为
`a2208ee7a38fb41d843a13ecdde858e67ef2f485`。以下路径均相对于该 commit：

- `pkg/protocol/underlay_packet.go`：UDP 每包显式 nonce、metadata 与 payload 加密、padding。
- `pkg/protocol/underlay_stream.go`：TCP underlay 共享隐式 nonce、按 session ID 分发与连接复用。
- `pkg/protocol/session.go`：open/response 的序号占位、累计 ACK、窗口、数据重排和关闭。
- `pkg/protocol/metadata.go`：32 字节 metadata；type 10/11 的低熵模式、mask、原始长度和旋转。
- `pkg/protocol/low_entropy.go`、`underlay_base.go`：8 字节低熵编码、tag 保留和 canonical padding。
- `pkg/appctl/proto/base.proto`、`clientcfg.proto`：显式 trafficPattern 字段与枚举。
- `apis/common/packet_over_stream.go`、`pkg/socks5/udp.go`：应用 UDP 的 stream framing 与 SOCKS5 报文。

参考地址：`https://github.com/enfein/mieru/tree/a2208ee7a38fb41d843a13ecdde858e67ef2f485`。
实现使用仓库现有 XChaCha20-Poly1305 / PBKDF2 工具，不增加 Mieru、sing-box 或 Xray
服务端运行时依赖。原 `segment.go` / `udp.go` 旧 framing 仍是独立兼容入口，不将其
已有 packet 测试记为官方 v2 UDP 承载已经验收。

## Owner 调用链

```text
NodeSpec.Transport / TrafficPattern
  -> txnode.buildHandler -> mieru.NewHandler（严格 pattern 校验）
  -> liveHandler 当前认证快照与既有共享安全历史
  -> TCP Handle / UDP ServePackets
  -> 官方 v2 解密、open、序号/ACK/窗口、重复抑制、重传
  -> 内层 SOCKS5 CONNECT 或 UDP ASSOCIATE
  -> core.Session.Conn 或 core.Session.Packets
  -> Server.ServeSession / 既有 packet relay
  -> 路由、目标拨号、用户/设备准入、限速、NativeMeter Begin/Complete
  -> 原 collector、持久化日志、Core 上报与回执
```

协议层不建立业务目标 socket。CONNECT 的成功/失败仍通过 `core.HandshakeReply`
返回内层 SOCKS5 REP；应用 UDP 的目标、socket 与计量仍由统一 packet relay 拥有。
UDP underlay 会话带真实来源和当前快照 `AuthValid`，读写与重传也检查快照有效性。
快照替换或 socket 关闭会取消旧 peer；相同凭据重新构造 handler 时保留旧 session
identity tombstone，旧 open 不能仅通过换 nonce 再建旧会话。

TCP underlay 使用一个认证密钥、唯一读游标和串行化写游标，多条逻辑 session 独立拥有
业务序号、SOCKS 请求、关闭与 core relay 生命周期。只有首条服务端 record 附显式 nonce；
后续 open/data/ACK/close 都沿同一游标前进。session 的 close request/response 不关闭
underlay，已结束 session 的迟到控制帧也先完整解密以保持游标。每个新 session 重新检查
当前认证快照并进入 `Server.ServeSession`。逻辑读写截止时间不会设置其他 session 的
读截止时间；无法完整写出的加密 record 则关闭整个 underlay，禁止以失步游标继续发送。
完整 record 边界上的 TCP FIN 只结束输入方向：已认证接收队列仍可交付，子 relay 最多
再用 3 秒完成尾部与回复，随后取消并关闭 underlay。部分 record、AEAD 错误和撤权不
进入该 drain，避免把不完整输入或旧认证数据当成可继续交付的尾部。

## 两种 UDP 必须分别验收

| 承载 | 应用业务 | 适配入口 |
|---|---|---|
| Mieru TCP | TCP CONNECT | `v2Conn` -> `core.Session.Conn` |
| Mieru TCP | UDP ASSOCIATE | `v2PacketTunnel` -> `core.Session.Packets` |
| Mieru UDP | TCP CONNECT | `v2DatagramConn` -> `core.Session.Conn` |
| Mieru UDP | UDP ASSOCIATE | `v2DatagramConn` + `v2PacketTunnel` -> `core.Session.Packets` |

官方 UDP underlay 每个 datagram 都携带 24 字节显式 nonce；同包 metadata 与 payload
分别按官方格式使用该 nonce，而不是 TCP 的隐式 nonce 游标。重传保持原业务 sequence
和明文，重新生成 nonce、padding 与当前 ACK。ACK 的 `unAckSeq` 表示严格小于该值的
序号已经接收；超过本端发送游标的 ACK 被拒绝。open/response 占用 sequence 0，业务
从 1 开始；ACK 不消耗业务 sequence。乱序片段只在缺失序号补齐后向 stream 暴露，
旧序号和重复缓存项不会再次交付。片段是有序 stream 的部分，不另外构建无界完整 PDU。

应用 UDP framing 为 `0x00 || uint16_be(length) || SOCKS5_UDP_datagram || 0xff`。
只接受 SOCKS5 reserved/fragment 为零的独立 datagram；保留多目标地址和 packet 边界。
协议头、ACK、padding、低熵膨胀和重传都在 core 计量边界之外；首次交付的业务字节只经
既有 Read/Write 或 ReadPacket/WritePacket 完成一次，保持原代际 I/O token 的 owner。

## 有界资源和关闭

| 资源 | 候选默认上限/处理 |
|---|---|
| 同一监听的 peer | 1024，官方 v2 与旧 packet 模式共享总数；超限不建立新 peer |
| TCP underlay 逻辑 session | 同时至多 64 个，每个接收队列至多 64 个 segment；队列溢出关闭对应 session，不静默丢业务字节继续传输 |
| v2 未确认发送窗口 | 64 个 segment，同时遵守远端窗口 |
| v2 接收重排/交付队列 | 合计 64 个 segment、256 KiB；缺失的 nextRecv 到达时可有界淘汰最远乱序包腾出空间，累计 ACK 不确认被淘汰项，等待发送端重试 |
| v2 数据报发送大小 | 最多 1400 字节，同时尊重更小的显式 MTU；低熵扩展和 padding 计入该限额 |
| v2 重传 | 初始 250 ms，指数退避至最多 2 s；总发送最多 12 次，耗尽关闭会话，不跳过可靠序号继续交付 |
| v2 peer 存活 | 默认 5 分钟无接收超时；绝对上限 2 小时；socket/context/认证失效立即终止 |
| v2 replay tombstone | 16384 项、10 分钟；容量满时拒绝新 session，避免驱逐仍需保护的历史 |
| 正常关闭的已接受输出 | 最多 3 秒等待确认与重传，随后释放；关闭请求本身不形成新业务计量 |

凭据无效和传输失败释放缓存；正常远端关闭允许读取已经接收的尾部。关闭 drain 不继续
接受新的业务写入，不取得新的计量 token。固定诊断 `PacketDiagnostics()` 仅包含
`peers`、`pending_segments`、`reassembly_bytes`、`retransmissions`、`duplicate_packets`、
`dropped_packets`，不含用户、凭据、地址、原始业务内容或 session ID 标签。

## traffic_pattern 配置

保留现有 `TrafficPattern string` 契约；非空值必须是官方 `trafficPattern` 形状的显式
JSON object。构造 `NewHandler` 时校验未知字段、枚举和范围；任意命名字符串与无效
参数均明确报错。`ValidateTrafficPattern` 可供外层提前校验。
空字符串与 `{}` 保持默认行为。示例 YAML：

```yaml
traffic_pattern: >-
  {"nonce":{"type":"NONCE_TYPE_FIXED","applyToAllUDPPacket":true,"customHexStrings":["010203040506"]},"padding":{"maxMiddlePaddingLen":13,"maxEndPaddingLen":19},"tcpFragment":{"enable":true,"maxSleepMs":0},"lowEntropy":{"mode":"LOW_ENTROPY_MODE_40","maskRotation":"LOW_ENTROPY_MASK_ROTATE_LEFT_3"}}
```

- `nonce`：random、printable、printable subset、固定 hex 前缀；修改长度至多 12 字节，保留
  其余随机 nonce 与用户名 hint。`applyToAllUDPPacket` 控制后续 UDP 包的前缀策略。
- `padding`：middle/end 长度各在 `[0,255]`，零明确禁用；UDP 受剩余 MTU 限制。
- `tcpFragment`：启用后将一条输出 record 分为至多两次 transport write，间隔最多
  `maxSleepMs`（`[0,100]`）；不改变业务片段或计量次数，不承诺操作系统实际 TCP 分包。
- `lowEntropy`：type 10/11 支持 32/40/48/56 模式，32-bit half-mask 重复为 64-bit mask；
  支持不旋转、右移 1-15、左移 1-15 的官方枚举编码。仅密文 body 膨胀，AEAD tag 原样
  保留；解码检查 mask bit 数、长度和所有非数据位一致的 padding 极性，再校验 AEAD。
  服务端只有在同一会话收到低熵数据且显式启用发送模式后，才以低熵回应。
- `seed`：显式有符号 32 位整数（包括 `0`）启用确定性字段生成，遵循固定官方
  v3.38.1 的 SHA-256 31 位映射和字段域；不引入上游 runtime 依赖。
- `unlockAll:true`：开放官方隐式取值范围；省略 seed 时按主机名及固定参考版本
  派生进程可重现的 seed。缺省未设置 seed/unlockAll 时保留原行为。
  隐式模式中显式字段优先（包括 `0`、`false`）；`null` 按未设置处理，重复字段拒绝。
  生成的 nonce 最小值高于显式最大值时拒绝配置，不会覆盖显式范围。

## 候选测试与验收状态

| 入口 | 候选断言 |
|---|---|
| `internal/dataplane/proto/mieru/entropy_test.go` | 固定 wire vector、旋转常量、四种模式、末片不足、padding 篡改、严格配置拒绝 |
| `internal/dataplane/proto/mieru/v2_packet_test.go` | 乱序/重复/窗口、累计 ACK、独立重传 nonce、重传耗尽关闭、快照 replay、piggyback/延迟 SOCKS 请求进入统一 relay |
| `internal/dataplane/proto/mieru/v2_tcp_test.go` | 同一 TCP underlay 的失败拨号后复用、empty-open、并发 CONNECT/UDP ASSOCIATE、独立 session 关闭与共享 nonce 连续性 |
| `internal/dataplane/proto/mieru/v2_failure_test.go` | TCP 部分 record 写入后不可继续、UDP abort 等待发送边界 |
| `TestInteropMieruOfficialUDPTransport` | 官方 v3.38.1 的 TCP-over-UDP 大流量、应用 UDP-over-UDP 跨 MTU、idle/reuse |
| `TestInteropMieruOfficialPacketFaults` | 官方 UDP 客户端经双向丢包/乱序/重复后 bulk 与应用 UDP 精确字节；撤权/轮换/重加后密文重放不增加 core 与 NativeMeter 物理计数；同端口 Reload、配置失败保流及真实绑定失败后的监听回滚与新客户端恢复 |
| `TestInteropMieruOfficialTrafficPatterns` | TCP/UDP × 四种低熵模式；显式 nonce/padding/TCP 分段；双向 bulk 和应用 UDP |
| `TestInteropMieruOfficialImplicitPatterns` | TCP/UDP × seed 0、int32 最小/最大值、主机 seed；官方客户端的双向 bulk 与应用 UDP |
| `internal/dataplane/proto/mieru/pattern_seed_test.go` | 固定官方 seed 向量、显式零/false 优先、范围冲突、重复字段拒绝及实例独立性 |

现有 `TestInteropMieruOfficialClient`、`Idle`、`DialFailure`、`Bulk` 保持独立回归入口。
新增官方测试必须纳入严格完整 manifest，并由 Actions 检查 PASS/FAIL/意外 Skip；普通
缺少二进制的本地发现模式仍沿用既有策略，但不是验收。

网络故障测试中的 NativeMeter 使用本地物理观察，不承担 usage_v2 结算权威或持久化
恢复验收。配置准备失败保留原流；实际 UDP socket 替换失败会恢复旧地址的监听，
由新客户端恢复业务，不承诺原 underlay 无中断。

尚需精确候选提交的完整 Go/race、上述官方客户端测试、路由/限速/计量组合、网络故障
注入、撤权、同端口 Reload/回滚及真实固定 Core C2 证据。源码和静态检查不能关闭这些
验收项，也不能把旧 packet 测试或 TCP 默认模式通过推广到四种组合。
