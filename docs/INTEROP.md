# 第三方客户端互通测试（txnode 数据面）

客户端只是**测试工具**：不进 `go.mod`、不进镜像、不进发布产物。测试在设置环境变量后才
运行。普通发现模式仅在未配置客户端时允许 `t.Skip`；设置了无效路径、已支持链路发生错误时均失败。

## 严格验收门禁（S0 实现）

工作流以 `scripts/interop-cases.v1.json` 声明用例、客户端版本/校验值、quick/full 范围及已知缺口，
通过 `scripts/interop_gate.py` 执行严格模式并核对 `go test -json` 结果。quick 用于 PR/main，
full 用于 nightly/dispatch/tag；标签发布依赖 full 成功。源码中已实现的门禁仍须由对应提交的 Actions 验收，
下文历史通过数不自动更新为新版本验收结果。

- 必需客户端缺失、校验值错误、用例缺失、父子结果不完整、支持用例失败和意外 Skip 均使门禁失败。
- 已知缺口必须按用例及固定 `INTEROP_KNOWN_GAP:<ID>` 标记，默认在探测前声明未执行/未验收。
- `TXNODE_INTEROP_DIAGNOSTIC_GAPS=1` 可在单独诊断运行中实际探测已知缺口，错误直接失败；严格汇总 runner 不启用此模式。
- REALITY 夹具自行生成匹配的 X25519 密钥对；不再因缺少外部公钥跳过 Mihomo。
- 四个下载客户端固定二进制 SHA-256。curl 使用 Ubuntu 24.04 的系统版本，检查版本及 HTTP/2 能力，记录实际二进制摘要；它不具有与下载客户端相同的二进制锁定保证。
- 每次保留 `events.jsonl`、`stderr.log`、`summary.json`、`summary.md`，记录源码提交/树、清单摘要和客户端来源。已知缺口与不适用组合不计作通过。

清单现有 39 个顶层用例（37 个适用、两项不适用），适用用例共 27 个声明子项；
quick 选择其中 8 个顶层。新增 `TestInteropXrayVMessNativeOutbound` 使用本仓库
outbound 连接固定 Xray 服务端，覆盖 AES-GCM、ChaCha20、none 的同流多次消息及
跨帧请求；它与 Xray 客户端连接本仓库服务端的既有测试分别验收。
候选 `7c9cd91e8ca4b0bb9ecfa571872c83d384480bee` 的 Actions `39535513954`
已通过 quick 8 顶层/5 子项和 full 37 顶层/27 子项；另两项不适用不计通过。
full artifact 为 `12316734483`。完整 Go/race 也通过独立 wire、并发及 Service VLESS/VMess
续期回归。此前完整互通暴露的 Naive h2 取消 watcher 竞争已由 `copyPipe` 在返回前
等待清理完成修复，并由确定性生命周期回归和真实第三方客户端门禁验证。
本结果只对应该 SHA；后续源码仍须重新验收。S3 与 Machine 的实际状态见
`OUTSTANDING-WORK.zh.md`。历史候选 `235ea2f` 已随 PR #3 合并为 `16f69b5`，
以下保留发现与修复过程中的历史失败。
`c2823dd` 的新 Service VMess 测试在首次 echo 即失败，尚未进入续期；随后源码
修复客户端的 salted command key、独立长度 nonce、双向长度认证和 tag/padding
编排，并补充真实 TCP 的 12 种 cipher/framing 组合。新增用例及修复须由新提交
Actions 取得结果，不能将同仓库两端互通当作第三方兼容证明。

新反向门禁在 `14c5401` 发现独立问题：Go HTTP/1 echo 夹具必须先读完请求
body 再写响应；VMess authenticated length 还须在 Seal 前减去长度 AEAD 的
16 字节开销、Open 后加回。`e9de82c` 修正夹具，`f9d74f2` 同步校准两端 wire
值、加入独立 raw AEAD 向量与共享 Proxy 并发回归，后者的 PR quick 已通过。
该完整矩阵已在 `235ea2f` 重验通过。反向用例只声明三种 cipher 的普通 chunk framing；
同仓库 12 组合中的 `none/padded` 和 `zero` 不属于已证明的固定 Xray 兼容范围。

以下命令供 GitHub Actions 环境使用，功能和网络验收继续遵守 README 的 Actions-only 约定：

```bash
scripts/fetch-interop-clients.sh "$RUNNER_TEMP/interop-clients"
export TXNODE_INTEROP_XRAY="$RUNNER_TEMP/interop-clients/xray/xray"
export TXNODE_INTEROP_MIHOMO="$RUNNER_TEMP/interop-clients/mihomo/mihomo"
export TXNODE_INTEROP_SINGBOX="$RUNNER_TEMP/interop-clients/singbox/sing-box"
export TXNODE_INTEROP_MIERU="$RUNNER_TEMP/interop-clients/mieru/mieru"
export TXNODE_INTEROP_CURL=/usr/bin/curl
python3 scripts/interop_gate.py --profile quick --output artifacts/interop-quick
python3 scripts/interop_gate.py --profile full --output artifacts/interop-full
```

以下旧版下载与运行片段只作为历史复现说明；候选版本验收使用上面的固定清单入口。

## 怎么跑

```bash
# Xray（官方 release，校验 dgst 后解压）
mkdir -p .clients/xray && cd .clients/xray
curl -sSLO https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
curl -sSLO https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip.dgst
sha256sum -c <(grep SHA2-256 Xray-linux-64.zip.dgst | sed 's/SHA2-256= //;s/^/ /;s/$/  Xray-linux-64.zip/')
unzip -q Xray-linux-64.zip

# sing-box（官方 release，覆盖 AnyTLS/TUIC/SS2022 等服务端协议）
mkdir -p .clients/singbox && cd .clients/singbox
curl -sSLO https://github.com/SagerNet/sing-box/releases/download/v1.14.3/sing-box-1.14.3-linux-amd64.tar.gz
tar xzf sing-box-1.14.3-linux-amd64.tar.gz && cp sing-box-1.14.3-linux-amd64/sing-box .

# Mihomo（官方 release）
mkdir -p .clients/mihomo && cd .clients/mihomo
curl -sSLO https://github.com/MetaCubeX/mihomo/releases/download/v1.19.32/mihomo-linux-amd64-compatible-v1.19.32.gz
gunzip -f mihomo-linux-amd64-compatible-v1.19.32.gz && mv mihomo-linux-amd64-compatible-v1.19.32 mihomo && chmod +x mihomo
```

```bash
cd TXnode
TXNODE_INTEROP_XRAY=$PWD/../.clients/xray/xray \
TXNODE_INTEROP_MIHOMO=$PWD/../.clients/mihomo/mihomo \
TXNODE_INTEROP_SINGBOX=$PWD/../.clients/singbox/sing-box \
TXNODE_INTEROP_MIERU=$PWD/../.clients/mieru/mieru \
go test ./internal/kernel/txnode/ -run TestInterop -v -timeout 600s
```

REALITY 需要服务端把 ClientHello 转发到借用站点，默认 `www.microsoft.com:443`，可用
`TXNODE_INTEROP_REALITY_DEST` 覆盖。

## 历史结果（Xray 26.3.27 / Mihomo v1.19.32 / sing-box 1.14.3，本机回环）

本节保留旧版记录。严格门禁已发现其中 Mieru 拨号失败及复用夹具不能充分证明目标行为，
当前源码和候选状态以清单、对应提交的 Actions 与 `OUTSTANDING-WORK.zh.md` 为准。

通过（29 个用例，覆盖 24 条链路）：

| 用例 | 客户端 | 备注 |
|---|---|---|
| VLESS over TCP / TLS / WebSocket / HTTPUpgrade | Xray | TCP 明文、TLS（证书 pinning）、WS、HTTPUpgrade 全部通过 |
| VMess over TCP / WebSocket | Xray | AEAD、分块掩码、padding、authlen 均已对齐 |
| Trojan + TLS | Xray | 证书 pinning |
| Shadowsocks（aes-128-gcm） | Xray | 经典 AEAD |
| VLESS + gRPC | Xray | Hunk protobuf 帧（0x0a + varint 长度） |
| VLESS + XHTTP（auto/stream-one） | Xray | auto = stream-up 双流配对（`x_session`） |
| VLESS + REALITY | Xray / Mihomo | 参考 TLS 栈；借用站点握手记录 ≤8 KiB |
| Hysteria2 | Mihomo / sing-box | TCP 请求帧与上游一致 |
| Hysteria2 UDP | sing-box | 上游 UDPMessage 帧（sessionID/packetID/frag/地址字符串） |
| TUIC | sing-box | TLS exporter token；address family 0/1/2 |
| Shadowsocks 2022 | Xray / sing-box | 单 PSK、响应头带 request salt、请求 padding |
| AnyTLS | sing-box | v2 prologue padding + 流内地址 |
| VLESS Encryption | Xray | 按 xray-core 26 的 1-RTT 握手与记录层重写（ML-KEM-768 + X25519、blake3 派生、ticket/padding） |
| Naive（HTTP/2 CONNECT） | curl 8.5 | h2 CONNECT + Basic；sing-box 的 naive outbound 依赖 Chromium cronet 库，发布二进制不带 |
| Snell v4 | sing-box | salt + AEAD 头/载荷记录、argon2id 派生、ReplyTunnel 应答 |
| Mieru v2（TCP） | 官方 mieru 3.38 | XChaCha20-Poly1305 隐式 nonce、SOCKS5 应答作为首个 dataServerToClient 段、MTU 分片、ACK 回复、20s 心跳 |
| Mieru v2 空闲后复用 | 官方 mieru 3.38 | 跨 25s 静默（心跳窗口）后新会话仍可传输 |
| Mieru v2 1 MiB 双向 | 官方 mieru 3.38 | 上行/下行各 1 MiB，校验字节一致；覆盖分片、序号与窗口字段 |
| Mieru v2 拨号失败 | 官方 mieru 3.38 | 目标不可达时内层 SOCKS5 收到 `05 05`（connection refused），不会挂起 |
| 多路复用 smux / yamux | sing-box 1.14 | 一个 mux 连接承载多条流，每条流带 SOCKS 地址头；流共享父会话的 user/限速/设备闸 |
| Xray Mux.Cool | Xray 26.3.27 | `[len][session][status][network][port][addr]` 帧 + 分块 body，服务端按会话解复用，多轮复用同一 mux 连接 |
| XUDP（VLESS UDP） | sing-box 1.14 | Mux.Cool 的 `NEW NETWORK=UDP` 会话：每个 mux 帧体是**一个分块**（`SIZE(2)|datagram`），帧边界即数据报边界；服务端 KEEP 帧带目标地址回包 |
| TUIC UDP | sing-box 1.14 | QUIC DATAGRAM 帧（与单向流同构），返回帧携带源地址；未开 DATAGRAM 时回落单向流 |

未通过 / 未覆盖（跳过，带原因）：

| 用例 | 客户端 | 现象 | 编号 |
|---|---|---|---|
| TUIC | Mihomo | 尚未通过，需参考服务端与逐帧对照后定位责任 | TUIC-mihomo |
| VLESS + HTTP/2 | — | Xray 26 已移除独立 h2 传输 | H2-removed |

### Mieru v2（MIERU-1 已关闭）

按 `docs/protocol.md`（mieru 3.38）实现，`internal/dataplane/proto/mieru/v2.go`：

- 密钥：`sha256(password || 0x00 || username)` → `PBKDF2-64(sha256, salt=sha256(be64(2 分钟取整时间)))`，
  服务端用 `time.Round(2m)` 对齐参考实现，并按 `-120/0/+120` 三个窗口试探；解密成功的窗口被
  记录并复用于服务端方向（客户端时钟偏移超过一个窗口时仍可应答）；
- 记录层：`[nonce 24][metadata 32+tag]`，两个方向各自只在首段携带 nonce，之后逐记录 +1；
  会话段用 `sessionStruct`，数据/ACK 段用 `dataAckStruct`，严格按文档偏移编解码；
- SOCKS5 语义：`openSessionRequest` 的 payload 是 SOCKS5 CONNECT 请求；服务端在**目的地址拨号成功后**
  通过 `core.HandshakeReply` 把 SOCKS5 应答作为首个 `dataServerToClient` 段回给客户端，拨号失败则回
  对应错误码。这是官方客户端在 openSessionResponse 后继续发数据的前提（此前卡在此处）；
- 数据面：按 `MTU-72` 分片（默认 MTU 1400 → 1328 字节/段），序号逐段递增；对客户端 ACK 回复
  `ackServerToClient`（携带接收游标），空闲 20s 发送空 data 段心跳；`closeSessionRequest` 关闭会话。

验证：`TestInteropMieruOfficialClient` / `TestInteropMieruOfficialIdle` / `TestInteropMieruOfficialBulk`
（1 MiB 双向）/ `TestInteropMieruOfficialDialFailure` 与 `internal/dataplane/proto/mieru` 的记录层单测。日志证据：官方客户端首段解出
`05 01 00 01 7f 00 00 01 00 01`，服务端回 SOCKS5 成功后客户端 `ATTACHED => ESTABLISHED` 并继续发数据。

已知差异：官方客户端在**同一条 SOCKS 连接**静默超过 ~20s 后再发第二个小请求时，偶发不把服务端响应
交回应用（服务端日志确认响应已按正确 nonce/序号发出）。互通用例因此每轮使用新连接；该行为需
官方客户端侧进一步确认，不计入服务端缺陷。

## 当前严格矩阵范围

清单已将 Naive、Mihomo TUIC、smux/yamux UDP、官方 Mieru UDP 承载和显式低熵/整形
组合列为受支持用例，运行错误必须失败。Naive 增加不可信根及错误 SAN，TUIC 对比
参考/native 服务端的 native/quic UDP 中继，并检查错误密码。清单同时核对各子用例，
不能只凭父用例 PASS。

仅保留固定 sing-box 不含 Mieru outbound、固定 Xray 移除独立 h2 两个不适用组合；
它们不计入通过数。REALITY 在测试内产生匹配密钥，不依赖外部公钥才能执行。

SIGKILL 使用 ready/ARM/gate 事件握手，在准确持久化阶段杀进程；超时仍失败，不能
自动变成环境不足或 Skip。当前源码和实际候选结果见 `docs/OUTSTANDING-WORK.zh.md`。

## 地址头 mux 写出与计量完成边界

固定 sing-box 1.14.3 对应的 sing-mux revision 为 `caf09fe32475`。
服务端保留 `smux v1.5.57` 和 `yamux v0.1.2` 的线格式；本地完成边界补丁、
完整许可证及确定性回归保存在 `internal/deps/{smux,yamux}`。

调用链为 `mux.Serve -> handleStream -> NewServerPackets -> core.Session.Packets ->
Server.ServeSession -> udpRelay.readBack -> PacketWriteCounter -> NativeMeter.Complete ->
原代际 NativeCollector/本地事件`。状态、地址和长度头不计入业务字节。
现有 `PacketStream.WritePacket` 兼容入口继续保留；支持可选 `WritePacketCount` 的
framing adapter 可同时返回实际 payload 字节和错误，core 保留错误并完成真实尾部计量。
不支持该可选接口的原 packet transport 继续使用既有完整报文成功/失败语义。

两个 mux 库的发送请求分别拥有 queued/active 完成状态：排队取消后不再读取或发送
调用方 buffer；已经开始的写入必须回收真实 `n + err`。完整帧已写出后发生撤权不能
把它记成零字节，部分写入也不能当作完整报文成功。TCP 子流同样保留真实写出尾部。
共享帧开始后，子流 deadline 可能等待该帧完成；正常子流关闭不关闭兄弟流。
父 transport 写入仍有安全上界（smux 30 秒、yamux 既有 ConnectionWriteTimeout），
撤权关闭父连接会立即打断底层 I/O。原“客户端读到应答后立即撤权”的回归保持不变。
这些实现仍须由包含补丁的精确提交执行 nested race、完整 Node 和严格互通验收。

## 复现

客户端由 `scripts/fetch-interop-clients.sh` 下载，按版本和 SHA-256 固定；
`--check` 只校验已有缓存。以下命令仅供 Actions，使用与 CI 相同的严格 runner：

```bash
scripts/fetch-interop-clients.sh "$RUNNER_TEMP/interop-clients"
TXNODE_INTEROP_XRAY="$RUNNER_TEMP/interop-clients/xray/xray" \
TXNODE_INTEROP_MIHOMO="$RUNNER_TEMP/interop-clients/mihomo/mihomo" \
TXNODE_INTEROP_SINGBOX="$RUNNER_TEMP/interop-clients/singbox/sing-box" \
TXNODE_INTEROP_MIERU="$RUNNER_TEMP/interop-clients/mieru/mieru" \
TXNODE_INTEROP_CURL=/usr/bin/curl \
python3 scripts/interop_gate.py --profile full --output artifacts/interop-full
```
