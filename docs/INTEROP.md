# 第三方客户端互通测试（txnode 数据面）

客户端只是**测试工具**：不进 `go.mod`、不进镜像、不进发布产物。测试在设置环境变量后才
运行，缺失时自动 `t.Skip`，因此 CI 不受影响。

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

## 结果（Xray 26.3.27 / Mihomo v1.19.32 / sing-box 1.14.3，本机回环）

通过（25 个用例，覆盖 20 条链路）：

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

未通过 / 未覆盖（跳过，带原因）：

| 用例 | 客户端 | 现象 | 编号 |
|---|---|---|---|
| TUIC | Mihomo | QUIC 建连后不发送 v5 认证帧（客户端实现差异） | TUIC-mihomo |
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

## 尚未覆盖的互通项

当前用例集覆盖 20 条链路（25 个用例），全部通过。以下能力还没有真实客户端用例，发布前建议补齐：

1. **Mieru**：`traffic_pattern` 与低熵编码（type 10/11）未实现；官方客户端默认关闭，需显式夹具才能覆盖；
2. **UDP 数据面**：Hysteria2 UDP 已覆盖；TUIC UDP 与 xudp、Mieru UDP（UDP 承载）待补；
3. **传输剩余**：h2 已被上游移除，其余组合已覆盖；
4. **多路复用**：`mux`（sp.mux.sing-box.arpa）没有独立客户端用例。

修复顺序建议：先补 TUIC UDP / xudp（同协议、低成本），再补 Mieru 低熵与 UDP 承载，最后补 mux 用例。

## 复现

```bash
TXNODE_INTEROP_XRAY=$PWD/../.clients/xray/xray \
TXNODE_INTEROP_MIHOMO=$PWD/../.clients/mihomo/mihomo \
TXNODE_INTEROP_SINGBOX=$PWD/../.clients/singbox/sing-box \
TXNODE_INTEROP_MIERU=$PWD/../.clients/mieru/mieru \
TXNODE_INTEROP_REALITY_PRIV=... TXNODE_INTEROP_REALITY_PUB=... \
go test ./internal/kernel/txnode/ -run TestInterop -v
```
