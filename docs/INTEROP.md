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

# Mihomo（官方 release）
mkdir -p .clients/mihomo && cd .clients/mihomo
curl -sSLO https://github.com/MetaCubeX/mihomo/releases/download/v1.19.32/mihomo-linux-amd64-compatible-v1.19.32.gz
gunzip -f mihomo-linux-amd64-compatible-v1.19.32.gz && mv mihomo-linux-amd64-compatible-v1.19.32 mihomo && chmod +x mihomo
```

```bash
cd TXnode
TXNODE_INTEROP_XRAY=$PWD/../.clients/xray/xray \
TXNODE_INTEROP_MIHOMO=$PWD/../.clients/mihomo/mihomo \
go test ./internal/kernel/txnode/ -run TestInterop -v -timeout 300s
```

REALITY 需要服务端把 ClientHello 转发到借用站点，默认 `www.microsoft.com:443`，可用
`TXNODE_INTEROP_REALITY_DEST` 覆盖。

## 结果（Xray 26.3.27 / Mihomo v1.19.32，本机回环）

| 用例 | 客户端 | 结果 | 说明 |
|---|---|---|---|
| VLESS over TCP | Xray | ✅ 通过 | `TestInteropXrayVLESS` |
| VLESS + WS（path `/ray`） | Xray | ✅ 通过 | `TestInteropXrayVLESSWebSocket` |
| Trojan + TLS（自签，证书 pinning） | Xray | ✅ 通过 | `TestInteropXrayTrojanTLS`；Xray 26 已移除 `allowInsecure` |
| Shadowsocks（aes-128-gcm） | Xray | ✅ 通过 | `TestInteropXrayShadowsocks` |
| VMess（AEAD） | Xray | ✅ 通过 | 修复了三处：cmdKey = MD5(uuid‖`c48619fe-…`)、SHAKE128 掩码以 body IV 为种子、length 块计入 AEAD tag 且 padding 明文置于密文后 |
| VLESS + REALITY | Xray / Mihomo | ✅ 通过 | 鉴权线格式已按参考实现对齐（HKDF salt=random[:20]、GCM nonce=random[20:]、AAD=零化 sessionID 的 ClientHello、version/time/shortId 布局、优先纯 X25519），TLS 终止改用 `xtls/reality` 参考栈。注意：借用站点的握手记录需 ≤8 KiB（参考实现的 8 KiB 捕获窗口），默认用例改用 `www.cloudflare.com`；首次握手会等后台 post-handshake 记录学习完成（最长 8 s，之后为 0） |
| Hysteria2 | Mihomo | ✅ 通过 | TCP 请求帧对齐上游：`varint 0x401` + 地址字符串 + padding，响应补 padding 长度字段 |

## 尚未覆盖的互通项

当前用例集覆盖 7 条链路，全部通过。以下协议/能力还没有真实客户端用例，发布前建议补齐：

1. **Mieru / Snell / TUIC / AnyTLS / Naive / SS2022**：Mihomo 或官方客户端可用，但需要额外的服务端参数夹具；
2. **VLESS Encryption**：样本/复刻只有服务端实现，客户端侧在 Xray 新版本中，需要按其参数生成用例；
3. **传输矩阵**：目前只测了 tcp/ws；grpc/h2/xhttp/httpupgrade/TLS 组合待补；
4. **UDP 数据面**：Hysteria2 UDP、TUIC UDP、xudp 的互通需要各自的客户端用例。

修复顺序建议：先补传输组合（同协议、低成本），再补 UDP，最后处理 VLESS Encryption。

## 复现

```bash
TXNODE_INTEROP_XRAY=$PWD/../.clients/xray/xray \
TXNODE_INTEROP_MIHOMO=$PWD/../.clients/mihomo/mihomo \
TXNODE_INTEROP_REALITY_PRIV=... TXNODE_INTEROP_REALITY_PUB=... \
go test ./internal/kernel/txnode/ -run TestInterop -v
```
