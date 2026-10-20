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
go test ./internal/kernel/txnode/ -run TestInterop -v -timeout 300s
```

REALITY 需要服务端把 ClientHello 转发到借用站点，默认 `www.microsoft.com:443`，可用
`TXNODE_INTEROP_REALITY_DEST` 覆盖。

## 结果（Xray 26.3.27 / Mihomo v1.19.32 / sing-box 1.14.3，本机回环）

通过（14）：

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

未通过 / 未覆盖（跳过，带原因）：

| 用例 | 客户端 | 现象 | 编号 |
|---|---|---|---|
| Hysteria2 UDP | sing-box | SOCKS5 UDP ASSOCIATE 请求超时；datagram 仍是复刻自有帧格式 | HY2-UDP-1 |
| Shadowsocks 2022 | Xray / sing-box | 客户端 method 创建失败或 identity/PSK 夹具不匹配 | SS2022-1 |

## 尚未覆盖的互通项

当前用例集覆盖 7 条链路，全部通过。以下协议/能力还没有真实客户端用例，发布前建议补齐：

1. **Mieru / Snell / TUIC / AnyTLS / Naive / SS2022**：Mihomo 或官方客户端可用，但需要额外的服务端参数夹具；
2. **VLESS Encryption**：样本/复刻只有服务端实现，客户端侧在 Xray 新版本中，需要按其参数生成用例；
3. **UDP 数据面**：Hysteria2 UDP 帧格式待对齐上游 UDPMessage（4B session、2B packet、frag、varint 地址字符串）；TUIC UDP 与 xudp 待补；
4. **传输剩余**：h2 已被上游移除，其余组合已覆盖。

修复顺序建议：先补传输组合（同协议、低成本），再补 UDP，最后处理 VLESS Encryption。

## 复现

```bash
TXNODE_INTEROP_XRAY=$PWD/../.clients/xray/xray \
TXNODE_INTEROP_MIHOMO=$PWD/../.clients/mihomo/mihomo \
TXNODE_INTEROP_SINGBOX=$PWD/../.clients/singbox/sing-box \
TXNODE_INTEROP_REALITY_PRIV=... TXNODE_INTEROP_REALITY_PUB=... \
go test ./internal/kernel/txnode/ -run TestInterop -v
```
