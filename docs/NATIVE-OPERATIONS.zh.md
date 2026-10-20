# 原生节点配置与诊断边界

本轮能力的功能验收以候选提交的 GitHub Actions 为准。接口和测试源码已加入并不等于
镜像已发布、Core 已采用或生产环境已验收。

## 配置迁移

运行内核继续只有 `kernel.type: txnode`。原 `singbox` / `xray` 值，以及
`kernel.custom_outbound`、`kernel.custom_route`、`kernel.custom_config` 均由配置校验拒绝。
这三个字段中的旧内核原生 JSON 不会被解释成 txnode 配置。

面板的结构化 routes/outbounds 继续进入现有 `model.NodeSpec`、renderer、
`kernel/txnode` router 和 `core.Server` 拨号链。它们的支持范围以已有 renderer 和
路由校验为准；不增加将任意 sing-box/Xray 原生配置透传到 Node 的入口。本轮不改变
renderer 源码、兼容指纹或固定 Core revision。

Mieru `traffic_pattern` 的受支持字段、严格拒绝项和官方客户端夹具见
`docs/MIERU-TRANSPORT.zh.md`。

## 连接身份与关闭

现有 `kernel.Kernel.CloseConnection(ctx, id)` 由 txnode 实现。调用方通过可选的
`kernel.ConnectionInspector.Connections(ctx, after, limit)` 取得连接身份；每页最多 128 条，
游标返回下一页的起点，列表可能随连接退出而变化。记录只包含不透明 ID、数字用户 ID
和 TCP/UDP 类型，不包含凭据、来源地址或目标地址。

ID 使用进程随机代号和全局递增的 session 序号。关闭请求只在所属 Node 当前及退役中
的 `core.Server` 注册表内查找。相同端口 Reload 后，旧 ID 仍指向原连接；进程重启后
旧 ID 失效，其他 Node 实例也不能使用它关闭连接。格式错误返回
`kernel.ErrInvalidConnectionID`；已退出、其他实例或其他进程的 ID 返回
`kernel.ErrConnectionNotFound`。在连接仍登记期间并发重复关闭是幂等的；请求开始前
已经取消的 context 不改变连接。

完整调用链是 `ConnectionInspector -> Kernel.liveServersLocked -> Server.ConnectionPage`
和 `Kernel.CloseConnection -> Server.CloseSession -> Session.Close -> relay teardown`。
`Session.Close` 取消限速等待并关闭 TCP/packet 传输；原代际的 meter 仍接收 I/O 完成和尾部。
这里提供内核能力，现有面板协议没有新增连接列表或关闭消息。

## 受限诊断

在本地配置显式设置：

```yaml
dataplane:
  diagnostics: true
```

Service 的既有 metrics 输出增加 `native_dataplane`。默认关闭该附加输出。
固定字段包括运行/准入状态、配置用户数、活跃 TCP/UDP session、配置及凭据代际、
退役 Server 数、未完成 I/O、Reload 成败、凭据撤权和显式关闭计数。Mieru 节点另有
固定的 UDP peer、待确认段、重组字节、重传、重复及丢弃计数。

调用链是 `Service.buildMetrics -> RuntimeDiagnosticProvider -> Kernel/Tracker/nativeMeter`
及 Mieru handler 的固定计数器。未完成 I/O 按原 meter 统计，计量 Complete 不会迁移到
新 collector。输出不包括连接 ID、UUID、密钥、授权内容、来源/目标地址、原始业务内容
或任意错误字符串。不能将这些本地观测计数当作 Core 结算账本。

## 交付与回滚

源码、静态检查、候选 Actions、合并、镜像发布和 Core 采用分别记录。
当前 GHCR 授权问题及已有失败证据见 `docs/RELEASE-BLOCKERS.zh.md`。
部署前记录不可变镜像摘要、Node/Core SHA 和配置差异；未验证旧版读取新持久化状态前，
不得用旧版直接接管同一状态目录。保留原始 usage journal、spool 和回执证据。
