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
renderer 源码和兼容指纹。固定 Core revision 以 `compatibility/core.v1.json` 为准，
采纳记录及实际 Machine 验收见 `CORE-MACHINE-COMPATIBILITY.zh.md`。

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
原生 Core 可通过两个固定 WS 事件接入：`ops.node.connections.request` 和
`ops.node.connections.result`。请求只允许 `list` / `close`，包含节点 ID、一次请求 ID、
15 秒截止时间，以及不透明游标/连接 ID；面板分页上限 100 条，页面默认 50 条。
Service 在原调度循环中调用上述内核 owner；Machine 通过原节点 mailbox 保持命令
顺序，未 ready 或超过 8 条时拒绝，状态同步仍保持原合并规则。

Core 的管理员读取/关闭权限分别校验，Redis 只传请求 ID，worker 从原短期回执
读取命令并复核当前节点归属、凭据和 socket。Node 的有界短期回执复用同一请求的
原结果，不将同一 ID 改用于另一连接。Core 只接受当前派发 socket 的匹配结果；
“已发送”不代表“已关闭”，超过截止时间未确认记为 unknown，不自动重复关闭。
列表和结果不含来源/目标地址、UUID 或密钥，不进入固定基数诊断指标。

## 普通授权续期

只有用户凭据、权限、Provider/会话身份和原计量策略不变、有限租约不缩短，且运行配置
相同的签名快照续期，才可进入连接保活路径。meter 暂停新的 I/O intent，原 token
在原 collector 完成并封口；新窗口从不早于旧整秒封口边界的位置开始。原 grant、
period、批次及 digest 不重标，成功续期不重启 kernel。

该能力要求协议能够在未读取任何下一帧字节的位置安全暂停。当前裸 TCP 路径提供
此能力；TLS、REALITY、Vision 等不透明承载使用原有重建路径。VMess 已读取部分
长度/body/padding 时不能把下一次读取迁移到新窗口；相关错误终止原流。

暂停到恢复的成功预算为两秒，同时受旧授权与候选租约限制。旧 watchdog 和 cutoff
在此期间保持生效；超时或封口后失败终止 owner，不能恢复旧 collector。OS fsync
不承诺可取消。凭据轮换、撤权、计量周期或策略变化仍按原生命周期重建。
新增 Service VLESS/VMess TCP、meter、collector 和协议边界回归须取得新提交的 Actions 结果，
不能据此宣称完整 Machine 或所有传输已支持连接连续性。

## 请求取消与终止归属

Service 使用所属请求 context，沿 `Initial/Poll/RefreshAuthorization/Discover ->
TXBoardControlPlane -> Client.*Context -> requestContext -> NewRequestWithContext`
传到 Core HTTP，并将同一 context 交给 Provider `Resolve`。Service 自身因租约或
权威终止而返回时，先取消请求 scope 再等待授权 worker；原生尾部清理继续使用原有
独立有限 context，原授权期、批次、回执与同步边界不变。

Machine 的 discovery、per-node prefetch、handshake 和 status 沿 native Context
扩展传递所属 context；Xboard/旧 adapter 的接口保持兼容。原无 context 方法保留为
委托 Background 的兼容入口，生产 TXBoard owner 使用 Context 方法。共享 WS 在
HTTP 升级后继续由同一 context 关闭私有连接，覆盖等待 session.ready 及阻塞写入。
取消本身不构造 AuthorityDenial；完成的原生 401/404 仍按原内容、身份及 scope 规则识别。

这些取消传播修复已由 `e5e98291` 的 Actions `39538582760` 通过 Go/source guards
及完整 Machine 验证；不能借此把 `7c9cd91e` 的 Machine 终止超时追认为已通过，
也不承诺 OS fsync 能取消。

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
独立镜像 `ghcr.io/anrcm0/txnode` 的发布结果与历史包失败证据见
`docs/RELEASE-BLOCKERS.zh.md`。
部署前记录不可变镜像摘要、Node/Core SHA 和配置差异；未验证旧版读取新持久化状态前，
不得用旧版直接接管同一状态目录。保留原始 usage journal、spool 和回执证据。

受控试运行由有实际部署权限的 owner 在选定环境执行，使用已验收的精确组合：

1. 记录当前及候选的 index/目标架构摘要、Node/Core SHA、renderer 指纹、配置和状态目录归属。先核对发布 artifact 中实际执行的两个架构与离线 capabilities，不把源码分支名或 `dev` 浮动标签当作部署锁。
2. 选择单个受控 Machine/Node，沿现有 Core 授权与 Provider mTLS 安装配置；同一状态目录保持单一进程 owner。先验证原 pending 批次得到匹配持久化回执后才开放新监听，不绕过启动恢复门禁。
3. 在有限流量下检查真实 VLESS/VMess 及所用 packet/mux 组合、双向字节、授权到期、凭据撤销、WS 端口更新和报告恢复。只能记录实际选择的协议/承载，不将回环矩阵扩大为生产全协议证明。
4. 按原有资源及业务预算检查断连、报告积压、FirstGap、未知尾部和拒绝原因。出现证据缺口或授权停止时保留原状态与回执，由 owner 处理；不清空 journal/spool 或换用无计量模式继续接受流量。
5. 回滚先停止候选的准入和进程，保存最后回执、待处理批次及状态版本，再按已验证的兼容路径恢复记录的镜像和配置。若旧版读取新状态尚未验证，保留新状态，使用能读取它的已验证版本恢复；不让旧进程覆盖新证据。

仓库 Actions 和镜像验证不代表这套试运行已经发生。实际环境、时间、流量范围、
旧/新摘要及回滚结果由部署 owner 另行记账；本轮不自动创建正式版本标签或生产部署。
