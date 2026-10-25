# 固定 Core 基线的 Machine 兼容门禁

Node 的固定 Core 基线以 `compatibility/core.v1.json` 为准，本轮兼容候选固定
`ANRCM0/TXBoard@097dc9748bbe665ae7672c43827998f1e9420e3a` 并要求
`node-connections/v1`。这里说明源码合约、真实 owner 调用链和 Actions 证据；
源码检查、语法检查、编译均不构成完整 Machine 功能验收。

## 2026-10-25 连接管理兼容候选

Core PR #307 将管理员节点详情页接入三个封闭操作：

| 操作 | 权限与 owner |
| --- | --- |
| `network.nodes.connections.list.request` | `network.nodes.read`；原 workflow 幂等 owner → NativeNodeConnections 短期请求回执 |
| `network.nodes.connections.close` | `network.nodes.manage`；原 workflow 幂等 owner → 相同 Node 命令派发链 |
| `network.nodes.connections.result.get` | `network.nodes.read`；当前管理员及 Node 作用域读取原请求结果 |

完整派发链为原 Core browser admission/actor → NativeNodeConnections → 仅含请求 ID
的 Redis 通知 → NodeWorker 重读短期回执与当前凭据、成员关系和 socket → 原 WS
`ops.node.connections.request` → Machine mailbox/Service 原调度 → 原 Kernel/Session
连接登记与关闭 → `ops.node.connections.result` → Core 原回执投影。没有新增连接或
账量 owner。Core 正式选择 Node `9f636d4ccaa5fd00cc2282cb8e64490d49c564e3`，
PR #307 已正常合并为 `7985843ddd94faebbecd201bd7c55b4f998f677b`。该 Core
与评审 head 树相同，固定 `097dc97` 仍在其 main 历史中；Node 所选提交也在
Node main 历史中，并与发布源码 `f2096569` 的全部非 Markdown blob/mode 相同。

请求绑定管理员、Node、当前 socket epoch、原输入和 15 秒截止时间；旧作用域与
错误结构仍拒绝。匹配但迟到的合法结果只收到 `accepted:false`，保持 unknown，
不会用通用错误帧触发共享 socket 重连。Node 的真实 WS 回归要求之后仍收到并
回复原 socket 的心跳；Core 回归覆盖独立、Machine 及已归组独立节点三种身份。

默认固定 Core Machine 门禁现在先核对这三个操作及原有五个操作和 ws-server 准入，
然后实际验证 limit=1 两页、不透明 ID、跨 Node 关闭拒绝、原 workflow 键重放、
目标连接 EOF 和其它流继续传输。原配置更新、授权、成员撤回、token 轮换、旧凭据
拒绝、原批次重放和 SQL 唯一 settled 断言继续执行。每次重放数量取自该运行实际
捕获的原批次，不把不同运行的批次数当作同一组固定样本。

最终功能候选 Node `9f636d4c` 的完整 Actions `40162774358` 与常规 PR
`40162775732` 均成功。full artifact `12587510910` 的原始事件为 38 个顶层、
38 个声明子项通过，两项固定上游不适用单列；新增 Mihomo 本地 DIRECT 控制只
证明固定客户端已 ready，不先访问 Node。Machine `12586759266` 本次原十份
批次对应十行唯一 settled SQL，C2 `12587596251` 来源一致。Node/Core SHA、tree、
清单、客户端 pin、全部声明子项及 ZIP 摘要已离线核对。

HTTP 夹具采用 Core 原 Octane/Swoole 入口、四个 worker、Swoole 6.2.3 和显式
OPcache，实际设置保存在 result。其五份兄弟节点 pending 的 HTTP 跨度为
1.89056 秒，原两秒页及十二秒就绪未改；数量上限 16 不保证任意单页耗时。
Core `e2ae095b` 单独组合 job `121077874060` / artifact `12587146921` 使用相同
Node，实际六份批次对应六行 SQL；它不套用固定 Core gate 的十份。

Octane 下曾因代理直接解析 gzip 字节而缺少 401 错误码证据；阶段诊断已确认原
HTTP 负向断言和 Workerman 预升级关闭实际发生。代理现在只对最多 64 KiB 的
副本解码，原响应头与压缩字节保持；真实网络回归、损坏/超大拒绝回归和最终
组合均实际通过。固定 Core 和独立组合分别观察到九个、八个 gzip 授权拒绝。
这不改写开发服务器下原两秒恢复失败或其它历史失败的唯一原因。

正式标签 `v2.3.0-rc.1` 的完整 Actions `40165006752` 也已通过全部八项功能
门禁并完成两架构构建及发布；本次固定 Core Machine artifact `12588550762`
为四份原 batch / 四行唯一 settled SQL。Core 合并后 `7985843` 的独立实际
组合 artifact `12587559546` 为八份 / 八行，来源为 Core `7985843` 与所选
Node `9f636d4c`；完整合并后 CI `40164915929` 的 26 项选中检查及 Images
`40164915924` 均成功，后者也实际发布双架构 Core 开发镜像。候选源码及镜像
摘要见 `CANDIDATE-DELIVERY.zh.md`。

前置候选 Node `50b05dfc` 与 Core `327c077` 的完整功能 Actions `40156485416`
已成功。Core `327c077` 的组合 gate `40156326727` / artifact `12584725893`
实际验证上述连接链，原三份批次对应三行唯一 SQL 记录；镜像 gate `40156326799`
的 `12585555600` / `12585525761` 分别验证三映像升级/恢复及三处资源限制、两处
完整备份材料。迟到应答修正后的 Node `3258d008` 与固定 Core `097dc97` 的完整
Actions `40157560438` 已成功：八项实际执行的功能 job 全部通过，full
`12585447058` 的原始事件为 38 个顶层、37 个子项通过，另两项不适用；Machine
`12584657736` 本次原八份批次对应八行唯一 settled SQL，C2 `12584772679` 的
来源也与该组合一致。所有声明的子项、客户端 pin、ZIP 摘要及公开来源均已核对。
Core `097dc97` 的 API job `121061923458` 实际通过迟到应答回归；其 43 项条件
跳过不计通过，原生 MySQL 门禁另以最终 Core 的同源工作流认定。

Core `3d62009`、`44249a4`、`321b11df` 的组合恢复曾因 usage_transport 拒绝；
最后一轮开发服务器实际五份 pending 的请求累计超过两秒页。`2649c5f` 镜像 gate
曾在调度器 100 秒观察断言失败，`a656ab3` 曾在初始限流预算键数量断言失败。
失败及当时公开诊断均保留，不据后续通过声明其唯一原因已定位。
夹具的运行方式及观测修正不修改生产两秒恢复页与
原退避保持；夹具十二秒就绪及调度观察断言继续有效。实际多机、生产 PKI、独立完整财务
对账及现场回滚仍未由这些托管 Actions 证明。

## 历史 2026-10-21 Core 基线

先前基线 `ANRCM0/TXBoard@553641029c0094480cd71105cb7b0a7efe9a9a8a` 经 Core
PR #291 完整检查后，于 2026-10-21 合并为
`2dc3e7b446e5c36f393fa6084fb8ad0d811b0d95`，固定提交仍保留在 main 历史中。
以下段落记录该历史 pin 的迁移和实测范围，不作为当前候选的新一轮执行。

## 从旧管理路径迁移到正式操作

旧 pin `d2e70b8c` 未准入原夹具使用的 `ws-server` 命令和四个 raw 管理 HTTP 路径。新候选补上现有原生 WS worker 的命令准入；管理操作沿用正式 Core browser owner，Node 夹具不要求重新开放未版本化的旧管理入口。

| 原夹具调用 | 当前正式操作与 owner |
| --- | --- |
| GET network-nodes 列表取配置 | `network.nodes.configuration.get` → `NetworkNodeAdminController.configuration`，返回完整配置和当前 revision |
| PUT network-nodes/{id} | `network.nodes.configuration.replace` → `replaceConfigured`，提交完整 configuration_json、expected_revision 和 UUID 幂等键 |
| PATCH network-nodes/{id} | `network.nodes.patch` → `patch`，保留单节点启停、成员关系通知和兄弟节点隔离 |
| POST network-machines/{id}/token/rotate 并直接取 token | `network.machines.token.rotate` → `nativeRotateToken`，回执只含 ok；另用 `network.machines.credentials.get` → `nativeCredentials` 重新鉴权后取得 token |
| CLI ws-server | `NodeWebSocketServer` → 真实 `NodeWorker`，Core PR #291 将其加入 `NativeRuntimeAdmission.COMMANDS`；仍要求原生安装已激活且 worker epoch 当前 |

操作通过实际 `POST /gateway/v1/core/admin/operations/{operation}` 调用，原管理员 Bearer、同源 Origin、X-Core-Admin-Path、明确的 `tx_internal_actor_grant`、严格 input schema、写操作 UUID 幂等键均保留。配置更新重放同一输入和键，必须取得同一结果；token 轮换重放同一键后重新读取凭据，必须保持同一新 token。不能把 token 放入轮换回执。

上述 owner 和绑定可在固定 Core 的以下源码确认：

- `api/resources/contracts/core-operations.v1.json`、`admin-bindings.v1.json`、`browser-surfaces.v1.json` 是运行时实际使用的编译合约。
- `api/app/Http/Controllers/Txapi/Admin/NetworkNodeAdminController.php` 的 replaceConfigured 在事务锁下比较 expected_revision，过期输入冲突，不静默覆盖。
- `api/app/Http/Controllers/Txapi/Admin/NetworkMachineAdminController.php` 的 nativeRotateToken 不返回凭据；nativeCredentials 每次检查当前安装权威。
- `api/tests/Feature/Txapi/NativeNetworkBrowserTest.php` 与 `NativeNodeConfigurationTest.php` 覆盖正式操作、当前授权、凭据独立读取、无 token 回执和过期 revision 冲突。它们的存在不是 Node 完整 Machine 验收结果。

## Core 准入与验收条件

`api/app/Listeners/EnforceInstallationAuthority.php` 在原生安装下先检查真实 native/open，再对非准备命令执行封闭的 COMMANDS 检查。新候选把 `ws-server` 加入正式运行库存，未放入准备命令列表；未激活或 worker epoch 过期仍拒绝。

Core 独立 PR #291 增加真实命令 listener 的未激活拒绝、激活成功及 stale worker 拒绝回归。合并提交 `2dc3e7b` 的 API、MySQL、native C2、browser ingress 和 Core image 五项工作流均通过，实际镜像发布也成功。它们只证明该 Core 提交，不代表随后 Core main 的其他提交。Node PR #5 单独采用已评审的 `5536410`，Node 夹具不修改 Core 应用或库存。

真实 WS owner 已有：`NodeWebSocketServer -> NodeWorker -> NativeNodeWebSocket -> TxNodeAuth`。NodeWorker 通过 ServerObserver/NodeSyncService 的事务后事件重读当前配置与成员关系；旧 token 在每次 heartbeat/node-scoped event 及服务端同步时重新检查。NodeRegistry 的 successor 清理避免旧连接抹掉后继状态。源码 owner 存在仍需真实进程验收。

## Node 夹具完整链

1. `native_setup.py` 生成隔离 CA、Core/Node mTLS 身份、Core 签名 seed，启动实际 Credential Provider；Node recipient 绑定真实客户端证书指纹。
2. `fixture.php` 经 InstallationAuthority.initialize(native)、方案发布、Provider 注册、readiness、activate，要求 native/open、epoch 2。新 Core 的 ModuleReadiness 和 ModuleReleaseReceipts 由真实 activation 生成；CORE_RELEASE_ID 固定为精确 Core SHA，再以 successor worker epoch 调用 runtimeReport 校验已批准 composition。
3. 账户经 HTTP 注册、订单、免费 checkout、core:native-work 履约和原幂等键重放；要求订单完成且原 tx_native_free_checkout 行为 completed。User UUID/token 保持空，由 Provider issuance 产生 subject。
4. 固定 Core 的 native-subscription-client 通过真实 recipient-render 取得 VLESS/VMess 凭据。Go Orchestrator 由 ExpandMachineNode 创建 per-node control plane/service，使用完整 Authorization、Provider mTLS 和 UsageV2。授权 manager 的状态目录按 node ID 隔离。
5. 真实双协议流验证共享 WS、REST 全阻断时的配置更新、兄弟连接连续性、503/断线恢复、successor device facts、跨 Machine 拒绝、单节点启停、token 轮换与旧 token 拒绝。原批次必须在重新开放监听前取得真实持久化 receipt，并在 Core SQL 中保持原 node/source epoch/batch ID/digest/payload/usage period，最终达到 settled。

Provider trust、安装激活、购买履约、recipient-render、签名有限授权、UsageV2 和以上业务断言不因入口迁移而缩减。独立完整财务对账、物理主机验证和生产 PKI 不由本 gate 证明。

## Node 运行时验收边界

启动恢复、普通授权续期及 WS 端口更新已经有 Node 源码和对应回归，仍须以当前候选提交的 Actions 结果认定。

- 启动恢复在 collector/listener 前恢复原意图并确认持久化 receipt；每页最多 16 个、最多 16 页，整体 30 秒、单页 2 秒。磁盘 spool 枚举仍是完整读取，不能把网络预算解释成磁盘或内存绝对上限。
- 普通续期走 `Service.applyNativeAuthorization -> renewNativeAuthorization -> Kernel.PauseNativeRenewal -> nativeMeter -> ReadPauseConn -> NativeCollector.RetireQuiescent -> NativeStore`。仅凭据、权限、period、terms、tariff、revocation 和身份不变且租约不缩短时保持已有流；不把旧 token 迁移到新窗口。不能安全暂停、身份或策略变化仍重建。
- WS 端口变更复用原 meter/collector，并阻止旧在途 REST 结果回滚新端口。签名用户、协议、安全参数、路由和有限租约仍保留；其他配置变化继续获取完整签名 snapshot。

裸 TCP 及明确保留完整帧起点的协议读取才声明可暂停。VMess 的半个 length/body/padding 不能重试；TLS、REALITY、Vision 和不透明承载不推导连续性。同仓 VLESS/VMess 测试也不能代替第三方互通。

## 静态前置和 Actions 证据

`preflight.py` 检查真实 Core HEAD、API 源码状态、精确 inventory Git blob、ws-server command，以及八个正式操作的 HTTP admission、编译 owner 绑定、admin actor/permission、幂等模式和 browser surface。输出 `required_contracts` 逐项记录及编译合约 blob；不执行 PHP，不建立数据库或网络连接，始终 `runtime_verified=false`。

新 pin 的九项必要合约应全部齐备；旧 `d2e70b8c` 的 `CORE_WS_COMMAND_NOT_ADMITTED` 仍由回归保留。若操作、权限、绑定、surface 或源码发生不兼容变化仍应失败。`test_preflight.py` 为 Actions 保留这些回归；缺口检查不能改成 allow-failure 或 skip。

`run.py` 在数据库探测、迁移、seed 和应用启动之前保存 sources.json 与 compatibility-preflight.json。前置缺口保存失败 result.json，failed_stage=compatibility_preflight；安装状态为 not_started，native_core_installation_admission=false。只有完整真实 gate 成功才记录相应成功字段、Core release/composition 指纹及断言。

公开只上传 sources.json、result.json、compatibility-preflight.json。原始日志、令牌、证书私钥、fixture.json、凭据、spool 和 SQL 快照保持私有。静态 inventory 齐备仍只是必要条件；真实正向全链必须来自 README 规定的 Actions。

## 已取得的真实 Machine 结果

取消传播修复候选 Node `e5e98291ba59c55b514b54793c6d46edcc461be4`
（tree `07970c700f103bc8bedb225031431c6ce9445d47`）的 Actions `39538582760`
已通过完整 Machine job `119021745734`，artifact `12318529666`。固定 Core 仍为
`5536410`，没有改写 Core 应用源码。真实安装、Provider、WS-only 端口更新、503
恢复、successor、隔离、撤回及重启用均执行；原 10 秒终止 join、旧 token 重启拒绝、
新 token 协议恢复通过。原六个批次实际重放，SQL 唯一 settled batch 行仍为六个，
原 payload、usage period 和 frozen period 的校验保留。Core C2 job `119021745839`
也通过。该结果不抹除以下历史失败，后续源码提交仍须记录自己的验证范围。

Node `7c9cd91e8ca4b0bb9ecfa571872c83d384480bee` 与上述固定 Core 的 Actions
`39534639986` 已完成完整 Machine gate。公开 artifact `12316279421` 的 result.json
记录真实 native 安装/激活、Provider mTLS、VLESS/VMess、canonical admin operations、
REST 全阻断时的 WS 配置、503 重连、successor 设备事实、跨 Machine 隔离、成员撤回、
重启用、token 轮换旧凭据拒绝及新凭据恢复。六个原批次实际重放，SQL 唯一行仍为六个；
runner 校验原 payload、授权 period、冻结 entry 和 settled 状态。

Machine 端口更新曾暴露 Node mailbox 的实际表示变化：`NodeSpecFromPanel` 创建的
空数组经 `cloneNodeSpec` 的 append-to-nil 变成 null，使仅端口变化的严格 JSON 比较失败，
转入被夹具阻断的完整 REST 授权路径。现在用 make/copy 保留空数组与 nil 的区别；
真实 owner 为 `MachineSocket -> TranslateTXBoardEvent -> NodeMailbox.Apply/Drain ->
Service.handleWSEvent -> reloadNativeWSPort`。mailbox 表示回归和 Service 的真实 mailbox
交付回归已纳入该候选 Go/race；授权、有限租约和 REST 阻断断言均保留。

中间候选 `b239e8b6` 的 Actions `39534451726` 已通过端口更新，但在重新启用节点时
因 12 秒新监听等待超时失败。该失败保留；公开证据不足以确定其原因，不能用后续通过
声称该超时已被单独定位。后续候选的通过不抹除这条历史结果。

同一 Node `7c9cd91e` 的后续完整 Actions `39535513954` 中，Machine 在 token
轮换后等待原 Orchestrator 返回的 10 秒断言失败，artifact `12317855239`。
这次端口更新、重启用和轮换操作已执行，但旧 token 终止 join、旧 token 重启拒绝及
最后恢复未执行通过。不能仅引用前一轮成功来宣布该候选稳定通过。

源码检查确认 TXBoard HTTP 请求没有绑定调用者 context，Provider Resolve 还使用
Background；Service 退出时却会等待授权刷新 worker，Machine 的同步发现也会等待
原 HTTP 超时。这是明确的取消传播缺口，但公开失败结果尚不能确定它就是本次
超时的具体等待点。修复及固定白名单失败诊断已进入 `e5e98291`，由该提交的
Go/source guards 和完整 Machine Actions 验证；不能据新成功反推旧失败的唯一原因。

本 gate 不证明独立完整财务对账、生产 PKI 或物理主机部署；相应字段继续为 false。
Node 后续文档提交、main 镜像发布和 Core 采用应另记实际提交，不继承此处的精确 SHA。
