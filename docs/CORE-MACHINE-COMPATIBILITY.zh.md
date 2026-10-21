# 固定 Core 基线的 Machine 兼容门禁

Node 的固定 Core 基线以 `compatibility/core.v1.json` 为准，当前为 `ANRCM0/TXBoard@d2e70b8c3896b8d9808595886cb544d133f179ee`。这里说明源码合约、真实 owner 调用链和待验收条件；源码检查、语法检查、编译均不构成完整 Machine 功能验收。

## 从旧管理路径迁移到正式操作

该 Core pin 仍未准入原夹具使用的 `ws-server` 命令和四个 raw 管理 HTTP 路径。但其已有正式的 Core browser 操作及 owner，Node 夹具现在使用它们，不要求重新开放未版本化的旧管理入口。

| 原夹具调用 | 当前正式操作与 owner |
| --- | --- |
| GET network-nodes 列表取配置 | `network.nodes.configuration.get` → `NetworkNodeAdminController.configuration`，返回完整配置和当前 revision |
| PUT network-nodes/{id} | `network.nodes.configuration.replace` → `replaceConfigured`，提交完整 configuration_json、expected_revision 和 UUID 幂等键 |
| PATCH network-nodes/{id} | `network.nodes.patch` → `patch`，保留单节点启停、成员关系通知和兄弟节点隔离 |
| POST network-machines/{id}/token/rotate 并直接取 token | `network.machines.token.rotate` → `nativeRotateToken`，回执只含 ok；另用 `network.machines.credentials.get` → `nativeCredentials` 重新鉴权后取得 token |
| CLI ws-server | `NodeWebSocketServer` → 真实 `NodeWorker` 已存在；该 pin 的 `NativeRuntimeAdmission.COMMANDS` 仍未含 `ws-server`，因此完整 gate 仍应失败 |

操作通过实际 `POST /gateway/v1/core/admin/operations/{operation}` 调用，原管理员 Bearer、同源 Origin、X-Core-Admin-Path、明确的 `tx_internal_actor_grant`、严格 input schema、写操作 UUID 幂等键均保留。配置更新重放同一输入和键，必须取得同一结果；token 轮换重放同一键后重新读取凭据，必须保持同一新 token。不能把 token 放入轮换回执。

上述 owner 和绑定可在固定 Core 的以下源码确认：

- `api/resources/contracts/core-operations.v1.json`、`admin-bindings.v1.json`、`browser-surfaces.v1.json` 是运行时实际使用的编译合约。
- `api/app/Http/Controllers/Txapi/Admin/NetworkNodeAdminController.php` 的 replaceConfigured 在事务锁下比较 expected_revision，过期输入冲突，不静默覆盖。
- `api/app/Http/Controllers/Txapi/Admin/NetworkMachineAdminController.php` 的 nativeRotateToken 不返回凭据；nativeCredentials 每次检查当前安装权威。
- `api/tests/Feature/Txapi/NativeNetworkBrowserTest.php` 与 `NativeNodeConfigurationTest.php` 覆盖正式操作、当前授权、凭据独立读取、无 token 回执和过期 revision 冲突。它们的存在不是 Node 完整 Machine 验收结果。

## 剩余 Core 准入条件

`api/app/Listeners/EnforceInstallationAuthority.php` 在原生安装下先检查真实 native/open，再对非准备命令执行封闭的 COMMANDS 检查。`ws-server` 不在准备命令列表，也未列入 COMMANDS；只切换安装环境变量无法启动它。

Core 独立适配应在既有安装权威下准入真实 ws-server，并在它自己的 Actions 验证命令 admission、未激活安装拒绝、有限原生授权及 Workerman 身份/成员隔离。Node 不修改 Core 应用、库存或 pin 来绕开门禁。只有 Core 独立变更取得精确 SHA 验收，再经单独兼容采用后，Node 才能重跑完整 gate。

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

`preflight.py` 检查真实 Core HEAD、API 源码状态、精确 inventory Git blob、ws-server command，以及五个正式操作的 HTTP admission、编译 owner 绑定、admin actor/permission、幂等模式和 browser surface。输出 `required_contracts` 逐项记录及编译合约 blob；不执行 PHP，不建立数据库或网络连接，始终 `runtime_verified=false`。

当前 pin 在正式操作合约齐备时，剩余预期 gap 是 `CORE_WS_COMMAND_NOT_ADMITTED`。若操作、权限、绑定、surface 或源码发生不兼容变化仍应失败。`test_preflight.py` 为 Actions 保留这些回归；缺口检查不能改成 allow-failure 或 skip。

`run.py` 在数据库探测、迁移、seed 和应用启动之前保存 sources.json 与 compatibility-preflight.json。前置缺口保存失败 result.json，failed_stage=compatibility_preflight；安装状态为 not_started，native_core_installation_admission=false。只有完整真实 gate 成功才记录相应成功字段、Core release/composition 指纹及断言。

公开只上传 sources.json、result.json、compatibility-preflight.json。原始日志、令牌、证书私钥、fixture.json、凭据、spool 和 SQL 快照保持私有。静态 inventory 齐备仍只是必要条件；真实正向全链必须来自 README 规定的 Actions。
