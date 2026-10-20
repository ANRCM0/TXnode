# 固定 Core 基线的 Machine 兼容缺口

本记录只说明源码合约缺口与已有失败证据，不是 Machine 功能验收。Node 的固定 Core 基线仍是 `ANRCM0/TXBoard@ca25f21de8ff41a476c1ffcf182359f3bc565122`，以 `compatibility/core.v1.json` 为准。本切片不修改 Core 应用、Core pin、授权策略或 CI 成败条件。

## 已有 Actions 失败

Node `75e1554` 的 Actions run `39463019286`，Core machine job `118770492079` 在真实 Machine 初始就绪阶段失败。结构化失败诊断定位 `internal/machine/native_core_machine_live_test.go:160` 的 readiness 等待，信号为 readiness timeout；这不是双节点、共享 WS 或 Provider 授权通过的证据。该执行使用 `CORE_INSTALLATION_MODE=legacy`，公开 evidence 的 `native_core_installation_admission=false`，不能解释成 native 安装验收。

## Node 的原生夹具准备与调用链

本切片补齐 Node 仓库自己的原生夹具准备，不修改固定 Core 源码，也不代表 Machine 功能已经验收。以下 Core 行号均对应上述不可变 pin。

1. `scripts/tests/node-native-machine/native_setup.py` 准备隔离 CA、Core/Node mTLS 身份、Core 签名 seed 和真实 Credential Provider 进程，沿用固定 Core 已有的受信配置入口。
2. `fixture.php` 调用真实 `InstallationAuthority.initialize(native)`、方案发布、Provider 注册、readiness 和 activate，要求 native/open、epoch 2；账户经 HTTP 注册、订单、免费 checkout 和 `core:native-work` 履约取得 Provider subject。固定 Core 的 recipient-render 客户端取得 VLESS/VMess 凭据，不直接填充 User UUID/token。
3. `internal/machine/machine.go` 通过 `ExpandMachineNode` 创建 per-node control plane 和 service。Go 夹具提供完整 `Authorization`、Provider mTLS 与 `UsageV2` 配置；`initAuthorization` 继续在既有 state 根目录下按 node ID 隔离 manager。
4. `internal/controlplane/txboard.go` 的 `Initial` 仍要求授权 manager、握手 trust 和完整签名 snapshot；`initNativeUsage` 使用该 snapshot 创建原生 collector、原有 NativeStore 和 UsageV2 spool。旧的 legacy terminal Batch 断言映射为原 node/source epoch/batch ID/payload digest/usage period 与真实持久化 receipt、SQL 唯一性。

这些准备全部位于静态前置检查之后。固定 pin 仍有下面五项 admission 缺口，因此真实安装、Provider、账户和完整 Machine 链尚未在此 gate 执行。

## Node 自身尚未满足的 Machine 行为

| 保留的原业务断言 | 当前原生实现及缺口 |
| --- | --- |
| 恢复旧使用量并取得 Core 持久化回执后才开放监听 | `OpenNativeStore` 保证原证据在本地导出；`initialSetup` 随后开放 kernel，`Run` 再启动异步上报 worker。当前不是回执先于监听的契约。需要独立的有界恢复和准入设计及真实内核验证，不能以最终上报成功替代该断言。 |
| 兄弟节点已建流跨授权刷新继续存活 | `applyNativeAuthorization` 在接受新签名修订前停止旧 kernel、排空计量并创建新 collector；现有 `TestNativeBillingRefreshResetAndEmptyRevocationPreserveOriginalSessions` 明确要求重新启动。持续连接的原断言尚未满足。 |
| 所有 config/users REST 请求阻断时仍由 WS 完成配置更新 | 强制签名授权下的 WS 通知触发 `requestAuthorizationPoll`，重新获取完整 REST snapshot；不能跳过签名验证来满足旧的 WS-only 断言。 |

这些是 Node 的兼容与验收缺口，不能归入 Core admission 缺失，也不证明当前原生计量已经丢失。夹具保留相应严格断言；即使后续 Core inventory 通过，也不能据此宣称完整 Machine 已通过。

## 固定 Core 调用链

| 固定 Core 源码 | 必要行为与缺口 |
| --- | --- |
| `api/app/Http/Controllers/Txapi/NodeProtocolController.php:19`、`:38`、`:42` | handshake 无条件读取 `NodeAuthorizationQueries::publicTrust()`；授权不可用返回 503。 |
| `api/app/Domains/Network/NativeProviderNodeAuthorization.php:30`、`:34` | publicTrust 首先调用 `InstallationAuthority::assertNativeRead()`。 |
| `api/app/Domains/Installation/InstallationAuthority.php:236`、`:292`、`:298` | assertNativeRead 进入 native domain；安装必须是 authority=native、phase=open，并校验 native 配置。legacy fixture 不满足。 |
| `api/app/Listeners/EnforceInstallationAuthority.php:50`、`:59` | native 命令必须在 `NativeRuntimeAdmission::COMMANDS` 中；未列入则抛出 `INSTALLATION_AUTHORITY_NATIVE_COMMAND_UNAVAILABLE`。 |
| `api/app/Domains/Installation/NativeRuntimeAdmission.php:9` | COMMANDS 缺少实际启动 Workerman 所用的 `ws-server`。 |
| `api/app/Http/Middleware/EnsureInstallationAuthority.php:20` | native HTTP 请求必须通过封闭的 admission inventory。 |
| `api/app/Domains/Installation/NativeRuntimeAdmission.php:13`、`:50` | HTTP inventory 缺少本 gate 必需的 network-nodes 列表、完整更新、启停更新及 Machine token rotate。 |

所以保留 legacy 不能取得必需的 native Provider trust；仅切换环境变量到 native 也不能让未激活安装、未准入 WS 命令和缺少的管理路径变为可用。不能用关闭 Provider 授权、伪造 trust、替换 Core API、放宽安装权威或跳过阶段来获得绿色结果。

## 独立 Core 适配的必需能力

- 验证经过真实安装生命周期进入 native/open 的隔离 fixture，包含锁定配置、Provider 注册、trust 和子节点可使用的有限签名授权；Node 已准备相应源码，密钥与租约仍须来自对应真实 owner 并经实际执行验证。
- 在安装权威下实现并准入真实 `ws-server`，覆盖 Machine 认证、单共享 tunnel、节点广播、断线重连、token 轮换及旧会话撤销。
- 实现并准入管理接口：`GET /txapi/admin/{admin}/network-nodes`、`PUT /txapi/admin/{admin}/network-nodes/{id}`、`PATCH /txapi/admin/{admin}/network-nodes/{id}`、`POST /txapi/admin/{admin}/network-machines/{id}/token/rotate`，保留管理员鉴权和状态一致性。
- 独立 Core 变更必须先取得它自己精确 SHA 的功能验收，再经单独兼容评审采用新 pin；随后 Node 重跑真实授权 fixture 和完整 gate，并分别处理上述 Node 行为缺口。静态 inventory 通过只是必要条件。

## 静态前置检查与证据

`scripts/tests/node-native-machine/preflight.py` 只读取固定 Core 源码及 Git 状态，检查实际 HEAD、API 源码差异、`COMMANDS` 和上述 HTTP 合约。输出只包含固定 gap code、公开路径和 revision，不输出日志、环境、令牌或异常正文。缺口返回非零。

`run.py` 在数据库探测、迁移、seed 和应用启动之前保存 `sources.json`、`compatibility-preflight.json`；发现缺口时保存 `result.json`，其中 `status=failed`、`failed_stage=compatibility_preflight`。CI 仍失败，不能把诊断前移解释成验收通过。当前固定 pin 预期缺少 `CORE_WS_COMMAND_NOT_ADMITTED` 及四个 `CORE_HTTP_NOT_ADMITTED` 必需项。

`sources.json` 区分请求的 native 模式与实际尚未启动的安装状态；只有真实 activate 成功后运行记录才声明 native。前置失败的 `native_core_installation_admission=false` 保持不变。

这项检查不证明 PHP 运行时、MySQL、安装激活、Provider 进程、签名租约或 WS 生命周期可用，也不消除上述 Node 行为缺口。功能结果仍须来自 README 规定的 Actions 执行。
