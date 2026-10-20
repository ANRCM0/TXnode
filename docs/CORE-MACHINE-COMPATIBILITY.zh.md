# 固定 Core 基线的 Machine 兼容缺口

本记录只说明源码合约缺口与已有失败证据，不是 Machine 功能验收。Node 的固定 Core 基线仍是 `ANRCM0/TXBoard@ca25f21de8ff41a476c1ffcf182359f3bc565122`，以 `compatibility/core.v1.json` 为准。本切片不修改 Core 应用、Core pin、授权策略或 CI 成败条件。

## 已有 Actions 失败

Node `75e1554` 的 Actions run `39463019286`，Core machine job `118770492079` 在真实 Machine 初始就绪阶段失败。结构化失败诊断定位 `internal/machine/native_core_machine_live_test.go:160` 的 readiness 等待，信号为 readiness timeout；这不是双节点、共享 WS 或 Provider 授权通过的证据。该执行使用 `CORE_INSTALLATION_MODE=legacy`，公开 evidence 的 `native_core_installation_admission=false`，不能解释成 native 安装验收。

## Node 调用链

以下 Node 行号对应本记录编写时的 `e462b67`；Core 行号均对应上述不可变 pin。

1. `internal/machine/machine.go:257` 通过 `ExpandMachineNode` 创建子配置，`:294` 创建 per-node control plane，`:295` 创建 service。`internal/config/config.go:933` 是子配置展开入口。
2. `internal/service/service.go:347` 初始化授权；`internal/service/authorization_adapter.go:29` 在 `Authorization.Enabled=false` 时直接返回。当前真实 Machine fixture 没有提供完整的 Provider 授权配置，因此子 service 没有授权 manager。
3. `internal/controlplane/txboard.go:96` 的 `Initial` 必须先有授权 manager，否则返回 `NODE_AUTHORIZATION_MANAGER_REQUIRED`；随后握手还必须提供 trust（`:105`），再进入带签名授权的 snapshot。仅补 Node fixture 的 Enabled 标志不等于完整配置，也不能解除下面的 Core 安装边界。

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

- 提供经过真实安装生命周期进入 native/open 的隔离 fixture，包含锁定配置、Provider 注册、trust 和子节点可使用的有限签名授权；密钥与租约必须来自对应真实 owner。
- 在安装权威下实现并准入真实 `ws-server`，覆盖 Machine 认证、单共享 tunnel、节点广播、断线重连、token 轮换及旧会话撤销。
- 实现并准入管理接口：`GET /txapi/admin/{admin}/network-nodes`、`PUT /txapi/admin/{admin}/network-nodes/{id}`、`PATCH /txapi/admin/{admin}/network-nodes/{id}`、`POST /txapi/admin/{admin}/network-machines/{id}/token/rotate`，保留管理员鉴权和状态一致性。
- 独立 Core 变更必须先取得它自己精确 SHA 的功能验收，再经单独兼容评审采用新 pin；随后 Node 才能补齐真实授权 fixture 并重跑完整 gate。静态 inventory 通过只是必要条件。

## 静态前置检查与证据

`scripts/tests/node-native-machine/preflight.py` 只读取固定 Core 源码及 Git 状态，检查实际 HEAD、API 源码差异、`COMMANDS` 和上述 HTTP 合约。输出只包含固定 gap code、公开路径和 revision，不输出日志、环境、令牌或异常正文。缺口返回非零。

`run.py` 在数据库探测、迁移、seed 和应用启动之前保存 `sources.json`、`compatibility-preflight.json`；发现缺口时保存 `result.json`，其中 `status=failed`、`failed_stage=compatibility_preflight`。CI 仍失败，不能把诊断前移解释成验收通过。当前固定 pin 预期缺少 `CORE_WS_COMMAND_NOT_ADMITTED` 及四个 `CORE_HTTP_NOT_ADMITTED` 必需项。

这项检查不证明 PHP 运行时、MySQL、安装激活、Provider 进程、签名租约或 WS 生命周期可用，也不消除 Node fixture 的授权配置缺口。功能结果仍须来自 README 规定的 Actions 执行。
