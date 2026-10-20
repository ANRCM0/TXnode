# 原生验收覆盖映射

本表依据仓库测试源码整理，区分测试已编写的断言与尚缺的跨层验收。测试文件存在、
静态检查通过、历史 CI 通过均不能证明当前提交已经通过功能验收；功能、race、网络和
互操作验证应在 GitHub Actions 对应提交运行，并记录实际 SHA、运行链接及结果。

## 已有测试源码与断言边界

| 范围 | 测试入口 | 已编写的断言 | 不能据此推出 |
|---|---|---|---|
| Service 的 usage_v2 生命周期 | `internal/service/native_usage_linux_test.go` 的 `TestNativeBillingRefreshResetAndEmptyRevocationPreserveOriginalSessions`、`TestNativeBillingRotationAndShutdownSealPriorCredentialEvidence`、`TestNativeCutoffClosesAffectedAdmissionAndHigherRevisionRecoversWithoutReposting` | 刷新、轮换、撤销、关闭和 cutoff 保留原授权会话证据 | 该文件使用 `nativeBillingKernel` / `stubNativeMeter`；不是完整真实内核 I/O 链路 |
| 原生流量授权与关闭 | `internal/service/native_authority_denial_test.go`、`authorization_adapter_test.go`、`membership_withdrawal_test.go` | 真实监听和已建立流在拒绝、到期、撤销时关闭，并检查尾部或重放 | 不能替代所有 observer、事件存储和 packet 计量路径 |
| 内核本地事件连接 | `internal/kernel/txnode/e2e_smoke_test.go` 的 `TestKernelLocalEventMeterAccountsRelay` | 真实 SOCKS5 TCP 流量经原生内核连接到 `usagebucket.Coordinator`，出现事件或持久化桶 | 当前成功条件不要求双向精确字节、Service 安装/退役 consumer、完整持久化恢复或 observer 输出 |
| 内核原生计量接线 | `internal/kernel/txnode/native_meter_test.go`、`native_generation_linux_test.go` | 原生计量事件、未知 collector 拒绝、授权代际 | 不能覆盖 Service 到 Coordinator / observer 的完整组合及所有 UDP packet 路径 |
| NativeStore 证据生命周期 | `internal/usageinterval/native_linux_test.go` | I/O intent 先于完成、原周期尾部、待完成证据隔离、迟到完成、关闭、时钟回退和离线到期 | 包内直接调用 collector；不是进程在真实数据面 I/O 中遭 SIGKILL 的证明 |
| bounded journal 突发退出 | `internal/usageinterval/crash_linux_test.go` 的 `TestBoundedIntervalSIGKILLRetainsOriginalSealedJournalAndNeverResumesTail` | 6 个精确故障点被父进程 SIGKILL；未发布尾部不导出、已发布原批次恢复、重复恢复保持 batch ID/digest、旧尾部不能续用 | 该入口覆盖 bounded Journal / Collector；不等于 NativeStore、Service 或真实协议进程端到端崩溃验收 |
| spool 与交付恢复 | `internal/usagev2/spool_test.go`、`quarantine_test.go`、`retention_test.go` | fsync/容量/损坏拒绝、原批次重放、收据查询、cutoff 隔离、保留窗口 | 不能仅凭包级恢复断言证明 Service 关闭顺序或真实 packet 计数正确 |
| 私有 Core 到原生 Node | `internal/service/native_c2_interop_test.go` 的 `TestNativeC2RuntimeEndToEnd`，CI `core-compatibility` | 源码提供 Core/Provider mTLS、真实 VLESS、离线到期、重放、轮换和结算路径 | 必须另外取得候选 Node SHA 与 pinned Core revision 的实际 CI 证据；不能替代以下挂起套件 |

## SIGKILL 夹具约束

父子进程通过专用事件管道传递 stage 和初始化阶段，stdout/stderr 只保存诊断。
子进程完成 spool、journal、collector 初始化后发出 `ready`，父进程发送对应 `ARM`，
子进程到达指定 fault hook 后发出 `gate` 并阻塞，父进程明确发送 SIGKILL。
父进程按 Go 测试 deadline 留出清理预算；没有外部 deadline 时仍使用有限预算。
失败信息包含目标 stage、最后进展阶段和子进程输出，并检查退出信号确为 SIGKILL。

原 6 个 stage 保持为 `before_seal`、`after_file_sync`、`after_publish`、
`after_dir_sync`、`before_spool`、`after_spool`。本轮只调整测试监督机制，
不调整生产计量、持久化提交点或恢复策略，也不把超时直接视为成功注入故障。

## 尚缺的原生跨层恢复

| 挂起文件 | 原生恢复验收应覆盖 |
|---|---|
| `docs/removed-tests/usage_event_store_adapter_test.go.txt` | 用真实 txnode 流量驱动 `Service.Run` 安装的 Coordinator；断言初始化、退役、关闭、持久化故障处理，以及恢复后逐用户/逐方向原始事件与桶不重复、不丢失 |
| `docs/removed-tests/usage_observer_adapter_test.go.txt` | 真实 txnode + Service + observer 全链路；断言真实 I/O 导致的 observer 输出、身份映射、生命周期关闭、错误隔离和原始计量口径 |
| `docs/removed-tests/store_io_test.go.txt` | 通过原生数据面 TCP/packet 夹具验证部分成功 I/O、正字节伴随错误、拒绝或失败写入的计数边界；避免恢复 sing-box 内部包装器依赖 |
| `docs/removed-tests/traffic_period_packet_test.go.txt` | 真实原生 UDP/packet 会话跨流量周期切换、迟到 packet、撤销与尾部关闭；断言物理方向、原周期身份和精确字节不被重新归属 |
| `docs/removed-tests/native_core_machine_live_test.go.txt` | 重新明确私有 Core checkout、machine 与原生 Node 的执行前提和独立入口；现有 C2 覆盖不能自动宣告该文件全部恢复 |

恢复时应逐项写出实际 owner 调用链和精确断言，再将替代测试纳入 Actions。只把旧文件
改成可编译、改用 mock，或引用现有单层测试，都不足以关闭这些缺口。
本轮不新增这些 Service 端到端测试，也不宣告挂起项已恢复。
