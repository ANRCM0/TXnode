# 原生验收覆盖映射

本表依据仓库测试源码整理，区分测试已编写的断言与尚缺的跨层验收。测试文件存在、
静态检查通过、历史 CI 通过均不能证明当前提交已经通过功能验收；功能、race、网络和
互操作验证应在 GitHub Actions 对应提交运行，并记录实际 SHA、运行链接及结果。

## 已有测试源码与断言边界

| 范围 | 测试入口 | 已编写的断言 | 不能据此推出 |
|---|---|---|---|
| Service 的 usage_v2 生命周期 | `internal/service/native_usage_linux_test.go` 的 `TestNativeBillingRefreshResetAndEmptyRevocationPreserveOriginalSessions`、`TestNativeBillingRotationAndShutdownSealPriorCredentialEvidence`、`TestNativeCutoffClosesAffectedAdmissionAndHigherRevisionRecoversWithoutReposting` | 刷新、轮换、撤销、关闭和 cutoff 保留原授权会话证据 | 该文件使用 `nativeBillingKernel` / `stubNativeMeter`；不是完整真实内核 I/O 链路 |
| 原生启动回执门禁 | `internal/service/native_startup_recovery_linux_test.go` | 真实 kernel 在固定旧 Session/Submission 得到匹配 persisted receipt 后才监听；跨页、lost ACK 不重发、未封口完成意图、cutoff、取消/超时、错误回执及 257 条 pending 拒绝；有效已 ACK 历史不占网络预算 | `454607f4` Go/race 通过，新运行时仍须新提交 Actions；回执不等于结算。spool 完整枚举仍不具备绝对磁盘时间/内存上限 |
| 原租约 WS 端口更新 | `internal/service/native_config_reload_linux_test.go` | 真实认证 WS 帧及 bounded VLESS；REST 503 下无拉取地变更端口，保留 collector/meter/session/digest/deadline、兄弟流；绑定失败保留旧监听、过期/撤权拒绝、旧 full poll 不回滚 | `454607f4` Go/race 通过，新运行时仍须新提交 Actions；只覆盖端口变化，不证明普通授权续期连接连续或完整 Machine 已通过 |
| 普通授权续期的 Service owner | `internal/service/native_usage_renewal_linux_test.go` | 真实 bounded VLESS 与 VMess AES128GCM/TCP 同流三次续期、稳定 hook/四个原 grant 唯一批次、非重叠区间和每 grant 双向精确字节；当前 cutoff 不恢复 paused owner；unsupported 保持原重建；凭据/权限/period/terms/revocation/Provider 身份及缩短租约不进入保活续期 | 新增源码待新提交 Actions；VMess 使用同仓库 outbound 客户端，不代替第三方互通；不是 TLS/REALITY/全部协议或完整 Machine 连续性证明 |
| 续期 meter 与严格封口 | `internal/kernel/txnode/native_renewal_linux_test.go`、`internal/usageinterval/native_strict_retire_linux_test.go` | Begin/Complete 在原 meter/collector 完成；foreign/duplicate token 拒绝、停止不可恢复、Commit 后仍暂停、整秒边界、不同 store/用户拒绝、未静止封口拒绝 | OS fsync 不可取消；包级断言不替代 Service 到协议的真实链路 |
| 协议安全读取暂停 | `internal/dataplane/core/read_pause_test.go`、`internal/dataplane/proto/vless/read_pause_test.go`、`internal/dataplane/proto/vmess/read_pause_test.go` | 裸 TCP 暂停/恢复及原 deadline；未知承载拒绝能力；VMess 完整帧起点保留 nonce/XOF，部分长度/body/padding 不跨窗口重试；VLESS/VMess 部分写保留实际计数及错误 | 不支持以 TLS 读取超时模拟安全暂停；不是完整 Service VMess 或所有加密承载续期验收 |
| 原生流量授权与关闭 | `internal/service/native_authority_denial_test.go`、`authorization_adapter_test.go`、`membership_withdrawal_test.go` | 真实监听和已建立流在拒绝、到期、撤销时关闭，并检查尾部或重放 | 不能替代所有 observer、事件存储和 packet 计量路径 |
| 内核本地事件连接 | `internal/kernel/txnode/e2e_smoke_test.go` 的 `TestKernelLocalEventMeterAccountsRelay` | 真实 SOCKS5 TCP 流量经原生内核连接到 `usagebucket.Coordinator`，出现事件或持久化桶 | 当前成功条件不要求双向精确字节、Service 安装/退役 consumer、完整持久化恢复或 observer 输出 |
| 内核原生计量接线 | `internal/kernel/txnode/native_meter_test.go`、`native_generation_linux_test.go` | 原生计量事件、未知 collector 拒绝、授权代际 | 不能覆盖 Service 到 Coordinator / observer 的完整组合及所有 UDP packet 路径 |
| NativeStore 证据生命周期 | `internal/usageinterval/native_linux_test.go` | I/O intent 先于完成、原周期尾部、待完成证据隔离、迟到完成、关闭、时钟回退和离线到期 | 包内直接调用 collector；不是进程在真实数据面 I/O 中遭 SIGKILL 的证明 |
| bounded journal 突发退出 | `internal/usageinterval/crash_linux_test.go` 的 `TestBoundedIntervalSIGKILLRetainsOriginalSealedJournalAndNeverResumesTail` | 6 个精确故障点被父进程 SIGKILL；未发布尾部不导出、已发布原批次恢复、重复恢复保持 batch ID/digest、旧尾部不能续用 | 该入口覆盖 bounded Journal / Collector；不等于 NativeStore、Service 或真实协议进程端到端崩溃验收 |
| spool 与交付恢复 | `internal/usagev2/spool_test.go`、`quarantine_test.go`、`retention_test.go` | fsync/容量/损坏拒绝、原批次重放、收据查询、cutoff 隔离、保留窗口 | 不能仅凭包级恢复断言证明 Service 关闭顺序或真实 packet 计数正确 |
| 私有 Core 到原生 Node | `internal/service/native_c2_interop_test.go` 的 `TestNativeC2RuntimeEndToEnd`，CI `core-compatibility` | 源码提供 Core/Provider mTLS、真实 VLESS、离线到期、重放、轮换和结算路径 | 必须另外取得候选 Node SHA 与 pinned Core revision 的实际 CI 证据；不能替代以下挂起套件 |
| Service 的事件和 observer 全链路 | `internal/service/native_observation_linux_test.go` 的 `TestNativeServiceObservationPersistsExactTCPUDPAndRecoversOriginalEvidence` | 真实 Service.Run + SOCKS TCP/UDP；31/27 字节逐方向落盘、身份映射、关闭、两次原 digest/receipt 恢复、observer 原始记录和 v1 58 字节计数 | 本地事件仍无结算权威；不能替代 usage_v2 进程崩溃恢复 |
| 存储失败隔离与进程归属 | 同文件的 `TestNativeObservationStorageFailureKeepsActualTrafficAndStopsRetrying`、`TestNativeObservationDirectoriesAndProcessOwnerRemainScoped` | observer 容量/不可写、event store 容量和关闭时 v1 仍精确；禁用无 I/O、失败不重试、目录隔离、进程单一 owner | 新增源码仍须在候选 Actions 执行 |
| 原生 packet 周期 | 同文件的 `TestNativePacketPeriodKeepsUnsampledOldTailAndFreshBytesSeparate` | 真实 UDP 原周期 13 已采样 + 7 未采样尾部，切换后 57 字节；旧控制连接关闭，旧20/新57分段 | 不是任意 packet 承载协议的互通证明 |
| 原生 I/O 错误边界 | `internal/dataplane/core/download_accounting_test.go`、`udp_accounting_test.go`、`chunk_hook_test.go` | 实际 relay copy 对短写、正字节伴错误、零成功写、取消限速及 packet 关闭完成 I/O 的计数 | 不恢复已移除内核的内部 wrapper；功能结果以候选 CI 为准 |
| Mieru 官方 UDP 网络损伤 | `internal/kernel/txnode/mieru_packet_fault_linux_test.go` 的 `TestInteropMieruOfficialPacketFaults` | 有界代理在双向真实注入丢包、乱序和重复；core 与 NativeMeter 物理计数精确；撤权重放不复活、Reload/监听回滚恢复 | 本地物理观察不是 usage_v2 结算或持久化恢复；真实 UDP socket 绑定失败不承诺原 underlay 无中断 |
| 固定 Core machine 契约 | `internal/machine/native_core_machine_live_test.go`、`scripts/tests/node-native-machine/`，CI `core-machine` | 已编写真实 Provider mTLS、native 安装/激活、账户/购买/履约及签名授权准备，生产 Orchestrator、双 Node、共享 WS/503/后继心跳、设备事实、隔离、轮换与原使用量重放断言 | 当前固定 Core native admission 缺五项必要能力，正向链路尚未执行；Node 普通续期仅有窄路径源码和待执行回归，详见 `CORE-MACHINE-COMPATIBILITY.zh.md`。不宣称 native installation machine 或数据库计费已验证 |

## SIGKILL 夹具约束

父子进程通过专用事件管道传递 stage 和初始化阶段，stdout/stderr 只保存诊断。
子进程完成 spool、journal、collector 初始化后发出 `ready`，父进程发送对应 `ARM`，
子进程到达指定 fault hook 后发出 `gate` 并阻塞，父进程明确发送 SIGKILL。
父进程按 Go 测试 deadline 留出清理预算；没有外部 deadline 时仍使用有限预算。
失败信息包含目标 stage、最后进展阶段和子进程输出，并检查退出信号确为 SIGKILL。

原 6 个 stage 保持为 `before_seal`、`after_file_sync`、`after_publish`、
`after_dir_sync`、`before_spool`、`after_spool`。本轮只调整测试监督机制，
不调整生产计量、持久化提交点或恢复策略，也不把超时直接视为成功注入故障。

## 挂起文件与原生替代断言

| 挂起文件 | 原生恢复验收应覆盖 |
|---|---|
| `docs/removed-tests/usage_event_store_adapter_test.go.txt` | 原生 Service 测试已编写真实 TCP/UDP、关闭、持久化恢复、失败隔离和进程归属断言；待候选 Actions |
| `docs/removed-tests/usage_observer_adapter_test.go.txt` | 原生 Service 测试已编写真实 I/O、身份、关闭、错误隔离、禁用和恢复断言；用户 delta/Reload 失败的细分边界仍由各自生命周期测试承担 |
| `docs/removed-tests/store_io_test.go.txt` | 原生 core relay 测试覆盖短写/正字节伴错/失败写和取消；使用当前物理方向口径，不恢复旧 wrapper |
| `docs/removed-tests/traffic_period_packet_test.go.txt` | 已编写真实 SOCKS UDP 周期切换、原周期尾部和精确分段断言；待候选 Actions |
| `docs/removed-tests/native_core_machine_live_test.go.txt` | 已编写固定 Core、生产 Orchestrator、真实原生 VLESS/VMess 和 machine 契约的独立入口；固定基线的 installation/Provider/Machine 合约冲突仍阻塞执行，不能以静态编译或单独 Core C2 通过关闭缺口 |

恢复时应逐项写出实际 owner 调用链和精确断言，再将替代测试纳入 Actions。只把旧文件
改成可编译、改用 mock，或引用现有单层测试，都不足以关闭这些缺口。
本轮新增测试的实际功能结果仍待对应提交 Actions；不按文件数量宣告旧套件全部恢复。
