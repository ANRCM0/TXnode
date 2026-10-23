# 原生验收覆盖映射

2026-10-24：目标失败互通新增官方 Mieru UDP 承载，与原 TCP 承载分别执行正向
控制、core 的 `ECONNREFUSED`、完整 SOCKS REP=05 和失败后的有效目标恢复。
严格清单要求两个子项；完整矩阵现为 37 个适用顶层、29 个子项及两项不适用。
候选 `66f171d6` 的两个子项通过，但同轮 Machine 成员恢复失败；诊断候选
`faeece51` 的完整功能通过且本次重放/SQL 均为 6，不能据此解释旧失败。
集成候选 `b2f2c7ae` 的完整功能 `39989542571` 与 PR CI `39989547284` 均已成功，
本次 Machine 原 batch 与 SQL 唯一 settled 行均为 5。严格 full 的原始事件明确
包含目标失败 TCP/UDP 两个子项通过，不能只由父用例结果推导覆盖。
完整状态与源码树见 `OUTSTANDING-WORK.zh.md`。

2026-10-23：最终运行时候选 `94d494202ba5f990494b692a4a67e237805f4cb7`
的 PR `39967692881` 与完整功能 `39967685398` 成功，包含 Go/race、严格 quick/full、
runtime stability、真实 Core C2、镜像冒烟与完整 Machine。Machine 本次按原始
batch 核对 5 个唯一 settled SQL 行、旧 token 拒绝、新 token 协议恢复及原周期。
同 SHA 的正式 S3 `39969066032` 已完成且失败：111/120 measured，九份不完整
样本使 usage_v2/upload 和 events/download 保持 incomplete；十项完整比较达标。
1810.902413957 秒/39 轮 soak 与七项带流量故障通过，S3 ledger 仍为 false。
带流量 SIGKILL 的 durable pending sequence 握手和失败 summary 已实际执行，
不能把功能、故障与 soak 通过推广为完整 S3 通过。

本表依据仓库测试源码整理，区分测试已编写的断言与尚缺的跨层验收。测试文件存在、
静态检查通过、历史 CI 通过均不能证明当前提交已经通过功能验收；功能、race、网络和
互操作验证应在 GitHub Actions 对应提交运行，并记录实际 SHA、运行链接及结果。

2026-10-21 历史运行时候选 `e5e98291ba59c55b514b54793c6d46edcc461be4` 的 Actions
`39538582760` 已通过 Go/source guards、runtime stability、严格 quick/full、
七项故障、Core C2、镜像冒烟及完整 Machine。取消回归包含实际阻塞 Core/Provider、
Machine owner 请求、升级后 WS ready 等待和父 context 活跃时的 Service 自身租约退出。
完整 Machine 的原 10 秒 join、旧 token 拒绝、新 token 恢复与六批次 SQL 唯一 settled
行核对通过，artifact `12318529666`。持续负载 1808.52358869 秒、37 次循环、四档
会话达标且错误全零。正式 A/B 仅 119/120 measured：候选 60/60、旧基线 59/60，
11 项比较达标，旧基线 events/download 一份账量不完整，最终 S3 仍为 false。

历史运行时候选 `7c9cd91e8ca4b0bb9ecfa571872c83d384480bee` 的 Actions
`39535513954` 已通过 Go/race、runtime stability、严格 quick/full 和七项故障。
其同 SHA 的 Actions `39534639986` 已通过完整真实 Machine、Core C2 与镜像冒烟。
后续完整运行 `39535513954` 的 Machine 在 token 轮换后的 10 秒终止等待失败；
该失败与前一轮通过一并记录，不能将 Machine 认定为稳定通过。
本表中的包级及 Service 测试已纳入历史 `e5e98291` 及最终 `94d49420` 的完整 Go/race；
它们各自的断言边界继续有效，历史 `7c9cd91e` 不接受后加的取消测试。
正式 S3、合并与注册表发布分别记录在 `OUTSTANDING-WORK.zh.md` 和
`RELEASE-BLOCKERS.zh.md`，不能由测试源码或单一 job 的通过推导。

历史候选 `235ea2f` 的 Actions `39499950483` 曾通过功能和持续负载，但正式 A/B
与完整 Machine 未通过，已随 PR #3 合并。该历史结果不作为当前候选的验收证据。

## 已有测试源码与断言边界

| 范围 | 测试入口 | 已编写的断言 | 不能据此推出 |
|---|---|---|---|
| Service 的 usage_v2 生命周期 | `internal/service/native_usage_linux_test.go` 的 `TestNativeBillingRefreshResetAndEmptyRevocationPreserveOriginalSessions`、`TestNativeBillingRotationAndShutdownSealPriorCredentialEvidence`、`TestNativeCutoffClosesAffectedAdmissionAndHigherRevisionRecoversWithoutReposting` | 刷新、轮换、撤销、关闭和 cutoff 保留原授权会话证据 | 该文件使用 `nativeBillingKernel` / `stubNativeMeter`；不是完整真实内核 I/O 链路 |
| 原生启动回执门禁 | `internal/service/native_startup_recovery_linux_test.go` | 真实 kernel 在固定旧 Session/Submission 得到匹配 persisted receipt 后才监听；跨页、lost ACK 不重发、未封口完成意图、cutoff、取消/超时、错误回执及 257 条 pending 拒绝；有效已 ACK 历史不占网络预算 | 当前候选 Go/race 已通过；回执不等于结算。spool 完整枚举仍不具备绝对磁盘时间/内存上限 |
| 原租约 WS 端口更新 | `internal/service/native_config_reload_linux_test.go` | 真实认证 WS 帧及 bounded VLESS；REST 503 下无拉取地变更端口，保留 collector/meter/session/digest/deadline、兄弟流；绑定失败保留旧监听、过期/撤权拒绝、旧 full poll 不回滚 | 当前候选 Go/race 已通过；只覆盖端口变化，不证明所有承载续期连续或完整 Machine 稳定通过 |
| 普通授权续期的 Service owner | `internal/service/native_usage_renewal_linux_test.go` | 真实 bounded VLESS 与 VMess AES128GCM/TCP 同流三次续期、稳定 hook/四个原 grant 唯一批次、非重叠区间和每 grant 双向精确字节；当前 cutoff 不恢复 paused owner；unsupported 保持原重建；凭据/权限/period/terms/revocation/Provider 身份及缩短租约不进入保活续期 | 当前候选 Go/race 已通过；VMess 使用同仓库 outbound 客户端，不代替第三方互通；不是 TLS/REALITY/全部协议或完整 Machine 连续性证明 |
| VMess 客户端与反向互通 | `internal/dataplane/outbound/vmess_test.go`、`internal/kernel/txnode/interop_test.go` 的 `TestInteropXrayVMessNativeOutbound` | 本仓库 TCP 两端四种 cipher 及三种 framing；固定 Xray inbound 的 AES-GCM/ChaCha20/none，同流多次及跨帧请求 | 当前候选 Go/race 和严格 full 已通过；同仓 framing 的额外组合不能推导为固定 Xray 兼容能力 |
| 独立 VMess wire 与并发 | 两包 `vmess_length_test.go` | AES/ChaCha 的 wire100 与 raw AEAD plaintext BE16(84) 独立对应，短块/非法 wire 拒绝；共享 Proxy 16 并发真实 TCP | 当前候选 Go/race、严格矩阵及续期回归通过；同仓库 none/padded、zero 不等于固定 Xray 能力 |
| 事件 consumer 唤醒 | `internal/usagebucket/consumer_wakeup_test.go` | 无 worker/store、持 coordinator 锁时封桶仍返回；空闲或已有通知均保留原字节及未 ACK 状态 | 消除封桶后等待定时扫描，不增加容量或忽略 CAPACITY_REACHED；不是所有旧 A/B 失败的因果证明 |
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
| Mieru 官方目标失败恢复 | `internal/kernel/txnode/interop_compat_linux_test.go` 的 `TestInteropMieruOfficialDialFailure` | TCP/UDP 承载分别验证真实 core 拨号拒绝、完整 REP=05 与新目标恢复；严格清单要求两个子项 | 不能把单一顶层 PASS 当作两个承载均已执行；这条用例不单独证明失败路径的持久化结算或资源总预算 |
| Machine mailbox 配置表示 | `internal/controlplane/mailbox_test.go`、`internal/service/native_config_reload_linux_test.go` | nil/空/非空配置在 Seed、Apply/Drain 后保留 JSON 表示；真实 Machine mailbox 交付端口更新，保持原签名 collector、兄弟流和 REST 阻断 | 当前候选 Go/race 已通过；未放宽仅端口变化的配置等价条件 |
| relay 取消与 HTTP 生命周期 | `internal/dataplane/core/pipe_lifecycle_test.go`、严格 Naive h2 互通 | channel 控制 deadline watcher，copyPipe 返回前等待取消清理，禁止 handler 退役后的 deadline/close；第三方完整 Naive 链 | 当前候选 Go/race 和严格 full 已通过；不推导所有 net.Conn 实现的 deadline 都有有界耗时 |
| 日志 canonical envelope | `internal/usagebucket/store_envelope_test.go` | BUCKET、全部控制类型、null 和转义字符的 envelope 与原 json.Marshal 逐字节相同，输入不变且 canonical decoder/digest 通过 | 当前候选 Go/race 已通过；编码优化不证明固定容量下全部事件性能样本无损 |
| native 请求取消与 worker join | `internal/txboard/request_context_test.go`、`socket_test.go`、`internal/machine/context_test.go`、`internal/service/authorization_cancellation_linux_test.go` | 阻塞 Core/Provider 实际请求服从父 context、Service 自身租约终止取消刷新后 join、Machine 五种 owner 请求取消、升级后 WS ready 等待取消；原完成拒绝类型保留 | `e5e98291` Go/source guards 和完整 Machine 已通过；不能解释全部旧超时或证明磁盘同步可取消 |
| Machine child 失败后的权威重查 | `internal/machine/child_failure_test.go`、完整 `TestNativeCoreMachineLive` | 真实 native HTTP 在有界通知后执行新的 discovery；严格 401 才停止 Machine，503 与成功重查保留 owner 和节点退避；重复通知仅占一个槽 | `94d49420` 完整 Go/race 与 Machine 通过；generic child 错误本身没有撤权权威，不保证所有网络/磁盘等待耗时 |
| Machine 恢复失败现场 | 同一 Machine live 入口及 `recovery_diagnostic.py` / `test_preflight.py` | 原恢复窗口失败时输出固定 schema/阶段、布尔状态、类别与有界 wait-chain；精确字段、类型、标签及关系的负例拒绝 | 诊断候选一次通过不证明旧超时已修复；discovery 观测包含阶段内实际完成的请求，不证明每个完成请求均在重新启用后发起 |
| 固定 Core machine 契约 | `internal/machine/native_core_machine_live_test.go`、`scripts/tests/node-native-machine/`，CI `core-machine` | 真实 Provider mTLS、native 安装/激活、账户/购买/履约、生产 Orchestrator、双 Node、共享 WS/503/后继心跳、设备事实、隔离、轮换与原使用量重放 | Node `e5e98291` 与 Core `5536410` 已在 Actions `39538582760` 完整通过，详见 `CORE-MACHINE-COMPATIBILITY.zh.md`；不证明独立完整财务对账、生产 PKI 或物理主机部署 |

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
| `docs/removed-tests/usage_event_store_adapter_test.go.txt` | 原生 Service 测试覆盖真实 TCP/UDP、关闭、持久化恢复、失败隔离和进程归属，已进入 `e5e98291` Go/race；只接受现行明确断言 |
| `docs/removed-tests/usage_observer_adapter_test.go.txt` | 原生 Service 测试已编写真实 I/O、身份、关闭、错误隔离、禁用和恢复断言；用户 delta/Reload 失败的细分边界仍由各自生命周期测试承担 |
| `docs/removed-tests/store_io_test.go.txt` | 原生 core relay 测试覆盖短写/正字节伴错/失败写和取消；使用当前物理方向口径，不恢复旧 wrapper |
| `docs/removed-tests/traffic_period_packet_test.go.txt` | 真实 SOCKS UDP 周期切换、原周期尾部和精确分段断言已进入 `e5e98291` Go/race；不外推其他协议的周期行为 |
| `docs/removed-tests/native_core_machine_live_test.go.txt` | 现行独立入口已在 Node `e5e98291` / Core `5536410` 的真实 Machine gate 通过；仅覆盖现行明确断言，不恢复旧内核 wrapper，也不推导独立完整财务对账 |

恢复时应逐项写出实际 owner 调用链和精确断言，再将替代测试纳入 Actions。只把旧文件
改成可编译、改用 mock，或引用现有单层测试，都不足以关闭这些缺口。
当前候选实际结果以开头记录的 SHA 和各 job 为准；不按文件数量宣告旧套件全部恢复。
