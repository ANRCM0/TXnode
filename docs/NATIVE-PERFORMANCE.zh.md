# 原生持续负载与新旧性能证据

日期：2026-10-21（Asia/Shanghai）。本文区分工具约定与具体 Actions 结果；源码实现
本身不构成功能或生产验收。

## 入口与证据绑定

工作流 `Native stability and performance evidence`（`.github/workflows/native-acceptance.yml`）支持手动选择候选 ref、每日调度及主 CI 调用。第一项 job 将 ref 解析为不可变完整 SHA；后续 job 均 checkout 该 SHA，并保留提交、源码树、Go 版本、runner 与客户端摘要。工作流本身不发布镜像或修改 Core pin。

所有功能、网络与负载执行仍限于 GitHub Actions。本地仅允许源码检查、Go 静态编译、格式和 AST 检查。缺少客户端、工具编译失败、实际负载不达标与证据不完整均不能记为通过。

## 已完成运行的结果

历史 Node `7c9cd91e8ca4b0bb9ecfa571872c83d384480bee` 的完整 Actions
`39535513954` 采集了 120/120 measured 正式样本，12 项比较中 11 项满足原阈值。
唯一超限为 ordinary/long CPU 比率 `1.0518343526007607 > 1.05`；吞吐比率
`1.0010625490445981`，该比较 CV `0.02694765224992716`。全部 12 项 CV 均低于
0.10，不能将这次超限改称 CV 噪声不足；报告 `accepted=false`。

其 240 个原始 CPU snapshot 与报告匹配，全部 120 个 CPU window 通过原 validator。
正式 events 的 40 个停止快照均无 drop/FirstGap，10 个 events/download 全部完成。
该正式 runner 为 EPYC 7763，不能用这一成功反推另一个 EPYC 9V45 runner 上独立
持久化诊断的容量问题已修复。30 分钟 soak 实际 1810.692 秒、39 次生命周期循环，
四档达到 100/250/500/1000 会话，错误为零；七项故障也通过。S3 ledger 因正式 A/B
超限仍为 false，原始性能/soak/S3 artifacts 为 `12318462976`、`12318463276`、
`12317904915`。

新取消传播候选 `e5e98291` 的 Actions `39538582760` 已完成，正式 A/B 为
119/120 measured：候选 60/60、旧基线 59/60。11 项完整比较均满足原阈值，
ordinary/long CPU `1.0262880019644047`、CV `0.02976481682981216`；最大完整
CV 为 `0.05961259572251982`。events/download 的旧基线只有 4/5 measured，
这项比较保持 incomplete，不报告有效比率。

唯一失败样本 g1 legacy/events/download 在原 meter 容量上产生 FirstGap
sequence 66433、约 4.689335697 秒，最终 drop 109274；store healthy，511 buckets、
约 45.49 MB，没有触及文件或字节上限。正式运行未启用持久化 observer，不能
用独立诊断的阶段 trace 为它作具体因果归属。全部 240 份原始 CPU snapshot
与报告匹配，119 份 measured 均通过原 validator；失败样本 CPU 数值自洽也不能
绕过账量失败，因此 ledger 的 `process_cpu_windows=false`。

同候选持续负载为 1808.52358869 秒、37 次循环，四档峰值达标且错误全零；
七项故障均通过。正式性能、soak 和 S3 artifacts 分别为 `12319073827`、
`12320055119`、`12319572656`。S3 的 `PERFORMANCE`、`equivalent_ab`、
`process_cpu_windows` 为 false，`allocation_windows` 和 `image_sizes` 为 true，
`full_S3_accepted=false`。旧基线失败不因候选 60/60 完成而删除，原基线、容量、
同步步骤、ACK、参数和阈值均保留。

独立 CPU profile 的 artifact `12318630962` 保留旧基线
events/download 容量失败，其余三个诊断 case 完成；诊断失败不计入正式样本，
也不被正式样本的结果删除。

## 持续负载 suite

`internal/kernel/txnode/native_soak_linux_test.go` 的 `TestNativeSessionSoak` 只有在 `TXNODE_NATIVE_SOAK=1`、`GITHUB_ACTIONS=true` 且提供固定 sing-box 客户端及输出目录时执行。普通测试发现中的 Skip 不构成负载验收；专用 job 要求最终汇总文件存在、完成四档且持续至少 1800 秒。

负载按 100、250、500、1000 个工作会话逐档运行，每档 450 秒。每三名 worker 分别执行：

- 直接协议客户端 → 使用固定根证书校验的原生 TLS VLESS TCP → TCP echo，保持长连接。
- sing-box → 原生 Shadowsocks AES-128-GCM UDP → UDP echo，保持 SOCKS UDP 控制与数据关联。
- sing-box smux → 原生 VLESS mux 子流 → TCP echo，保持父连接复用。

每个业务请求发送并校验 1024 字节，成功后等待 20ms。每档必须真正达到目标同时活跃会话数，三类完成量均达到固定下限，每名 worker 至少完成 100 次；任何新代流量错误、内容不一致或容量不足均失败。工具不将预期 worker 数当成已完成会话数。

每 45 秒，承载 TCP worker 的同一个原生 TLS Node 执行新增用户、连接握手与尾部回显、凭据轮换、撤权关闭、删除重加、无效证书失败保留、同端口交替换证 Reload 和无效协议替换失败后的原监听保留。负载使用同时信任两份预先固定自签根的客户端，不关闭证书校验；每轮独立校验服务器证书摘要。旧代流仅允许明确的 EOF/连接关闭类错误，超时和新代错误不能归为预期故障；每名 TCP worker 都必须在当前新代成功转发后才完成本轮。每档至少八轮，实际旧代断开数必须精确等于本档轮数乘 TCP worker 数。UDP 和 mux Node 在这些变更中继续承载流量，用于核对实例隔离。

每 5 秒保存 `soak-samples.jsonl`：实际活跃数、内核连接数、完成/失败数量、业务字节、延迟分桶、goroutine、FD、heap、heap objects 与 RSS。p50/p95/p99 为固定 2 的幂次毫秒桶的上界估计，最后桶为溢出桶，不用于精确延迟结论。持续负载包含测试进程的 origin 和客户端驱动；资源数字不是独立 Node 进程的净占用。

关闭监听和外部客户端、等待 UDP 空闲回收、两次 GC 后，使用首次执行前固定的预算：较预热基线最多增加 96 个 goroutine、32 个 FD、128 MiB 活 heap、100000 个存活对象。Go 1.26 的 net splice 池通过异步 runtime.AddCleanup 关闭 pipe FD，因此第二次 GC 后仅再等待最多五秒的清理调度，数值预算不变。客户端日志直接写入 artifact 文件并使用 warn 级别，不在 Go 进程内累积 bytes.Buffer；客户端必须在最终采样前执行 Kill、Wait 和日志关闭。保留 baseline/final FD 类型和 symlink 明细、heap/goroutine pprof、原生 runtime diagnostics，资源失败继续判失败；不得为通过预算清空受保护的协议重放历史。它是本夹具的初始回归预算，不是生产容量承诺；禁止在看到失败后就地放宽。

`soak-summary.json` 中 `accepted` 只描述上述负载 profile，不能单独代表完整 S3。

首轮资源失败后，SS 重放缓存的候选实现将常见盐改为包含原长度的固定精确键和单调
到期时间，长盐继续使用完整字符串；共享缓存只保留一个惰性清理 timer，空表释放。
完整 94 秒窗口和跨 handler 历史不变，Stop 不清空受保护记录。该存储变化的资源收益
仍必须在包含它的提交上按原预算测量，不能沿用较早候选的业务成功或静态编译结果。

工作流的 `faults` job 对同一不可变候选执行以下真实流量故障，使用 Go race detector，并要求七个顶层用例全部执行、无 skip、无 fail。证据另存为 `native-faults-<SHA>`，不把短时故障夹具计入 1800 秒持续负载窗口：

- 同一原生 TLS VLESS Node 的 32 条活跃流量持续经历用户轮换、删除重加、无效证书失败保留、同端口换证 Reload；所有 32 条旧代连接必须实际结束并在新代恢复。
- 原生 SOCKS 会话真实进入限速等待后撤权，要求等待取消并关闭连接；另一个经过真实鉴权的会话在客户端写出端注入 7 字节短写，要求实际交付字节与原生及兼容计量尾部均为 7。
- 同一个原生 VLESS Node 的 32 条正常长流持续转发时，另一条流的真实上游只返回 3 字节后断开；要求仅该流结束，保留实际 8 字节上传/3 字节下载尾部且正常流继续完成业务。
- 同一个 Service 的 16 条流量观察独立签名 lease 自动续租，再将真实报告队列的准备锁阻塞并使授权服务离线；有限 lease 到期必须关闭准入和旧流，恢复后先回放原批次再开放新签名代流量。
- 子进程中的真实 Node 和 NativeStore 承载 8 条流量，父进程等待实际双向 durable evidence 握手后发出 SIGKILL；恢复必须保留原授权期和批次摘要、隔离未完成 I/O、拒绝旧签名代，并在新授权期恢复实际流量。
- 真实 Node 的 4 条流量连接异步事件 coordinator，在已有私有 fsync hook 挂起磁盘同步后仍须转发；读取实际未落盘事件/密封桶/进行中写入队列，要求没有丢弃且不超原有固定容量。超时 Close 不得交出独占锁，恢复后保留双向原始证据及 unknown tail。故障 hook 和队列快照仅由 `_test.go` 导出，不进入生产二进制。

这些夹具分别证明限定的组合故障，不能证明 1000 并发时全部故障、持续窗口内故障覆盖或生产容量。最终完整 S3 还需要同 SHA 的持续负载、故障和等价 A/B 证据共同满足验收范围，不能凭单个 job 的通过推导。

## 同 runner A/B 工具

`scripts/native-acceptance.py` 在一个 Linux runner/job 中为以下版本创建临时隔离 checkout：

- 旧基线：`a1ad2695e1143269168c36a274283de3342e91c7`，选择 sing-box 服务端。
- 候选：工作流解析后的完整 SHA，选择唯一原生 txnode 服务端。

两份源码均以固定 Go `1.26.0`、`GOTOOLCHAIN=local`、`CGO_ENABLED=0`、同一组 `-trimpath -ldflags=-s -w` 及既有 release build tags 编译。各 checkout 注入本候选版本携带的相同测量 server、只读 bucket 诊断 helper 和各自的 factory 适配；不修改原数据面或模块依赖。报告记录工具、模板、业务二进制和测量二进制摘要，避免将注入的测量入口冒充历史仓库的原生功能。每侧构建前最多三次模块预取，失败间隔五秒，保留完整日志及逐次退出码；耗尽仍为 incomplete，且预取改变任一已提交模块锁即失败。

固定 SOCKS5/RFC1929、IPv4 回环、无 TLS、相同目标服务与 buffer。两侧都安装相同的结构化 `127.0.0.1/32 → direct` 路由，避免旧基线的默认私网封锁改变被测路径。每种模式分别执行上传、下载、短连接、长连接；每个样本 2 秒预热、10 秒计量、4 个客户端线程。至少 5 组采样，组内按旧→新、新→旧交替。每次使用新进程和全新的状态目录，预热计量与正式计量使用同一个配置。事件存储仅在 benchmark 显式设为 1 GiB；生产默认 64 MiB 和其他队列上限不变，容量耗尽仍然失败。usage_v2 使用合法的 91 秒授权窗口，预热加采样不得超过 60 秒；不绕过 NativeWindow 的 120 秒上限。

三种模式：

| 模式 | 实际配置及可比范围 |
| --- | --- |
| ordinary | 两侧普通内核转发；报告仅比较相同 SOCKS 明文路径 |
| usage_v2 | 两侧安装 `NativeStore` / `NativeCollector`、相同授权身份和窗口，启用 enforcing；停止后要求真实持久化记录，并核对原始上传/下载字节等于预热加正式采样的实际协议业务 I/O |
| events | 两侧安装异步本地事件 coordinator；每个样本均要求 durable physical upload/download 总量精确等于预热及正式采样的实际协议业务 I/O，全部记录保持原 user 7、unattributable、unknown tail、nonbilling、无降级或丢弃；只有共同的 `physical-byte-observation-v1` 投影全部通过才输出该限定范围比率 |

`usage_v2` 的真实持久化开销和容量限制属于被测语义；遇到 collector 拒绝、持久化失败、超时或计量不一致即记录未完成，不能自动退化到无计量转发。测试不模拟 Core 回执、正式结算或多轮授权续租。

每份样本保留应用有效字节吞吐、实际完成量、客户端观测的 p50/p95/p99、独立 Node 测量进程 CPU 秒/GiB 与 50ms 采样峰值 RSS。预热结束和正式采样结束时，harness 通过 SIGUSR1 请求被测进程原子写出 `runtime.MemStats` 快照，用 TotalAlloc / Mallocs 差值报告每业务字节分配量和分配次数；快照操作位于 CPU 计量窗口外。CPU 不包括外部 Python 客户端和目标服务，但吞吐仍可能受它们制约。延迟使用每线程有界确定性样本，不作为无损全量直方图。

CPU 方法版本为 `process-cputime-ns-v1`，报告 schema 为 `txnode-native-performance/v2`。
两侧注入同一个临时 harness，通过独立 SIGUSR2 分支读取 Linux
`CLOCK_PROCESS_CPUTIME_ID`，覆盖该 Node 进程全部线程的 CPU，不采用线程 CPU 时钟。
顺序为预热、MemStats 起点、CPU 起点、原 10 秒业务采样、CPU 终点、MemStats 终点。
每次 CPU 读取前后分别采 `CLOCK_MONOTONIC`，并保留 `clock_getres` 返回的正分辨率、
原始 CPU 纳秒值、PID、严格 1/2 序号、每进程随机 nonce 与原子快照文件。
控制器记录请求和收到文件的单调时间及往返时长，核对读取落在请求/确认之间、
两次分辨率一致、CPU 差值为正，且整个业务采样位于两个 CPU 观察之间。
不支持、超时、身份/顺序错误或任何无效证据均为 incomplete，不退回旧时钟。

`/proc/<pid>/stat` 的 utime/stime 与 CLK_TCK 继续作为次要诊断，窗口包含快照请求与
确认的边缘时间，不用于 v2 的比率或验收。纳秒数值和内核宣告的分辨率不等于实际测量
精度；信号调度、起点快照写入和进程后台工作仍可进入 CPU 窗口，往返诊断不将这些
开销扣除，也不引入新的 CPU 上限或低负载豁免。五组、2 秒预热、10 秒计量、4 线程、
全部 120 个样本及原 5%/10% 预算不变。旧 v1 的 a8 普通上传 1.10 与 71 事件长连接
1.05263 越界继续保留，不与 v2 样本合并或用新结果抹除。v2 仍须独立通过完整验收。
时钟定义参照 Linux man-pages `clock_gettime(2)` 与 `proc_pid_stat(5)`；本工具不以
纳秒接口宣称消除调度噪声。

分配窗口仍由两次 MemStats 观察界定，因此包含 CPU 快照的编码与写入等少量工具分配。
两侧使用完全相同的工具，报告不扣除这些开销，也不将结果表述为数据面自身的净分配量。

构建结果保留两侧相同参数的业务二进制体积。镜像测量先解析同一 Alpine 3.20 的不可变 RepoDigest，使用同一 runtime Dockerfile、ca-certificates/tzdata 与入口包装已构建的两份业务二进制；真实执行 docker build 和 inspect，保留 recipe、build.log、image ID 与未压缩 Size。此项比较相同 runtime 封装，不能代替两版历史 Dockerfile、注册表压缩传输体积或发布镜像验收。旧 Xray 服务端、其他协议、跨地域实网、TLS 与正式 Core 结算未纳入 A/B 工具。事件内部路径、时间戳和事件数量允许不同并原样记录，物理字节投影通过不证明这些内部边界完全相同。不能用本回环结果推广整个双内核版本或生产场景。

## 独立持久化诊断

`.github/workflows/native-persistence-diagnostics.yml` 和主 CI 的
`persistence_diagnostics=true` 入口执行单独的 `--persistence-diagnostics-only`。
固定五组、2 秒预热、10 秒计量、4 线程，只测 events/download；旧/新两侧分别交替
observer OFF/ON，均不启用 CPU profiler。正式 A/B 仍清除继承的诊断环境变量，
其 120 份样本、比较阈值及持久化边界不变。

诊断的 `persistence_samples`、`observer_pairs` 与正式 `samples`、`comparisons` 分开。
`collection_complete` 仅代表证据采集完成；`accepted` 始终为 false，不写入正式 S3
通过结果。只有一对 OFF/ON 都完成无损字节核对时才提供限定范围的比率；失败后的
原始流量仍保留，不能作为成功事件计量的性能或 observer 开销比率。

启用 observer 时只保留固定阶段统计、最大值关联的 bucket/sequence 和 64 点环。
环在首次观察到 FirstGap 时冻结；没有新增周期 goroutine 或逐事件 I/O。阶段 wall 时间
包含调度及 observer 开销，不是独立 syscall/disk 延迟；meter 与 observer 的时钟起点不同，
不能直接相减。worker_gap 从一次 ACK 后开始，不能覆盖最初建库和首次 claim 的等待。

精确 Node `7c9cd91e` 的 Actions `39534639986`、artifact `12316907973` 已采集
20 份诊断，但全部账量不完整，10 对均无可比较比率。OFF/ON 都复现失败，说明
CPU profiler 和启用 observer 不是失败的必要条件，不能据此计算 observer 性能影响。
19 份为 meter `CAPACITY_REACHED` 且 store healthy；另一份候选 OFF 触发原有文件数
上限：4078 个现存文件加本次 4 文件保留量超过 `4096 - 16 = 4080`，当时约
372.6 MB，未达 1 GiB 字节上限。

候选 ON 的四组首次观察缺口与同一 claim 的 head_publish wall 峰值
52.703/20.591/18.442/23.567 ms 重合，另一组与 record_file_sync_wall 14.530 ms
重合。它们定位观察窗口，不能区分 rename、fsync、调度、GC 或编码的因果贡献。
旧侧有三组在第一次 bucket ACK 前填满 1152 个事件容量；初始 worker 等待未被
after-ACK worker_gap 覆盖，也不能据较小的已采集阶段峰值排除启动/调度停顿。
本轮没有为诊断而扩大队列/文件上限、合并同步步骤或提前 ACK。

## 判定与保留物

固定初始调查阈值为候选吞吐不低于旧基线的 95%，CPU/GiB 不高于 105%。5 组中任一侧吞吐或 CPU 的变异系数超过 10% 则为未决；时钟分辨率不足、缺少样本或模式失败则为未完成。越过阈值要求复现和说明，不自动断言根因。

`report.json` / `report.md` 保留每一份原始样本、失败原因、来源、构建参数和比较范围；每份样本的目录还保留 `server.log`、`sample.json`、持久化状态与 `evidence.json`。events 在 Node Stop 后和 coordinator Close 返回后各写一份有界诊断，保留原 meter 的 Reason/FirstGap 及 coordinator/store 状态；Close 失败仍保留原错误并使样本失败。两个快照分别加锁，不代表原子状态，也不进入吞吐或 CPU 采样窗口。工作流保留所有失败产物。任意模式缺样本、语义投影不完整、噪声或阈值越界均使性能 job 失败；events 没有成功豁免。

正式五组结束后，两侧各另跑相同参数的 ordinary/download 和 events/download CPU profile 诊断，共四份。harness 只在设置 `TXNODE_NATIVE_AB_CPU_PROFILE` 时启用 Go CPU profiler，覆盖该独立进程的启动、预热、测量与正常关闭。`diagnostic-*` 目录保留 `cpu.pprof`、`cpu-top.txt`、二进制及 profile SHA、样本状态和 `metadata.json`；这些样本单列于 `diagnostics`，不进入正式 120 份样本、比率或 accepted 计数。events 诊断仍执行同一物理字节投影核对，不退化为 ordinary。正式 usage_v2/short 存在失败时，另对两侧各做一次固定诊断，保留失败阶段、错误类型和服务端退出状态；独立诊断成功不消除原失败。

同一工作流另有独立 `performance-diagnostics` job，使用 `--diagnostics-only` 提前构建两侧并收集上述四份下载 profile，输出单独 artifact，无需等待 24 分钟正式采样。该模式跳过镜像和正式矩阵，`accepted` 始终为 false，退出码要求 ordinary/events 与 legacy/candidate 的四种组合恰好覆盖且全部诊断完整，不参与 S3 验收。CPU top 同时写入 job log。

调查记录：`f1451d5` 的五组正式样本完整，但普通下载 CPU/GiB 比率约为 1.1462。
`6f8ae3c` 的独立下载 profile 总 CPU 为原生 6.85 秒、旧侧 5.95 秒；原生
`spliceOne` 累计 5.15 秒，其中重复 `os.File.Fd` / `SetBlocking` 约 0.45 秒。
Linux splice 实现将管道描述符保留到本次 relay 结束，避免在每段 I/O 中重复取描述符；
内部管道使用带 CLOEXEC/NONBLOCK 的原始 Pipe2 描述符，不注册 Go 文件 poller；
等待仍由两端 socket 的 RawConn 负责。真实 TCP 回归检查双向字节、上传 FIN 后下载、
取消终止及返回后没有新增 pipe 遗留。
TCP 两方向的计数闭包按会话创建一次，逐段仍调用原 Tracker/OnTraffic 计数。
`RawConn` 的等待、EAGAIN、取消和半关闭边界继续保持。
兼容计数在每次真实 drain 写出之后更新，部分成功后再遇关闭、取消或 syscall 错误时
仍保留已写字节；零写按本次返回量判定无进展。syscall callback 按方向复用。

纯本地事件观察通过 `SpliceChunkHook` 显式允许无有效限速、透明 bare TCP 的
splice。上传在 socket-to-pipe 前执行原 `Begin(copyBuf)`，按实际读量和错误完成；
下载在首次 pipe-to-client 写前 `Begin(n)`，整个 drain 按实际写出总量完成一次。
所有 hook 和流量计数均在 RawConn 回调外执行，原 token、会话、方向、EOF、取消及
错误边界保留，单向拒绝或失败须终止另一个方向。正常 EOF 保留半关闭并确认取消
watcher 退出后再释放子 context。带 `NativeCollector` 的 `usage_v2` 不允许此优化，
继续使用原用户态复制和强制准入路径；TLS、缓冲包装、有效限速及未显式允许的 hook
也继续使用原复制路径。事件分块和数量可能不同，仍须通过原物理字节和 owner 断言。

原 `usage_v2` 失败样本中的部分完成记录符合时钟顺序拒绝，不能单凭聚合 journal
确定具体根因。源码中 `CompleteIO` 在 collector 锁外采样、`BeginIO` 在锁内采样；
双时钟观察可与并发操作交错。完成采样现与 Begin/Complete 共用 collector 锁，
不修改原 wall 回退、单调 deadline、grant、退休或原 token 拒绝条件。锁后观察是
完成上界，等待锁时越过租约的字节仍保留为不 eligible；不会因此延长授权。
私有时钟注入只用于确定性测试，不改变公开调用、持久化格式或既有保护历史。
profile 支持定位开销，不证明修复后的性能结果，新候选仍按
上述五组、原 5% 阈值和原资源预算执行。

性能报告的 `accepted` 只描述上述 A/B 范围。最终 `acceptance` job 下载同一 SHA 的三个 job 产物，核对持续时间、四档实际承载 Node 代际恢复和精确旧流断开数、七项故障无 skip、12 组比较全部满足固定阈值、至少 120 份分配窗口及两侧实际镜像体积；所有证据和 job 都成功时，`s3-acceptance.json` 的 `full_S3_accepted` 才由计算结果变为 true。缺失、失败、噪声或阈值越界均为 false，并保留具体 checks。这一结果严格限定为本文固定的 Actions 回环验收范围；PR 合并、合并后 main、发布镜像、Core 采用、物理多机及受控试运行必须分别记账。
