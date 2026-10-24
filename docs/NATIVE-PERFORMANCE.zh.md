# 原生持续负载与新旧性能证据

日期：2026-10-25（Asia/Shanghai）。本文区分工具约定与具体 Actions 结果；源码实现
本身不构成功能或生产验收。

## 入口与证据绑定

工作流 `Native stability and performance evidence`（`.github/workflows/native-acceptance.yml`）支持手动选择候选 ref、每日调度及主 CI 调用。第一项 job 将 ref 解析为不可变完整 SHA；后续 job 均 checkout 该 SHA，并保留提交、源码树、Go 版本、runner 与客户端摘要。工作流本身不发布镜像或修改 Core pin。

所有功能、网络与负载执行仍限于 GitHub Actions。本地仅允许源码检查、Go 静态编译、格式和 AST 检查。缺少客户端、工具编译失败、实际负载不达标与证据不完整均不能记为通过。

## 2026-10-25 事前延迟预算补项

对照 `NEXT-DEVELOPMENT.zh.md` 的完整要求，现行 S3 v2 的十三项检查虽然已有
完整通过，但 p50/p95/p99 仅记录，尚不能证明事前固定的延迟预算已验收。I/O
timeout 不是百分位预算，不将原 `613d6a36` 的 120 份结果倒填成延迟通过。

新增显式 `latency_profile=percentiles-5pct-v1`：沿用初始 5% 调查口径，对每个
mode/workload 的 p50/p95/p99 分别比较五组中位数，候选/旧侧上限 1.05；任一侧
该百分位的 population CV 超过 0.10 则未决。缺失、重复、失败、非法数值/顺序、
不一致工具或基线均拒绝。它采用原每 worker 最多 20000 条有界确定性观测，不
声称是无损全量直方图或生产 SLO。policy 的 canonical SHA-256 固定为
`3cb81c29e2e169abeb750869a076313a245175fd7b0e3186184bc94b5dc55e96`。

完整调用链为 workflow `source` 生成 `latency-plan.json`，绑定精确 candidate/
tree、baseline、run ID、workflow/tool revision、测量及预算工具摘要和上述固定
policy；后续 performance job 下载本次 plan，并在原构建/负载命令之前验证及
复制。工具和 candidate 必须是同一 workflow 提交，且工具文件逐字匹配其已提交
内容，不能用新预算接受旧运行。采样后 `native_latency.py` 只读取原 report，
输出十二组/三十六项比较；即使原测量失败也保留独立拒绝 JSON。

选择该 profile 的 S3 v3 另重算并核对原始 plan、复制件及 latency archive，
增加 `latency_evidence`、`latency_windows`、`latency_comparisons`。原 CPU、
吞吐、噪声、资源、容量、同步、ACK、负载及所有 v2 检查保留。新 profile 的
延迟 artifact 和最终 ledger 明确单列，任何失败或未决均不能得到完整通过。
`observations-only` 继续产生原 v2 形状，保留旧报告/失败及既有通过的原范围。

本补项目前只有源码、AST/YAML 和边界检查，新增单元与新 profile 的完整
Actions 尚待执行；不把实现或原 v2 通过宣布为整个 S0-S4 目标完成。

## 2026-10-25 候选 record 准备路径

候选 `613d6a36357d0a4888fe9be3ac7faec29a948861`，tree
`3d8e8459f829f2eef8cb12f2738440862206f5d0`，只在 writer 中复用完整收据校验
已生成的 canonical bucket 字节，避免 enclosing record 再遍历一次事件。原
reader/recovery 校验、record schema/摘要、容量、持久化顺序及 private ACK 保留。
完整 owner 调用链及兼容入口见 `OUTSTANDING-WORK.zh.md` 本日期记录。

独立诊断 `40113618442`（工具 `6f6169a9cd6374bf1fc51731b35b7ddcccae2390`，
artifact `12567223820`）使用 Go 1.26.0，三项根回归/race 与 39 子用例通过，无
skip/fail。五组交替 benchmark 固定 300ms，两种算法均在同一候选内运行；二十
份原始结果、源码/模块锁/工具摘要、测试事件和统计重算均匹配。

| record | 原路径中位 ns/op | 复用中位 ns/op | 复用/原路径 | 原/复用 B/op | 原/复用 allocs/op |
|---|---:|---:|---:|---:|---:|
| 1 event | 8253 | 7990 | 0.9681 | 4259 / 5668 | 10 / 11 |
| 128 events | 324845 | 209500 | 0.6449 | 183545 / 185983 | 14 / 15 |

最大 population CV 分别为 1.10% / 1.18%。128-event 准备耗时约低 35.5%，代价
为每 record 增加一次分配及约 2.4 KB；小 record 约多 1.4 KB。此处 ns/op 是
操作 wall 耗时，不等于进程 CPU/GiB、磁盘吞吐或端到端性能。它不证明先前容量
失败的唯一原因，也不补计正式 A/B；实验 driver/workflow 不合入 main。

### 精确候选的完整验收

完整功能 `40114164643` 与独立完整 native `40114161320` 均成功。后者在
Go 1.26.0、Linux/amd64、同一个 4 CPU Actions job 内交替测量固定勘误基线
`4904a193` 与候选；五组/2 秒预热/10 秒测量/4 线程及原容量、fsync、ACK、
5%/10% 阈值保持，没有设置 affinity/GOMAXPROCS 或替换文件系统。

| 范围 | 实际结果 | artifact |
|---|---|---|
| 来源与补丁 | 精确候选 SHA/tree、独立勘误补丁和来源匹配 | `12567148242` |
| 旧侧 collector | 七项回归/race 全通过，无 skip/fail | `12567946904` |
| 带负载故障 | 七项全部通过，无 skip/fail | `12567746646` |
| 持续负载 | 1812.103511547 秒、40 次生命周期循环、四档达到 100/250/500/1000 会话，业务错误为零 | `12570115028` |
| 完整 A/B | 120/120 measured，双方各 60；十二项比较全部满足原阈值 | `12568317048` |
| 最终 S3 | 十三项 checks 均为 true，`full_S3_accepted=true` | `12569830105` |
| 独立下载 profile | 四份完整，单列且不计入正式比率 | `12567499009` |

| mode/workload | 吞吐候选/旧侧 | CPU/GiB 候选/旧侧 | 最大 CV |
|---|---:|---:|---:|
| ordinary/upload | 1.000095 | 1.028058 | 0.032261 |
| ordinary/download | 0.998653 | 1.022461 | 0.007081 |
| ordinary/short | 1.017311 | 0.811861 | 0.020144 |
| ordinary/long | 0.999989 | 1.019343 | 0.035438 |
| usage_v2/upload | 0.999548 | 0.977367 | 0.005384 |
| usage_v2/download | 1.009094 | 0.975102 | 0.015195 |
| usage_v2/short | 1.023673 | 0.988126 | 0.020126 |
| usage_v2/long | 1.000393 | 0.971070 | 0.005901 |
| events/upload | 0.999729 | 0.932265 | 0.053651 |
| events/download | 1.001009 | 1.016211 | 0.011962 |
| events/short | 1.007309 | 0.879245 | 0.037864 |
| events/long | 0.999762 | 1.021389 | 0.021917 |

完整下载并核对 120 份 sample、240 份 CPU、240 份 runtime、四份实际二进制、
源码/模板/模块锁及 ZIP 摘要，十二项比较和最终 ledger 重算与归档完全一致。
两侧实际对照镜像体积为 76,512,713 / 53,804,489 bytes，业务二进制摘要与构建
报告匹配；它们是性能 job 的同配方镜像，不是 GHCR 发布证明。正式 events 的
物理字节投影与原 owner 账量尾部均完整，没有使用独立 profile 补正式样本。

soak 的 362 份资源记录和原始 Go JSON 均已核对。GC 后 goroutine 9 -> 5、
FD 20 -> 12、heap 651,992 -> 122,019,112 bytes、存活对象 2244 -> 16631，
均在原固定预算内；四档各十次承载 TLS 生命周期，精确预期旧流断开累计 6190，
恢复代际各为 11，TCP/UDP/mux 错误及饥饿 worker 全零。它只覆盖记录中的 TLS
VLESS TCP、Shadowsocks UDP 与 smux TCP 混合负载，不推广为所有协议的持续运行。

本次通过只属于候选 `613d6a36` 与显式 `legacy-clock-serialized-v1` 的固定
Actions 回环范围。原基线默认不变，其历史 106/120、单 CPU 115/120，以及上一
勘误候选 119/120 的失败继续保留；不同 runner 之间不据此证明编码是容量缺口
的唯一原因或已经保证所有环境零缺口。PR、main、实际 GHCR、Core 采用、正式
标签和物理/生产试运行分别记账，不能由该 S3 通过推导。

## 2026-10-24 独立时钟勘误基线

经用户明确选择，新增 `legacy-clock-serialized-v1`，固定提交
`4904a193d4564cf67af55728da0b338ff3b1268f`，tree
`edfe6051a97952aba014bf874927bca8bc0b550d`。它直接以原 `a1ad269` 为父提交，
唯一源码差异是将 `NativeCollector.CompleteIO` 的 `time.Now()` / `stamp`
采时移到既有 `c.mu` 锁内。所有 eligibility、grant、deadline、退休、容量、
持久化、同步和错误处理条件均原样保留；没有观察钩子或第三方代码升级。

原 `original-a1ad269-v1` 继续为默认选项，历史失败和未决报告保持其原始身份。
`native_baselines.py` 在构建前核对完整 SHA/tree、唯一父提交、唯一变更文件、
逐字节两行移动和补丁摘要。勘误版必须显式选择
`--baseline-profile legacy-clock-serialized-v1`；其 A/B、独立 profile 和 S3 artifact 名增加相同前缀，
JSON 同时记录原提交、实际勘误提交和补丁身份。

工作流 `native-acceptance.yml` 的 `baseline_profile` 输入支持这两个固定选项。
勘误验收另要求该固定旧源码上的七项原生 collector 回归/race 测试成功，并将
候选、旧源码 SHA/tree 绑定到该 job 的产物；原基线的该 job 为跳过，不记作已执行。
S3 汇总拒绝身份缺失、原/勘误交叉或不匹配的 baseline build。五组、2 秒预热、
10 秒测量、4 线程、完整 120 cell、队列、fsync、ACK 和 5%/10% 阈值保持。
本节只声明新入口及源码差异；实际 Actions 结果需要单独记录，不因此宣称通过。

### 勘误 profile 的首轮完整 Actions

运行 `40105537448` 固定候选 `6deacea61c574f0a1fced95d6c65db2c150f0a72`，tree
`3148d1895668e8989148ed7681ab39253da86a57`，显式选择上述固定 `4904a193` 勘误
基线。没有设置 CPU affinity、GOMAXPROCS 或替换文件系统，原完整参数保持。
最终为 failure，S3 账本如实拒绝；本轮不重试以选择通过结果。

| 范围 | 实际结果 | artifact |
|---|---|---|
| 来源与补丁 | 固定 SHA/tree、唯一父提交/变更文件及逐字节采时移动均匹配 | `12564681684` |
| 旧侧 collector | 七项原生 collector 回归/race 全部通过，无跳过或失败 | `12564413106` |
| 带负载故障 | 七项实际负载故障全部通过，无跳过或失败 | `12564915060` |
| 持续负载 | 1810.605879718 秒、39 次生命周期循环；100/250/500/1000 会话档位均达到，业务错误为零 | `12565162183` |
| 完整 A/B | 119/120 measured，旧侧 60/60、候选 59/60；十一项达标、一项 incomplete | `12565696275` |
| S3 账本 | `full_S3_accepted=false`，`PERFORMANCE` / `equivalent_ab` / `process_cpu_windows` 为 false | `12565316688` |

唯一缺口为 g4 候选 events/download 的 shutdown-accounting。原始 node-stop 与
coordinator-close 快照均保留 meter `CAPACITY_REACHED`，登记容量 1152，首个
缺口 sequence 28673、实际 5 字节 upload；累计 dropped events 239476。store
仍为 healthy、220 个文件及 19,683,325 字节，coordinator 最终另记录
`STORE_EVIDENCE_INVALID`。这些状态不等于 store 硬容量耗尽或降级，也不能仅凭
关闭后快照确定某次 fsync 的唯一责任；原正式样本未启用阶段 observer。

完整下载并核对 120 份 sample、240 份 CPU、240 份 runtime、四份实际二进制，
模块锁/模板/源码摘要及十二项比较重算均匹配。该失败样本有完整数值 CPU 和分配
窗口，但原 CPU 谓词同时要求 `status=measured`，所以 CPU gate 仍拒绝它；
`image_sizes`、`allocation_windows`、`evidence_complete` 均为 true，不能据此
补足其计量尾部。重算的 S3 账本与归档 JSON 完全相同，原拒绝条件不变。

同候选的 PR CI `40105527049` 与完整功能运行 `40105980034` 成功：Go/race、
strict quick/full、runtime stability、固定 Core Machine/C2 及镜像冒烟均执行。
full 原始事件按固定 manifest 重算为 37 个顶层、29 个子测试通过，2 个固定上游
不可用组合单列。独立诊断四份 download、8 份 CPU/8 份 runtime 和四份 profile
亦完成核对（`12564602515`），不进入正式 120 cell。

本次十一项完整比较在本 profile 的原预算内，不消除原 `a1ad269` 的 106/120、
单 CPU 115/120 或历史 CPU 调查结果，也不证明换了基线后所有环境均无拒绝。
勘误 profile 自身仍未完整通过 S3；后续候选改动与交付必须继续绑定具体源码。

## 2026-10-24 events/long 窗口调用栈

整进程扩展采集 `40100710905` / artifact `12562712198` 复用原二进制，十二份
profile 均完成。旧侧 3.92 秒、新侧 3.49 秒的 CPU 样本中，关闭后 `ReadRecord`
分别占 0.99 / 1.05 秒；该阶段不在原 CPU 测量窗口内，不能据此解释正式比率。

窗口限定补采 `40102555123` / artifact `12563489354` 使用独立工具
`bde74a86acf16784c3be2214f9bb2c63a6521be1`，两侧仍为原 `a1ad269` / `90508592`。
仅诊断 harness 的 profiler 启停移到原两次 CPU snapshot 外侧；生产源码、原
snapshot 函数、nonce、字节证明和关闭后账量核对保留。两份新 harness 摘要明确
区别于原冻结二进制。每侧六份交替、每份 2 秒预热及 55 秒测量、4 线程和 CPU 0，
持久化 observer 关闭；55 秒及 profiler 参数属于诊断，不生成验收比率。

| 窗口内互斥栈分类 | 旧侧 CPU 样本权重 | 新侧 CPU 样本权重 |
|---|---:|---:|
| 全部 | 5.15 秒 | 5.18 秒 |
| Coordinator worker | 4.78 秒 | 4.65 秒 |
| relay | 0.09 秒 | 0.14 秒 |
| 独立后台 GC | 0.19 秒 | 0.32 秒 |
| 其余 | 0.09 秒 | 0.07 秒 |

十二份原始 profile 和窗口元数据、两份合并 profile、24 份 CPU / 24 份 runtime、
源码/overlay/helper/模块锁及原账量证明均匹配；两侧达到采集前固定的至少 2 秒
CPU 样本预算，关闭后 `ReadRecord` 样本权重为零。两侧主要热点均在事件持久化
worker 的 JSON 编码与摘要校验；累计函数权重不可相加，带 profiler 的样本权重
也不是原 CPU/GiB 的新旧验收比率。目前仍未确定原 5% 越界的唯一原因。

## 2026-10-24 main 的定时 Actions 结果

定时运行 `40040191779` 固定 main `90508592b4c0b433eb9a71f367694a981aa958e1`，
tree `935e2d2f17c4d723ad025361216c697b8b818ccf`，最终结论为 failure。
本次核验沿用已经启动的每日运行，没有手动重试以选择通过结果；正式工作流、旧
`a1ad269`、五组参数、容量、同步、ACK 及原阈值均保持不变。

| 范围 | 本次实际结果 | artifact |
|---|---|---|
| 持续负载 | 1810.552856540 秒、39 次生命周期循环；100/250/500/1000 会话档位均达到、业务错误为零 | `12539938013` |
| 真实带负载故障 | 七项原始 Go JSON case 全部通过，源码 SHA/tree 与本次候选一致 | `12539191326` |
| 正式 A/B | 106/120 measured，旧侧 51/60、新侧 55/60；七项达标、四项 incomplete、一项 unresolved | `12539504349` |
| S3 账本 | `full_S3_accepted=false`；`PERFORMANCE`、`equivalent_ab`、`evidence_complete` 为 false | `12540346123` |

四份旧侧 usage_v2 失败分别为 g1 short measurement、g1 long warmup、g3 upload
warmup 和 g4 upload measurement，原日志均为 `USAGE_INTERVAL_UNKNOWN`。四份
持久化 native envelope 的 payload digest 均匹配，各有一个已完成且不合格的 upload，
实际字节为 1024/32768/32768/32768，均不超过原请求量。collector 未退休、无 I/O
error，单操作 wall/elapsed 不倒退，仍在原 grant 内；至保守的单调 deadline 下界
仍至少余 80.96 秒。依原源码逐项排除后指向全局顺序守卫；本次未捕获内存 `c.last`，
不能把推定写成直接时钟对 capture，也不据此改写前一轮的 1 字节 download 证据。

另十份失败均为 events/download：五组双侧全部 meter `CAPACITY_REACHED`、store
未降级，单 meter 登记容量仍为 1152。原正式样本没有启用阶段 observer，不能借用
其他诊断的阶段 wall 峰值解释它们的唯一原因。

usage_v2/download 的五组样本两侧均完整，但 throughput 比率
`0.9397034945178865`、CPU 比率 `1.0016318773549537`，最大 CV
`0.2683557663955059 > 0.10`，按原判定为 unresolved，不记为已确认的性能退化或
通过。四项 incomplete 为 usage_v2/upload、short、long 与 events/download。

已完整下载本次正式性能 artifact：120 份原始 sample.json 与报告一致；116 个
CPU/分配量窗口对应的 232 份 CPU 与 232 份 runtime 原文件逐字段及算式匹配，
另外两份中断样本只留下起始 snapshot。四份下载的业务/夹具二进制 SHA-256 均
与各自 build metadata 一致；十二项比较使用原工具纯计算重算一致。完整压缩包
下载不等于 240 个 CPU 文件齐备，116 个数值窗口也不补足十份计量失败。

S3 账本仍因缺少 `cpu_measurement` 提前终止后续 image/allocation 检查；没有生成
的检查不能记为通过。独立 CPU profile job 的四份 download 诊断均 measured
（artifact `12538649028`），不计入这 120 份正式样本。下节 `94d49420` 的
111/120 保留为其所属源码的历史结果，本次 main 的正式结果为 106/120。

## 2026-10-24 独立单 CPU Actions profile

独立分支 `diagnose/native-single-cpu-actions` 的工具提交
`7bcc42e91c55e4b382075d44ed2948f74502467b`，tree
`4136b5e15f899d65dbade8ae7790df1877fff0f3`，仅改变实验工作流；生产源码、
原测量脚本、公共模板和模块锁均与候选 `90508592` 相同。一次性 Actions
`40041704618` / artifact `12540691528` 已完成，不替换上述默认调度的正式结果。

执行前的 plan 固定原五组、2 秒预热、10 秒测量、4 线程及全部原阈值；从 driver
允许的 `[0,1,2,3]` 中确定性选择 CPU 0，实际 exec driver affinity 为 `[0]`，
子进程按内核规则继承，没有独立采样每个子线程的 affinity。没有设置
`GOMAXPROCS` 或自行改变现有 ext4 挂载；原队列、fsync 和私有 ACK 保留。
plan、driver、环境及报告摘要均已交叉核对。原 job 为 AMD EPYC 9V74，本 job 为
Xeon Platinum 8573C，runner ID 也不同，不能从两个 job 的差异推导 CPU affinity
是时钟或容量差异的唯一原因。

本次 115/120 measured（旧侧 55/60、候选 60/60），五份缺口均为旧侧
events/download 的 meter `CAPACITY_REACHED`，store healthy。usage_v2 本次两侧
均完整，不构成原旧基线已修复或今后不再拒绝的证明。十二项比较中九项达标，
一项 incomplete，另两项按原 5% 阈值要求 investigate：

| 独立 profile 比较 | throughput 新/旧 | CPU/GiB 新/旧 | 最大 CV |
|---|---:|---:|---:|
| ordinary/long | 0.9999899371 | 1.1188543557 | 0.0592052522 |
| events/long | 0.9994738247 | 1.0738371596 | 0.0764985171 |

两项 CV 均低于原 10% 噪声上限，不能按噪声未决或样本缺失处理，也不能用候选
60/60 覆盖旧侧缺口及这两项越界。所有 120 份 sample、240 份 CPU 和 240 份
runtime 原文件，以及 CPU/分配量算式、源码/模板/模块摘要和十二项比较均匹配；
本 artifact 未保留四份业务/夹具二进制，不声称独立重算它们的 binary hash。

采集 job 的 success 仅表示完整收集及验证 120 个 cell；其 measurement step 为
failure，原报告 `accepted=false`，独立 envelope 也保留
`collection_complete=true`、`accepted=false` 和 `full_S3_accepted=false`。
本 profile 没有自己的 30 分钟 soak，不与默认 job 的 soak 拼接成一次通过。
实验工作流不合入 main，原始默认与单 CPU 两份失败结果都保留。

## 2026-10-24 长连接 CPU 定向调查

工具提交 `2dbf6834d4aa313b50b782e5326e718490e4d051` 的独立 Actions
`40059251852` / artifact `12547191583`，固定使用原候选 `90508592` 与旧
`a1ad269`，测量脚本、模板、Go 1.26.0、模块锁和四份二进制摘要均与单 CPU
profile 匹配。只复现 ordinary/long 和 events/long，保留 CPU 0、五组交替、
2 秒预热、10 秒测量及 4 线程；不重跑正式矩阵或补入正式样本。

20 份未追踪样本全部 measured，原始比较重算一致：

| 定向复现 | throughput 新/旧 | CPU/GiB 新/旧 | 最大 CV | 原规则结果 |
|---|---:|---:|---:|---|
| ordinary/long | 1.0000216312 | 0.9847583126 | 0.1366565637 | unresolved |
| events/long | 0.9996417392 | 1.0532690294 | 0.0662570970 | investigate |

ordinary 的新结果不消除前一 profile 的越界；events 仍越过原 5% 调查线。
该 job 最终失败，因为随后四份 syscall 采集显式使用 `strace -I 1`，SIGINT
终止 tracer 后统计文件为空，采集异常又打断末尾账量检查；四份保留为 incomplete。
这不是 20 份未追踪样本失败，也不能将旧的追踪样本补称为 measured。

补采工具 `119064c6701540c3e81e941c5e7b8032b1c6e566` 的 Actions
`40061564735` / artifact `12546509874` 不构建或重跑未追踪比较，直接核对并
复用前一 artifact 的固定二进制。先在同一 runner 验证退出控制：`-I 1` 未捕获
SIGINT、留下空文件；`-I 2` 捕获信号并写完整统计。两种模式退出后，目标进程
都已脱离追踪且继续推进；两者退出码同为 -2，不能只按退出码认定统计完整。
采集异常现独立记账，原测量与 shutdown-accounting
仍继续执行。

四份补采均 measured，每份 980 次操作；ordinary 两侧 splice 各 8816 次，
events 为旧 8816 / 新 8815 次，events 两侧 fsync 各 115 次。本轮没有观察到
这两类调用次数倍增；单份 ptrace 下的调度和系统调用统计不足以解释原 CPU
差值的唯一原因。追踪窗口从首次 CPU 请求前到第二次 CPU 回执后，只有计数
用于诊断，追踪 CPU 和耗时不进入阈值比较。

两份完整 artifact 的摘要、24 份完整样本对应的 48 份 CPU / 48 份 runtime、四份二进制、
原模块锁及 syscall 行/总计均已离线核对。补采 job success 只表示采集完成。
原基线、容量、同步、ACK、负载和阈值保持，两个实验脚本及工作流不合入 main；
本次不新增正式 A/B、soak 或故障证据，完整 S3 继续为 false。

## 2026-10-23 最终运行时候选的历史结果

最终运行时候选 `94d494202ba5f990494b692a4a67e237805f4cb7`，tree
`72699fc5973bee9e006cd82ee9f2930bbeaa26f7`，完整 native Actions
`39969066032` 已完成且失败。正式性能为 111/120 measured（旧侧 55/60、新侧
56/60）；十项完整比较都满足原阈值。usage_v2/upload 的 g1 旧侧出现 measurement
EOF，events/download 的 g1/g3/g4/g5 双侧共八份 shutdown-accounting 不完整，
两项均保持 incomplete。ordinary/upload CPU `1.018597687348134`、ordinary/long
CPU `1.0089442521725174`；不能由完整比较通过推导缺失比较通过。

soak 实际 1810.902413957 秒、39 轮，四档达到 100/250/500/1000、业务错误为零；
七项故障通过。正式 artifact `12509414091`、soak `12509324775` 和 S3
`12510033035` 对应此 SHA。S3 的 `PERFORMANCE`、`equivalent_ab`、
`evidence_complete` 为 false，缺失 CPU 字段使后续 image/allocation 检查没有生成，
`full_S3_accepted=false`。111 份 measured report CPU window 均通过原 validator；
未声称已下载并匹配 240 份原始 CPU 文件。其完整功能 Actions `39967685398` 已
成功，Machine 本次原 batch/SQL 唯一 settled 行均为 5；功能不替代正式 S3。

九份失败均已取得原始证据。g1 legacy usage_v2/upload 的四条连接记录
`USAGE_INTERVAL_UNKNOWN`，并非进程在 measurement 时已经退出。八份 events
均为 meter `CAPACITY_REACHED`，store 未降级；node-stop 与 coordinator-close
两份 meter 相同。八份失败窗口的 16 份 CPU 原文件也与 report 匹配，但数值自洽
不能绕过计量缺口。这些原文件复核与 111 份 measured 的 report window 复核范围
分别记账，不记为 240 份原文件已全部下载。

2026-10-24 对同一原始 legacy usage_v2/upload collector 状态的离线复核显示：
一份已完成但不合格的 download 事件为 1 字节，完成时距离持久化窗口到期尚约
78.16 秒；它的单操作 wall/elapsed 均不倒退，collector 未退休、没有 pending。
依据固定旧源码，完成 elapsed 为 10.844819355 秒，低于构造器推得的保守单调
deadline 下界 89 秒，且位于原 grant 内。因此可以按条件排除把拒绝守卫缩小到
`c.last` 的 wall/monotonic 顺序比较。原内存 `c.last` 未持久化，仍不能证明两种
时钟顺序出现差异的唯一原因，也不能把现行源码中锁内采时的回归结果倒用为旧
基线已修复。没有修改 `a1ad269` 身份、容量、同步、ACK、负载或原阈值；这份
分析不补计缺失的正式样本。

| events/download | FirstGap sequence | FirstGap elapsed ns | DroppedEvents |
|---|---:|---:|---:|
| g1 legacy | 140417 | 6202608789 | 138898 |
| g1 candidate | 82305 | 3709239997 | 198976 |
| g3 legacy | 67201 | 3115954314 | 207478 |
| g3 candidate | 95361 | 4276214935 | 182796 |
| g4 legacy | 183041 | 8292310276 | 86550 |
| g4 candidate | 66689 | 3031895984 | 209504 |
| g5 legacy | 181505 | 8307182288 | 85812 |
| g5 candidate | 237569 | 10784446100 | 29540 |

本轮正式 runner 为 Xeon Platinum 8573C。主机型号是执行环境记录，不单独解释
容量缺口或证明磁盘、调度、编码中的唯一根因。原基线与候选均保留原容量、同步
和 ACK；没有重复同一候选运行以选择通过结果。

前一测试修正候选 `e1e2a96bc7915ad4a5b5648f207836e5f950e6b5` 的 Actions
`39958140736` 已完成 120/120 measured，11 项比较达标，唯一 ordinary/long
CPU/GiB `1.0642920938104765 > 1.05`。该比较吞吐
`1.0000924227834154`、CV `0.06566531846344348`；全部比较的最大 CV
`0.08904020850146029 < 0.10`。这是阈值越界，不能记为缺样本、events 容量失败或
CV 未决。七项故障与 1809.607773683 秒、38 轮 soak 通过；S3 只有
`PERFORMANCE`、`equivalent_ab` 为 false，其余八项为 true。

其正式、soak、S3 artifacts 为 `12505247297`、`12505416903`、`12504514927`。
全部 120 份 report CPU window 均通过原 validator。离线下载仅取得 68/240 份原始
CPU snapshot 且逐字段匹配，16/40 份 event meter snapshot 均无 drop/gap；完整压缩包
未成功下载，不能把这次部分原文件复核写成 240 份完整核验。

独立 long profile 分支 `c9647a35` 的 `39962792221` 仅执行四份诊断，
ordinary/events 两侧均 measured，`accepted=false`，不属于正式矩阵。ordinary
pprof 总样本为旧侧 40 ms、新侧 50 ms，其中新侧 10 ms 指向 spliceOne callback
中的 runtime.ifaceeq；采样量不足以证明上述正式越界的唯一原因。后继
`01805796` 将 callback 改为比较具体 syscall.Errno，保留 EINTR/EAGAIN、其他错误、
原部分写计数、hook、buffer 和持久化边界。其 `39965363544` 已完成 120/120
measured，ordinary/long CPU 比率 `1.0325303858902604` 达标，唯一越界变为
ordinary/upload CPU `1.0522877502360797 > 1.05`，对应吞吐
`0.99982202118296`、CV `0.056566858352544096`。其余 11 项达标，soak
1809.495551609 秒、38 轮及七项故障通过，S3 仍因 `PERFORMANCE`、
`equivalent_ab` 为 false 而失败。全部 120 份 report CPU window 有效，本次没有
下载 240 份原始 CPU 文件，不记为完整原文件复核。这些结果不移用为最终
`94d49420` 的同 SHA 验收，也不能据此证明 errno 改动是两轮差异的唯一原因。
诊断分支的工具改动没有合入候选，正式五组、原参数、容量、同步、ACK 及阈值
保持不变。

独立 upload 诊断分支 `2522145b151192774f6f031ea3bcb2f9f5602fd5` 的
`39970404154` 仅将四个诊断 case 改为 upload，运行时与 `94d49420` 相同；其工具
改动没有进入 PR。四份诊断均 measured，8 份原始 CPU snapshot 与 report 逐字段
匹配，profile 摘要一致，`accepted=false`。ordinary 两侧各完成 980 次操作，
CPU window 为旧侧 230674717 ns、新侧 224322087 ns，但 pprof 总样本仅为
10 ms/20 ms，热点不足以解释中间候选的正式 upload 越界。该单次结果既不替代
五组正式比较，也不触发放宽阈值或再次选择较优运行。

2026-10-23 复核：main `8cebddbb` 的后续运行 `39694804417` 已取得完整 S3
通过，正式 120/120 measured、十项 ledger checks 全 true。随后 `39872986575`
正式性能再次 120/120 measured 并通过，持续负载也通过；该轮 S3 false 来自带流量
SIGKILL 故障断言失败，不是旧 `e5` 的缺失样本。独立 CPU 诊断两侧 events/download
账量不完整的失败另行保留，不计入正式样本。下文是各自精确提交的历史记录，
不能把一次通过推广为稳定通过，也不能将后续失败沿用旧样本原因解释。

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

- 默认旧基线：`a1ad2695e1143269168c36a274283de3342e91c7`，选择 sing-box 服务端；独立时钟勘误版需显式选择并按前节身份记账。
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

## 2026-10-24 独立完成时钟诊断

正式旧基线的完成拒绝缺少原内存 `c.last`。独立工具候选
`1554f896b3cda00379fa412d4b777d923aef00c5` 的 Actions `39995975714`、artifact
`12520710393` 已完成五组交替 usage_v2/upload 诊断。源版本固定为旧
`a1ad2695e1143269168c36a274283de3342e91c7` 和当前
`067a082b875496ec676f2ac211e04605526926bc`；两份临时构建都在原 eligibility 判定之后、
更新 `c.last` 之前增加同一个首次拒绝采集钩子。该钩子只记录固定的时钟、数值和
条件，不记录用户标识或凭据；非拒绝路径不调用采集函数。构建元数据单列原源码、
修改后源码、helper、补丁、公共 harness 及模块锁摘要，不能把诊断二进制称为未修改
的旧基线。七项证据策略单测通过；本地只做 AST、Linux 静态编译和 vet。

| 首次拒绝 | 阶段 / 实际上传字节 | 相对 `c.last` 的 wall / elapsed | 未满足条件 | 单调 deadline 尚余 |
|---|---|---|---|---|
| g2 legacy，sequence 314 | warmup / 32768 | -5 ns / +5 ns | 仅 global-order | 87.915588120 秒 |
| g5 legacy，sequence 156 | warmup / 32768 | -5 ns / +5 ns | 仅 global-order | 88.757566727 秒 |

这两份原始 capture 的单操作 wall/elapsed 均不倒退、grant 内、未退休且 deadline
未到；按原表达式重算与拒绝位完全一致，随后客户端出现 EOF。旧侧其余三份与当前
五份诊断完整，当前未捕到拒绝。五次有限观测不证明当前永不拒绝，也不能补计正式
120 份样本。该 runner 记录 4 CPU、Go 1.26.0、clock source 为 tsc；这些环境字段
不单独证明物理时钟、VDSO、虚拟化或调度的唯一原因。历史正式运行没有相同 capture，
不能把这两次 -5/+5 ns 数值倒写到历史事件。

为隔离采时位置，后继诊断工具 `867c39038bd7d0ec40088855cf44e31e19da5dab` 增加
第三份 `legacy_serialized` 临时副本：只把旧 `CompleteIO` 的 now/stamp 观察移到原
collector 锁内，原 eligibility、wall 回退、deadline、grant、实际字节、持久化和
拒绝行为保留；测试要求还原该移动和采集钩子后与原源码逐字相同。五组三方 Actions
`39997272907` 已完成，artifact `12520132744` 保留三份构建的源码覆盖摘要和五组
原始文件。原旧侧 4/5 完整，g5 在 measurement 拒绝 32768 字节上传；仍只有
global-order 不满足，wall 差 -7 ns、elapsed 差 +33 ns，单调 deadline 尚余
87.251510109 秒。`legacy_serialized` 和当前候选各 5/5 完整且没有捕到拒绝。
同一旧代码仅移动采时位置的有限对照支持该修正，但不证明所有环境下零故障，也不
建立物理时钟机制的唯一归因。它是明确命名的诊断源码覆盖，不替换正式 `a1ad269`
的身份或原失败；不把两轮不同 runner 的计数合并为故障概率或性能比率。

事件侧八份最新正式失败快照的 `RetainedEventCapacity` 都是 1152；当前内核以
`MaxEvents=128`、`MaxSealed=8` 建立 meter。65536 是 coordinator 的总登记上限，
不能当作该单 meter 实际容量。store 未降级与 meter 填满并不矛盾。当前源码的独立
无 profiler OFF/ON 配对 `39997913837`、artifact `12520822997` 已采集完整 20 份：
7 份账量完整、13 份 meter `CAPACITY_REACHED` 且 store healthy；OFF 失败 7 份、
ON 失败 6 份，13 份失败的 node-stop 与 coordinator-close meter 均相同。
只有 g4 两侧各一对 OFF/ON 都完整，不能从其余八对计算有效开销比率，也不能据
两对推导通用 observer 开销。实际 40 份原始 CPU snapshot 与该诊断报告逐字段匹配，
源码、模板、模块锁及逐样本 metadata 也已核对；这不是正式 240 份 CPU 原文件的
补全，更不能替换原正式矩阵。

6 份 ON 失败的冻结环都在同一 claim 的下一次 after-ACK 首次观察缺口。原始
before-write 快照中的剩余槽位，恰好等于至 FirstGap 的 sequence 增量；阶段峰值与
该 claim 的 bucket/sequence 对齐，能够定位生产者填满有界队列时的写入窗口：

| ON 失败 | claim bucket | 写入前剩余槽位 / 至缺口新增事件 | 同 claim 的最大阶段 wall |
|---|---:|---:|---|
| g1 legacy | 402 | 600 / 600 | record_file_sync_wall 96.574932 ms |
| g2 legacy | 38 | 959 / 959 | head_publish 49.272499 ms |
| g3 legacy | 196 | 525 / 525 | record_file_sync_wall 19.346781 ms |
| g5 legacy | 1576 | 900 / 900 | head_publish 41.849943 ms |
| g2 candidate | 432 | 1009 / 1009 | head_publish 63.006815 ms |
| g3 candidate | 117 | 1008 / 1008 | head_publish 47.721738 ms |

这些 wall 窗口仍包含调度等待及 observer 成本，不能独立归因于 rename 或
fsync syscall，也不能把 OFF 的失败或更早正式运行指派给同一个峰值。关闭 profiler
和关闭 observer 仍有失败，说明它们不是容量失败的必要条件。没有为本轮改变
队列/文件上限、同步、ACK 或负载；完整 S3 继续保持未通过。

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

汇总入口为 `scripts/native-s3-summary.py`。各项证据独立求值，缺 CPU 字段不会
省略镜像大小或分配窗口检查；缺失或损坏输入按固定检查名记录错误，仍以非零
状态拒绝验收并保留完整 JSON。验证器从工作流自身 SHA 读取，测量 candidate
继续使用同一组产物的固定来源。历史失败产物的重放只核对记账完整性，不补样本、
不改变原始归档结果，也不替代新候选的实际性能验收。
