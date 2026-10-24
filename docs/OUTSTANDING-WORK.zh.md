# 剩余事项与验收状态（txnode 数据面）

本表跟踪 S0–S4 的实现和实际验收。开发顺序及完整要求见
[NEXT-DEVELOPMENT.zh.md](NEXT-DEVELOPMENT.zh.md)，严格互通入口见
[INTEROP.md](INTEROP.md)。历史 `a6d0e96` 的“29 通过、6 跳过”不代表当前候选。

## 2026-10-24 时钟勘误入口与窗口 profile

经用户明确选择新增独立基线 `legacy-clock-serialized-v1`，固定旧侧提交
`4904a193d4564cf67af55728da0b338ff3b1268f`。相对原 `a1ad269`，仅将
CompleteIO 的两行采时移入原锁，全部拒绝条件及历史失败保留。默认验收继续
使用原基线；勘误版需显式选择，源码校验、A/B 产物及 S3 身份独立记录，另需
该旧源码上的原生 collector 回归/race 通过。入口实现不等于 Actions 已通过。

窗口 profile `40102555123` / artifact `12563489354` 的十二份采集及原账量证明
均完成，原始 CPU/runtime/profile 和窗口元数据已核对；两侧 CPU 样本权重
5.15 / 5.18 秒，关闭后 ReadRecord 权重为零。两侧主要热点均为持久化 worker
中的 JSON/摘要路径，目前不能将原几个毫秒的 CPU 差值归为唯一原因。它使用
原 `a1ad269` / `90508592`、独立 55 秒窗口及诊断 harness，不进入正式比率。

原正式 106/120、单 CPU 115/120 及全部原失败继续保留。勘误基线后续完整
Actions、真实性能比较、S3、合并、发布与 Core 采用需要各自证据。

首轮勘误 profile Actions `40105537448` 固定候选 `6deacea6` / 旧侧 `4904a193`，
完整 A/B 为 119/120（旧侧 60/60、候选 59/60）；十一项比较达标，唯一缺口为
g4 候选 events/download 的计量尾部。meter `CAPACITY_REACHED`、容量 1152，
store healthy；不归为 store 硬容量耗尽，不补样本或重试选绿。1810.605879718 秒
soak、39 次生命周期循环、四档会话及七项带负载故障通过，但最终 S3 账本仍为
false。120 份 sample、240 份 CPU、240 份 runtime、四份二进制与原账本已核对。

同一 `6deacea6` 的完整功能运行 `40105980034` 成功，full 为 37 顶层/29 子测试
通过、2 项上游不可用单列，并执行 runtime stability、Core Machine/C2 和镜像
冒烟。它与 PR CI `40105527049` 不代替仍失败的勘误 S3，完整计量缺口继续跟踪。

## 2026-10-24 长连接 CPU 调查补项

独立 Actions `40059251852` / artifact `12547191583` 固定原 `90508592` / `a1ad269`
和单 CPU 方法，只复现两项 long 比较。20 份未追踪样本全部 measured；ordinary
CPU/GiB 比率 `0.9847583126`，CV `0.1366565637`，按原规则 unresolved；events
CPU/GiB 比率 `1.0532690294`，CV `0.0662570970`，仍为 investigate。该 job 的
四份后续追踪因 `strace -I 1` 退出控制而失败，保留为 incomplete，不改写原结果。

补采 `40061564735` / artifact `12546509874` 验证 `-I 1` / `-I 2` 控制对照后，
复用摘要匹配的原二进制，四份追踪均完成原计量尾部；不重建或重跑未追踪比较。
ordinary 两侧 splice 各 8816 次，events 两侧 fsync 各 115 次，尚不足以确定 CPU
差值的唯一原因。两份 artifact 及 24 份完整样本的 48 份 CPU / 48 份 runtime
原文件已核对。
实验脚本与工作流留在独立分支；完整 S3 仍为 false，正式 106/120 和独立单 CPU
115/120 保留各自来源。本次只追加调查证据，不产生新运行时或发布验收。

## 2026-10-24 S3 汇总完整性修正

正式运行 `40040191779` 的原 ledger 在缺少 `cpu_measurement` 时提前结束共享
`try`，后面的镜像大小与分配窗口检查没有生成。验证器候选
`9f3ff8deff30c396721b6e81962a36e456923964` 将原 CPU 谓词原样提取到
`scripts/native-s3-summary.py`，逐项捕获缺失或损坏证据，使每项固定检查都有
显式结果。任何失败仍拒绝验收，CLI 在非零退出前写 JSON 与 job summary。
生产源码、原 CPU 谓词 AST、测量脚本、soak/fault/performance job 定义、原始
基线、容量、fsync、ACK、负载与阈值均保持。

Actions `40055572834` / artifact `12545083199` 只重放同一份原始失败产物：
通过 GitHub 读取原运行的 job 结论，原验证器结果与归档 ledger 完全相同；
新验证器明确记录 `process_cpu_windows=false`、`image_sizes=true`、
`allocation_windows=false`，两版都以非零状态退出，完整 S3 仍为 false。
七项新回归全部通过，无跳过；原/新验证器、测试和输入报告摘要已核对。
它不新增性能、soak 或故障样本，也不把原 106/120 改写为验收通过。
独立重放工作流保留在诊断分支，不合入 main。

## 2026-10-24 启动诊断与 Machine 夹具修正

文档 PR #11 合并后的 `40045439602` 在事件容量回归失败：异步 worker 可以
先于内核挂接而停止，Service 的 `LOCAL_ATTACH_REFUSED` 提前返回遮住实际
`STORE_CAPACITY_REACHED`。修正仅使 coordinator 的真实 Degraded/Reason
优先显示；健康 worker 的真正挂接拒绝继续保留原标签。确定性回归仍要求真实
SOCKS 流量为 19/19 v1 字节、失败后停止本地观察且重复初始化不重建 consumer。

Machine 的后续失败另行保留：`40046295510`、`40047881008`、`40049351108`
分别在新 token 恢复或成员重新启用阶段失败，不补称为通过。独立插桩运行
`40051450211` 观察到一次启动 submit 在累计两秒页预算到期时失败，该次请求
自身用时 246,859,141 ns。后台到期和清理取消单列；代理后端耗时包含排队和
PHP 处理，不能单独视作 Core 内部执行时间或全部历史失败的唯一根因。

验收夹具现在将 TLS 握手放到原连接 worker，并只为 PHP HTTP 子进程设置四个
worker，避免单个未完成握手或串行 PHP 队列阻塞其它连接。Node/Workerman
环境、Core pin、证书校验、原两秒恢复页、十二秒就绪、十五秒退避，以及原始
batch/周期重放和 SQL 唯一记录断言保留。新增的显式请求屏障回归在具备固定
PHP 环境的 Machine job 执行；它要求独立请求在原两秒内返回且被阻塞请求尚未释放。

最终未插桩功能候选为 `79ef3f4330549ea5d6a8af4e7d025ad8fce89f18`，tree
`1995e121843dca9b7443e38c0b58554784e47324`。常规 PR CI `40052280101` 和
完整功能 `40052277069` 均成功：Go/race、runtime stability、严格 quick/full、
真实固定 Core C2、Machine 和镜像冒烟通过。full artifact `12543434146` 的
原始 JSON 为 37 个适用顶层、29 个子项通过，另两项不适用；Machine artifact
`12543862367` 的本次原始批次与 SQL 唯一 settled 行均为 7，旧 token 拒绝、
新 token 恢复、成员撤出和 WS-only 配置断言通过。它不等于独立完整账单对账
或生产 PKI 证明。本段文档更新不改变该候选的非文档源码。

三份独立反事实已核对原始日志及固定源码摘要：`40046534638` 的旧 Service
适配器在新确定性回归准确失败，修正版七个 case 各二十次 race，共 140 PASS；
`40049559568` 的原 TLS 代理在慢握手场景超时，修正版两项网络回归通过；
`40052359178` 在同一 runner/PHP/屏障下复现原串行子进程环境时，独立请求
准确两秒超时，四 worker helper 返回 200，测试约 72 ms。最后一项使用 identity
adapter 在新 harness 中复现旧环境，未宣称执行旧源码文件。插桩克隆及独立
实验工作流不合入 main，也不替代最终未插桩候选的验收。

本修正不改变下面正式 A/B 的 106/120 measured 与完整 S3 未通过状态。合并后
main CI、镜像发布、Core 采用和生产部署继续分别记账。

## 2026-10-24 Actions 执行环境复核

main `90508592b4c0b433eb9a71f367694a981aa958e1` 的定时 native Actions
`40040191779` 已完成，正式 A/B 为 106/120 measured（旧侧 51/60、新侧 55/60），
完整 S3 仍为 false。本次没有手动重试同一正式运行来挑选通过结果。四份旧侧
usage_v2 发生 `USAGE_INTERVAL_UNKNOWN`，十份 events/download 触及原 1152
事件容量且 store healthy；七项比较达标、四项缺样本、一项 usage_v2/download
因 CV `0.2683557663955059 > 0.10` 未决，不能称为已确认退化。

四份拒绝的原 native envelope digest、实际字节和 grant/deadline 已逐项核对，原
条件排除指向全局顺序守卫，但本次没有内存 `c.last` capture。120 份 sample 与
报告相符，116 个 CPU/分配量窗口对应 232 份 CPU 和 232 份 runtime 原文件；
四份下载的二进制摘要匹配。持续负载为 1810.552856540 秒、39 次生命周期循环，
四档达到 100/250/500/1000、业务错误为零；七项带负载故障实际通过。
正式、soak、S3 artifacts 分别为 `12539504349`、`12539938013`、
`12540346123`。历史 `94d49420` 的 111/120 与本次 106/120 分别保留。

同一候选的独立单 CPU profile `40041704618` / artifact `12540691528` 为
115/120 measured，旧侧 55/60、候选 60/60；五份失败全部为旧侧
events/download 的 meter 容量。该 profile 的 ordinary/long 与 events/long
CPU/GiB 比率分别为 `1.1188543556860076`、`1.0738371596011695`，对应 CV
`0.059205252205926616`、`0.07649851709072823`，按原规则为越界调查项。
九项比较达标、一项 incomplete，不把这两项当噪声或旧侧缺口处理。

driver affinity 从原 `[0,1,2,3]` 固定为 `[0]`，原 fsync、容量、ACK 和阈值
保留；240 份 CPU 与 240 份 runtime 原文件均与报告及算式匹配。两个 job 的
runner ID/主机型号不同，不能把结果差异单独归因于 affinity。采集 job success
与测量 step failure、原报告 `accepted=false` 分别记录，不与正式 soak 拼接为
完整 S3。实验工具 `7bcc42e9` 仅在独立分支，生产源码及正式工作流不变。

## 2026-10-24 验收补项与完成审计

Mieru 的目标失败互通原来仅执行 TCP 承载。测试候选 `66f171d6` 将原断言分别在
官方客户端 TCP/UDP 承载执行，并由严格清单要求两个子项。其完整功能运行
`39979828676` 的互通实际为 37 个适用顶层、29 个子项通过，另两项不适用；
但 Machine 在成员重新启用后的原 12 秒监听恢复窗口失败，整轮不能记为通过。

PR #9 的独立诊断候选 `faeece51278bc9c144378c6084c8d2a26a8303bb`，tree
`4e89bcc44abb6bb0147cc262904b943ebd447116`，已通过 PR CI `39983267140` 与
完整功能 `39983274210`，并合并为 main `07d33c49`。本次 Machine 原 batch 与
SQL 唯一 settled 行均为 6；旧 token 拒绝、新 token 恢复、原周期重放及成员恢复
均通过。该候选没有包含新增 Mieru 子项，也没有证明前次超时的唯一原因。

诊断仅在失败时记录固定阶段/原因、目标 tracked/done/backoff、固定失败类别、
owner/context/共享 WS/监听状态和有界 wait-chain 标签。原生 discovery 装饰器
仅观察实际成功结果的两个布尔值；不改变请求或返回值，不导出身份、凭据、原始
错误、响应正文或堆栈。原 12 秒恢复、10 秒 join、15 秒节点退避及重放要求保留。

同步该 main 后，Mieru 候选为 `b2f2c7ae9f4324080f0a99443fd46e85960ebf2d`，tree
`ce1e7914dd8f78c903f91a5914697407d52cc202`。完整功能 `39989542571` 与 PR CI
`39989547284` 均成功：Go/race、runtime stability、严格 quick/full、真实固定
Core C2、镜像冒烟和完整 Machine 通过。full artifact `12517082074` 绑定该 SHA/tree，
两个目标失败子项实际通过；Machine artifact `12517492453` 本次原 batch 与 SQL
唯一 settled 行均为 5，不套用诊断候选的六批次。生产运行时相对 `94d49420`
没有新增修改；本次未重跑相同运行时的正式 A/B 以选择通过结果。

| 阶段 | 本轮审计结论 |
|---|---|
| S0 | 严格缺失/错误/Skip 门禁、quick/full、事件/observer/packet 和 SIGKILL 真实入口已实现；新候选仍按各自 Actions 接受 |
| S1 | 固定版本 REALITY、Naive 与 Mihomo TUIC 已进入严格矩阵；两个上游不适用组合单列，不计通过 |
| S2-A | smux/yamux UDP、统一 owner/路由/限速/计量、父子撤权及实例隔离已有真实用例 |
| S2-B | 官方 UDP 承载、损伤/重复/撤权/重载已有验收；新增 UDP 目标失败补项已在本次完整候选通过 |
| S3 | 负载、故障与 A/B 工具及原始报告齐备；main `90508592` 最近正式 A/B 为 106/120 measured，完整 S3 未通过；`94d49420` 的 111/120 为历史结果 |
| S4 | 显式 Mieru 整形/低熵、连接 ID 跨 Reload 关闭、受限诊断与配置/回滚说明已有实现和测试 |

开发镜像交付、Core 采用、正式标签和生产部署继续分别记账；本次测试补项不改变
下面正式 S3 的失败。历史 main `8ad0d395` 的实际独立镜像交付不等于本次 main
已经发布，也不等于 Core 已采用。

S3 后续独立诊断 `39995975714` 已在明确带采集钩子的旧源码副本中复现两次完成
拒绝：5 份旧侧中 g2/g5 预热 EOF，实际上传各 32768 字节；唯一不满足条件均为
`c.last` 的全局顺序，wall 少 5 ns、elapsed 多 5 ns，deadline/grant 尚余约 88 秒。
当前源码的五份诊断完整。原 capture、补丁、模块锁及报告已离线交叉核对；不是
正式 A/B，也不证明旧正式样本的唯一时钟机制。三方采时位置对照 `39997272907`
同样完成：原旧侧 4/5 完整，g5 measurement 再次只有全局顺序拒绝（wall -7 ns、
elapsed +33 ns）；仅移动旧采时位置的诊断副本和当前候选各 5/5 完整。对照保留
所有拒绝条件，不构成原基线已修复或替换。当前源码的无 profiler 事件 OFF/ON
配对 `39997913837` 已采集 20 份，但只有 7 份账量完整，13 份均为 meter 容量且
store healthy；13 份失败的 node-stop/coordinator-close meter 一致。OFF 与 ON
均失败，只有 g4 两侧各一对完整。六份 ON 失败的冻结 claim 中，剩余容量与
FirstGap 前新增 sequence 精确相等；同 claim 最大阶段 wall 峰值分别为四份
head_publish 与两份 record_file_sync_wall，不能据此推导唯一 syscall 原因或移用到旧正式
样本。本次 40 份诊断 CPU 原文件、metadata 和源码摘要已核对，不能补齐正式样本。
完整 S3 保持未通过；原基线身份、容量、同步、ACK、参数和阈值继续固定。详细边界见
`NATIVE-PERFORMANCE.zh.md`。

## 2026-10-23 修复与最终运行时候选

最终运行时候选为 `94d494202ba5f990494b692a4a67e237805f4cb7`，tree
`72699fc5973bee9e006cd82ee9f2930bbeaa26f7`。PR Actions `39967692881`
与完整功能运行 `39967685398` 均成功：Go/race、runtime stability、严格 quick/full、
真实固定 Core C2、镜像冒烟及完整 Machine 通过。full 为 37 个适用顶层和 27 个子项
通过，两项明确不适用不计为通过。Machine 使用原 Core `5536410`，实际完成旧 token
拒绝、新 token 启动、原周期重放和 VLESS/VMess 恢复；本次原始 batch 与 SQL 唯一
settled 行均为 5，不沿用历史运行的六批次数字。

同 SHA 的完整 native `39969066032` 最终失败。正式五组 A/B 为 111/120 measured
（旧侧 55/60、新侧 56/60），十项完整比较满足原阈值；usage_v2/upload 的 g1 旧侧
measurement 出现 EOF，events/download 的 g1/g3/g4/g5 双侧八份 shutdown-accounting
不完整，这两项保持 incomplete。ordinary/upload、ordinary/long CPU 比率分别为
`1.018597687348134`、`1.0089442521725174`，不能用十项通过补齐九份缺失样本。
原 validator 接受全部 111 份 measured CPU window；没有将 report 复核写成全部
240 份原始 CPU 文件下载完成。

九份失败的原始证据已逐份核对：旧侧 upload 日志为 `USAGE_INTERVAL_UNKNOWN`，
八份 events/download 的 meter 均为 `CAPACITY_REACHED`，store 均未降级，
node-stop 与 coordinator-close 快照中的 meter 相同。它们不能解释成单纯退出清理
错误，也不能在固定基线中悄悄修改周期或容量后继续沿用原比较身份。

持续负载实际 1810.902413957 秒、39 轮，四档达到 100/250/500/1000 会话且业务
错误为零；七项带流量故障 7/7 通过。S3 artifact `12510033035` 保持
`full_S3_accepted=false`：`PERFORMANCE`、`equivalent_ab`、`evidence_complete`
为 false，`evidence_error` 为缺少 `cpu_measurement`；其后的 image/allocation
检查未生成，不能补称为通过。正式与 soak artifacts 为 `12509414091`、
`12509324775`。当前不据功能与负载通过推导完整 S3、main、镜像发布或生产部署通过。

本轮保留八条真实负载和原 64 KiB checkpoint，以独立用户完成一字节 echo 后的
空闲连接建立真实未完成上传 Read intent；该字节纳入实际 I/O 上界，checkpoint
仍只统计原用户。恢复必须保留同用户、同 sequence 的 intent，旧凭据拒绝、原周期、
实际字节上界和原批次重放继续执行。故障 summary 独立 always-run，命令失败、
证据缺失/截断、skip 或 package fail 均保持拒绝；Go CI 增加十次 race 重复回归。

完整功能进一步暴露 Machine 退出后缺少及时权威重查：`01805796` 的两个 child
先以 `native_usage` 类失败并关闭 listener，owner 没有 typed terminal cause，
只观察到一次 config 401。子节点失败现以容量一、非阻塞通知唤醒 Run owner，
由 owner 执行既有 discovery；只有该严格 native 请求确认的 Machine 拒绝才终止
整机。普通 503/网络故障不制造撤权，原 15 秒节点退避、10 秒 join 和 12 秒新 token
readiness 保留。新增真实 native HTTP 的 401/503/成功重查及有界通知回归纳入
`94d49420` Go/race；完整 Machine 也已实际通过。公开失败诊断只保留固定类别、
数量与四类端点 401 聚合，不导出凭据、响应正文、原始错误或 runtime stack。

`e1e2a96b` 的正式运行 `39958140736` 为 120/120 measured，11 项达标，唯一
ordinary/long CPU/GiB 比率 `1.0642920938104765 > 1.05`；吞吐比率
`1.0000924227834154`、该比较 CV `0.06566531846344348`，不能改称噪声未决。
soak 实际 1809.607773683 秒、38 轮、四档达到 100/250/500/1000 且业务错误为零；
七项故障通过，但 S3 的 `PERFORMANCE`、`equivalent_ab` 为 false。独立 long profile
在 splice callback 采到接口比较，样本量不足以证明唯一原因；后继仅改为直接比较
syscall.Errno，保留 EINTR 重试、EAGAIN 等待、其他错误、部分写计数与 hook。
原基线、容量、同步、ACK、五组参数与阈值均未变，最终效果仍由新运行接受。

中间候选 `01805796` 的完整 native `39965363544` 同样为 120/120 measured；
ordinary/long CPU `1.0325303858902604` 达标，唯一 ordinary/upload CPU
`1.0522877502360797 > 1.05`，对应吞吐 `0.99982202118296`、CV
`0.056566858352544096`。其余 11 项、1809.495551609 秒/38 轮 soak 和七项
故障通过，S3 仍为 false。最终候选追加 Machine owner 修复，仍须记录自己的
正式结果；不能把该历史阈值越界改成噪声未决或沿用为新候选通过。

## 同一旧 main 的后续定时运行

同一 main `8cebddbb70a9cc8dfada58a0d9cd5cf4b6051492` 的定时运行
`39694804417` 已完成完整 S3：正式 A/B 120/120 measured、持续负载和七项故障通过，
`full_S3_accepted=true`，十项 checks 均为 true。source artifact 的 commit/tree
与该 main 一致，status 为空；下面旧 `e5e98291` 的 119/120 不代表更新运行的结果。

随后定时运行 `39872986575` 的正式 A/B 仍为 120/120 measured，性能及持续负载
通过，但带流量故障失败，独立 CPU 诊断中的两侧 events/download 也账量不完整。
该轮 S3 为 false；故障 summary 缺失是测试失败后 shell 提前退出的下游结果。
实际失败为 `TestNativeLoadedSIGKILLRestartsWithOriginalUsagePeriod` 的
`active in-flight I/O vanished from crash quarantine`，不是编译或总超时。

旧失败没有保留当时完整 journal。原握手缺少“杀进程时确有未完成 intent”的前提，
修正此前提不能反推旧失败的唯一原因。完整 S3 曾通过与随后故障失败两条记录并存；
独立诊断也不因正式 A/B 通过而删除。

## 2026-10-21 合并与交付快照

PR #5 已于 2026-10-21 合并为 main `112760455433de1f9556b030b42b7a774a928fd1`，
tree `7cf10cc16c8dc299c60db4c691bba868c26fe063` 与最终 PR head `4b7af523` 相同；
后者相对运行时候选 `e5e98291` 只追加七份文档。最终 PR Actions `39542127317`
的 Go/race、quick、Core C2 和镜像冒烟通过。main 的 Actions `39542829266` 也已
成功：Go/race、quick、Core C2、镜像冒烟及新独立镜像发布实际通过。
`ghcr.io/anrcm0/txnode:dev-sha-112760455433` 已推送，amd64/arm64 子摘要均经
实际拉取及离线 capabilities 验证，`dev` 已提升到同一索引；发布产物为
`12320338211`，完整摘要见 `RELEASE-BLOCKERS.zh.md`。后续文档提交不重建相同
运行时。这些交付记录不改写下面历史候选的正式 S3 失败。

2026-10-21：取消传播修复候选为 Node
`e5e98291ba59c55b514b54793c6d46edcc461be4`，源码树
`07970c700f103bc8bedb225031431c6ce9445d47`，完整 Actions `39538582760`。
Go/source guards、runtime stability、严格 quick/full、七项带流量故障、Core C2、
镜像冒烟及完整 Machine 均通过。Machine artifact `12318529666` 验证原 10 秒
join、旧 token 重启拒绝、新 token 协议恢复和原六批次重放后的六个 SQL 唯一 settled
行；这不是独立完整财务对账或生产 PKI 认证。

该候选的持续负载通过：实际 1808.52358869 秒、37 次带流量生命周期循环，四档
均达到 100/250/500/1000 会话，TCP/UDP/mux 错误均为零，artifact `12320055119`。
正式五组 A/B 的 artifact `12319073827` 共 119/120 measured：候选 60/60、
旧基线 59/60。12 项比较中 11 项满足原阈值，ordinary/long CPU 比率为
`1.0262880019644047`，全部完整比较的 CV 小于 0.10；events/download 缺少
一份旧基线样本，不能计算有效比较比率。

唯一正式失败为 g1 legacy/events/download 的账量缺口：meter `CAPACITY_REACHED`，
FirstGap sequence 66433、约 4.689335697 秒，最终 drop 109274；store healthy，
511 buckets、约 45.49 MB，未触及文件或字节上限。停止前后快照一致，不能将其
解释成 shutdown 新增的缺口。240 份原始 CPU snapshot 与报告逐字段匹配；
119 份 measured 的原 validator 均通过，失败样本即使 CPU 数值自洽仍不接受。
S3 artifact `12319572656` 的 `full_S3_accepted=false`；`PERFORMANCE`、
`equivalent_ab`、`process_cpu_windows` 为 false，持续负载、七项故障、同候选、
带负载生命周期、带负载故障、镜像体积和 allocation windows 为 true。
该结果不宣称 S3 全部完成，也不通过改写基线、容量或阈值补齐失败样本。

独立 CPU profile job `119020899421` 失败，artifact `12318630962` 保留旧基线
events/download 在原事件容量上的缺口：FirstGap sequence 65409、约 4.625 秒，
同 claim 文件同步阶段 wall 峰值约 92.081 ms。store healthy；wall 包含调度和
诊断开销，不能单独归因于磁盘，也不能用来解释另一次正式运行的具体因果。
其余三个诊断 case 完成，这四项不计入正式 A/B。

## `7c9cd91e` 的历史完整运行

修复分支 `fix/native-acceptance-followups` / PR #5 基于 main
`8ec187840c95de179c5e990dfa39636e75bd874a`，采用已评审的 Core
`553641029c0094480cd71105cb7b0a7efe9a9a8a`。该历史完整运行的 Node 为
`7c9cd91e8ca4b0bb9ecfa571872c83d384480bee`，Actions `39535513954`。
以下结果只对应记录的 SHA，不作为后续取消传播修复的验收。

| `7c9cd91e` 的实际结果 | 状态 |
|---|---|
| Go/race、runtime stability、七项故障、Core C2、镜像冒烟 | 通过；七项故障 7/7，无 skip |
| 严格 quick/full | quick 8 顶层/5 子项；full 37 顶层/27 子项通过，另两项不适用不计通过 |
| 30 分钟持续负载 | job `119011177323` 通过；只覆盖该 SHA 的实际运行 |
| 正式五组 A/B 与 S3 ledger | 120/120 measured、11/12 达标；ordinary/long CPU `1.0518343526007607 > 1.05`，job `119011177324` 与汇总 `119020250031` 失败。正式产物 `12318462976` 保留原始失败，不计入 S3 通过 |
| 完整 Machine | 同 SHA 的 `39534639986` 曾完整通过；`39535513954` 在 token 轮换后的 10 秒终止 join 等待失败，最后恢复未执行通过 |
| 独立持久化诊断 | `39534639986` 已采集 20/20；账量全部不完整，10 对无可比较比率，`accepted=false` |
| 合并与注册表交付 | PR #5、main 后续检查和新独立包发布分别跟踪，不由上述 job 推导 |

本轮修复已明确连接 ID 与客户端的对应关系，拒绝把读取超时当作关闭；relay 在 HTTP
handler 返回前等待取消 watcher 清理，消除完整 Naive h2 互通发现的竞争。日志 envelope
复用 canonical payload，并由逐字节等价回归检查；原格式、容量、全部同步步骤与 ACK
边界保留。上述三项已进入 `7c9cd91e` 的 Go/race 和互通结果。

Machine 使用现有 canonical admin operations，保留配置 revision、幂等键、独立凭据
读取权限、真实安装模块回执、购买履约和签名授权。mailbox 的 nil/空数组表示修复后，
实际 WS 端口更新已通过；终止等待的新失败则暴露 TXBoard HTTP/Provider 未传父
context 的源码缺口。后续取消传播修复覆盖 Service worker、Machine discovery/status/
handshake 及升级后 WS I/O；原 10 秒断言、拒绝规则和持久化条件不放松，
已由新候选 `e5e98291` 的 Go/source guards 与完整 Machine Actions 验证。

独立诊断表明 OFF/ON 均可触及原有事件容量，一例达到文件数上限；部分失败窗口与
存储发布或同步阶段 wall 峰值重合，但不能据此断言磁盘 syscall 或编码是唯一原因。
正式样本禁用 observer，诊断不计入 S3 通过；详见 `NATIVE-PERFORMANCE.zh.md`。

Core 准入修复已通过独立 PR #291 合并为 `2dc3e7b`，该合并提交五项工作流及实际
镜像发布成功；Node 保留已评审 pin `5536410`。Core 对新 Node 的采用仍是独立评审。
本仓库发布目标改为 `ghcr.io/anrcm0/txnode`，实际创建、双架构摘要验证与 `dev` 提升
见 `RELEASE-BLOCKERS.zh.md`。试运行和回滚步骤见 `NATIVE-OPERATIONS.zh.md`，
文档准备不代表已执行生产部署或正式版本发布。

## PR #3 合并快照

S0-S4 原开发分支已通过 PR #3 squash 合并，合并提交为
`16f69b5c70a46d0f59594795668a0975a28785cf`，源码树与候选 `235ea2f` 一致。
后续 PR #4 将 main 更新为 `8ec18784` 并采用 Core `d2e70b8c`。

| 最终候选 `235ea2f` 的实际结果 | 状态 |
|---|---|
| Go/race、runtime stability、七项故障、Core C2、镜像冒烟 | 通过 |
| 严格 quick/full | quick 8 顶层/5 子项；full 37 顶层/27 子项通过，另两项不适用 |
| 30 分钟持续负载 | 1810.79 秒、39 轮、最高 1000 会话，业务错误为零，原资源预算通过 |
| 正式五组 A/B | 109/120 完整；双方各五份事件下载 CAPACITY_REACHED，旧侧一份 usage_v2/long EOF；四项噪声未决 |
| S3 汇总 | `full_S3_accepted=false`，Actions `39499950483` 整体失败 |
| 完整 Machine | 旧固定 Core preflight 阻塞，后续链路未执行 |

合并后 `16f69b5` 的 CI `39526625462` 中 Go/quick/C2/镜像冒烟通过，
历史 GHCR 包推送缺少包侧写权限；`8ec18784` 的 CI `39526677523` 则在连接管理测试
出现 `still-live` EOF，后续发布跳过。修复分支 `fix/native-acceptance-followups`
为两条真实连接先建立确定身份，并拒绝把读取超时当作关闭；日志 envelope 复用
canonical payload，所有持久化同步和 ACK 边界保持原值。独立诊断可观察各阶段
wall 时间与有界 backlog；正式样本禁用 hook，诊断结果不计入性能门禁。
这次合并记录不能据静态检查声称容量问题已解决；后续结果在当前工作节单独记录。

Machine 夹具迁移至现有 canonical admin operations，保留配置版本、幂等键及
凭据读取权限，新增真实安装模块回执检查。Core `ws-server` 准入修复在独立
PR #291 验收；固定 Core 的采纳与完整 Machine 运行结果另行记录。
本仓库改用独立镜像包 `ghcr.io/anrcm0/txnode`，旧包权限不再作为发布前提；
实际创建、双架构发布及摘要验证的状态见 `RELEASE-BLOCKERS.zh.md`。

## 历史开发与验收记录

2026-10-21：分支 `feat/interop-acceptance-gates` 已编写以下 S0-S4 实现与验收入口。
最近已取得功能结果的候选为 `454607f4ca999431bcb0af6b2bcf4a5def0eddaf`，
Actions `39489699245` 的 Go/race、quick/full、runtime stability、七项故障、
固定 Core C2 和镜像冒烟均通过，包含启动恢复、WS 端口更新及对应回归。
完整互通为 36 个顶层、24 个子项通过和两项不适用。该提交的正式五组 CPU v2 A/B
已通过：120/120 份样本与原始 CPU 证明核对有效，12/12 组比较在原阈值内；
持续负载 1809.665 秒、38 轮、最高 1000 会话，业务错误为零且原资源预算通过。
同 SHA 的 v2 S3 汇总 10 checks 全 true、`full_S3_accepted=true`。新增普通授权
续期改变了 meter、协议读取与 Service 发布路径，须取得新提交的完整 Actions，
不得沿用 `454607f4` 的通过状态。

`edd07db` 的 Go/race、严格 quick/full、七项故障、runtime stability、Core C2 与
镜像冒烟已通过；`c2823dd` 补强逐 grant 字节断言和真实 Service VMess 后，
Go job 在 VMess 首次 echo 失败，完整续期未执行。源码已修复本仓库 VMess outbound
的 command key salt、长度认证 nonce/密钥、wire tag 和 clear padding，并新增
真实 TCP 12 种组合及本仓库客户端到固定 Xray 服务端的反向互通门禁。
严格清单现为 39 个顶层（37 个适用、两项不适用）、27 个子项，quick 为 8 个顶层。
另修复 panel 重连测试等待点，使其等待客户端收到认证确认后再断言连接状态。
这些变更仅经本地静态检查，必须由新提交重新完成全部门禁；旧失败记录保留。

随后 `14c5401` 的新增反向门禁暴露 authenticated length 的独立 wire 偏差：
两端均缺少长度 AEAD 开销的减/加，不能由同仓库互通发现。`f9d74f2` 校准两端、
加入独立 raw AEAD 向量和共享 Proxy 并发回归；HTTP/1 echo 夹具也先完整读取请求。
该提交的 PR quick 已通过，最终提交仍须全量验收。

`edd07db` 的正式 A/B 为 112/120 measured：旧侧 usage_v2 两份 EOF，另有六份
events/download 因 meter `CAPACITY_REACHED` 失败（候选五组及旧侧一组）。
原始状态表明积压在正常关闭前已触顶，store 未 degraded，不能将它归因于磁盘
总容量。新增封桶后非阻塞唤醒既有 consumer，消除仅等 20ms 扫描的空闲延迟；
不增加 meter/store 容量、不提前 ACK、不改变丢失和失败判定。此改进不能证明
所有旧失败已定位或修复，仍须新提交正式实测。该轮 1810.789 秒、39 轮、最高
1000 会话的持续负载通过，但其 S3 汇总保持 `full_S3_accepted=false`。

历史 `8f41aacb0796f7f3d1cc491e64cfb53665505a89` 的完整 S3 v1 验收已通过：
120 份样本、12 组比较均在原阈值内，持续负载 1809.908 秒、38 轮。后继
`08191208` 的 CPU v2 正式测量取得 118/120 份有效样本，旧基线 long/short 各有
一份 EOF，整轮失败；候选侧 60 份完整，通过的 10 组比较不能替代整轮结果。
该提交持续负载 1812.130 秒、40 轮通过，但新增启动夹具的 race 使 Go job 失败，
此夹具竞争已在 `454607f4` 修正并通过 Go/race。保留旧失败和原测量阈值。

上一候选 `71abaa9` 的 30 分钟负载通过：1810.439 秒、39 轮承载生命周期、最高
1000 会话，业务错误为零且原资源预算通过。正式 A/B 的 120/120 样本完整、字节核对
通过；12 组中 events/long CPU/GiB 比率 1.05263158 越过 1.05，整轮仍未通过。
`a8a008d` 的完整五组在 ordinary/upload CPU 比率 1.10 越界。这些 v1 失败结果保留。
CPU v2 改用带 PID、nonce、序号、单调时间边界及分辨率证据的同进程 CPU 快照，
新旧两侧使用相同工具；五组、预热、计量时间、并发和原阈值不变，不混合 v1/v2 样本。

Node 自己的 Machine 夹具已补齐真实 Provider mTLS、安装初始化/激活、HTTP 账户/
购买/履约、recipient-render、签名授权与 UsageV2 的源码准备；Linux 静态编译、
Python AST 和格式检查通过，完整运行未验收。原业务断言继续保留；固定 Core 的
五项 admission 缺失以及 Node 自身的回执先于监听、授权刷新连接连续性、WS-only
配置三项行为要求详见 `CORE-MACHINE-COMPATIBILITY.zh.md`。启动回执与仅端口变化的
WS 更新已在 `454607f4` Go/race 通过。普通续期新增稳定 meter、原 token owner、
严格封口与窄范围安全读取暂停源码；真实 VLESS/VMess TCP 同流续期、cutoff、unsupported
回退和资格负向回归已编写，静态检查通过，待新提交 Actions。TLS/REALITY 等
不透明承载继续重建，不能声称所有传输的连接连续性。不能将这些全部归因于 Core，
也不能把源码准备或 inventory 检查当作完整 Machine 通过。

中间候选 `6f8ae3c54eaf2466915781b7bee676920e318281` 的 Actions `39470031165`
已通过 Go/race、固定 mux 依赖的 race 回归、quick/full 严格互通、七项负载故障、
镜像冒烟与固定 Core C2。完整互通为 36 个顶层用例和 24 个子用例通过、两项不适用，
不能把不适用项加入通过数。mux 写出尾部竞争修复已包含在该提交中。
独立 Core machine 仍失败；固定 Core 的 installation 准入与 Provider trust/Machine
合约不兼容，完整 owner 链和后续适配要求见 `CORE-MACHINE-COMPATIBILITY.zh.md`。
中间候选结果不代替最终源码的完整验收；最终报告保留实际 SHA、工作流与失败产物。

`f1451d5` 的 Actions `39465904761` 已完成 1810.668 秒持续负载，四档均达到
100/250/500/1000 会话、39 轮承载节点生命周期变更，业务错误和饥饿 worker 均为零。
固定资源预算通过：GC 后 heap 由 655760 增至 122008968 字节，存活对象由 2242
增至 16617，FD 由 20 降至 12，goroutine 由 9 降至 4。该结果证明该提交的
SS 紧凑历史缓存通过原预算，不能代替后续 mux 和 splice 修复的持续负载。

同一 `f1451d5` 的 A/B 已取得全部 120 份正式样本，普通下载 CPU/GiB 仍比旧基线
高约 14.6%，性能 job 保持失败。`6f8ae3c` 的独立 profile 显示原生
`spliceOne -> os.File.Fd -> SetBlocking` 约占 0.45 CPU 秒，旧侧没有这段热点；
后续管道描述符缓存须由同参数、同阈值的新候选再次测量。

`4055c7a` 的严格 quick/full、runtime stability 与七项负载故障通过；Go job 在测试前
遇到模块代理 HTTP/2 下载错误，下游 Core/image gate 未执行，新增 pipe 回归尚未获
该轮测试证据。其独立下载诊断中普通 CPU/GiB 比率约 1.0207、逐段闭包分配消失，
事件模式仍约 1.1204；这些四份诊断不属于正式 120 份样本。

随后源码补齐兼容 splice 部分写后失败的实际计数，并仅对纯本地事件观察显式允许
保留逐 I/O Begin/Complete 的零拷贝。带授权 collector 的路径不允许此优化。
新增真实 pipe 的部分写/关闭/取消/EPIPE/零写与 hook 生命周期回归，下一候选须重新
执行 Go/race、严格互通、Core C2、完整持续负载与原阈值 A/B。Go 模块预取仅增加
三次有限传输重试，不跳过依赖或源码检查。

另将 NativeCollector 完成时钟采样移入原 collector 锁，消除源码中的并发采样交错。
原回退、到期、退休及 token 归属条件全部保留；等待锁后到期的实际尾部仅保留为
不 eligible。新增固定时钟的有效完成和保守拒绝回归。旧 EOF 的 journal 未保留
当时完整 last stamp，修复机制不能冒充旧失败的最终因果证明。

`6efec53` 的 Go/race、quick/full、runtime stability、七项故障、镜像冒烟与固定
Core C2 已通过；严格 full 仍为 36 个适用顶层、24 个子项通过及两项不适用。
正式 A/B 在旧树构建时因 Xray 模块 HTTP/2 下载错误中止，尚无样本；独立候选
events/download 的 coordinator 返回 evidence 错误，账量未确认。测量工具随后
增加两侧相同的只读原 meter 状态快照，以及有界模块预取和锁文件摘要核对；
失败仍为失败，不变更容量、等待、模式或验收阈值。

## 历史 `e5e98291` 分阶段快照

以下功能结果对应 `e5e98291` 的 Actions `39538582760`；性能和持续负载单独记录。

| 范围 | 已编写实现 | 实际验收与边界 |
| --- | --- | --- |
| S0 严格门禁 | 固定客户端/用例清单、quick/full、父子结果核对、意外 Skip 拒绝、SIGKILL 精确阶段握手 | Go/race、严格 quick/full、Core C2 与七项故障通过；2 项不适用不计通过，已支持链路的错误不跳过 |
| S1 REALITY / Naive / TUIC | REALITY 自生成匹配密钥；Naive 信任根/SAN、协商填充帧和 h2 半关闭；TUIC TCP、UDP native/quic 对照和分片，UDP echo 保留 4096 字节断言 | 已进入新候选严格 full 通过结果；保留固定客户端及对照范围，不推广全部客户端版本 |
| S2-A smux/yamux UDP | 依固定 sing-mux 客户端版本对齐 packet 格式，复用 core 策略、限速、计量及撤权 | 新候选完整 Go/race 与严格 full 通过；地址头 mux 和 Mux.Cool/XUDP 的断言分别记账 |
| S2-B Mieru UDP / TCP 复用 | 有界 UDP 状态机、确认/重传/重组、nonce 与重放历史；TCP underlay 多 session、丢包缺口恢复及认证 FIN 尾部；官方客户端网络损伤/精确计量 | 新候选严格 full 通过官方客户端与网络损伤组合；物理 I/O 计数不代替 usage_v2 的独立完整结算对账 |
| S3 原生覆盖 | Service+Coordinator+observer、真实 UDP 周期、I/O 短写/失败、启动回执、WS 端口 Reload、普通续期与严格窗口交接；固定 Core 完整 Machine | 新候选 Go/race 和完整 Machine 通过；原 10 秒终止 join、新旧 token 及 6/6 原批次 SQL 断言保留。Service 续期连续性限已测 VLESS/VMess TCP |
| S3 持续负载/故障 | 30 分钟 100/250/500/1000 会话、带流量撤权/轮换/换证 Reload、慢盘、报告阻塞和 SIGKILL | 新候选 1808.52358869 秒、37 次循环、四档全部达标且错误为零；七项故障 7/7 通过 |
| S3 新旧 A/B | 固定旧 `a1ad269`、同 runner/toolchain、三模式、五组交替、四种 workload、CPU 原始窗口、分配及实际镜像体积 | 新候选 119/120 measured，11/12 比较达标；旧基线 events/download 一份账量不完整，S3 为 false。候选 60/60 完成不补齐旧基线缺失样本 |
| S4 可选/运维 | Mieru 显式整形及低熵编码、严格未知配置拒绝；节点/进程范围连接 ID、受限诊断、迁移说明 | 新候选 Go/race 和严格 full 通过对应组合；试运行、回滚步骤已准备，实际生产试运行未执行 |

## 支持范围与保留的不适用组合

`TestInteropSingBoxMieru` 因固定 sing-box 二进制没有 Mieru outbound 而不适用，
Mieru 使用官方客户端验收。`TestInteropXrayVLESSH2Removed` 因固定 Xray 已移除
独立 h2 传输而不适用。这两项在清单中单独记录，不计为通过。

Naive、Mihomo TUIC 和 smux/yamux UDP 已进入受支持矩阵，不能再用运行错误转为
Skip。固定 curl 的 HTTP/2 CONNECT 仅覆盖其自身路径，不能替代 sing-box Naive
客户端的填充帧、证书信任及错误 SAN 断言。

## 覆盖与交付边界

真实入口与断言映射见 [NATIVE-ACCEPTANCE-COVERAGE.zh.md](NATIVE-ACCEPTANCE-COVERAGE.zh.md)；
负载和比较的参数、资源预算、噪声判定见 [NATIVE-PERFORMANCE.zh.md](NATIVE-PERFORMANCE.zh.md)。
本地只允许源码、格式、语法和静态编译/诊断；功能、race、网络、容器及负载只在
GitHub Actions 执行。

发布权限与 Core 采用单独记录在 [RELEASE-BLOCKERS.zh.md](RELEASE-BLOCKERS.zh.md)。
S0–S4 的源码或 Actions 完成不代表分支已合并、GHCR 已发布、Core 已更新 pin 或已完成生产试运行。
