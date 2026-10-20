# 剩余事项与验收状态（txnode 数据面）

本表跟踪 S0–S4 的实现和实际验收。开发顺序及完整要求见
[NEXT-DEVELOPMENT.zh.md](NEXT-DEVELOPMENT.zh.md)，严格互通入口见
[INTEROP.md](INTEROP.md)。历史 `a6d0e96` 的“29 通过、6 跳过”不代表当前候选。

## 当前候选状态

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

| 范围 | 已编写实现 | 待完成或待验收 |
| --- | --- | --- |
| S0 严格门禁 | 固定客户端/用例清单、quick/full、父子结果核对、意外 Skip 拒绝、SIGKILL 精确阶段握手 | 新候选 Go/race、严格矩阵、Core C2 均须通过；已支持链路的 EOF 不再跳过 |
| S1 REALITY / Naive / TUIC | REALITY 自生成匹配密钥；Naive 信任根/SAN、协商填充帧和 h2 半关闭；TUIC TCP、UDP native/quic 对照和分片，UDP echo 保留 4096 字节断言 | 三类路径在中间候选通过；全部客户端仍须最终候选严格互通 |
| S2-A smux/yamux UDP | 依固定 sing-mux 客户端版本对齐 packet 格式，复用 core 策略、限速、计量及撤权 | 新候选双向大包、父子关闭、实例隔离和精确计量的 Actions 结果 |
| S2-B Mieru UDP / TCP 复用 | 有界 UDP 状态机、确认/重传/重组、nonce 与重放历史；TCP underlay 多 session、丢包缺口恢复及认证 FIN 尾部；新增官方客户端网络损伤/精确计量入口 | 普通官方 UDP、失败目标复用和显式整形在中间候选通过；丢包、乱序、重复、撤权密文重放及同端口 Reload/回滚须最终候选执行 |
| S3 原生覆盖 | Service+Coordinator+observer、真实 UDP 周期、I/O 短写/失败；固定 Core machine 独立入口、真实授权夹具；启动回执与原租约 WS 端口 Reload；普通续期稳定 meter 与严格窗口交接 | 启动/WS 在 `454607f4` Go/race 通过；新续期须新提交 Actions，Service 联合回归限普通 VLESS/VMess TCP。Machine 仍被固定 Core admission 阻塞，完整断言未执行 |
| S3 持续负载/故障 | 30 分钟 100/250/500/1000 会话工具；真实承载节点撤权/轮换/换证 Reload、限速取消、报告阻塞、慢盘和 SIGKILL 恢复；FD/heap/goroutine 诊断 | `454607f4` 七项 race 故障和 1809.665 秒、38 轮持续负载均在原预算内通过。最终候选仍须取得同 SHA 的完整窗口和故障证据 |
| S3 新旧 A/B | 固定旧 `a1ad269` 与候选、同 runner/toolchain、三种模式、五组交替、上传/下载/短/长连接、分配窗口及相同 runtime 实际镜像构建；CPU v2 原始进程快照与独立 profile | `8f41aacb` v1 完整验收通过，`08191208` v2 因旧侧两份 EOF 失败；`454607f4` v2 120/120 原始证明、12/12 比较及精确 S3 汇总通过。续期新源码须重跑完整测量，不混用历史结果，阈值不变 |
| S4 可选/运维 | Mieru 显式整形及低熵编码、严格未知配置拒绝；节点/进程范围连接 ID、受限诊断、迁移说明 | 官方客户端所有显式组合、跨重载关闭与诊断隐私须由新候选验收 |

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
