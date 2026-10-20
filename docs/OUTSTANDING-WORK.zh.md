# 剩余事项与验收状态（txnode 数据面）

本表跟踪 S0–S4 的实现和实际验收。开发顺序及完整要求见
[NEXT-DEVELOPMENT.zh.md](NEXT-DEVELOPMENT.zh.md)，严格互通入口见
[INTEROP.md](INTEROP.md)。历史 `a6d0e96` 的“29 通过、6 跳过”不代表当前候选。

## 当前候选状态

2026-10-21：分支 `feat/interop-acceptance-gates` 已编写以下 S0-S4 实现与验收入口。
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

| 范围 | 已编写实现 | 待完成或待验收 |
| --- | --- | --- |
| S0 严格门禁 | 固定客户端/用例清单、quick/full、父子结果核对、意外 Skip 拒绝、SIGKILL 精确阶段握手 | 新候选 Go/race、严格矩阵、Core C2 均须通过；已支持链路的 EOF 不再跳过 |
| S1 REALITY / Naive / TUIC | REALITY 自生成匹配密钥；Naive 信任根/SAN、协商填充帧和 h2 半关闭；TUIC TCP、UDP native/quic 对照和分片，UDP echo 保留 4096 字节断言 | 三类路径在中间候选通过；全部客户端仍须最终候选严格互通 |
| S2-A smux/yamux UDP | 依固定 sing-mux 客户端版本对齐 packet 格式，复用 core 策略、限速、计量及撤权 | 新候选双向大包、父子关闭、实例隔离和精确计量的 Actions 结果 |
| S2-B Mieru UDP / TCP 复用 | 有界 UDP 状态机、确认/重传/重组、nonce 与重放历史；TCP underlay 多 session、丢包缺口恢复及认证 FIN 尾部；新增官方客户端网络损伤/精确计量入口 | 普通官方 UDP、失败目标复用和显式整形在中间候选通过；丢包、乱序、重复、撤权密文重放及同端口 Reload/回滚须最终候选执行 |
| S3 原生覆盖 | Service+Coordinator+observer、真实 UDP 周期、I/O 短写/失败；固定 Core machine 独立入口和受限失败诊断 | Service 的精确 TCP/UDP、存储失败隔离与周期断言在中间候选通过；Core machine 被固定基线的授权/准入合约阻塞，不以 mock、Skip 或更长超时关闭该缺口 |
| S3 持续负载/故障 | 30 分钟 100/250/500/1000 会话工具；真实承载节点撤权/轮换/换证 Reload、限速取消、报告阻塞、慢盘和 SIGKILL 恢复；FD/heap/goroutine 诊断 | `f1451d5` 持续负载在原资源预算内通过；`6f8ae3c` 七项 race 故障通过。最终候选仍须取得同 SHA 的完整窗口和故障证据 |
| S3 新旧 A/B | 固定旧 `a1ad269` 与候选、同 runner/toolchain、三种模式、五组交替、上传/下载/短/长连接、分配窗口及相同 runtime 实际镜像构建；独立 CPU profile | `f1451d5` 的 120 份样本完整且精确持久化字节核对通过；普通及事件模式 CPU 越过原调查阈值，不能算通过。已定位重复 Fd/SetBlocking 热点，最终性能修复须重跑，噪声或越界继续保留未决与原因 |
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
