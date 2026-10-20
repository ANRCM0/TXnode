# 剩余事项与验收状态（txnode 数据面）

本表跟踪 S0–S4 的实现和实际验收。开发顺序及完整要求见
[NEXT-DEVELOPMENT.zh.md](NEXT-DEVELOPMENT.zh.md)，严格互通入口见
[INTEROP.md](INTEROP.md)。历史 `a6d0e96` 的“29 通过、6 跳过”不代表当前候选。

## 当前候选状态

2026-10-21：分支 `feat/interop-acceptance-gates` 已编写以下 S0-S4 实现与验收入口。
中间候选 `9f7f4a010e25c334c9b592074959e95d4a9e6ea2` 的 Actions `39461423092`
通过 Go/race、quick 互通、镜像冒烟与固定 Core C2；完整互通的 Naive 半关闭及独立
Core machine 仍失败。后续已有对应修复及有限失败诊断，必须由新候选重新执行。
中间候选结果不代替最终源码的完整验收；最终报告保留实际 SHA、工作流与失败产物。

| 范围 | 已编写实现 | 待完成或待验收 |
| --- | --- | --- |
| S0 严格门禁 | 固定客户端/用例清单、quick/full、父子结果核对、意外 Skip 拒绝、SIGKILL 精确阶段握手 | 新候选 Go/race、严格矩阵、Core C2 均须通过；已支持链路的 EOF 不再跳过 |
| S1 REALITY / Naive / TUIC | REALITY 自生成匹配密钥；Naive 信任根/SAN、协商填充帧和 h2 半关闭；TUIC TCP、UDP native/quic 对照和分片，UDP echo 保留 4096 字节断言 | TUIC 在中间候选通过；Naive 半关闭修复和全部客户端仍须最终候选严格互通 |
| S2-A smux/yamux UDP | 依固定 sing-mux 客户端版本对齐 packet 格式，复用 core 策略、限速、计量及撤权 | 新候选双向大包、父子关闭、实例隔离和精确计量的 Actions 结果 |
| S2-B Mieru UDP / TCP 复用 | 有界 UDP 状态机、确认/重传/重组、nonce 与重放历史；TCP underlay 多 session、丢包缺口恢复及认证 FIN 尾部；新增官方客户端网络损伤/精确计量入口 | 普通官方 UDP、失败目标复用和显式整形在中间候选通过；丢包、乱序、重复、撤权密文重放及同端口 Reload/回滚须最终候选执行 |
| S3 原生覆盖 | Service+Coordinator+observer、真实 UDP 周期、I/O 短写/失败；固定 Core machine 独立入口和受限失败诊断 | Service 的精确 TCP/UDP、存储失败隔离与周期断言在中间候选通过；Core machine 首轮失败须诊断并重验 |
| S3 持续负载/故障 | 30 分钟 100/250/500/1000 会话工具；真实承载节点撤权/轮换/换证 Reload、限速取消、报告阻塞、慢盘和 SIGKILL 恢复；FD/heap/goroutine 诊断 | 首轮达到 1000 会话并完成 1800 秒，业务无错误但 GC 后资源超预算，不能算通过；已补客户端回收和完整历史窗口的 SS 缓存紧凑存储，最终候选仍须重跑原预算 |
| S3 新旧 A/B | 固定旧 `a1ad269` 与候选、同 runner/toolchain、三种模式、五组交替、上传/下载/短/长连接、分配窗口及相同 runtime 实际镜像构建 | 首轮 harness 的旧默认私网策略、非法授权窗口和事件容量使样本不完整；已改为等价显式配置，仍须核对持久化字节并重跑。噪声或越界保留未决与原因 |
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
