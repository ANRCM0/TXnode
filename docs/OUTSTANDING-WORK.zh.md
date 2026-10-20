# 剩余事项与验收状态（txnode 数据面）

本表跟踪 S0–S4 的实现和实际验收。开发顺序及完整要求见
[NEXT-DEVELOPMENT.zh.md](NEXT-DEVELOPMENT.zh.md)，严格互通入口见
[INTEROP.md](INTEROP.md)。历史 `a6d0e96` 的“29 通过、6 跳过”不代表当前候选。

## 当前候选状态

2026-10-21：分支 `feat/interop-acceptance-gates` 正在完成严格门禁后的修复。
已推送 `e1e91d95d3a74a67c340883ea6c4456c9c4681f8` 的 Actions
`39458346998` 失败；其结果不能用历史绿色记录替代。后续修复仍需新提交的完整验收。

| 范围 | 已编写实现 | 待完成或待验收 |
| --- | --- | --- |
| S0 严格门禁 | 固定客户端/用例清单、quick/full、父子结果核对、意外 Skip 拒绝、SIGKILL 精确阶段握手 | 新候选 Go/race、严格矩阵、Core C2 均须通过；已支持链路的 EOF 不再跳过 |
| S1 REALITY / Naive / TUIC | REALITY 自生成匹配密钥；Naive 信任根/SAN 与认证夹具；TUIC TCP、UDP native/quic 对照和分片 | 首轮真实执行发现 Naive 填充记录兼容问题；UDP 4096 字节夹具的 2048 缓冲截断也需修复并重跑 |
| S2-A smux/yamux UDP | 依固定 sing-mux 客户端版本对齐 packet 格式，复用 core 策略、限速、计量及撤权 | 新候选双向大包、父子关闭、实例隔离和精确计量的 Actions 结果 |
| S2-B Mieru UDP / TCP 复用 | 有界 UDP 状态机、确认/重传/重组、nonce 与重放历史；TCP underlay 的多 session 生命周期修复 | UDP 承载首轮已执行；TCP 拨号失败后复用和低熵多 session 首轮失败，修复须由官方客户端重验 |
| S3 原生覆盖 | Service+Coordinator+observer、真实 UDP 周期、I/O 短写/失败；固定 Core machine 独立入口 | SOCKS 控制连接关闭后的 UDP 生命周期及原周期累计口径修复待新候选执行 |
| S3 持续负载/故障 | 30 分钟 100/250/500/1000 会话工具；真实承载节点撤权/轮换/Reload、限速取消、报告阻塞、慢盘和 SIGKILL 恢复 suite | 持续窗口、实际负载数量、故障断言及 GC 后资源证据必须绑定最终源码；容量不足不能算通过 |
| S3 新旧 A/B | 固定旧 `a1ad269` 与候选、同 runner/toolchain、三种模式、五组交替、上传/下载/短/长连接 | 首轮部分样本不完整，不能比较性能；修复 harness、核对计量等价后重跑。噪声或越界保留未决与原因 |
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
