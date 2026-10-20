# 原生持续负载与新旧性能证据

日期：2026-10-21（Asia/Shanghai）。本文描述源码工具，不代表已经取得 Actions 或生产验收。

## 入口与证据绑定

独立工作流 `Native stability and performance evidence`（`.github/workflows/native-acceptance.yml`）支持手动选择候选 ref 和每日调度。第一项 job 将 ref 解析为不可变完整 SHA；后续 job 均 checkout 该 SHA，并保留提交、源码树、Go 版本、runner 与客户端摘要。它不修改发布、Core pin 或既有 `ci-node.yml`。

所有功能、网络与负载执行仍限于 GitHub Actions。本地仅允许源码检查、Go 静态编译、格式和 AST 检查。缺少客户端、工具编译失败、实际负载不达标与证据不完整均不能记为通过。

## 持续负载 suite

`internal/kernel/txnode/native_soak_linux_test.go` 的 `TestNativeSessionSoak` 只有在 `TXNODE_NATIVE_SOAK=1`、`GITHUB_ACTIONS=true` 且提供固定 sing-box 客户端及输出目录时执行。普通测试发现中的 Skip 不构成负载验收；专用 job 要求最终汇总文件存在、完成四档且持续至少 1800 秒。

负载按 100、250、500、1000 个工作会话逐档运行，每档 450 秒。每三名 worker 分别执行：

- sing-box → 原生 VLESS TCP → TCP echo，保持长连接。
- sing-box → 原生 Shadowsocks AES-128-GCM UDP → UDP echo，保持 SOCKS UDP 控制与数据关联。
- sing-box smux → 原生 VLESS mux 子流 → TCP echo，保持父连接复用。

每个业务请求发送并校验 1024 字节，成功后等待 20ms。每档必须真正达到目标同时活跃会话数，三类完成量均达到固定下限，每名 worker 至少完成 100 次；任何稳定流量的 I/O 错误、内容不一致或容量不足均失败。工具不将预期 worker 数当成已完成会话数。

每 45 秒，一个独立原生 SOCKS Node 在持续负载旁执行新增用户、连接握手与尾部回显、凭据轮换、撤权关闭、删除重加、同端口 Reload 和无效替换失败后的原监听保留。检查旧凭据不复活、旧会话实际关闭和计量尾部不丢失；其突变不允许影响其他 Node 的稳定业务流量。该覆盖是“并行负载下独立 Node 生命周期”，不是负载承载 Node 本体的 Reload 证明。

每 5 秒保存 `soak-samples.jsonl`：实际活跃数、内核连接数、完成/失败数量、业务字节、延迟分桶、goroutine、FD、heap、heap objects 与 RSS。p50/p95/p99 为固定 2 的幂次毫秒桶的上界估计，最后桶为溢出桶，不用于精确延迟结论。持续负载包含测试进程的 origin 和客户端驱动；资源数字不是独立 Node 进程的净占用。

关闭监听并等待 UDP 空闲回收、两次 GC 后，使用首次执行前固定的预算：较预热基线最多增加 96 个 goroutine、32 个 FD、128 MiB 活 heap、100000 个存活对象。它是本夹具的初始回归预算，不是生产容量承诺；禁止在看到失败后就地放宽。

`soak-summary.json` 中 `accepted` 只描述上述负载 profile，`full_S3_accepted` 固定为 `false`。以下 S3 故障仍明确未实现：负载 Node 本体证书和授权 lease 刷新、报告阻塞、慢盘、短写、限速取消、负载中的进程被杀及重启、持久化队列深度。既有崩溃测试与生命周期测试可以提供独立证据，不能自动替代这些组合故障。

## 同 runner A/B 工具

`scripts/native-acceptance.py` 在一个 Linux runner/job 中为以下版本创建临时隔离 checkout：

- 旧基线：`a1ad2695e1143269168c36a274283de3342e91c7`，选择 sing-box 服务端。
- 候选：工作流解析后的完整 SHA，选择唯一原生 txnode 服务端。

两份源码均以固定 Go `1.26.0`、`GOTOOLCHAIN=local`、`CGO_ENABLED=0`、同一组 `-trimpath -ldflags=-s -w` 及既有 release build tags 编译。各 checkout 仅注入本候选版本携带的相同测量 server 模板及各自的 factory 适配；不修改原数据面或模块依赖。报告记录工具、模板、业务二进制和测量二进制摘要，避免将注入的测量入口冒充历史仓库的原生功能。

固定 SOCKS5/RFC1929、IPv4 回环、无 TLS、相同目标服务与 buffer。每种模式分别执行上传、下载、短连接、长连接；每个样本 2 秒预热、10 秒计量、4 个客户端线程。至少 5 组采样，组内按旧→新、新→旧交替。每次使用新进程和全新的状态目录，预热计量与正式计量使用同一个配置。

三种模式：

| 模式 | 实际配置及可比范围 |
| --- | --- |
| ordinary | 两侧普通内核转发；报告仅比较相同 SOCKS 明文路径 |
| usage_v2 | 两侧安装 `NativeStore` / `NativeCollector`、相同授权身份和窗口，启用 enforcing；停止后要求真实持久化记录，并核对原始上传/下载字节等于预热加正式采样的实际协议业务 I/O |
| events | 两侧安装异步本地事件 coordinator，停止后要求存在 durable bucket、状态未降级；保留原始测量，但在两侧事件边界的完整等价性未证明前不输出性能比率，结果为未决 |

`usage_v2` 的真实持久化开销和容量限制属于被测语义；遇到 collector 拒绝、持久化失败、超时或计量不一致即记录未完成，不能自动退化到无计量转发。测试不模拟 Core 回执、正式结算或多轮授权续租。

每份样本保留应用有效字节吞吐、实际完成量、客户端观测的 p50/p95/p99、独立 Node 测量进程 CPU 秒/GiB 与 50ms 采样峰值 RSS。CPU 不包括外部 Python 客户端和目标服务，但吞吐仍可能受它们制约。延迟使用每线程有界确定性样本，不作为无损全量直方图。

构建结果保留两侧相同参数的业务二进制体积；镜像体积和每字节分配量尚未测量。旧 Xray 服务端、其他协议、跨地域实网、TLS 与正式 Core 结算未纳入本工具。不能用本回环结果推广整个双内核版本或生产场景。

## 判定与保留物

固定初始调查阈值为候选吞吐不低于旧基线的 95%，CPU/GiB 不高于 105%。5 组中任一侧吞吐或 CPU 的变异系数超过 10% 则为未决；时钟分辨率不足、缺少样本或模式失败则为未完成。越过阈值要求复现和说明，不自动断言根因。

`report.json` / `report.md` 保留每一份原始样本、失败原因、来源、构建参数和比较范围；每份样本的目录还保留 `server.log`、`sample.json`、持久化状态与 `evidence.json`。工作流保留所有失败产物。Events 等价性未决会显示为未决；普通或 usage_v2 的缺样本、噪声或阈值越界使性能 job 失败。

即使已有可比子集位于初始阈值内，整个报告仍为 `measured-with-limitations`，且 `full_S3_accepted=false`。完整 S3、精确提交 Actions 成功、PR 合并、合并后 main、镜像发布、Core 采用和受控试运行必须分别记账。
