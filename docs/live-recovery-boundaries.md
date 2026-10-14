# B3.9 Core 恢复边界验收

2026-10-14，固定 `64309e8` 和五个冻结候选源码的 WSL r24 快照，
分别验证 VLESS、AEAD VMESS 的 Core 代际变化、实例漂移及真实 SQL 恢复。
[报告](live-recovery-boundaries-verification.json)保存每个独立案例的源码、原始回执、
HTTP 观察、SQL 备份和恢复哈希；[契约](../../contracts/v2/node-usage/live-revocation-service-v1.md)
明确每条拒绝路径。每例先实际结算历史43/79字节，计费64/118，共182字节。

代际案例停止原 Service 与 Core HTTP 进程，通过 Core CLI 将当前 source
显式升级为 generation 2，并重启实际 Core HTTP 服务。其真实握手提供新代际；
保留 generation 1 的本地 storage 拒绝绑定，Service 初始化失败，kernel 与
listener 未启动。旧 SQL batch/entry 整行哈希和本地 JSON 均保持不变。

实例案例只改变新 Core HTTP 进程的实例配置，原 SQL source 保持原身份。
Core 实际返回 `CORE_INSTANCE_RECOVERY_REQUIRED`，不提供 isolated capability；
Node 在初始化时拒绝启动。这验证同库配置漂移的 Core 拒绝路径；
合法新 Core 实例使用旧 Node storage 的本地身份比较还需独立验收。

回执缺失案例在历史流量前保存完整 SQL 快照，实际182字节结算后再保存第二份。
停止原 Node/Core 进程后，把早期快照实际导回专用测试库，核对 batch、entry、
outbox、方向计费和总账全部归零。随后由 Core 正常发放 source epoch 2
及有限 grant，避免同 epoch 重启拒绝提前遮蔽回执检查。

新的真实 Service 启动 listener 后，常规 worker 查询本地保留的已确认旧回执，
实际收到404 `BATCH_NOT_FOUND` 并停止，listener 关闭。透明转发器在转发前
持久记录 submit 尝试，响应也在回写客户端前落盘，取消连接不会抹掉已观察请求。
第二次启动没有任何 usage submit；原本地 JSON 清单与哈希不变，恢复后的 SQL
用量、方向计费和总账仍为零。该案例是运行期拒绝，不声称 listener 从未打开。

备份与恢复仅使用名称、主机、凭据均受 guard 限制的测试库；SQL 文件0600，
公共制品只有哈希，不导出 SQL、私钥或 token。`--no-tablespaces` 让 MySQL CI
使用测试库权限即可保存应用表，保持无需全局 PROCESS 的边界。

同一 Go 源码的全 Node race 回归475个主测试、334个子测试通过，
5项环境门控跳过、0失败；恢复条件测试另行实际运行。受影响包 vet、PHP语法、
Python编译、actionlint及文档链接检查通过。source 延续也在 r24 使用同一新夹具
复验两协议；此前 `64309e8` 六个远端 workflow 已全部通过，包括独立 Oracle
MySQL8.4 source 延续及 Node 镜像兼容构建。`b1d172e` 的六个 workflow 已全部成功，
包括扩展八案例 Oracle MySQL8.4 恢复 matrix。

本批完成这些隔离恢复案例，未开启生产 v2。生产 Provider、可信时间、完整恢复
协调、全局 writer coverage/drain 与权威切换仍按各自阶段门禁推进。
