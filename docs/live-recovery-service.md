# B3.9 source epoch 延续验收

2026-10-14，固定 `4779b32` 和四个候选源码文件的 WSL r22 快照完成
VLESS、AEAD VMESS 的真实 Service 重启与 source epoch 延续。
[报告](live-recovery-service-verification.json)保存冻结源码、依赖、请求、回执和 SQL 备份哈希；
[契约](../../contracts/v2/node-usage/live-revocation-service-v1.md)定义恢复边界。

首个进程使用真实协议上传43、下载79字节，常规 worker 封存并取得 Core 持久 ACK；
Core 分方向按3:2向下取整结算64/118，共182字节。进程正常结束后，Core CLI
为新 installation 分配 epoch 2，再次分配返回同一 source，并签发新的有限 grant。

第二个实际 Service 进程使用原 mode 目录，查询历史 settled receipt 后，
通过真实协议上传37、下载19字节，以 TCP FIN/EOF 完成在途 I/O。
新 epoch 独立产生第二个 batch，结算55/28，共83字节；期间累计上传119、下载146，
合计265。SQL 恰好有两条 batch、两条 entry，再次 worker 扫描为空。

新进程前后的历史本地 JSON 文件哈希完全相同，历史 SQL batch 和 entry
整行哈希保持相同。透明 TLS 观察器单独确认新进程查询旧回执，且没有重提交
旧 batch；旧 User u/d 仍为0/0，原生流量批次表为空。每种协议完成后，
核对专用测试库的确切2/2/265状态，保存0600完整 SQL 备份再重建该测试库。

同一 Go 测试源码的完整 Node race 回归475个主测试、334个子测试通过，
4项环境门控跳过、0失败。真实协议恢复测试已另行运行，跳过数不替代其证据。
受影响包 vet、Python 编译和新增恢复 workflow 的 actionlint 通过。
新增 Oracle MySQL8.4/Redis7.4 独立协议 matrix 将在推送后核对。

这完成 B3.9 的 source 延续切片。Core 实例/回执代际不匹配、真实 SQL 恢复后
已确认回执消失仍待实际验收；生产 Provider、可信时间、全局写入排空及权威切换
门禁继续保留。本阶段没有修改 Core 权威写入候选，也没有开启生产 Node v2。
