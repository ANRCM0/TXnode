# B3.8 真实协议 Service 用量验收

2026-10-14，本批在固定 `b914536` 提交与精确候选文件的 Linux 隔离快照中，
分别完成真实 VLESS 与 AEAD VMESS 的 Service → sing-box → Core SQL 结算闭环。
验收记录见 `live-protocol-service-verification.json`；契约见
`contracts/v2/node-usage/live-protocol-service-v1.md`。

测试通过 `NewChecked` 正常构造 Service、native controlplane 和 sing-box，
真实锁定客户端连接实际监听器与独立回环 TCP origin，没有注入内存内核、
手工调用 tracker 或提供用量计数映射。独立 origin/client 记录的解码数据分别
为上传43字节、下载79字节；实际计量点产生相同原始方向。客户端发出 TCP FIN，
origin 观察真实 EOF 并关闭写半部，实际 I/O 全部完成后由常规 worker 封存区间。

本批唯一既有运行时代码修改在 `singbox.go` 的 Start：仅当明确准备了 bounded
usage tracker 时，先验证整组生成的 inbound，再将 listen 固定为127.0.0.1，
然后才创建内核与监听器。普通 v1 的 `::` 默认监听保持原语义。默认监听回归、
完整 inbound 校验与真实 `/proc/net/tcp` 监听地址检查均通过。

两种协议均在关闭 Service 之前，等到了实际5秒 report ticker 发出的 native
心跳。透明 TLS 转发器观察 Core 返回202 accepted、protocol1、settlementnone；
请求没有非空 Traffic 或 traffic_batch_id。原生 User u/d 保持0/0，原生流量批次
表为空。错误 UUID 被真实协议认证拒绝，未到达 origin。

Core SQL 持久化原始 batch/source/digest/receipt 与 accepted outbox，常规结算
worker 分方向计算3:2向下取整：上传64、下载118、合计182。第二轮扫描为空，
关闭并重新打开 spool 后取得原始 settled receipt。原批次重放不新增计费，
同 batch ID 的不同规范内容返回真实409；同 source epoch 新启动 live Service
在监听器创建前拒绝。VLESS、VMESS 的批次与回执各自保留，不复用证据。

本地完整 Node race 回归473个主测试、332个子测试通过，3项条件跳过、0失败。
其中旧实际 Core fixture、新 live protocol fixture 为显式独立运行，其跳过不
被计为协议验证；新 fixture 的两种协议本批已分别运行成功。受影响包 go vet
和新增协议矩阵 workflow 的 actionlint 均通过。远端 CI 尚待主任务提交推送。

本批不完成全部 B3。开放真实协议连接时的原生轮询变更、租约到期、UDP/mux
拒绝、Core恢复代际变化与新 epoch 接续仍需独立运行验收；生产 Provider、PKI、
多 Service 和灰度切换也不因本批测试通过而启用。现有 isolated-copy gate、
未知尾部拒绝、半开区间和有限租约规则全部保持。