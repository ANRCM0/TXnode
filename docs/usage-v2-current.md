> Retirement update (2026-10-16): isolated Usage Service, unsigned TXBoard user snapshots, old User UUID signing and delta/device pushes are retired. This document preserves earlier implementation evidence; current runtime uses [Provider delivery](native-provider-node.md) and [native subscription usage](native-subscription-usage.md). Shared kernel, finite authority, receipt and recovery safeguards remain.

# Node Usage v2 第一运行切片

状态：实现受限 schema 的批次编码、独立持久 spool、HTTP 接收确认与状态恢复；默认运行路径仍为 v1。此切片不宣称完成授权租约、撤销或内核采集分段。

中心设计：[Node Usage v2](https://github.com/ANRCM0/TXBoard/blob/main/contracts/v2/node-usage/README.md)。

## 协议与 HTTP

`POST /txapi/node/v2/usage/submit` 提交 `{payload,payload_digest}`。`POST /txapi/node/v2/usage/batch/get` 提交 `{protocol_version,node_id,source_epoch,batch_id,payload_digest}`，只查询已认证的节点及其历史来源。两者复用 Native Bearer、`X-TX-Node-ID`、可选 `X-TX-Machine-ID`，要求 HTTPS 且禁止重定向。

外层使用 TXAPI `{data,request_id}`。成功 data 为回执，字段为 `protocol_version:2`、`core_instance_id`、`receipt_generation`、`node_id`、`source_epoch`、`batch_id`、`payload_digest`、`receipt_status:"persisted"`、`settlement_status`、`accepted_at`、`receipt_id`；settled 另含 `settled_at`。结算状态接受 `pending|processing|retry_wait|quarantined|settled`。查询查无记录须以 404 和 `error.code:"BATCH_NOT_FOUND"` 表示。409 `BATCH_PAYLOAD_CONFLICT` 保持原文件。HTTP 202、v1 queued、无类型 2xx 都不是持久接收确认。

握手可选 `usage_v2` 对象：`protocol_version:2`、`core_instance_id`、`node_id`、`source_epoch`、`receipt_generation`、`retention_seconds`、`max_late_report_seconds`、`receipt_retention_seconds`、`issued_at`、`grants`。retention_seconds 是 Node 完整 payload 的最短恢复保留窗，不能短于最大迟报窗。grants 仅含 `user_id`（Core 批准的现有内核运行 ID 映射）、`access_subject_id`、`auth_snapshot_id`、`tariff_revision_id`、`terms_id`、`usage_period_id`、`issued_at`、`lease_expires_at`、`revocation_version`；业务 ID 和版本为规范十进制字符串，时间是 UTC safe integer 秒。此对象不含 Provider 凭据。

回执必须逐字段匹配本地批次、Core 实例与 receipt generation。generation 改变或已确认批次查询缺失会停止普通重放，保留恢复材料并要求显式受审计恢复，不能解释为首次接收。旧 epoch pending 可以查询及重放；禁止用新握手 epoch 改写旧 payload。

## 编码与持久化

payload 使用中心 draft 字段与 entry 顺序。实现只支持这一受限 ASCII 字符串、safe integer 时间 schema 的 canonical JSON，不是通用 RFC 8785 编码器；该 schema 的输出与 JCS 一致。键按 ASCII 字典序，entries 按 `(access_subject_id,auth_snapshot_id,tariff_revision_id,usage_period_id)` 字典序，重复键拒绝。业务 ID 非零规范十进制，字节允许零且每方向至多 1 PiB。解析前限制 1 MiB，拒绝重复 JSON 键、未知字段、非法时间、非规范十进制与不排序 entry。中心示例 golden digest 是 `sha256:d7a022a63a0937d08be73abb133abf633350e187b128d8dc40485c74619c5eee`。

独立 v2 spool 保存完整提交对象、Core 实例、协议、协商恢复参数及回执，不读取或转换 v1 pending。写入采用同目录临时文件、0600、文件 fsync、原子 rename、目录 fsync；失败后不发送且不更换批次 ID。启动遇到损坏记录会失败并保留原文件，不静默跳过。单进程持有 Linux 文件锁；spool 容量不足会背压。persisted、quarantined 和 settled 均保留本地 payload；此切片没有自动 GC，不能提前删掉恢复材料。

## 启用边界

Native adapter 提供显式 v2 reporter 构造入口，需 Core capability、独立持久目录、v1 pending 已清空、调用方确认采集计数为空的交接。接口只接收已经按授权/period/tariff 边界切好的 `[started_at,ended_at)` 与原始字节，不猜主订阅、不预乘倍率。默认 Service 的 v1 tracker 不自动接入 v2，它无法证明旧累计计数属于哪个授权区间；完整 runtime 切换需要分段采集和租约/撤销执行验收。

失去 HTTP 响应后先查询，同身份同摘要恢复回执；没有接收记录时才重放原提交。persisted 后只查询结算，不因当前授权已过期改身份。Core 已持久但响应丢失、同 ID 改摘要、epoch/core/generation 回执不符、磁盘/fsync 失败均须保留原记录。

2026-10-12 在 Linux / Go 1.26.3 上对 `usagev2`、`txboard`、`controlplane`、`reporting` 执行 `go test -race -count=1`，56 个主用例和 39 个子用例通过，无跳过。测试包含关闭 spool 后旧实例不能在失去目录锁时覆盖新所有者的会话。真实 Core HTTPS 互操作的可复现入口位于中央仓库 `scripts/tests/usage-v2-interop/`；此证据仍不等于默认 Node Service 已切换。
