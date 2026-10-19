# 已挂起的旧内核测试

这些测试直接依赖已删除的 sing-box / Xray 内核实现（`*singbox.ConnTracker`、
`sing-vmess` 客户端夹具、sing-box inbound），随旧内核一起移除。它们覆盖的是
**usage_v2 原生计量、本地事件桶、native 授权联调**这几条链路；这些链路需要
`internal/dataplane` 的 per-IO chunk 钩子（`ChunkHook`）才能在新内核上重建。

处理方式：

1. 文件名保留 `.go.txt` 扩展名，**不参与编译**，作为可执行规格保留；
2. 恢复顺序（对应 REWORK-PLAN 的 P3）：
   - 数据面 `ChunkHook`（Begin/Complete）+ `usage_v2` 的 `NativeMeter` 实现；
   - `usagebucket.Meter` 的 Bind/Session 接入；
   - 逐个把夹具从 sing-vmess 客户端换成 VLESS/VMess/Hysteria2 客户端（数据面自带服务端）；
3. 在此之前，`kernel.type: txnode` 对 `usage_v2` 明确返回不可用，服务会以
   `NATIVE_USAGE_SESSION_STOPPED` 拒绝该模式，而不是静默降级。
