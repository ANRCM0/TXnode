# 已挂起的旧内核测试

这些测试直接依赖已删除的 sing-box / Xray 实现（`*singbox.ConnTracker`、
`sing-box` 的 `buf`/`adapter` 包装器、`sing-vmess` 客户端夹具）。
其中 `sing-vmess` 只是**测试客户端**，从未进入运行时依赖或发布产物。P3 完成后，其中
大部分已按原生内核重建并恢复；本目录只保留**仍无法脱离 sing-box 内部类型**的部分。

## 已恢复（原生 txnode 重建）

- `native_usage_linux_test.go` —— usage_v2 授权/刷新/截断生命周期（内核侧用契约桩）
- `native_authority_denial_test.go` —— 授权拒绝关闭真实监听/已建立流，并保留精确计量尾部
- `authorization_adapter_test.go` / `authorization_blocking_test.go` —— 签名授权到期、
  离线报告阻塞下的流关闭与尾部重放
- `membership_withdrawal_test.go` / `meter_generation_test.go` / `traffic_period_test.go` ——
  用户撤销、计量代际、流量周期
- `provider_native_interop_test.go` —— Provider 快照到真实数据面的链路
- `native_c2_interop_test.go` —— 私有 Core/Provider mTLS 到原生 VLESS、离线到期、原周期重放、轮换隔离及结算；客户端使用仓库内的最小 VLESS 线协议夹具

除保留真实 VLESS 协议的 native C2 闭环外，这些测试的协议夹具已从 VLESS/VMess 客户端改为 **SOCKS5**（原生内核自带该入站），
见 `internal/service/socks_fixture_test.go`；断言关心的授权、计量、周期语义与协议无关。

## 原生替代入口与保留参考

| 文件 | 依赖 | 恢复条件 |
|---|---|---|
| `usage_event_store_adapter_test.go` | `usagebucket` + sing-box `ConnTracker.RoutedPacketConnection` 直接造事件 | `internal/service/native_observation_linux_test.go`：真实 Service、TCP/UDP、Coordinator、精确落盘、原记录恢复及错误隔离 |
| `usage_observer_adapter_test.go` | 同上，`RoutedConnection` 包装器 | 同文件：真实 I/O、身份、observer 关闭与恢复、容量/不可写及禁用；细分边界见覆盖映射 |
| `store_io_test.go` / `traffic_period_packet_test.go` | sing-box packet-conn 计数包装器 | 原生 core 实际 I/O 错误测试，加 Service SOCKS UDP 的旧20/新57精确周期分段 |
| `native_core_machine_live_test.go` | 私有 Core checkout 与 machine 联调 | `internal/machine/native_core_machine_live_test.go` + `scripts/tests/node-native-machine/`：固定 Core、生产 Orchestrator、双 Node/WS/轮换/尾部重放；独立 `core-machine` job |
| `protocol_fixture_helpers_test.go` | 已由 `socks_fixture_test.go` 取代 | 文件仅作参考 |

文件名保留 `.go.txt` 扩展名，不参与编译。

## 验收状态与恢复边界

“已恢复”表示存在对应原生测试源码，不等于当前提交已经通过验收。完整覆盖映射、
夹具限制和后续恢复条件见 [原生验收覆盖映射](../NATIVE-ACCEPTANCE-COVERAGE.zh.md)。
新增替代入口必须由候选 Actions 执行。固定 Core 的 legacy installation 无法提供 Node
强制要求的 Provider trust，而 native installation 尚未准入 machine WS 与管理操作；
因此该独立入口仍被合约阻塞，不能声称已完成兼容路径验证。具体调用链和适配要求见
[Core Machine 兼容阻塞](../CORE-MACHINE-COMPATIBILITY.zh.md)。
`TestKernelLocalEventMeterAccountsRelay` 只证明真实 SOCKS5 流量能触发本地事件链路；
它的通过条件是存在事件或持久化桶，不能替代 Service 生命周期、逐方向精确计数、
observer 输出或 packet 路径的断言。`.go.txt` 文件也不属于 CI 的可执行测试集合。
