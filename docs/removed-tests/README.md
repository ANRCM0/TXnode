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

## 仍挂起

| 文件 | 依赖 | 恢复条件 |
|---|---|---|
| `usage_event_store_adapter_test.go` | `usagebucket` + sing-box `ConnTracker.RoutedPacketConnection` 直接造事件 | 需要把夹具改为"真实 txnode 内核 + Coordinator"驱动（部分覆盖已由 `TestKernelLocalEventMeterAccountsRelay` 提供） |
| `usage_observer_adapter_test.go` | 同上，`RoutedConnection` 包装器 | 同上 |
| `store_io_test.go` / `traffic_period_packet_test.go` | sing-box packet-conn 计数包装器 | 需要新的数据面 packet 计数夹具 |
| `native_core_machine_live_test.go` | 私有 Core checkout 与 machine 联调 | 同上 |
| `protocol_fixture_helpers_test.go` | 已由 `socks_fixture_test.go` 取代 | 文件仅作参考 |

文件名保留 `.go.txt` 扩展名，不参与编译。
