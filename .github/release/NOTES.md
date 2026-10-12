# TX-Node v2.3.0

本文件保留合仓前拟发布的 TX-Node v2.3.0 说明，聚焦原生 TXBoard 节点协议、多控制平面适配和运行时可靠性。它与旁边的 VERSION 是历史记录，不再驱动 `tx-core` 统一版本或发布；当前策略见 [Node README](../../README.md)。

## 新功能与改进

- **TXBoard 原生控制平面**：新增 `panel.provider: txboard`，支持 `/txapi/node/v1` Bearer + Node/Machine 身份请求头、握手、配置及用户拉取、流量上报、Machine 节点发现和状态上报。
- **原生 WebSocket**：适配 TXBoard 版本化事件帧、重连、心跳、用户/配置事件及 Machine 节点消息。服务端 WebSocket 可选，HTTP 轮询仍可独立运行。
- **多面板兼容**：保留 `panel.provider: xboard`（缺省）和 Local/Standalone 路径。Xboard 协议继续由独立适配器提供，不影响 TXBoard 原生通信。
- **稳定性与计费保护**：运行时采用持久化待上报流量批次及稳定批次 ID；TXBoard 的 `HTTP 202` 代表队列已接收，并不代表 MySQL 已完成结算。请结合服务端队列与账本核对。
- **部署职责边界**：安装、升级、回滚以及历史 native/systemd 迁移由独立 `ANRCM0/TX-Node-Installer` 负责；本仓库不再发布历史宿主管理工具。

## 兼容性与注意事项

- 已移除旧 `xbctl` / `xboard-node` 的**新版发布产物**；历史安装仍可由 Installer 识别和迁移。现有 Xboard 协议适配器与旧 Compose 配置路径回退暂时保留。
- `audit.enabled` 的嵌入式 AccessAudit reporter 目前仅通过 Xboard 兼容适配器暴露旧审计接口；**TXBoard 原生 Provider 尚不支持原生审计上报**。请在原生 TXBoard 部署中保持 `audit.enabled: false`。
- 对现有 Docker 部署升级前，请使用新版 Installer 检查 `/etc/txnode` 的持久化挂载，备份或迁移原容器中的未确认流量文件；不要用空挂载直接覆盖旧运行时目录。
- **发布前验收**：Go/CI 通过不替代真实 TXBoard + TX-Node + Installer 联调。生产发布前仍需验证节点和 Machine HTTP、可选 WebSocket、流量队列结算与重启重放，以及 sing-box/Xray 代表性协议。

## Release assets

发布工作流为 Linux 双架构生成以下运行时二进制：

- `tx-node-linux-amd64`
- `tx-node-linux-arm64`

Docker 多架构镜像继续发布到 `ghcr.io/anrcm0/tx-node`。合仓后的根工作流使用统一 `v*` Tag、开发版 `dev-sha` 和 stable/preview 渠道，并向统一 Release 上传双架构二进制。本文件不会自行打 Tag或改写统一 Release 的说明。
