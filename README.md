# TX-Node

TX-Node 是 TXBoard 体系中的独立 **Agent / Data Plane Runtime**，同时保留 Xboard 协议兼容。它负责 Control Plane 通信、Machine / Node 编排、Kernel 生命周期、用户与流量策略执行、运行状态上报和有限 typed ops；它不是第二个 Control Plane，也不是通用主机管理 Agent。

TX-Node 支持 `sing-box` / `xray-core` 双内核。安装、升级、回滚与主机部署生命周期统一由公开的 TXBoard-Deploy 负责。

运行时职责收口规则见 [`docs/runtime-boundary.md`](docs/runtime-boundary.md)。

下一轮 Core First 演进参考 [主仓 B0 基线](../docs/architecture/v2/README.md)、[Node Usage v2](../contracts/v2/node-usage/README.md) 与 [Credential Provider v1](../contracts/v2/credential-provider/README.md)（Target/Draft）。隔离Usage v2的订阅权威、有限授权租约与撤销版本仍未接管默认业务。当前原生v1默认先持久提交SQL receipt再返回202，`receipt_status=persisted`证明接收记录已保存，`settlement=queued`仍不证明账本结算。

项目起源于 [cedar2025/Xboard-Node](https://github.com/cedar2025/Xboard-Node)。TX-Node 保留 Xboard 面板 API、认证字段和现有节点配置的协议兼容，但不再以周期性同步上游作为开发模式；上游后续修复会按需审查并选择性移植。独立维护策略见 [`docs/standalone.md`](docs/standalone.md)。

## Control Plane Provider 支持状态

普通节点与 Machine Mode 均通过 `panel.provider` 选择远程控制平面；省略该字段或设置为 `xboard` 时使用现有 Xboard 兼容协议。`txboard` 启用 TXBoard 原生 `/txapi/node/v1` HTTP/WSS 协议（Node 与 Machine Mode）；原生 WebSocket 默认由 TXBoard 服务端关闭，不影响 HTTP 轮询。P0.5已完成隔离真实Core/Workerman双节点联调；部署到生产仍须对应环境验收。Standalone模式使用本地控制平面。

Provider 的构造错误处理、配置继承及原生协议验收边界见 [`docs/control-plane-providers.md`](docs/control-plane-providers.md)。

## 协议接入与验收范围

| 协议 | sing-box适配 | Xray适配 |
| --- | --- | --- |
| Shadowsocks（含SS2022） | 已接入 | 已接入；部分加密方式有多用户限制 |
| VMess、VLESS、Trojan | 已接入 | 已接入 |
| Hysteria 1 | 已接入 | 未开放 |
| Hysteria 2 | 已接入 | 已接入，仅v2 |
| TUIC v5、AnyTLS、NaiveProxy、Mieru | 已接入 | 未开放 |
| SOCKS5、HTTP/HTTPS代理 | 已接入 | Node运行时未开放 |

表格依据两内核的[sing-box协议列表](internal/kernel/singbox/singbox.go)和[Xray协议列表](internal/kernel/xray/xray.go)。Xray有SOCKS/HTTP配置生成代码，但当前Node运行时校验未开放。XHTTP/SplitHTTP使用Xray；Machine模式已有按传输选择内核的逻辑。VLESS Encryption适配需要Xray。

P0.5/P0.6已经完成真实Machine控制、持久流量接收、去重扣量、超额撤销、reset观察周期与崩溃恢复。两内核×VLESS/VMess TCP有真实计量/撤销证据，完整Core/Redis worker链覆盖sing-box VLESS/VMess；通用UDP packet计量测试不能代表全部协议认证链。详细见[Machine验收](docs/native-machine-control-verification.json)、[流量验收](docs/native-traffic-quota-verification.json)与[当前开发进度](../docs/architecture/v2/current-progress.md)。

有限离线授权、生产凭据交付/密钥恢复、其余协议完整验收和HA仍在后续路线中。

## 安装与部署

TX-Node 的运行时源码现位于 TXBoard 主仓（后续名 `tx-core`）的 `node/`，保持独立的 Go module、进程和镜像。安装、升级、多面板实例、隔离实例和主机运维脚本由统一公开安装仓维护：

[TXBoard-Deploy 的 Node 安装器](https://github.com/ANRCM0/TXBoard-Deploy/tree/main/node)

推荐安装入口：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ANRCM0/TXBoard-Deploy/main/node/deploy.sh)
```

TXBoard 生成的非交互安装命令同样使用公开 Installer。运行时镜像仍由本仓库 CI 构建并发布到：

```text
ghcr.io/anrcm0/txboard-node:latest
```

Node 运行时与 TXBoard-Deploy 的职责边界：

- **TX-Node**：Go 运行时、ControlPlane、Machine、内核适配、审计客户端、配置模型、测试、Docker 镜像与二进制发布。
- **TXBoard-Deploy/node**：安装/升级/卸载、Docker Compose、`txnode` 运维命令、多面板 `instances:`、隔离实例、配置备份与回滚。
- 运行时仓库不再维护 `deploy.sh` / `install.sh` 的副本，避免安装逻辑双轨演进。

开发者应克隆完整 monorepo 后进入 `node/`。Go module/import 保留 `github.com/ANRCM0/TX-Node`，不因目录移动更名；构建从此目录解析本地模块，无需从旧仓库下载自身源码。需要直接运行二进制时，可以参照 [config.yml.example](config.yml.example) 复制并填写凭据：

```bash
git clone https://github.com/ANRCM0/TXBoard.git
cd TXBoard/node
make build
cp config.yml.example config.yml
# 编辑 config.yml 中的 panel.url、token 和 node_id
./tx-node -c ./config.yml
```

常用开发/发布命令：

```bash
make test
make build
make build-all
make docker
```

## 镜像发布策略

Core、Gateway、Node 使用同一 monorepo `v*` Tag 和根目录发布渠道解析器。主仓新建 Node 镜像包 `ghcr.io/anrcm0/txboard-node`，不会写入、覆盖或转绑旧 `ghcr.io/anrcm0/tx-node` 包。Go 模块、CLI 和 Release 二进制仍使用 `tx-node` 名称。

| 渠道 | 自动触发条件 | GHCR 镜像 | GitHub Release |
| --- | --- | --- | --- |
| **开发版** | Push/合并到 `main`，且 Node gates 通过 | `ghcr.io/anrcm0/txboard-node:dev` + `:dev-sha-<12位monorepo SHA>` | 不创建 |
| **稳定版** | 推送严格匹配 `vX.Y.Z` 的 Git Tag，且 Node gates 通过 | `ghcr.io/anrcm0/txboard-node:vX.Y.Z`、`:latest` | 同一 Tag 的统一 Release 附 Linux amd64/arm64 二进制 |
| **预览版** | 推送 `vX.Y.Z-rc.N`、`-beta.N` 或 `-preview.N`，且 Node gates 通过 | 精确预览 Tag、`:preview` | 同一 Tag 的 prerelease 附双架构二进制 |

- `main` 与 PR 按 Node、相关协议契约及构建脚本路径触发验证；文档或测试-only Push 不发布镜像。Node gates 包含完整 Go 测试、vet、运行时 race/stability 和实际 Docker 版本/配置路径 smoke；镜像发布只在这些检查全部通过后进行。
- `:dev` 指向成功构建且尚未被 `main` 后续 Node runtime 变更取代的镜像。并发文档/测试-only 提交不取消原构建，也不阻挡同一 runtime 的发布；若新的 runtime 提交正在构建或失败，`:dev` 仍保留上一次成功镜像。
- 稳定版更新 `:latest`；预览版只更新 `:preview`，不会覆盖稳定版。非上述格式的 Tag 拒绝发布。
- 新包在首次正式版本发布前只有开发通道，测试安装须显式选择 `dev`；已有容器不会因镜像包名称变更自动切换，升级由 TXBoard-Deploy 管理。
- 维护者正常推送统一 `v*` Tag 后，三个根目录工作流分别发布各自镜像。Node 工作流在自身 gates、双架构 binaries 和镜像发布成功后创建或复用同 Tag 的 GitHub Release，再上传 Node 二进制；这不证明三个镜像原子发布或三个组件均已验收。
- 原 `node/.github/release/VERSION` / `NOTES.md` 保留为旧 Node 发布记录，不再决定统一版本；旧单组件手动打 Tag 工作流已移除。统一 Node CI 位于 [根工作流](../.github/workflows/ci-node.yml)。
- 版本、完整 commit 和 OCI revision/source 来自 monorepo 构建输入。Docker context 仅为 `node/`，不依赖其中存在 `.git`。
- 开发版不应部署到生产环境。安装器默认使用稳定渠道 `:latest`；更新 GHCR 标签不会自动更新正在运行的容器，实际升级需由 [TXBoard-Deploy](https://github.com/ANRCM0/TXBoard-Deploy) 执行。
- **发布不等于上线验收**：首次启用原生 TXBoard 模式前，仍需验证 Machine / Node 联调、WS、双内核及异步流量队列结算与持久化重放。

## 访问审计（可选 · 双面板）

**一个 sing-box Reporter、两个协议适配器。** 数据采集、规则匹配、限长队列和失败重试是共享实现；根据 `panel.provider` 选择审计规则/上报传输。默认关闭，不作为流量计费依据。

| Provider | 审计 API | 面板端要求 |
| --- | --- | --- |
| Xboard `xboard` | 保留 `/api/v1/plugin/access-audit/rules` 和 `/report`，原 Xboard 插件认证不变 | 需另外安装并启用兼容的 AccessAudit 服务端插件 |
| TXBoard `txboard` | 原生 `/txapi/node/v1/audit/rules` 与 `/audit/report`，Bearer + Node/Machine 身份请求头 | TXBoard 原生规则/日志管理模块及迁移表 |

TXBoard 后台入口：**节点管理 → 访问审计**，可增删编辑规则、启停规则并查询记录；默认的管理员操作审计日志是另一套功能。TXBoard 原生上报为每个连接事件生成可重试的稳定随机 ID，服务端按节点和事件 ID 去重。API 最多接受 200 条/批，1 MiB 请求体。Xboard 兼容 payload 不变。

示例（两个 Provider 都适用，前提是面板实现了对应审计接收接口）：

```yaml
audit:
  enabled: true
  report_all: false
  batch_max: 50
  flush_interval: 15
  rules_refresh: 5
  queue_cap: 5000
```

- **`report_all: false`（默认）**：只上报规则命中，0 条启用规则 = 0 条事件；`report_all: true` 会采集全部观察到的连接并显著提高隐私与性能成本。
- **仅 sing-box** 的内嵌连接采集已适配；Xray、Standalone 暂不具备同等嵌入式采集能力。
- 审计队列位于内存，拥塞/进程异常时可能丢失日志；与持久化的流量计费待确认批次完全隔离，不保证审计恰好一次或崩溃后重放。
- TXBoard 默认 30 天留存，依赖部署方持续运行 Laravel 调度器（`schedule:run`）。日志可含敏感访问目标和来源 IP，只有授权管理员应有查询权限。
- 上线需先部署原生 TXBoard API/数据表，更新节点镜像，再显式启用 `audit.enabled`。使用旧 TXBoard 版本时请保持关闭。

相关实现：[Reporter](internal/audit/reporter.go)、[双传输适配器](internal/audit/transport.go)、[可选能力](internal/controlplane/capabilities.go)、[原生协议契约](../contracts/node-protocol/access-audit-v1.md)。

## Xboard 兼容与项目来源

TX-Node 保留 Xboard 面板协议及兼容配置字段。`xbctl` 和 `xboard-node` 二进制兼容产物已从 TX-Node v2 主线移除。历史 native/systemd 安装仍可由 TXBoard-Deploy 的 Node 安装器识别、迁移和清理；新的 Docker 运维入口统一为 `deploy.sh` / `txnode`。

项目历史来源于 [cedar2025/Xboard-Node](https://github.com/cedar2025/Xboard-Node)。后续 TX-Node 版本独立维护和发布；上游修复仅按需审查、移植，不再整分支同步。详见 [`docs/standalone.md`](docs/standalone.md)。

## License

MPL-2.0。项目保留其历史来源及适用的上游版权与许可证声明。

> **Disclaimer**: This project is for educational and learning purposes only.
