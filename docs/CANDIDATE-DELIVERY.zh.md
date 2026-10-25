# v2.3.0-rc.1 候选交付说明

日期：2026-10-25（Asia/Shanghai）。用户选择先完成可交付候选，目前没有固定
性能 runner 或实际测试主机。本说明跟踪本轮源码、Core 采用、验收和构建交付，
完整 S3 v3 与实际环境验收继续单列。

## 2026-10-25 实际候选交付

`v2.3.0-rc.1` 已于 2026-10-25 13:28:42（Asia/Shanghai）发布为 GitHub
prerelease。标签源码为 `f20965691b87558ff212eb673866eec1bf679f25`，tree
`a6e99a4311478c7e5df03863a80555cfa65c77bb`。标签 Actions `40165006752`
的 12 项实际任务全部成功：八项功能门禁、两个架构的二进制构建、镜像发布和
Release 附件交付。未选择的 S3 与独立诊断不计通过。

本标签 full artifact `12587856948` 的原始事件为 38 个顶层、38 个声明子项通过，
两项上游不适用单列；清单、客户端 pin 与所有子项已核对。Machine `12588550762`
本次原四份批次对应四行唯一 settled SQL；C2 `12588191594` 同样记录精确的
Node `f2096569` / Core `097dc97` 来源。原十份批次属于前置 `9f636d4c` 运行。

实际下载的四份附件、GitHub 资产摘要、`SHA256SUMS`、发布清单及原构建记录已
交叉核对；两份 ELF 与各自原 Actions artifact 字节完全相同，内嵌版本、提交、
GOOS/GOARCH、CGO=0 和 `vcs.modified=false` 均相符，没有在本机执行二进制。

| 二进制 | 字节数 | SHA-256 |
| --- | ---: | --- |
| `tx-node-linux-amd64` | 45191330 | `282b9e50a6e85a3b416d5a0d108cbee2369e97591e6a0f54719ba2008730fe40` |
| `tx-node-linux-arm64` | 41484450 | `65dccfa403b8f594bb7e3fd403b408b59ece7f8794f5ed7dc851002a2dce3772` |

| Node 候选镜像 | 不可变摘要 |
| --- | --- |
| Index | `ghcr.io/anrcm0/txnode@sha256:d9f120277615af1c09a83772858a8552d9622c5df0ef82c8fa5a44b4be78d22e` |
| linux/amd64 | `sha256:c4412029ed83ba50bfe99f55a973ad38f65ff5223859de6face71b59ee7291e7` |
| linux/arm64 | `sha256:023bba4a3f6c8300eb96ddc94ce1e19217ae405a8e4309055d4ed77116e87998` |

Actions 的双架构元数据与离线 capabilities 均实际通过，arm64 使用 QEMU。
2026-10-25 13:42 的匿名注册表读取确认本标签及 `preview` 指向该 index，两个
子 manifest/config 的实际 SHA-256、架构、版本和源码标签一致。`preview` 会变化，
部署锁使用这里的不可变摘要；没有提升 Node stable/latest。

## 交付内容与版本关系

- Mieru `seed` / `unlockAll` 已由 PR #19 交付，按固定官方 v3.38.1 语义生成，
  保留显式零/false 优先、严格范围、重复字段和冲突拒绝。
- Node 连接管理已由 PR #20 交付，沿原 Service/Kernel/Session owner 分页和关闭，
  原 I/O token、计量尾部、撤权和 Reload 归属不变。
- Core PR #307 提供节点详情页、三个封闭管理员操作和当前作用域的结果回执；
  合法迟到结果得到 `accepted:false`，保持 unknown，Node 继续原 socket 的心跳。
- 发布准备 PR #21 已合并为 `c4954346`。候选使用 `preview` 通道；稳定版 `latest`
  的提升不属于本次候选交付。

| 身份 | 精确来源与用途 |
| --- | --- |
| 合并前完整功能 Node | `9f636d4ccaa5fd00cc2282cb8e64490d49c564e3`，tree `3958ecd15cb81b4c2fa5b2400b6b4602e14cd674` |
| Node 固定支持的 Core | `097dc9748bbe665ae7672c43827998f1e9420e3a`，tree `ceb234b78c450eb0791151e093601c77e5fe523e`；manifest 要求 `node-connections/v1` |
| Core 正式采用的 Node | `9f636d4ccaa5fd00cc2282cb8e64490d49c564e3`；PR #307 已合并为 Core `7985843ddd94faebbecd201bd7c55b4f998f677b`，tree `c671683a9a2e3476d606dad8f285493a76f6a863` |
| 标签和二进制的精确源码 | `f20965691b87558ff212eb673866eec1bf679f25`；以 `release-manifest.json` 和标签 Actions 为准，文档后续提交不改写该构建来源 |

最终候选文档与已执行完整功能验证的 Node 分别记录提交；生产 Go、模块锁与
构建输入保持相同，不把不同提交号写成同一源码树。Core 组合候选相对固定的
`097dc97` 只更改测试、工作流及 Node gitlink，应用、合约和 Web 源码保持相同。
最终文档、合并、标签和构建仍须各自取得实际来源及 CI，不互相替代。
Node PR #22 经正常 merge 保留 `9f636d4c` 在 main 历史中；其与标签源码的全部
618 项非 Markdown blob/mode 相同。Core 正常 merge 保留 `097dc97` 在 main
历史中；固定基线与 Core 主线除 CI、夹具脚本及 Node gitlink 外的 1603 项
blob/mode 相同。Core 所选 Node 与标签源码分别记账，不把不同 SHA 写成同一树。

## 已取得的候选功能证据

Node `9f636d4c` 的完整 Actions `40162774358` 已成功，八个实际执行的 job
包括 Go/race 与源码守卫、quick、full、runtime stability、固定 Core C2/Machine、
镜像配置/元数据和分类。未选择的 S3、诊断、发布 job 为条件跳过，不计通过。
常规 PR CI `40162775732` 也已成功。

| 范围 | 当前候选的实际结果 |
| --- | --- |
| 完整互通 | artifact `12587510910`，原始事件 38 个适用顶层、38 个子项通过；两项固定上游不适用继续单列 |
| 官方隐式 Mieru | TCP/UDP 各四个 seed 用例均实际通过；全部客户端 pin 与声明子项已核对 |
| Mihomo 启动控制 | 独立本地 DIRECT 请求在原八秒预算内证明客户端就绪，不预先访问 Node；声明的 startup-control 子项实际通过 |
| 真实固定 Core Machine | artifact `12586759266`；正式管理员分页、跨 Node 拒绝、原键重放、目标 EOF、其它流继续；原十份批次与十行唯一 settled SQL 对应 |
| Core C2 来源 | artifact `12587596251`，Node/Core SHA 与 tree 均与上述组合一致 |
| Core 独立组合 | `e2ae095b` 的 job `121077874060`、artifact `12587146921`；采用相同 Node，本次原六份批次对应六行唯一 settled SQL，不套用固定 Core gate 的十份 |
| 迟到应答 | Node 实际 WS 回归在原 socket 完成后续心跳；Core API job `121061923458` 实际通过三种身份的迟到结果、unknown 保留及原 socket 断言 |

静态 preflight 仍记录 `runtime_verified=false`；真实结果来自完整运行的 result，
不将 inventory 齐备当作运行成功。公开产物只保留固定断言、计数和原始私有
结果摘要；完整 SQL/payload 不导出，它不是独立完整财务对账。

Machine HTTP 使用原 Core 的 Octane/Swoole 入口、四个 worker 和固定 Swoole
6.2.3，实际记录字节码缓存与版本。固定 Core 运行中九个 gzip 授权拒绝、独立
Core 组合中八个 gzip 拒绝均被正确观测。代理只对有上限的副本解码，原响应头和
字节继续原样转发；真实网络回归同时断言原压缩字节相等、错误码及损坏/超大拒绝。

Core 的合并前精确 head CI `40162819951` 实际通过 26 项，Images `40162819917`
成功。合并后 `7985843` 的真实 Machine artifact `12587559546` 本次为原八份
批次/八行 SQL，沿相同 Node `9f636d4c` 执行；合并后完整 CI `40164915929`
已在 `7985843` 实际通过 26 项选中检查。普通 Core API 的 43 项条件跳过不计为
该 API job 的通过项。

Core main Images `40164915924` 的构建验收及双架构发布均已成功，三映像门禁
`12587942062` 与配对资源/备份 `12587767355` 已核对。匿名读取确认实际发布为
`ghcr.io/anrcm0/txboard-core@sha256:4689da2c542539fd88aba9c86098cf558e6d530b94861f9d04103f81a1388d68`，
两个架构 config 均记录 Core `7985843`；旧 `txboard` 仓库的兼容别名摘要相同。
该 Core 发布只核对双架构注册表元数据；实际镜像运行门禁与 Node 的双架构离线
capabilities 分别记账，不推广为 Core arm64 运行或物理主机验收。测试模块升级
及备份恢复也不等于生产升级。

## 发布产物和读取顺序

标签工作流必须在该源码通过完整互通、runtime stability、固定 Core C2/Machine
之后构建和发布。预发布包含：

1. `tx-node-linux-amd64` 与 `tx-node-linux-arm64`。
2. `SHA256SUMS`，分别对应两份原二进制的 SHA-256。
3. `release-manifest.json`，记录完整源码 SHA/tree、tag、run、固定 Core、二进制
   原构建记录和已验证的双架构不可变镜像索引/子摘要。

下载后先核对标签来源、manifest 与二进制校验和，再选择目标架构的镜像摘要。
发布 job 校验原 build record，拒绝二进制被改写、混用来源或缺少镜像离线执行证明。
arm64 capabilities 使用 QEMU，这不是物理 arm64 主机验收。

## 保留的未完成项与失败

完整 S3 v3 仍为 false。正式 `40121606962` 的 120 份样本中，普通上传/长连接
CPU 比率 1.05657 / 1.07283 超过 1.05，usage_v2 下载 p99 比率 1.10584、CV
0.27941 按原规则未决。有限诊断及默认原基线的另一次夜间运行不替换该拒绝。
最新分项和夜间原始数据核对见 [性能记录](NATIVE-PERFORMANCE.zh.md)。

本轮早期组合恢复 usage_transport 拒绝、镜像调度 100 秒超时及限流初始预算键
数量不符继续保留，后续通过不构成其唯一根因已关闭。PHP 开发服务器下的最新
失败中，兄弟节点五份 pending 的逐项查询/提交累计超过原两秒页；最终固定 Core
运行也实际恢复五份 pending，HTTP 跨度 1.89056 秒，但不据此保证任意 16 份批次
都能在两秒内完成。超预算继续拒绝监听并执行原退避，不能清空原批次换取启动。

Octane 下另一次跨 Machine gate 已独立确认 HTTP 拒绝及 Workerman 关闭均发生，
失败的是代理从 gzip 响应中读取 401 错误码的证据；相应解码与原字节保持回归已在
最终 Node 的 Actions 实际通过。这不改写之前开发服务器失败的原因。

原限流观测的键集合等值断言另改为记录原 PTTL 与耗时：
任何新预算键仍拒绝，旧键消失须符合其原到期时间；不清除预算或修改生产 TTL。
所有失败与修正的验证范围以各自精确提交为准。

实际主机试运行、生产 PKI、物理多机、独立完整财务对账及现场回滚均未执行。
部署时保存旧/新 Node/Core、不可变镜像摘要、配置和状态目录 owner；保留原始
journal、spool 和回执。旧版本未被验证可读新状态时，不让它覆盖该状态目录。
受控试运行和回滚步骤见 [运维说明](NATIVE-OPERATIONS.zh.md)。
