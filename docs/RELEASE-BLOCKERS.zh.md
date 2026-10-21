# Node 镜像交付与历史阻塞记录

核对日期：2026-10-21（Asia/Shanghai）。PR #5 已合并为 main
`112760455433de1f9556b030b42b7a774a928fd1`，tree
`7cf10cc16c8dc299c60db4c691bba868c26fe063`，与最终 PR head `4b7af523` 完全相同。
相对完整验收的运行时候选 `e5e98291`，仅追加七份验收文档。

## 独立发布路径

PR #5 将发布目标改为 `ghcr.io/anrcm0/txnode`，由独立 Node 仓库的
`GITHUB_TOKEN` 创建和发布，不再以写入历史 Core 包作为独立交付前提。
旧 `txboard-node` 包、旧部署及其权限保持原状；已有部署升级到独立镜像时须
显式使用新路径和已验证摘要。保留 `TXBOARD_IMAGE_REPO` 的显式覆盖能力。
main Actions `39542829266` 已成功；Go/race、quick、固定 Core C2、镜像冒烟及
独立镜像发布实际通过。完整 Machine、full 和 S3 在 main 中按事件条件跳过，
不计为该 main 的新验收；完整运行时候选的来源和 S3 失败保留在
`OUTSTANDING-WORK.zh.md`。

## 已发布的独立开发镜像

发布 job `119036065730` 使用该仓库 `GITHUB_TOKEN` 实际推送新包成功，随后从
注册表按两个子摘要拉取、核对 source/revision/version 和默认配置命令，并在
`--network none` 下分别执行 `--capabilities`。arm64 使用 QEMU；这不证明物理
arm64 主机部署或生产运行。

| 项目 | 实际结果 |
| --- | --- |
| 不可变标签 | `ghcr.io/anrcm0/txnode:dev-sha-112760455433` |
| `dev` 与不可变标签的索引摘要 | `sha256:5bd79f161a81f75805bd43d6d24f952e067b5bd31c3ba9593666f0dfb67f0f02` |
| linux/amd64 子摘要 | `sha256:9b94bd90c76a1d0bfdfedad5d606608c4348a8da29314b506b4be4285127576f` |
| linux/arm64 子摘要 | `sha256:fbbf085863dc1aa650f21eed6c46c650c9752d4e5828ae66b7bdb52c97124e64` |
| OCI source / revision | `https://github.com/ANRCM0/TXnode` / `112760455433de1f9556b030b42b7a774a928fd1` |
| 双架构元数据与离线 capabilities | 均通过，artifact `12320338211` |
| `dev` 提升 | 成功，产物中摘要与发布索引一致 |

2026-10-21 04:23:35 UTC 的匿名只读注册表查询中，`dev` 和不可变标签的 manifest
均返回 HTTP 200，索引及两个架构子摘要与 Actions 产物一致。本地没有执行容器；
实际拉取和运行的验收证据来自 Actions。

该开发镜像交付已完成。后续只改文档的 main 不重复发布运行时，不能把文档提交
当成此镜像的构建 revision。未创建新 SemVer 标签或正式 Release；Core 采用、
独立完整财务对账、生产 PKI 和实际部署仍分别记录。正式 S3 未通过也不会因
开发镜像推送成功而改为通过。

## 历史 `txboard-node` 包的事实

- PR #3 已合并为 `16f69b5`。其 main CI `39526625462` 的 Go/quick/Core C2/镜像冒烟通过，发布 `dev-sha-16f69b5c70a4` 仍失败于 `permission_denied: write_package`；`dev` 提升跳过。
- PR #4 后的 `8ec18784` CI `39526677523` 在连接管理测试失败，尚未尝试发布。不能用旧 SHA 的重跑交付新 main。
- 当前 API 凭据为 fine-grained PAT，包管理读取返回 403。agent-browser 无可连接的 Chrome/CDP，Codex 无可用浏览器表面；这不能推断用户在全部浏览器中均未登录。没有读取浏览器凭据或更改包权限。
- 历史包若需要继续发布，须单独为 `ANRCM0/TXnode` 授予包侧 Write。当前采用新的独立包，不再要求管理员修改旧包权限，也没有执行旧包的权限变更。
- `dev-sha-16f69b5c70a4` 和 `dev-sha-8ec187840c95` 匿名读取均为 `404 MANIFEST_UNKNOWN`。以下历史失败与旧 `dev` 元数据继续保留。

- main Actions `39445453354` 的测试、镜像冒烟与真实固定 Core C2 通过，发布 job 失败。
- 推送目标为 `ghcr.io/anrcm0/txboard-node:dev-sha-25e6da54bfaf`，错误为 `denied: permission_denied: write_package`；后续 `dev` 提升步骤跳过。
- 当前发布 job 已声明 `contents: read`、`packages: write`，使用本仓库的 `GITHUB_TOKEN` 登录 GHCR。
- 当前 API 凭据对 `ANRCM0/TXnode` 显示仓库 admin/maintain/push 权限，但读取包设置与仓库默认 workflow 权限均返回 HTTP 403。仓库管理权限不代表当前凭据有包管理能力；这里不能推断实际包授权设置。
- 当时匿名读取旧包 `dev` manifest 成功，摘要为 `sha256:e461bc828fb52f1c7d32c5df2a5ad8848ece20c15eafb4fbce72ac2310e745f5`。
- 该历史 `dev` 镜像的 amd64 config 元数据为：

```text
org.opencontainers.image.source=https://github.com/ANRCM0/TXBoard
org.opencontainers.image.revision=ca25f21de8ff41a476c1ffcf182359f3bc565122
org.opencontainers.image.version=dev-sha-ca25f21de8ff
```

这些元数据说明该次读取的旧包 `dev` 是 Core 拆分前的镜像。它们不证明旧包当前
关联仓库或 Actions 授权设置，也不代表新独立包 `txnode:dev` 的状态。

## 历史包的可选核对

1. 使用具备该包管理能力的身份进入 `ANRCM0/txboard-node` 包设置，检查关联仓库、权限继承以及 Manage Actions access。
2. 检查 `ANRCM0/TXnode` 是否在允许访问的工作流仓库列表中，并有写入权限；同时核对账号/仓库策略是否限制 `GITHUB_TOKEN`。
3. 修正实际缺失项后，选择精确提交重新发布，保留失败和修复后的 job 来源；不删除现有包，也不改为覆盖已有不可变标签。
4. 确认 amd64/arm64 manifest、source/revision、不可变标签摘要与 `dev` 提升；随后按摘要拉取并执行镜像冒烟。

旧包设置未能通过当前凭据读取，以上步骤未执行，不能记为旧包权限已修复。
这些可选操作不作为新独立包发布的前提。

## 完成条件

- 对选定源码提交向 `ghcr.io/anrcm0/txnode` 的 GHCR 推送实际成功，不能只看登录成功或 workflow 权限声明。
- 新不可变镜像与源码 SHA 对应，两个目标架构均存在，按摘要运行验证通过。
- `dev` 按现有防回退规则提升并再次核对摘要；若 main 已有更新运行时，记录未提升原因。
- 正式版本标签和 Core 采用分别评审，不由开发镜像推送结果自动推导。

权限规则参考：`https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility`。
