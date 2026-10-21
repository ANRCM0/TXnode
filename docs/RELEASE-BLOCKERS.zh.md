# Node 镜像发布阻塞记录

核对日期：2026-10-20（Asia/Shanghai）。源码基线：`25e6da54bfaf4c6d7c0ed2e78ea2f6b60cf5fc90`。

## 已确认事实

- main Actions `39445453354` 的测试、镜像冒烟与真实固定 Core C2 通过，发布 job 失败。
- 推送目标为 `ghcr.io/anrcm0/txboard-node:dev-sha-25e6da54bfaf`，错误为 `denied: permission_denied: write_package`；后续 `dev` 提升步骤跳过。
- 当前发布 job 已声明 `contents: read`、`packages: write`，使用本仓库的 `GITHUB_TOKEN` 登录 GHCR。
- 当前 API 凭据对 `ANRCM0/TXnode` 显示仓库 admin/maintain/push 权限，但读取包设置与仓库默认 workflow 权限均返回 HTTP 403。仓库管理权限不代表当前凭据有包管理能力；这里不能推断实际包授权设置。
- 匿名读取现有 `dev` manifest 成功，摘要为 `sha256:e461bc828fb52f1c7d32c5df2a5ad8848ece20c15eafb4fbce72ac2310e745f5`。
- 该 `dev` 镜像的 amd64 config 元数据仍为：

```text
org.opencontainers.image.source=https://github.com/ANRCM0/TXBoard
org.opencontainers.image.revision=ca25f21de8ff41a476c1ffcf182359f3bc565122
org.opencontainers.image.version=dev-sha-ca25f21de8ff
```

这些元数据说明当前 `dev` 仍是 Core 拆分前的镜像。它们不证明包当前关联仓库或 Actions 授权设置，但明确不能将 Node 新 main 的源码合并表述为 `dev` 已更新。

## 下一步核对

1. 使用具备该包管理能力的身份进入 `ANRCM0/txboard-node` 包设置，检查关联仓库、权限继承以及 Manage Actions access。
2. 检查 `ANRCM0/TXnode` 是否在允许访问的工作流仓库列表中，并有写入权限；同时核对账号/仓库策略是否限制 `GITHUB_TOKEN`。
3. 修正实际缺失项后，选择精确提交重新发布，保留失败和修复后的 job 来源；不删除现有包，也不改为覆盖已有不可变标签。
4. 确认 amd64/arm64 manifest、source/revision、不可变标签摘要与 `dev` 提升；随后按摘要拉取并执行镜像冒烟。

包设置未能通过当前凭据读取，以上步骤属于尚待执行的权限核对，不能记为已修复。继续开发不依赖此设置核对完成。

## 完成条件

- 对选定源码提交的 GHCR 推送实际成功，不能只看登录成功或 workflow 权限声明。
- 新不可变镜像与源码 SHA 对应，两个目标架构均存在，按摘要运行验证通过。
- `dev` 按现有防回退规则提升并再次核对摘要；若 main 已有更新运行时，记录未提升原因。
- 正式版本标签和 Core 采用分别评审，不由开发镜像推送结果自动推导。

权限规则参考：`https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility`。
