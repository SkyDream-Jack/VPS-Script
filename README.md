# VPS-Script

面向 Ubuntu / Debian 新 VPS 的初始化与日常管理面板。在 SSH 终端里按需选择功能，执行前显示影响，执行后给出只读状态；默认只读，修改需要显式启用。

当前版本：**v0.6.0-dev（开发/测试版）**。自动化测试覆盖解析、参数、回滚模拟和安装包校验，但系统修改、SSH/防火墙超时恢复、3x-ui 与 Hy2 端到端仍未在真实 VPS 上完成验收，**不要直接用于唯一的生产入口**。请先准备服务商控制台、快照和第二个 SSH 会话。

## 一键安装 / 升级

在测试 VPS 的 root SSH 终端运行：

```bash
f=$(mktemp) && curl -fsSL https://raw.githubusercontent.com/SkyDream-Jack/VPS-Script/main/test-releases/latest/install.sh -o "$f" && bash "$f" && rm -f "$f"
```

脚本会下载并校验固定版本的入口和测试包，然后要求输入 `YES` 确认。安装到 `/opt/vps-script`，启动命令为 `/usr/local/bin/vps-script`；重复运行同一命令会升级程序目录，保留 `/etc`、`/var` 中的 SSH、防火墙、BBR、Hy2 和 3x-ui 配置。

> 短入口本身没有在命令行中固定 SHA-256；它会校验随后下载的 `bootstrap.py` 和测试包。需要先审查或固定入口摘要时，使用 [最新测试说明](https://github.com/SkyDream-Jack/VPS-Script/blob/main/test-releases/latest/INSTALL.md) 中的完整摘要和可审查命令。

安装完成后会自动进入修改模式菜单。之后：

```bash
vps-script              # 只读模式
vps-script --experimental   # 修改模式
vps-script status       # 全部只读状态
```

## 面板导航与状态

首页按六个任务分组，先显示带采集时间的只读摘要。首页只在初次进入和按 `R` 时重新采集，返回首页时可能仍是先前缓存；修改后可按 `R` 再核对。`M` 切换只读/修改模式，`0` 退出。

带模块状态的子菜单自动显示短摘要，统一用 `S` 查看详细状态；成功操作后刷新对应模块状态。诊断与测试、第三方测试、工具维护与恢复没有 `S`；完整报告从 `5 诊断与测试 → 1 完整状态报告` 按编号查看。首页、模块与详细报告的采集时刻可能不同，不把旧摘要当作最新结果。

| 主菜单 | 包含功能 | 对应只读命令 |
| --- | --- | --- |
| 1. 系统与软件 | APT 更新/升级/常用工具、swap、时区 | `status system`、`status packages`、`status swap`、`status timezone` |
| 2. SSH 与安全 | SSH 端口/公钥、UFW、Fail2ban | `status ssh`、`status ufw`、`status fail2ban` |
| 3. 代理服务 | 3x-ui 首次安装与状态、已有 Hy2 服务的端口跳跃转发 | `status panel`、`status hy2` |
| 4. 网络与调优 | 监听端口/实际队列、DNS 只读查看、BBR/fq、高级内核调优 | `status dns`、`status bbr`、`status tuning` |
| 5. 诊断与测试 | 完整/分项状态报告、内置测试、独立外部测试子菜单 | `status all`、`status --json`、`doctor` |
| 6. 工具维护与恢复 | 版本、更新、卸载说明、现有恢复能力说明 | 查看说明，不自动恢复全机 |

Hy2 菜单只管理端口转发，不安装 Hy2 服务端，也不修改客户端。外部 NQ、TQ、IPQuality、NetQuality、YABS 集中放在诊断模块的子菜单中，仍需逐项确认。

首页摘要、模块状态和详细报告使用相同的只读检查；依赖缺失、无权限和无法解析会保留为未知。刷新或读取状态不启动测速，主动网络探测和外部脚本由测试菜单单独执行。现有命令行 section、别名和 JSON schema 保持兼容，菜单分组不改变命令含义。

状态分组别名：`network` = BBR + 内核调优 + Hy2，`security` = SSH + UFW + Fail2ban，`common` = swap + 时区 + DNS。

```bash
vps-script status security
vps-script status tuning
vps-script status --json > /tmp/vps-status.json
vps-script doctor
```

所有状态查询只读：不发起公网探测，不读取面板账户/密码，不显示 Fail2ban 封禁 IP 列表。监听地址、规则和 IP 仍可能敏感，分享前请遮盖。

## SSH 登录策略：保留 root + 22（可选）

如果你希望**保留 root 登录和 22 端口，只关闭密码认证**：

1. 进入 `2 SSH 与安全 → 1 SSH 登录 → 3 仅允许公钥认证`；
2. **不要**执行“新增 SSH 端口”和“关闭旧端口”；
3. 确认 UFW 已放行 `22/tcp`，云防火墙也放行 22；
4. 从第二个会话确认 root 账号能用密钥登录，且密码/键盘交互被拒绝；
5. 可选：把 `PermitRootLogin` 从 `yes` 改成 `prohibit-password`，语义更明确；本工具不会自动改 root 登录开关。

这个方案适合单管理员、密钥保管良好的 VPS。它不是最高安全级别：22 端口会持续被扫描，root 拥有全部权限。更稳妥的替代方案是普通用户 + sudo + 仅公钥 + 新端口；端口变更主要是减少噪音，不是真正的安全边界。

## 安全边界（当前版本）

- 修改功能要求 Linux、Ubuntu/Debian、root、交互式终端，并且逐项确认；默认菜单只读。
- SSH 和 UFW 的 180 秒超时恢复使用 systemd 瞬态定时器，不保证跨重启；启用前请准备服务商控制台。
- UFW 首次启用会检查默认入站策略必须为 `deny`；删除活动 TCP 规则时会保护当前 SSH 端口，无法识别会话时停止。已有 nftables/iptables 规则、Docker、firewalld 或 nftables.service 时可能保守停止。Fail2ban 与 UFW 的先后顺序需要按提示操作。
- 关闭密码登录会影响**所有账户**；面板只验证当前执行账户的公钥，其他账户是否有可用公钥需要自行确认。保留 root + 22 时，root 仅能密钥登录，但 22 仍会被持续扫描；请使用强密钥并保留控制台。
- Hy2 只管理项目专属 NAT 表，不修改云防火墙；必须在云厂商控制台放行 UDP 跳跃范围和目标端口，并从外部网络实测客户端。
- 3x-ui 安装脚本以 root 运行且会访问 GitHub/APT/公网 IP 查询服务；项目固定了版本和入口摘要，但上游包和可选证书步骤仍有各自信任边界。
- swap 只管理 `/swapfile-vps-script` 和带标记的 fstab 行；已有其他 swap 时停止。
- 内核网络调优只改项目 sysctl 文件，不代表实际提速；参数效果需同机、同对端 A/B 测试。不做 qdisc 整形、不改内核、不自动 RPS/MSS/DNS。
- 外部 NQ/TQ/IPQuality/NetQuality/YABS 不是本项目代码，按各自 AGPL/GPL/WTFPL 许可证运行；需要修改模式、输入 `RUN`，会下载远程脚本/rootfs/二进制并可能上传 IP/结果。先用“预览”审查，只在测试 VPS 上运行。
- 软件包升级、3x-ui 安装、内核/服务重启无法保证完整回滚；重要机器请先快照。

## 危险操作前的备份与恢复

需要在危险修改前准备恢复材料，但当前保护是按模块实现的：SSH 保存本次项目配置，SSH/UFW 有受限的超时恢复；BBR/内核调优记录原值；Hy2 和 swap 只能移除各自管理的规则或文件。它们不能代替整机快照，也不是所有操作都可以撤销。

APT 升级、3x-ui/外部脚本运行前，应先准备服务商快照或独立备份及控制台。操作成功后也要实际验证 SSH、服务和外部连通性。`6 工具维护与恢复` 提供现有能力的说明，**本版没有统一历史、一键整机恢复或初始化向导**。具体覆盖和下一阶段的自动备份计划见 [开发说明](docs/DEVELOPMENT.md#现有备份与恢复覆盖) 和 [项目计划](docs/PLAN.md#下一阶段备份与初始化计划)。

## 本地开发

```bash
./vps-admin --demo                 # 虚构数据，不检查本机
./vps-admin status --demo
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

本地安装（Linux、root、交互式终端，不下载）：

```bash
bash install-local.sh --preview
bash install-local.sh
bash install-local.sh --upgrade
```

详细设计、验证清单和审查记录见 [项目计划](docs/PLAN.md)、[开发说明](docs/DEVELOPMENT.md)、[测试计划](docs/TESTING.md) 和 [审查与改进记录](docs/REVIEW.md) 和 [优化调研与计划](docs/OPTIMIZATION.md)。
