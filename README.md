# VPS-Script

面向 Ubuntu / Debian 新 VPS 的初始化与日常管理面板。在 SSH 终端里按需选择功能，执行前显示影响，执行后给出只读状态；默认只读，修改需要显式启用。

当前版本：**v0.5.1-dev（开发/测试版）**。自动化测试覆盖解析、参数、回滚模拟和安装包校验，但系统修改、SSH/防火墙超时恢复、3x-ui 与 Hy2 端到端仍未在真实 VPS 上完成验收，**不要直接用于唯一的生产入口**。请先准备服务商控制台、快照和第二个 SSH 会话。

## 一键安装 / 升级

在测试 VPS 的 root SSH 终端运行：

```bash
f=$(mktemp) && curl -fsSL https://raw.githubusercontent.com/SkyDream-Jack/VPS-Script/main/test-releases/latest/install.sh -o "$f" && sudo bash "$f" && rm -f "$f"
```

脚本会下载并校验固定版本的入口和测试包，然后要求输入 `YES` 确认。安装到 `/opt/vps-script`，启动命令为 `/usr/local/bin/vps-script`；重复运行同一命令会升级程序目录，保留 `/etc`、`/var` 中的 SSH、防火墙、BBR、Hy2 和 3x-ui 配置。

> 短入口本身没有在命令行中固定 SHA-256；它会校验随后下载的 `bootstrap.py` 和测试包。需要先审查或固定入口摘要时，使用 [最新测试说明](https://github.com/SkyDream-Jack/VPS-Script/blob/main/test-releases/latest/INSTALL.md) 中的完整摘要和可审查命令。

安装完成后会自动进入修改模式菜单。之后：

```bash
vps-script              # 只读模式
vps-script --experimental   # 修改模式
vps-script status       # 全部只读状态
```

## 面板模块

| 模块 | 能做什么 | 执行后查看 |
| --- | --- | --- |
| 系统概览 | 发行版、内核、架构、内存、磁盘、运行时间、systemd | `status system` |
| 系统软件 | APT 索引更新、升级、基础/网络/监控/安全工具安装 | `status packages` |
| 3x-ui | 检测现有安装、固定版本安装、读取面板端口/路径（不读密码） | `status panel` |
| BBR / fq | 检查、启用、恢复；记录原值；需要时写入 `tcp_bbr` 开机加载 | `status bbr` |
| 内核网络调优 | 保守 / 代理中转 / 大带宽缓冲三档，动态缓冲区、冲突检测、回滚、可选 TCP Fast Open | `status tuning` |
| SSH | 仅公钥认证（可保留 root/22）、新增端口、关闭项目旧端口、放行 UFW 新端口 | `status ssh` |
| UFW | 查看规则、允许/删除端口、带 180 秒超时恢复的首次启用 | `status ufw` |
| Fail2ban | 查看 jail/封禁计数、创建项目 SSH jail、SSH 端口变化后刷新、解封 IP | `status fail2ban` |
| Hy2 | 创建/移除项目专属 nftables 跳跃端口转发和开机服务，可选放行 UFW | `status hy2` |
| 常用工具 | swap 创建/移除、时区查看/设置、DNS 只读查看 | `status swap`、`status timezone`、`status dns` |
| 测试与体检 | 内置机器/网络/线路/带宽测试；白名单外部 NQ、TQ、IPQuality、NetQuality、YABS | 终端输出 |
| 状态查询 | 单项/分组/全部状态，支持 JSON | `status --json` |

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

1. 进入 `3 SSH 与安全 → 7 只允许公钥认证`；
2. **不要**执行 `5 新增 SSH 端口` 和 `6 关闭旧端口`；
3. 确认 UFW 已放行 `22/tcp`，云防火墙也放行 22；
4. 从第二个会话确认 root 账号能用密钥登录，且密码/键盘交互被拒绝；
5. 可选：把 `PermitRootLogin` 从 `yes` 改成 `prohibit-password`，语义更明确；本工具不会自动改 root 登录开关。

这个方案适合单管理员、密钥保管良好的 VPS。它不是最高安全级别：22 端口会持续被扫描，root 拥有全部权限。更稳妥的替代方案是普通用户 + sudo + 仅公钥 + 新端口；端口变更主要是减少噪音，不是真正的安全边界。

## 安全边界（当前版本）

- 修改功能要求 Linux、Ubuntu/Debian、root、交互式终端，并且逐项确认；默认菜单只读。
- SSH 和 UFW 的 180 秒超时恢复使用 systemd 瞬态定时器，不保证跨重启；启用前请准备服务商控制台。
- UFW 首次启用会检查默认入站策略必须为 `deny`；已有 nftables/iptables 规则、Docker、firewalld 或 nftables.service 时可能保守停止。Fail2ban 与 UFW 的先后顺序需要按提示操作。
- 关闭密码登录会影响**所有账户**；面板只验证当前执行账户的公钥，其他账户是否有可用公钥需要自行确认。保留 root + 22 时，root 仅能密钥登录，但 22 仍会被持续扫描；请使用强密钥并保留控制台。
- Hy2 只管理项目专属 NAT 表，不修改云防火墙；必须在云厂商控制台放行 UDP 跳跃范围和目标端口，并从外部网络实测客户端。
- 3x-ui 安装脚本以 root 运行且会访问 GitHub/APT/公网 IP 查询服务；项目固定了版本和入口摘要，但上游包和可选证书步骤仍有各自信任边界。
- swap 只管理 `/swapfile-vps-script` 和带标记的 fstab 行；已有其他 swap 时停止。
- 内核网络调优只改项目 sysctl 文件，不代表实际提速；参数效果需同机、同对端 A/B 测试。不做 qdisc 整形、不改内核、不自动 RPS/MSS/DNS。
- 外部 NQ/TQ/IPQuality/NetQuality/YABS 不是本项目代码，按各自 AGPL/GPL/WTFPL 许可证运行；需要修改模式、输入 `RUN`，会下载远程脚本/rootfs/二进制并可能上传 IP/结果。先用“预览”审查，只在测试 VPS 上运行。
- 软件包升级、3x-ui 安装、内核/服务重启无法保证完整回滚；重要机器请先快照。

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
