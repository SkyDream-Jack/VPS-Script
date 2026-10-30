# VPS-Script

面向 Ubuntu / Debian 新 VPS 的初始化与日常管理面板。在 SSH 终端里按需选择功能，执行前显示影响，执行后给出只读状态；默认只读，修改需要显式启用。

当前版本：**v0.8.0-dev（开发/测试版）**。自动化测试覆盖解析、参数、回滚模拟和安装包校验，但系统修改、SSH/防火墙超时恢复、3x-ui 与 Hy2 端到端仍未在真实 VPS 上完成验收，**不要直接用于唯一的生产入口**。请先准备服务商控制台、快照和第二个 SSH 会话。

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

## 初始化向导

升级后在首页按 `I`，或直接运行：

```bash
vps-script init --experimental   # 逐步配置，仍需每项确认
vps-script init                  # 只读规划、查看状态与记录
vps-script init --demo           # 演示流程，不读取真实主机
```

输入编号（例如 `1,3,5`）选择索引更新、基础工具和时区；没有默认勾选项。向导按展示的顺序逐步处理所选项目，每步先显示当前状态，再等待选择：

- `E` 进入本步原有配置与确认流程；执行后停留本步，`N` 才进入下一步。
- `S` 跳过，`R` 刷新，`D` 查看详细状态，`H` 打开现有备份记录与恢复菜单。
- 步骤选择处 `Q` / `0` 退出；参数或确认过程中用 `Ctrl+C` 退出。失败后不会自动继续；仍要跳过需输入 `CONTINUE`，重试已处理步骤需输入 `RETRY`。

退出保留已经执行的修改及其持久记录，不自动撤销。再次进入会重新检查主机并重新选择步骤，不把旧记录当作当前状态，也不自动重跑上次计划。结果区分取消/未执行、无变更、命令完成、部分完成和待核实，并列出本步骤的记录 ID；业务可用性仍需实际验证。

向导覆盖 APT、基础工具、swap、时区、UFW、SSH、Fail2ban、BBR/fq、3x-ui 和已有 Hy2 服务的跳跃转发。首次 UFW 启用排在 Fail2ban 安装/配置前，二者安装分开；已有活动防护服务/规则时仍可能拒绝，不自动停用。依赖不会自动补装，业务与云防火墙端口由用户确认。网络/监控工具、高级调优、关闭旧 SSH 端口与主动测试继续从原菜单选择。向导不自动安装 Hy2 服务端、重启系统或创建服务商快照。

## 面板导航与状态

首页按六个任务分组，先显示带采集时间的只读摘要。首页只在初次进入和按 `R` 时重新采集，返回首页时可能仍是先前缓存；修改后可按 `R` 再核对。`I` 打开初始化向导，`M` 切换只读/修改模式，`0` 退出。

带模块状态的子菜单自动显示短摘要，统一用 `S` 查看详细状态；成功操作后刷新对应模块状态。诊断与测试、第三方测试、工具维护与恢复没有 `S`；完整报告从 `5 诊断与测试 → 1 完整状态报告` 按编号查看。首页、模块与详细报告的采集时刻可能不同，不把旧摘要当作最新结果。

| 主菜单 | 包含功能 | 对应只读命令 |
| --- | --- | --- |
| 1. 系统与软件 | APT 更新/升级/常用工具、swap、时区 | `status system`、`status packages`、`status swap`、`status timezone` |
| 2. SSH 与安全 | SSH 端口/公钥、UFW、Fail2ban | `status ssh`、`status ufw`、`status fail2ban` |
| 3. 代理服务 | 3x-ui 首次安装与状态、已有 Hy2 服务的端口跳跃转发 | `status panel`、`status hy2` |
| 4. 网络与调优 | 监听端口/实际队列、DNS 只读查看、BBR/fq、高级内核调优 | `status dns`、`status bbr`、`status tuning` |
| 5. 诊断与测试 | 完整/分项状态报告、内置测试、独立外部测试子菜单 | `status all`、`status --json`、`doctor` |
| 6. 工具维护与恢复 | 版本、更新、卸载、恢复说明、备份历史/详情/选择恢复/清理 | `history`、`history --json`；不是整机恢复 |

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
- 外部 NQ/TQ/IPQuality/NetQuality/YABS 不是本项目代码，按各自 AGPL/GPL/WTFPL 许可证运行；需要修改模式、输入 `RUN` 及外部备份声明 `SNAPSHOT`，会下载远程脚本/rootfs/二进制并可能上传 IP/结果。先用“预览”审查，只在测试 VPS 上运行。
- 软件包升级、3x-ui 安装、内核/服务重启无法保证完整回滚；重要机器请先快照。

## 自动备份、历史与选择恢复

已接入的系统修改在执行前创建持久记录；记录或备份失败会阻止执行。按模块保存必要配置和运行值，完成后记录结果与恢复范围。记录位于 `/var/lib/vps-script/backups`，目录 `0700`、文件 `0600`；查看界面和 JSON 不输出配置正文。

进入 `6 工具维护与恢复 → 5 备份记录与恢复`：选项 1 查看历史，2 选择记录查看详情，3 请求恢复，4 永久删除已完成记录。可按编号或完整 ID 选择；恢复需修改模式和 `RESTORE <ID>` 确认，删除需 `DELETE <ID>`。只读查询也可直接运行：

```bash
vps-script history
vps-script history --json
```

指定一条记录可用 `vps-script history <ID>` 查看；`vps-script restore <ID> --experimental` 请求恢复。将 `<ID>` 换成实际的 32 位记录 ID，不能填文件路径。

**自动记录不等于所有操作都能自动撤销。** 只有命令已完成、操作后快照完整且模块支持的记录才显示“可请求恢复”；恢复前再次检查当前状态必须匹配，拒绝覆盖后续人工修改。SSH 恢复仍需第二会话验证；UFW 只支持安全识别的新增允许规则/首次启用反向操作。BBR、调优、Hy2、swap 和时区各有受限的恢复范围，见 [完整覆盖表](docs/DEVELOPMENT.md#现有备份与恢复覆盖)。失败/中断记录保留材料供人工核对，现有模块的失败回退仍会执行。

APT 安装/升级、3x-ui 和外部脚本仅记录操作，不能完整回滚。原有确认后还需输入 `SNAPSHOT` 声明已准备外部快照或独立备份；工具不核实快照是否存在或可恢复。APT 索引更新仍记录，但不要求这项声明。外部脚本上传的数据也不能通过服务器恢复撤回。

最多保留 100 条、总量上限 32 MiB，单条 2 MiB、单文件 256 KiB；达到限制时停止相关修改，不自动淘汰旧记录。失败、运行中和中断记录不能从菜单删除。删除备份不会撤销系统修改。程序升级保留这些记录，初始化向导复用同一记录与恢复机制；本版不提供一键整机恢复。

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
