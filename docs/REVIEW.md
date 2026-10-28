# 原型审查与 v0.3.0-dev 改进记录

审查日期：2026-10-28。对象：本地 `VPS-Script` v0.2.1-dev 原型及 GitHub `SkyDream-Jack/VPS-Script` 远端。

> v0.4.0-dev 追加：在 v0.3.0-dev 基础上增加内核网络调优（保守/代理/缓冲三档）、动态缓冲区、冲突检测/回滚和 `status tuning`。调研与取舍见 [OPTIMIZATION.md](OPTIMIZATION.md)。改动前已建立标签 `backup/pre-tuning-2026-10-28` 和本地备份包。
>
> v0.5.0-dev 追加：测试与体检（内置机器/网络/线路/带宽 + 白名单外部 NQ/TQ/IPQuality/NetQuality/YABS）。外部脚本不打包、不自动运行，先预览再确认；见 [TESTING-TOOLS.md](TESTING-TOOLS.md)。

## 结论

原型的模块划分、固定命令白名单、root/交互终端前置检查、文件身份校验和超时回滚方向是正确的，测试也覆盖了不少失败路径。主要问题不在“功能列表不够长”，而在**可用性闭环**：

1. 本地 v0.2.1-dev 没有提交到远端，文档中的一键地址实际 404；
2. 安装器没有升级路径，重复执行会拒绝覆盖；
3. UFW、Fail2ban、SSH 端口三者没有串起来，组合使用时互相阻塞；
4. 状态查询只有四个粗分类，执行完操作后没有对应模块的结构化状态；
5. 文档反复强调“未验证”，但缺少一份集中、可执行的下一步计划。

v0.3.0-dev 针对上述问题做了改进。提交后 GitHub Actions 在 Ubuntu 22.04 / 24.04 / 26.04（含 arm）和 Debian 12 / 13 容器中通过；一键安装与再次升级也在 Ubuntu 24.04 runner 上通过。但仍未完成真实 VPS 端到端验收。

## 主要发现与处理

| 级别 | 发现 | 证据 | v0.3.0-dev 处理 |
| --- | --- | --- | --- |
| P0 | 一键地址 404：本地已有 v0.2.1-dev，但远端只有 v0.2.0-dev | `git ls-remote` 远端 HEAD；raw v0.2.1 INSTALL.md 返回 404 | 建立 v0.3.0-dev 发布并推送；README 改用 `test-releases/latest/install.sh` |
| P0 | 工作目录没有 `.git`，无法维护/推送 | `git status` 报 not a repository | 初始化 Git，保留远端历史，提交并推送 |
| P0 | 一键命令很长、难复制；安装器拒绝已有安装 | 旧 INSTALL.md 是 Python 单行；`install-local.sh` 遇目标即退出 | 新增 `install.sh` 短入口、固定摘要、`--upgrade` 原子替换程序目录 |
| P0 | UFW 启用会拒绝运行中的 Fail2ban；Fail2ban 又拒绝任何已有 jail | `firewall.ensure_no_competing_services`；`fail2ban.configure` | UFW 检查默认入站必须为 deny；Fail2ban 在 UFW 活跃时使用 `banaction = ufw`；已有系统 sshd jail 只报告不覆盖；新增端口刷新 |
| P0 | 改 SSH 端口不会放行 UFW，也不会刷新 Fail2ban 端口 | `ssh.change` 只写 SSH 配置 | 新增“修改前放行 UFW 新端口”选项；成功后刷新项目 jail 端口 |
| P1 | BBR 只写 sysctl，模块未内建时重启后可能不加载 | 无 `modules-load.d` | 需要时写入 `vps-script-bbr.conf`，恢复时校验并删除 |
| P1 | Hy2 应用失败会遗留配置/状态；UFW 未联动 | `hy2.apply` 只抛出错误；`change` 不碰 UFW | 失败时清理项目文件和规则（无法确认时保留状态）；可选放行 UDP 范围和目标端口 |
| P1 | 没有按模块的状态查询，也不支持 JSON | 旧 `status` 只有 system/network/security/panel | 新增 11 个 section、分组别名、`--json`、`doctor`；执行后自动显示对应状态 |
| P1 | `APT_CONFIG` 会被传给 root APT 子进程 | `packages.apt_env` 保留该变量 | 不再继承；检测到只提示 |
| P1 | 关闭密码登录只验证当前账户，却影响所有账户 | `ssh.change` 只检查目标用户 | 菜单列出可登录账户，要求输入 `ALL USERS`，并明确其他账户公钥未验证 |
| P1 | 没有 swap、时区、DNS 等常用功能 | 旧菜单无入口 | 新增 swap 文件管理、timedatectl 时区设置、DNS 只读查看 |
| P1 | 没有升级/卸载说明 | 旧安装器明确“更新与卸载尚未完成” | 新增升级命令与“保留系统配置”的升级逻辑；维护菜单给出卸载说明 |
| P2 | 菜单是平铺列表，执行后没有反馈 | 旧 `cli.py` | 模块子菜单、状态选项、修改模式开关、执行后状态回显 |
| P2 | 文档与 CI 仍引用旧版本 | README/CI/INSTALLATION | 统一 v0.3.0-dev、latest 入口、新增测试与发布说明 |

## 仍然存在的风险

- **未在真实 VPS 验收。** 自动测试以模拟为主；SSH 第二会话、UFW 超时恢复、systemd socket、nftables 重启持久化和 Hy2 客户端跳端口都必须逐项实测。
- **UFW + Fail2ban 仍是顺序式。** 如果 Fail2ban 已经用 nftables 写入规则，UFW 预检可能保守停止；推荐顺序是先启用 UFW，再创建使用 `ufw` 动作的项目 jail。复杂既有环境仍可能拒绝自动修改。
- **SSH 只处理标准 Debian/Ubuntu 布局。** `Match`、非标准 `Include`、多因素认证、非 `/usr/sbin/sshd` 会停止；这是有意保守，不是缺陷。
- **3x-ui 只做首次安装和状态读取。** 没有自动更新、卸载、证书签发或面板端口自动放行；上游安装脚本及后续下载仍有独立信任边界。
- **Hy2 不管理云防火墙。** 服务端 NAT 规则存在不代表公网客户端可用；必须在云厂商控制台放行 UDP 范围并从外部网络测试。
- **没有 Web 面板。** 首版是 SSH 终端面板，避免额外暴露 root 级 HTTP 服务。若需要 Web，建议只绑定 `127.0.0.1`、通过 SSH 隧道访问，并单独做认证/CSRF/命令白名单设计。

## 下一阶段建议

1. **真实验收（优先）**：一台可丢弃 Ubuntu 24.04 + 一台 Debian 12，按 `docs/TESTING.md` 记录双 SSH 会话、UFW 超时、Fail2ban 封禁/解封、BBR 重启、Hy2 客户端跳端口。
2. **安全栈向导**：把“UFW -> Fail2ban -> SSH 端口”做成有顺序的检查清单，每步仍单独确认；补测已有 nftables/Docker 场景。
3. **3x-ui 生命周期**：增加更新前备份、版本检测、面板端口放行、TLS/访问验证；不自动跟随 latest。
4. **变更日志与恢复入口**：统一 `/var/lib/vps-script/` 事务记录，提供“查看最近变更/恢复”菜单。
5. **可选 Web 面板**：在 TUI 功能层稳定后，再做本地绑定 + SSH 隧道的只读/操作界面。
