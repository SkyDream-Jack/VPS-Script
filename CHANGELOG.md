# Changelog

## v0.5.1-dev — 2026-10-28

### Changed

- 明确 SSH “仅公钥认证”不会修改 SSH 端口，也不会禁用 root 登录；菜单文案改为“禁用密码；保留 root 和当前端口”。
- `status ssh` 对 `PermitRootLogin yes` + 密码/键盘交互关闭的情况改为“信息”而非“建议改 no”，并说明 root 实际只能密钥登录；仍建议手动改为 `prohibit-password`。
- README/DEVELOPMENT 增加“保留 root + 22 + 仅公钥”方案及风险说明。

## v0.5.0-dev — 2026-10-28

### Added

- 测试与体检菜单：机器/系统信息、网络接口/DNS/ICMP 延迟、mtr/traceroute 线路、Cloudflare 单线程下载带宽测试。
- 外部测试白名单：NodeQuality（NQ）、TcpQuality（TQ）、IPQuality、NetQuality、YABS。
- 外部脚本预览（前 120 行 + SHA-256）、官方命令查看、临时文件执行、修改模式 + `RUN` 确认。
- `docs/TESTING-TOOLS.md`：NQ/TQ/IPQuality/NetQuality/YABS 调研、许可证、数据外发与信任边界。

### Changed

- 版本升至 `0.5.0-dev`。
- README/PLAN/DEVELOPMENT/TESTING/INSTALLATION 更新。

### Not included

- 不复制/打包 AGPL/GPL 测试脚本；不自动运行外部测试；不解析/上传结果。
- 不固定上游脚本 SHA；每次运行显示本次下载摘要。
- 不做自动安装 mtr/nexttrace/speedtest；内置测试缺少命令时提示。

## v0.4.0-dev — 2026-10-28

### Added

- 内核网络调优模块 `tuning.py`：保守 / 代理中转 / 大带宽缓冲三档。
- 动态缓冲区：按内存和用户输入的预期带宽/RTT 估算 `tcp_rmem`/`tcp_wmem`/`tcp_mem`，不套固定值。
- 冲突检测、项目专属 sysctl 文件、状态文件、失败回滚、外部修改后拒绝恢复。
- 可选 TCP Fast Open；conntrack 已存在时按内存设置 `nf_conntrack_max`。
- `status tuning`、主菜单“VPS 优化”、执行后状态回显。
- `docs/OPTIMIZATION.md`：tcpfit / vps-netpilot / TCP-Optimize / kejilion 等调研与取舍。
- 备份标签 `backup/pre-tuning-2026-10-28`。

### Changed

- 版本升至 `0.4.0-dev`。
- `status network` 现在包含 BBR、内核调优和 Hy2。
- README/PLAN/DEVELOPMENT/TESTING/INSTALLATION 更新。

### Not included

- qdisc/HTB 整形、initcwnd、RPS/RFS、MSS Clamp、DNS 切换、内核替换（BBRv3/XanMod/锐速）。
- 真实 VPS A/B 性能数据；当前不宣称“加速”。

## v0.3.0-dev — 2026-10-28

### Added

- 结构化状态查询：`status system|packages|panel|bbr|ssh|ufw|fail2ban|hy2|swap|timezone|dns|all`，支持 `--json` 和 `doctor`。
- 短安装入口 `install.sh`、固定 SHA-256、`test-releases/latest/` 和 `--upgrade` 升级流程。
- 模块执行后自动显示对应只读状态。
- UFW 默认入站策略检查、删除规则；Fail2ban 状态/解封、SSH 端口刷新、`ufw` 封禁动作；SSH 修改前可选放行新端口。
- BBR 的 `tcp_bbr` 模块持久化文件及恢复。
- Hy2 失败清理、可选 UFW UDP 放行。
- 常用工具：项目 swap 创建/移除、时区查看/设置、DNS 只读查看。
- 主菜单修改模式开关、维护菜单、审查记录和更完整的安装/升级文档。

### Changed

- 版本升至 `0.3.0-dev`；安装器支持原地升级，保留 `/etc`、`/var` 系统配置。
- APT 子进程不再继承 `APT_CONFIG`。
- 仅公钥认证会列出所有可登录账户并要求 `ALL USERS` 确认。
- README、PLAN、DEVELOPMENT、INSTALLATION、TESTING 更新到当前实现。

### Known limitations

- 未完成真实 VPS 端到端验收。
- 3x-ui 只支持首次固定版本安装和状态读取，不含自动更新/卸载/证书签发。
- UFW 与既有 Fail2ban/nftables 规则组合仍可能保守停止。
- 没有 Web 管理界面；首版为 SSH 终端面板。
