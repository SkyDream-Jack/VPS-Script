# Changelog

## v0.6.0-dev — 2026-10-30

### Changed

- 首页整理为六个入口：系统与软件、SSH 与安全、代理服务、网络与调优、诊断与测试、工具维护与恢复；`M` 切换模式、`R` 刷新首页。
- swap/时区归入系统，Hy2 端口跳跃归入代理服务，BBR/高级调优归入网络；外部脚本移入独立测试子菜单。
- 首页摘要、模块状态和详细报告统一复用只读检查；首页带采集时间并按 `R` 刷新，带模块状态的子菜单统一用 `S` 详查；成功操作后刷新对应模块状态。
- 现有 CLI section、分组别名与 JSON schema 保持兼容。
- SSH 状态区分“密码/键盘交互已关闭”和“仅公钥已确认”，避免认证方法未明确时错误提示密码仍开启。
- 文档逐项说明现有备份/恢复范围，纠正“移除模块等于整机恢复”的理解，并列出下一阶段的统一备份、历史和向导计划。

### Scope

- 本轮调整导航和状态呈现，不增加初始化向导、统一变更历史或一键整机恢复。
- Hy2 入口仍只管理已有服务的端口跳跃规则；外部脚本仍需单独确认；默认只读及各模块安全检查保持不变。
- APT、3x-ui 和外部脚本执行前仍需外部快照/独立备份；SSH/UFW 超时恢复仍不保证跨重启。

## v0.5.2-dev — 2026-10-30

### Fixed

- swap 通过原子替换写入补齐换行后的 fstab，只移除独立且完整匹配的项目条目；检测操作期间的外部编辑。
- UFW 首次启用安全读取 `/etc/default/ufw`，启用后核对实际策略；删除活动 TCP 规则时保护当前 SSH 端口，无法识别会话时拒绝删除。
- 升级预先准备启动命令，统一处理失败恢复、互斥和路径身份检查；恢复失败保留备份并准确报告。
- SSH 状态不再把 DENY/OUT/受限来源等规则认作已放行；修复 Fail2ban 树状输出计数。
- 调优更换档位或参数时明确要求先恢复；应用未完成、配置未创建时仍可根据有效快照恢复，保留外部修改检测。
- root 一键入口不再依赖 sudo；维护菜单使用相同入口并保留 SSH 上下文。
- `doctor --json`（含演示）输出合法 JSON；演示模式预览外部脚本不联网。

### Tests

- 新增配置边界、拒绝规则、当前 SSH 保护、不同参数重复执行和失败后重试的回归测试。
- 使用安装器实际事务代码，在临时目录注入升级失败，验证旧目录和启动命令恢复。
- CI 分开验证当前提交构包后的首次安装、旧版升级，以及已发布的一键入口；验证安装版本和文件内容。
- 保留开发版标记；真实 VPS 的 SSH 连接、UFW 超时恢复、重启持久化和 Hy2 客户端验收仍需单独完成。

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
