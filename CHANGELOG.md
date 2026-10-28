# Changelog

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
