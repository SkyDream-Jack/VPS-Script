# VPS-Script

这是一个正在开发中的 VPS 初始化与日常管理工具。目标是在 SSH 终端中提供清晰的菜单，让使用者按需安装、配置、检查和维护服务，并在高风险操作前显示影响和恢复方式。

当前阶段：**本地开发原型**。尚未在 Linux 虚拟机或真实 VPS 上验证，不可用于生产。默认模式只提供查询；APT、3x-ui、BBR/fq、SSH、UFW、Fail2ban 和 Hy2 的修改功能均是默认关闭的试验代码，只能在有控制台和备份的可丢弃测试环境中验证。

`dist/vps-script-v0.1.0-dev.tar.gz` 是修复 UFW 预检前的旧测试包，请不要使用。更新的开发包也尚未通过 Linux 和 VPS 验证。

已确定首版使用 SSH 终端菜单，面向 Ubuntu 和 Debian；具体发行版版本和架构的支持情况以测试结果为准。详细需求、设计取舍、实施顺序和验收标准见 [项目计划](docs/PLAN.md)。

## 体验原型

需要 Bash 和 Python 3；不会自动安装依赖。在本项目目录运行：

```bash
./vps-admin --demo
```

演示模式使用虚构数据，不查询当前系统。在 Linux 上，`./vps-admin` 可以进入只读菜单，`./vps-admin status` 可以输出全部检查；也可以通过 `status system`、`status network`、`status security` 或 `status panel` 查询单项。检查不发起公网探测；某些本地状态需要 root 才能读取，权限不足显示为未知。列表中的监听地址、规则和 IP 等仍可能属于敏感信息，分享前应检查并遮盖。

试验功能会检查系统、权限和交互终端，并在执行前说明影响和要求确认；具体限制与未验证事项见 [开发与验证说明](docs/DEVELOPMENT.md)，实际验证顺序见 [测试计划](docs/TESTING.md)。[本地安装说明](docs/INSTALLATION.md)提供安装路径预览。[GitHub 测试版一键入口](https://github.com/SkyDream-Jack/VPS-Script/blob/main/test-releases/v0.2.0-dev/INSTALL.md)只有对应代码和测试包实际上传后才可用。

本地测试：

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```
