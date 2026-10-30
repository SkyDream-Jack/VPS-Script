# 安装、升级与卸载

当前为 v0.6.0-dev 开发版本，尚未通过真实 VPS 端到端验证，不应在重要服务器使用。一键安装后自动进入试验菜单；直接运行 `vps-script` 时默认只读。使用 `--experimental` 或菜单内“启用修改模式”后才可以选择试验性的系统修改，且每项仍需单独确认。

## 一键安装 / 升级

在测试 VPS 的 root SSH 终端运行：

```bash
f=$(mktemp) && curl -fsSL https://raw.githubusercontent.com/SkyDream-Jack/VPS-Script/main/test-releases/latest/install.sh -o "$f" && bash "$f" && rm -f "$f"
```

脚本只从 `raw.githubusercontent.com` 下载短入口、`bootstrap.py` 和固定版本测试包，并依次校验 SHA-256。短命令需要 `curl`、系统 Python 3，以及能访问 GitHub；在 root SSH 中直接运行，不依赖 `sudo`，并保留 SSH 会话上下文。安装到 `/opt/vps-script`，创建 `/usr/local/bin/vps-script`。

重复运行同一命令会升级：先暂存旧程序目录，再替换为新目录，保留 `/etc`、`/var` 中的 SSH、防火墙、BBR、Hy2 和 3x-ui 配置。安装/升级使用互斥锁，提前准备启动命令；失败时恢复旧目录和启动命令，并验证结果。如果恢复失败，会保留 `/opt/.vps-script-transaction.*/` 及必要的启动命令备份，并打印具体路径供人工检查。

短入口本身没有在命令中固定 SHA-256；它校验随后下载的 `bootstrap.py` 和测试包。需要先审查或固定入口摘要时，使用 [最新测试说明](https://github.com/SkyDream-Jack/VPS-Script/blob/main/test-releases/latest/INSTALL.md) 中的完整摘要。命令和摘要来自同一仓库时，校验只能检测与命令中固定值不一致的内容，不能单独证明仓库未被入侵。

## 预览与本地安装

在源码目录运行：

```bash
bash install-local.sh --preview
```

预览不需要 root，不下载或修改系统。在 Ubuntu / Debian 的交互式终端，用 root 运行 `bash install-local.sh`；`--upgrade` 用于已安装机器。脚本使用本地源码，不访问互联网。

安装器不覆盖已有目标（除非 `--upgrade`），也不自动安装 Python 或其他依赖。启动命令准备或提交失败时会尝试恢复安装前状态；恢复未完成则保留材料并报告路径，不把部分安装描述为成功。

## 安装后的菜单

首页入口依次是 `1 系统与软件`、`2 SSH 与安全`、`3 代理服务`、`4 网络与调优`、`5 诊断与测试`、`6 工具维护与恢复`。`M` 切换只读/修改模式，`R` 刷新只读首页，`0` 退出。首页显示采集时间且返回时复用缓存；带模块状态的子菜单自动显示摘要，`S` 查看详细状态，成功操作后刷新该模块。诊断与测试、第三方测试、工具维护与恢复没有 `S`；完整报告从 `5 → 1` 进入按编号选择。完整状态报告和主动测试放在诊断模块，外部脚本需进入单独子菜单。

导航改变不影响 `vps-script status ...`、`doctor` 或 JSON 输出格式。普通启动仍默认只读；安装后自动打开修改菜单也不会自动执行所有初始化操作。

“工具维护与恢复”提供版本、更新、卸载和现有恢复能力说明，当前没有统一备份历史或一键整机恢复。危险修改前应先查看 [各模块恢复范围](DEVELOPMENT.md#现有备份与恢复覆盖)；APT 升级、3x-ui/外部脚本运行前尤其需要外部快照或独立备份。SSH/UFW 的瞬态回滚不替代控制台和第二会话。

## 升级与卸载

升级优先重新运行一键命令；也可以在源码目录运行 `bash install-local.sh --upgrade`。

卸载程序不会自动恢复系统配置：

```bash
rm -f /usr/local/bin/vps-script
rm -rf /opt/vps-script
```

先按需要使用 BBR/内核调优的“恢复”、Hy2/swap 的“移除”，并独立确认结果。SSH、UFW、Fail2ban、时区、APT 和 3x-ui 并没有统一撤销接口，需要按实际配置人工处理；不要在 SSH/UFW 变更尚待验证时卸载。直接删除程序目录不会回滚系统修改，也不应顺带删除 `/var/lib/vps-script` 中尚需检查的恢复材料。

## 旧产物

`dist/vps-script-v0.1.0-dev.tar.gz` 早于后续 UFW 安全检查修复，已过时，不要用来测试或安装。`test-releases/v0.2.0-dev`、`v0.2.1-dev` 是历史测试包；新测试请使用 `latest`。
