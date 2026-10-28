# 安装、升级与卸载

当前为 v0.4.0-dev 开发版本，尚未通过真实 VPS 端到端验证，不应在重要服务器使用。安装后默认菜单只读；使用 `--experimental` 或菜单内“启用修改模式”后才可以选择试验性的系统修改，且每项仍需单独确认。

## 一键安装 / 升级

在测试 VPS 的 root SSH 终端运行：

```bash
f=$(mktemp) && curl -fsSL https://raw.githubusercontent.com/SkyDream-Jack/VPS-Script/main/test-releases/latest/install.sh -o "$f" && sudo bash "$f" && rm -f "$f"
```

脚本只从 `raw.githubusercontent.com` 下载短入口、`bootstrap.py` 和固定版本测试包，并依次校验 SHA-256。需要 `curl` 或 `wget`、系统 Python 3，以及能访问 GitHub。安装到 `/opt/vps-script`，创建 `/usr/local/bin/vps-script`。

重复运行同一命令会升级：先暂存旧程序目录，再替换为新目录，保留 `/etc`、`/var` 中的 SSH、防火墙、BBR、Hy2 和 3x-ui 配置。升级失败时会尽量恢复旧目录；如果恢复失败，会保留 `/opt/.vps-script.previous.<pid>` 供人工检查。

短入口本身没有在命令中固定 SHA-256；它校验随后下载的 `bootstrap.py` 和测试包。需要先审查或固定入口摘要时，使用 [最新测试说明](https://github.com/SkyDream-Jack/VPS-Script/blob/main/test-releases/latest/INSTALL.md) 中的完整摘要。命令和摘要来自同一仓库时，校验只能检测与命令中固定值不一致的内容，不能单独证明仓库未被入侵。

## 预览与本地安装

在源码目录运行：

```bash
bash install-local.sh --preview
```

预览不需要 root，不下载或修改系统。在 Ubuntu / Debian 的交互式终端，用 root 运行 `bash install-local.sh`；`--upgrade` 用于已安装机器。脚本使用本地源码，不访问互联网。

安装器不覆盖已有目标（除非 `--upgrade`），也不自动安装 Python 或其他依赖。若启动命令创建失败，会保留已复制目录并提示检查。

## 升级与卸载

升级优先重新运行一键命令；也可以在源码目录运行 `bash install-local.sh --upgrade`。

卸载程序不会自动恢复系统配置：

```bash
rm -f /usr/local/bin/vps-script
rm -rf /opt/vps-script
```

SSH、UFW、Fail2ban、BBR、内核调优、Hy2、swap、时区和 3x-ui 的配置需要先用各模块的“恢复/移除”功能处理。直接删除程序目录不会回滚这些系统修改。

## 旧产物

`dist/vps-script-v0.1.0-dev.tar.gz` 早于后续 UFW 安全检查修复，已过时，不要用来测试或安装。`test-releases/v0.2.0-dev`、`v0.2.1-dev` 是历史测试包；新测试请使用 `latest`。
