# 本地安装与启动

当前为开发版本，尚未通过真实 Linux 虚拟机或 VPS 验证，不应在重要服务器使用。默认菜单提供只读检查；使用 `--experimental` 后才可以选择试验性的系统修改，且每项仍需要单独确认。

## 预览

在源码目录运行 `bash install-local.sh --preview` 可以查看目标路径；预览不需要 root，不下载或修改系统。

## 可丢弃的 Linux 测试环境

在 Ubuntu / Debian 的交互式终端，用 root 运行 `bash install-local.sh`。脚本使用本地源码，不访问互联网；确认后将程序放入 `/opt/vps-script`，并创建 `/usr/local/bin/vps-script`。之后运行 `vps-script` 查看菜单。

安装器不覆盖已有目标，也不自动安装 Python 或其他依赖。若启动命令创建失败，会保留已复制目录并提示检查。现阶段尚未提供自动升级或卸载流程；系统配置和备份也不会随删除程序目录自动恢复。

本地旧产物 `dist/vps-script-v0.1.0-dev.tar.gz` 早于后续 UFW 安全检查修复，已过时，不要用来测试或安装。保留旧文件仅便于区分历史产物；新产物也仍是未完成 Linux 验证的开发版本。

## GitHub 测试版入口

`release/build_release.py` 可以生成版本化测试包；`bootstrap.py` 下载并校验固定版本、限制解压内容，在用户确认后调用本地安装器，并可在成功后启动试验菜单。测试包准备放在仓库 `test-releases/版本/` 下，而非 GitHub Release；对应版本和入口必须实际上传后才可下载。

面向测试 VPS 的命令和对应摘要在仓库的 [试用说明](https://github.com/SkyDream-Jack/VPS-Script/blob/main/test-releases/v0.2.0-dev/INSTALL.md)。命令固定入口脚本和测试包的摘要，但如果命令和摘要来自同一仓库，仅靠它们不能证明仓库本身未被入侵。此入口未在真实 Linux/VPS 验证，不得用于重要服务器。
