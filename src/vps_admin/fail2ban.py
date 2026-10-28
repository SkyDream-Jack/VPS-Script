"""Fail2ban SSH jail 的试验性配置，遇到现有 jail 时保守停止。"""

import os
from pathlib import Path
import re
import stat
import subprocess

from . import bbr, checks, packages

JAIL = "vps-script-sshd"
HEADER = "# Managed by VPS-Script; do not edit while managed.\n"


class Fail2banFailure(Exception):
    pass


def ssh_ports(output):
    ports = []
    for line in output.splitlines():
        fields = line.split()
        if fields and fields[0].lower() == "port":
            if len(fields) != 2 or not fields[1].isdigit():
                raise Fail2banFailure("无法解析 SSH 端口")
            port = int(fields[1])
            if not 1 <= port <= 65535:
                raise Fail2banFailure("SSH 端口超出范围")
            if port not in ports:
                ports.append(port)
    if not ports or len(ports) > 15:
        raise Fail2banFailure("无法确认 SSH 端口，或端口数超过 multiport 限制")
    return tuple(ports)


def jail_names(output):
    for line in output.splitlines():
        match = re.search(r"Jail list:\s*(.*)$", line)
        if match:
            text = match.group(1).strip()
            return tuple(item.strip() for item in text.split(",") if item.strip())
    raise Fail2banFailure("无法解析 Fail2ban jail 列表")


def jail_config(ports):
    if not ports or len(ports) > 15 or any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise Fail2banFailure("无效的 SSH 端口")
    return (HEADER + f"[{JAIL}]\nenabled = true\nfilter = sshd\nport = {','.join(str(port) for port in ports)}\n"
            "backend = systemd\nmaxretry = 5\nfindtime = 10m\nbantime = 10m\n").encode("utf-8")


class Fail2banManager:
    def __init__(self, root=Path("/"), runner=None):
        self.root = Path(root)
        self.runner = runner or subprocess.run
        self.files = bbr.BBRManager(self.root)
        self.files.lock = self.root / "run/lock/vps-script-fail2ban.lock"
        self.config = self.root / "etc/fail2ban/jail.d/50-vps-script-sshd.local"

    def command(self, name):
        result = checks.find_command(name)
        if not result:
            raise Fail2banFailure(f"未找到 {name}")
        return result

    def run(self, args, check=True):
        try:
            result = self.runner(args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30, check=False,
                                 env={"PATH": packages.SAFE_PATH, "LC_ALL": "C"})
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Fail2banFailure(f"无法执行 {args[0]}: {exc}") from exc
        if check and result.returncode != 0:
            raise Fail2banFailure(f"{args[0]} 返回 {result.returncode}: {(result.stderr or '').strip()}")
        return result

    def _directory_ok(self):
        try:
            info = os.lstat(self.config.parent)
        except OSError as exc:
            raise Fail2banFailure(f"无法读取 jail 配置目录: {exc}") from exc
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022 or (self.root == Path("/") and info.st_uid != 0):
            raise Fail2banFailure("jail 配置目录不安全")

    def configure(self):
        with self.files.locked():
            client, sshd, systemctl = (self.command(name) for name in ("fail2ban-client", "sshd", "systemctl"))
            active = self.run((systemctl, "is-active", "fail2ban.service"), check=False)
            if active.returncode != 0 or active.stdout.strip() != "active":
                raise Fail2banFailure("Fail2ban 服务未运行或状态未知；请先安装并检查服务")
            names = jail_names(self.run((client, "status")).stdout)
            if "sshd" in names or JAIL in names:
                return "已有 SSH jail；没有覆盖。请检查其实际端口、后端和封禁状态。"
            if names:
                raise Fail2banFailure("存在其他活动 jail，暂不自动重载，避免影响现有防护")
            ports = ssh_ports(self.run((sshd, "-T")).stdout)
            # systemd 后端需要发行版 Python 的 systemd 绑定。
            self.run(("/usr/bin/python3", "-I", "-c", "import systemd.journal"))
            self._directory_ok()
            if os.path.lexists(self.config):
                raise Fail2banFailure("项目 jail 文件已存在，拒绝覆盖")
            data = jail_config(ports)
            self.files._atomic_create(self.config, data, 0o644)
            try:
                self.run((client, "-t"))
                self.run((client, "reload"))
                self.run((client, "status", JAIL))
            except (Fail2banFailure, OSError):
                try:
                    if os.path.lexists(self.config) and self.files._read_regular(self.config) == data:
                        os.unlink(self.config)
                        self.run((client, "reload"), check=False)
                except (OSError, bbr.BBRFailure, Fail2banFailure):
                    print("自动清理未完成；请检查 Fail2ban 配置和服务。")
                raise
            return f"项目 SSH jail 已加载，端口 {', '.join(map(str, ports))}；实际日志匹配和封禁仍需验证。"


def configure(experimental=False):
    error = packages.preflight(experimental)
    if error:
        print(f"未执行：{error}")
        return 2
    print("【试验功能】创建独立的 SSH Fail2ban jail；默认 10 分钟内失败 5 次封禁 10 分钟。")
    print("需要已运行的 Fail2ban 和 systemd 日志支持；误封可能影响 SSH，请准备服务商控制台。")
    print("存在已有活动 jail 时会保守停止，避免覆盖或重载其他防护。")
    try:
        if input("输入 YES 继续，其他内容取消：").strip() != "YES":
            print("已取消。")
            return 0
        print(Fail2banManager().configure())
        return 0
    except EOFError:
        print("已取消。")
        return 0
    except (Fail2banFailure, bbr.BBRFailure, OSError) as exc:
        print(f"操作未完成：{exc}")
        return 1
