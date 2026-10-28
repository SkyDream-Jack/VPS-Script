"""Fail2ban SSH jail 的试验性配置，遇到现有 jail 时保守停止。"""

import ipaddress
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

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


def jail_config(ports, banaction="ufw"):
    if not ports or len(ports) > 15 or any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise Fail2banFailure("无效的 SSH 端口")
    if banaction not in ("ufw", "iptables-multiport", "nftables-multiport"):
        raise Fail2banFailure("不支持的封禁动作")
    return (HEADER + f"[{JAIL}]\nenabled = true\nfilter = sshd\nport = {','.join(str(port) for port in ports)}\n"
            f"backend = systemd\nbanaction = {banaction}\nmaxretry = 5\nfindtime = 10m\nbantime = 10m\n").encode("utf-8")


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

    def _banaction(self):
        ufw = checks.find_command("ufw")
        if ufw:
            result = self.run((ufw, "status"), check=False)
            if result.returncode == 0 and "Status: active" in result.stdout:
                return "ufw"
        return "iptables-multiport"

    def _replace_managed(self, old, new):
        current = self.files._read_regular(self.config)
        if current != old:
            raise Fail2banFailure("jail 配置在操作期间发生变化")
        temporary = None
        try:
            fd, temporary = tempfile.mkstemp(prefix=".vps-script-fail2ban-", dir=str(self.config.parent))
            with os.fdopen(fd, "wb") as file:
                os.fchmod(file.fileno(), 0o644)
                file.write(new)
                file.flush()
                os.fsync(file.fileno())
            if self.files._read_regular(self.config) != old:
                raise Fail2banFailure("jail 配置在写入时发生变化")
            os.replace(temporary, self.config)
            temporary = None
        finally:
            if temporary is not None:
                os.unlink(temporary)

    def configure(self):
        with self.files.locked():
            client, sshd, systemctl = (self.command(name) for name in ("fail2ban-client", "sshd", "systemctl"))
            active = self.run((systemctl, "is-active", "fail2ban.service"), check=False)
            if active.returncode != 0 or active.stdout.strip() != "active":
                raise Fail2banFailure("Fail2ban 服务未运行或状态未知；请先安装并检查服务")
            names = jail_names(self.run((client, "status")).stdout)
            if "sshd" in names:
                return "已有系统 sshd jail；没有覆盖。请检查其实际端口、后端和封禁状态。"
            if JAIL in names:
                return "项目 SSH jail 已存在；如需更新端口，请使用“刷新 SSH 端口”。"
            if names:
                raise Fail2banFailure("存在其他活动 jail，暂不自动重载，避免影响现有防护")
            ports = ssh_ports(self.run((sshd, "-T")).stdout)
            # systemd 后端需要发行版 Python 的 systemd 绑定。
            self.run(("/usr/bin/python3", "-I", "-c", "import systemd.journal"))
            self._directory_ok()
            if os.path.lexists(self.config):
                raise Fail2banFailure("项目 jail 文件已存在，拒绝覆盖")
            banaction = self._banaction()
            data = jail_config(ports, banaction)
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
            return f"项目 SSH jail 已加载，端口 {', '.join(map(str, ports))}，封禁动作 {banaction}；实际日志匹配和封禁仍需验证。"

    def refresh_ports(self):
        """SSH 端口变化后，只更新项目 jail 的 port 行。"""
        with self.files.locked():
            if not os.path.lexists(self.config):
                return "未发现项目 jail；没有更新。"
            current = self.files._read_regular(self.config)
            try:
                text = current.decode("utf-8")
            except UnicodeError as exc:
                raise Fail2banFailure("项目 jail 配置编码无效") from exc
            if not text.startswith(HEADER):
                raise Fail2banFailure("项目 jail 配置不属于本项目，拒绝覆盖")
            old_ports = []
            banaction = "iptables-multiport"
            for line in text[len(HEADER):].splitlines():
                key, separator, value = line.partition("=")
                if not separator:
                    continue
                if key.strip() == "port":
                    old_ports = [int(item) for item in value.strip().split(",") if item.strip().isdigit()]
                elif key.strip() == "banaction":
                    banaction = value.strip()
            if not old_ports:
                raise Fail2banFailure("项目 jail 缺少可识别的 port 行")
            client, sshd = (self.command(name) for name in ("fail2ban-client", "sshd"))
            new_ports = ssh_ports(self.run((sshd, "-T")).stdout)
            if tuple(old_ports) == tuple(new_ports):
                return f"项目 jail 端口已是最新：{', '.join(map(str, new_ports))}。"
            data = jail_config(new_ports, banaction)
            self._replace_managed(current, data)
            try:
                self.run((client, "-t"))
                self.run((client, "reload"))
                self.run((client, "status", JAIL))
            except (Fail2banFailure, OSError):
                self._replace_managed(data, current)
                self.run((client, "reload"), check=False)
                raise
            return f"项目 jail 端口已更新为 {', '.join(map(str, new_ports))}；请检查封禁状态。"

    def unban(self, address):
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as exc:
            raise Fail2banFailure("IP 地址无效") from exc
        with self.files.locked():
            client = self.command("fail2ban-client")
            names = jail_names(self.run((client, "status")).stdout)
            jail = JAIL if JAIL in names else ("sshd" if "sshd" in names else None)
            if jail is None:
                raise Fail2banFailure("没有找到项目或系统 SSH jail")
            self.run((client, "set", jail, "unbanip", str(parsed)))
            return f"已请求从 {jail} 解封 {parsed}；请检查状态确认。"


def configure(experimental=False):
    error = packages.preflight(experimental)
    if error:
        print(f"未执行：{error}")
        return 2
    print("【试验功能】创建独立的 SSH Fail2ban jail；默认 10 分钟内失败 5 次封禁 10 分钟。")
    print("需要已运行的 Fail2ban 和 systemd 日志支持；误封可能影响 SSH，请准备服务商控制台。")
    print("已有系统 sshd jail 时不会覆盖；UFW 已启用时优先使用 ufw 封禁动作。")
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


def refresh_ports():
    try:
        print(Fail2banManager().refresh_ports())
        return 0
    except (Fail2banFailure, bbr.BBRFailure, OSError) as exc:
        print(f"Fail2ban 端口刷新未完成：{exc}")
        return 1


def unban(address, experimental=False):
    error = packages.preflight(experimental)
    if error:
        print(f"未执行：{error}")
        return 2
    try:
        print(Fail2banManager().unban(address))
        return 0
    except (Fail2banFailure, bbr.BBRFailure, OSError) as exc:
        print(f"操作未完成：{exc}")
        return 1
