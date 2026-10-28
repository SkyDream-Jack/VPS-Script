"""固定命令的只读检查；不读取面板凭据或其他秘密。"""

from dataclasses import dataclass
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
from typing import Optional


# 不使用继承的 PATH，也不从用户输入构造命令。
COMMAND_DIRS = ("/usr/sbin", "/usr/bin", "/sbin", "/bin")
COMMANDS = {
    "listening": ("ss", "-H", "-lntup"),
    "qdisc": ("tc", "qdisc", "show"),
    "ssh_service": ("systemctl", "show", "ssh.service", "--property=LoadState,ActiveState,SubState,UnitFileState"),
    "sshd_service": ("systemctl", "show", "sshd.service", "--property=LoadState,ActiveState,SubState,UnitFileState"),
    "ssh_socket": ("systemctl", "show", "ssh.socket", "--property=LoadState,ActiveState,SubState,UnitFileState"),
    "fail2ban_service": ("systemctl", "show", "fail2ban.service", "--property=LoadState,ActiveState,SubState,UnitFileState"),
    "xui_service": ("systemctl", "show", "x-ui.service", "--property=LoadState,ActiveState,SubState,UnitFileState"),
    "ufw": ("ufw", "status", "verbose"),
    "fail2ban": ("fail2ban-client", "status"),
    "fail2ban_ssh": ("fail2ban-client", "status", "sshd"),
    "fail2ban_managed": ("fail2ban-client", "status", "vps-script-sshd"),
    "sshd_config": ("sshd", "-T"),
    "hy2_ipv4": ("nft", "list", "table", "ip", "vps_script_hy2"),
    "hy2_ipv6": ("nft", "list", "table", "ip6", "vps_script_hy2"),
}
SSH_CONFIG_KEYS = frozenset({
    "port", "listenaddress", "passwordauthentication", "kbdinteractiveauthentication",
    "pubkeyauthentication", "permitrootlogin", "authenticationmethods",
})
MAX_OUTPUT_CHARS = 12000


@dataclass(frozen=True)
class Result:
    state: str
    output: str = ""
    exit_code: Optional[int] = None


def find_command(name: str) -> Optional[str]:
    for directory in COMMAND_DIRS:
        candidate = Path(directory) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def run_check(name: str) -> Result:
    """运行预定义的只读命令，缺少依赖或失败均保留为未知。"""
    args = COMMANDS[name]
    executable = find_command(args[0])
    if executable is None:
        return Result("unknown", f"未找到 {args[0]}；无法读取该项。")

    env = {"PATH": ":".join(COMMAND_DIRS), "LC_ALL": "C", "LANG": "C"}
    try:
        completed = subprocess.run(
            (executable, *args[1:]),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return Result("unknown", "检查超时；结果未知。")
    except OSError as exc:
        return Result("unknown", f"无法运行检查：{exc}")

    if completed.returncode != 0:
        # 不把没有权限、服务未运行或命令错误推断成某种确定的系统状态。
        error = completed.stderr.strip() or completed.stdout.strip() or "没有错误详情"
        return Result("unknown", error[:MAX_OUTPUT_CHARS], completed.returncode)

    output = completed.stdout.strip()
    if name == "sshd_config":
        # 不输出整个配置：其余项可能包含路径、主机或其他不必要的信息。
        output = "\n".join(
            line for line in output.splitlines()
            if line.split(maxsplit=1) and line.split(maxsplit=1)[0].lower() in SSH_CONFIG_KEYS
        )
    if len(output) > MAX_OUTPUT_CHARS:
        output = output[:MAX_OUTPUT_CHARS] + "\n……输出已截断"
    return Result("ok", output or "无输出。", completed.returncode)


def read_value(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return "未知（无法读取）"


def os_release(path: str = "/etc/os-release") -> dict:
    """只解析需要的键；绝不把 os-release 作为 shell 脚本执行。"""
    wanted = {"PRETTY_NAME", "ID", "VERSION_ID"}
    values = {}
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return values
    for line in lines:
        key, sep, value = line.partition("=")
        if not sep or key not in wanted:
            continue
        try:
            parts = shlex.split(value, comments=False, posix=True)
        except ValueError:
            continue
        if len(parts) == 1:
            values[key] = parts[0]
    return values


def system_report() -> str:
    release = os_release()
    memory = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition(":")
            if separator and key in ("MemTotal", "MemAvailable"):
                memory[key] = value.strip()
    except (OSError, UnicodeError):
        pass
    try:
        uptime_seconds = int(float(Path("/proc/uptime").read_text(encoding="ascii").split()[0]))
        days, remainder = divmod(uptime_seconds, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes = remainder // 60
        uptime = f"{days} 天 {hours} 小时 {minutes} 分钟"
    except (OSError, UnicodeError, ValueError, IndexError, OverflowError):
        uptime = "未知"
    try:
        load = " / ".join(f"{value:.2f}" for value in os.getloadavg())
    except (OSError, AttributeError):
        load = "未知"
    try:
        disk = shutil.disk_usage("/")
        disk_text = f"{disk.used / 1024**3:.1f} / {disk.total / 1024**3:.1f} GiB 已用"
    except OSError:
        disk_text = "未知"
    euid = os.geteuid() if hasattr(os, "geteuid") else None
    privilege = "root" if euid == 0 else "普通用户（部分检查可能需要 root）"
    return "\n".join((
        f"系统：{release.get('PRETTY_NAME', '未知')}",
        f"系统标识：{release.get('ID', '未知')} {release.get('VERSION_ID', '未知')}",
        f"架构：{platform.machine() or '未知'}",
        f"内核：{platform.release() or '未知'}",
        f"运行时间：{uptime}",
        f"系统负载（1 / 5 / 15 分钟）：{load}",
        f"内存总量：{memory.get('MemTotal', '未知')}；可用：{memory.get('MemAvailable', '未知')}",
        f"根分区：{disk_text}",
        f"当前权限：{privilege}",
        "支持状态：开发原型，尚无经过完整验证的发行版。",
    ))


def format_result(title: str, result: Result) -> str:
    label = "已读取" if result.state == "ok" else "未知或检查失败"
    code = "" if result.exit_code is None or result.exit_code == 0 else f"；退出码 {result.exit_code}"
    return f"[{title} | {label}{code}]\n{result.output}"


def network_report() -> str:
    values = (
        ("TCP 拥塞控制", "/proc/sys/net/ipv4/tcp_congestion_control"),
        ("可用 TCP 拥塞控制", "/proc/sys/net/ipv4/tcp_available_congestion_control"),
        ("默认队列", "/proc/sys/net/core/default_qdisc"),
    )
    return "\n\n".join((
        "\n".join(f"{label}：{read_value(path)}" for label, path in values),
        "TCP 默认值不等于 Hy2 / QUIC 的拥塞控制；默认队列也不代表所有接口的实际队列。",
        format_result("实际接口队列", run_check("qdisc")),
        format_result("TCP / UDP 监听", run_check("listening")),
        format_result("项目 Hy2 IPv4 规则", run_check("hy2_ipv4")),
        format_result("项目 Hy2 IPv6 规则", run_check("hy2_ipv6")),
        "监听信息不证明公网可访问；普通用户可能看不到其他进程名称。",
    ))


def security_report() -> str:
    checks = (
        ("ssh.service", "ssh_service"),
        ("sshd.service", "sshd_service"),
        ("ssh.socket", "ssh_socket"),
        ("SSH 默认上下文配置", "sshd_config"),
        ("UFW", "ufw"),
        ("Fail2ban 服务", "fail2ban_service"),
        ("Fail2ban jail", "fail2ban"),
        ("系统 SSH jail", "fail2ban_ssh"),
        ("项目 SSH jail", "fail2ban_managed"),
    )
    return "\n\n".join((
        *(format_result(title, run_check(name)) for title, name in checks),
        "SSH 默认上下文不包含特定用户、来源或 Match 条件的完整判断；公钥能否登录需要独立验证。",
        "UFW、Fail2ban、SSH 和云防火墙是独立检查项；云防火墙状态未检查。",
    ))


def panel_report() -> str:
    return "\n\n".join((
        format_result("3x-ui 服务", run_check("xui_service")),
        format_result("TCP / UDP 监听", run_check("listening")),
        "服务状态和监听信息不证明面板可从公网访问，也不证明客户端协议可用。",
        "本检查不读取面板账户、密码、订阅链接或数据库。",
    ))
