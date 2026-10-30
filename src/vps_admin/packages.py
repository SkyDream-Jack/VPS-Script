"""APT 操作的试验性实现。

模块只允许固定动作；实际修改需要显式启用试验模式、Linux、Ubuntu/Debian、
root、交互终端和再次确认。尚未在隔离 Linux 环境验证，不应在重要机器使用。
"""

from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import platform
import re
import shlex
import subprocess
import sys
from urllib.parse import urlsplit

from . import backup, checks

APT = "/usr/bin/apt-get"
SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
PROXY_VARS = ("http_proxy", "https_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "all_proxy", "ALL_PROXY")
URL_PATTERN = re.compile(r"https?://[^\s<>\"'#]+", re.IGNORECASE)


@dataclass(frozen=True)
class AptAction:
    title: str
    arguments: tuple
    simulate: bool
    impact: str


# 包名不可由菜单输入拼接，避免未经审查的命令参数进入 root 进程。
ACTIONS = {
    "update": AptAction("更新软件包索引", ("update",), False, "读取已有软件源并下载索引；不会更换软件源。"),
    "upgrade": AptAction("升级已安装软件包", ("upgrade",), True, "升级软件包可能重启服务或要求处理配置文件；无法保证完整回滚。"),
    "base": AptAction("安装基础工具", ("install", "ca-certificates", "curl", "wget", "git", "unzip", "tar"), True, "安装列出的软件及依赖，依赖项可能升级；软件包维护脚本以 root 执行。"),
    "network": AptAction("安装网络诊断工具", ("install", "iproute2", "iputils-ping", "dnsutils", "traceroute"), True, "安装列出的软件及依赖；不会自动发起诊断探测。"),
    "monitor": AptAction("安装常用查看工具", ("install", "htop", "jq"), True, "安装列出的软件及依赖。"),
    "security": AptAction("安装安全工具", ("install", "ufw", "fail2ban", "python3-systemd"), True, "安装 UFW、Fail2ban 和 systemd 日志支持；安装后的服务状态仍需检查。"),
}


def origin_from_url(url: str):
    """只返回经过校验的协议、主机和端口，不暴露凭据或请求路径。"""
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
        if parsed.scheme.lower() not in ("http", "https") or not host:
            return None
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r"[a-z0-9._-]+", host):
                return None
            display_host = host
        else:
            display_host = f"[{address}]" if address.version == 6 else str(address)
        return f"{parsed.scheme.lower()}://{display_host}" + (f":{port}" if port else "")
    except ValueError:
        return None


def source_origins(root: Path = Path("/etc/apt")):
    """列出默认 APT 源文件中可辨认的 HTTP(S) 来源；不是完整网络审计。"""
    sources = [root / "sources.list"]
    parts = root / "sources.list.d"
    try:
        sources.extend(sorted(parts.glob("*.list")))
        sources.extend(sorted(parts.glob("*.sources")))
    except OSError:
        return (), True
    origins = set()
    unreadable = False
    for path in sources:
        try:
            if not path.exists():
                continue
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            unreadable = True
            continue
        for line in text.splitlines():
            if line.lstrip().startswith("#"):
                continue
            for url in URL_PATTERN.findall(line):
                origin = origin_from_url(url)
                if origin:
                    origins.add(origin)
    return tuple(sorted(origins)), unreadable


def apt_env():
    """避免把任意代码注入类环境变量传给 root 子进程，保留常见代理设置。"""
    env = {"PATH": SAFE_PATH, "HOME": "/root"}
    # 不继承 APT_CONFIG：它能让调用者改变 APT 的配置目录、钩子和来源。
    for name in (*PROXY_VARS, "LANG", "LC_ALL", "TERM"):
        if name in os.environ:
            env[name] = os.environ[name]
    return env


def preflight(experimental: bool):
    if not experimental:
        return "软件修改尚未在 Linux 隔离环境验证；默认关闭。"
    if platform.system() != "Linux":
        return "只允许在 Linux 上运行。"
    distribution = checks.os_release().get("ID", "")
    if distribution not in ("ubuntu", "debian"):
        return "未识别为 Ubuntu 或 Debian，已停止。"
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return "此操作需要 root；请先查看系统权限。"
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return "需要交互式终端；不会从管道或无人值守环境执行。"
    if not os.path.isfile(APT) or not os.access(APT, os.X_OK):
        return "未找到 /usr/bin/apt-get，已停止。"
    return None


def apt_command(action: AptAction, simulate: bool = False):
    args = [APT, "-o", "APT::Get::AllowUnauthenticated=false", "-o", "quiet=0"]
    if simulate:
        args.append("--simulate")
    if action.arguments[0] != "update":
        args.extend((
            "--no-remove", "-o", "APT::Get::Assume-Yes=false",
            "-o", "APT::Get::AutomaticRemove=false", "-o", "APT::Get::force-yes=false",
            "-o", "APT::Get::allow-downgrades=false", "-o", "APT::Get::allow-change-held-packages=false",
        ))
        if action.arguments[0] == "upgrade":
            args.extend(("-o", "APT::Get::Upgrade-Allow-New=false"))
    else:
        args.extend(("-o", "Acquire::AllowInsecureRepositories=false", "-o", "Acquire::AllowDowngradeToInsecureRepositories=false"))
    args.extend(action.arguments)
    return tuple(args)


def run_action(name: str, experimental: bool = False) -> int:
    """在完成检查和交互确认后运行固定 APT 操作。"""
    action = ACTIONS[name]
    error = preflight(experimental)
    if error:
        print(f"未执行：{error}")
        return 2

    print(f"\n【试验功能】{action.title}")
    print("该功能尚未通过真实 Linux/VPS 验证，只能用于可丢弃的测试环境。")
    print(action.impact)
    print("APT 会遵守本机配置；其代理、重定向、钩子和包维护脚本也可能访问网络或改变系统。")
    print("下载并发和超时由本机 APT 配置决定。执行期间请查看 APT 输出。")
    origins, unreadable = source_origins()
    print("默认源文件中识别到的 HTTP(S) 来源（可能包含禁用项）：")
    for origin in origins:
        print(f"  {origin}")
    if not origins:
        print("  未识别到；可能使用自定义源文件、非 HTTP 源或无法读取。")
    if unreadable:
        print("  有源文件无法读取，来源列表不完整。")
    print("此列表不包含全部代理、APT 自定义源位置、重定向或软件包脚本的连接。")
    if any(os.environ.get(name) for name in PROXY_VARS):
        print("检测到代理环境变量；不会显示其中的地址或凭据。")
    if os.environ.get("APT_CONFIG"):
        print("检测到 APT_CONFIG；为避免改变 APT 配置/钩子，未传入子进程。")

    args = apt_command(action)
    print("执行命令：" + " ".join(shlex.quote(value) for value in args), flush=True)
    env = apt_env()
    if action.simulate:
        print("\n先显示 APT 模拟结果（系统状态可能在模拟后发生变化）：", flush=True)
        try:
            result = subprocess.run(
                apt_command(action, simulate=True), stdin=subprocess.DEVNULL,
                check=False, timeout=120, env=env,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"模拟未完成，已停止：{exc}")
            return 1
        if result.returncode != 0:
            print(f"模拟失败（退出码 {result.returncode}），未执行修改。")
            return 1

    try:
        confirmed = input("输入 YES 继续，其他内容取消：").strip() == "YES"
    except EOFError:
        confirmed = False
    if not confirmed:
        print("已取消，没有执行 APT 修改命令。")
        return 0

    snapshot = name != "update"
    if snapshot and not backup.confirm_external_snapshot():
        print("已取消；没有执行 APT 修改命令。")
        return 0

    exit_code = 1
    def execute():
        nonlocal exit_code
        print("\n开始执行；请关注交互提示，尽量避免中断软件包管理器。", flush=True)
        result = subprocess.run(args, check=False, env=env)
        if result.returncode != 0:
            exit_code = result.returncode if result.returncode > 0 else 1
            raise RuntimeError(f"APT 返回退出码 {result.returncode}")
        return result

    try:
        backup.track("packages", name, execute, restore_supported=False, details={
            "action": name,
            "external_snapshot": "user_declared_unverified" if snapshot else "not_required_for_index_update",
            "limitation": "仅记录操作；不能自动回滚软件包、索引或维护脚本造成的变化。",
        })
    except (backup.BackupFailure, OSError) as exc:
        print(f"APT 操作或记录未完成：{exc}；命令如已启动，可能已部分执行，请检查输出和状态。")
        return exit_code
    print("APT 命令退出码为 0；请检查上方警告、服务状态以及是否需要重启。")
    if name == "update":
        print("部分源出错时 APT 仍可能使用旧索引，请检查上方警告。")
    return 0
