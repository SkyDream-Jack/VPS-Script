"""常用只读信息和少量低风险设置（时区、DNS 查看）。"""

from pathlib import Path
import re
import subprocess

from . import checks, packages

TIMEZONE_RE = re.compile(r"^(?:UTC|[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)+)$")
MAX_TIMEZONES = 2000


class CommonFailure(Exception):
    pass


def _run(args, *, timeout=20):
    try:
        return subprocess.run(
            args, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, check=False,
            env={"PATH": packages.SAFE_PATH, "LC_ALL": "C", "LANG": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CommonFailure(f"无法运行 {args[0]}：{exc}") from exc


def timezone_status():
    configured = ""
    try:
        configured = Path("/etc/timezone").read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        pass
    effective = ""
    command = checks.find_command("timedatectl")
    if command:
        result = _run((command, "show", "--property=Timezone", "--value"), timeout=5)
        if result.returncode == 0:
            effective = result.stdout.strip()
    return {"configured": configured or "未知", "effective": effective or configured or "未知"}


def list_timezones():
    command = checks.find_command("timedatectl")
    if not command:
        raise CommonFailure("未找到 timedatectl")
    result = _run((command, "list-timezones"), timeout=15)
    if result.returncode != 0:
        raise CommonFailure("无法读取时区列表")
    values = tuple(line.strip() for line in result.stdout.splitlines() if line.strip())
    if not values or len(values) > MAX_TIMEZONES:
        raise CommonFailure("时区列表为空或异常")
    return values


def validate_timezone(name):
    if not isinstance(name, str) or not TIMEZONE_RE.fullmatch(name):
        raise CommonFailure("时区名称格式无效")
    if name not in list_timezones():
        raise CommonFailure("时区不在 timedatectl 列表中")
    return name


def set_timezone(name):
    validate_timezone(name)
    command = checks.find_command("timedatectl")
    if not command:
        raise CommonFailure("未找到 timedatectl")
    result = _run((command, "set-timezone", name), timeout=20)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise CommonFailure(f"设置时区失败：{detail}")
    return f"时区已设置为 {name}；已有服务是否重新读取时区需单独检查。"


def dns_status(path=Path("/etc/resolv.conf")):
    nameservers = []
    search = []
    path = Path(path)
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            fields = line.split()
            if not fields or fields[0].startswith("#"):
                continue
            if fields[0] == "nameserver" and len(fields) >= 2:
                nameservers.append(fields[1])
            elif fields[0] == "search" and len(fields) >= 2:
                search.extend(fields[1:])
    except (OSError, UnicodeError) as exc:
        raise CommonFailure(f"无法读取 /etc/resolv.conf：{exc}") from exc
    return {
        "nameservers": tuple(dict.fromkeys(nameservers)),
        "search": tuple(dict.fromkeys(search)),
        "symlink": path.is_symlink(),
    }


def timezone_change(experimental=False):
    error = packages.preflight(experimental)
    if error:
        print(f"未执行：{error}")
        return 2
    try:
        current = timezone_status()
        print(f"\n当前时区：{current['effective']}（/etc/timezone：{current['configured']}）")
        print("将调用 timedatectl set-timezone；不会修改时钟或 NTP 配置。")
        name = input("新时区（例如 Asia/Shanghai）：").strip()
        if not name:
            print("已取消。")
            return 0
        validate_timezone(name)
        if input("输入 YES 继续，其他内容取消：").strip() != "YES":
            print("已取消。")
            return 0
        print(set_timezone(name))
        return 0
    except (CommonFailure, EOFError) as exc:
        print(f"操作未完成：{exc}")
        return 1


def show_dns():
    try:
        status = dns_status()
    except CommonFailure as exc:
        print(f"无法读取 DNS：{exc}")
        return 1
    print("DNS 名称服务器：" + ("、".join(status["nameservers"]) or "未配置"))
    print("搜索域：" + ("、".join(status["search"]) or "未配置"))
    print("/etc/resolv.conf " + ("是符号链接（可能由 systemd-resolved 管理）" if status["symlink"] else "是普通文件"))
    print("本工具不修改 DNS，避免覆盖 systemd-resolved、云厂商或容器配置。")
    return 0
