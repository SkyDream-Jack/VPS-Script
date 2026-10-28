"""内置的只读/轻量机器与网络测试。

不下载第三方测试脚本；外部 NQ/TQ/IPQuality/NetQuality/YABS 由
``external.py`` 单独管理并需要明确确认。
"""

import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import time

from . import checks, common, packages

PING_TARGETS = ("1.1.1.1", "8.8.8.8", "223.5.5.5")


class BenchFailure(Exception):
    pass


def _run(args, *, timeout=20, cwd=None):
    try:
        return subprocess.run(
            args, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, check=False, cwd=cwd,
            env={"PATH": packages.SAFE_PATH, "LC_ALL": "C", "LANG": "C", "HOME": "/root"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BenchFailure(f"无法运行 {args[0]}：{exc}") from exc


def _read(path):
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return ""


def _cpu_model():
    text = _read("/proc/cpuinfo")
    for key in ("model name", "Model", "Hardware", "Processor"):
        for line in text.splitlines():
            name, sep, value = line.partition(":")
            if sep and name.strip() == key and value.strip():
                return value.strip()
    return platform.processor() or "未知"


def _memory():
    values = {}
    for line in _read("/proc/meminfo").splitlines():
        key, sep, value = line.partition(":")
        if sep and key in ("MemTotal", "MemAvailable"):
            values[key] = value.strip()
    return values


def _uptime():
    try:
        seconds = int(float(_read("/proc/uptime").split()[0]))
    except (ValueError, IndexError):
        return "未知"
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    return f"{days} 天 {hours} 小时 {rest // 60} 分钟"


def _virt():
    command = checks.find_command("systemd-detect-virt")
    if not command:
        return "未知（未找到 systemd-detect-virt）"
    result = _run((command,), timeout=5)
    if result.returncode != 0:
        return "未知"
    value = result.stdout.strip()
    return "none（物理机或未识别）" if value == "none" else value


def machine_report():
    release = checks.os_release()
    memory = _memory()
    try:
        disk = shutil.disk_usage("/")
        disk_text = f"{disk.used / 1024**3:.1f} / {disk.total / 1024**3:.1f} GiB 已用"
    except OSError:
        disk_text = "未知"
    try:
        load = " / ".join(f"{value:.2f}" for value in os.getloadavg())
    except (OSError, AttributeError):
        load = "未知"
    cores = os.cpu_count() or 0
    lines = [
        "=== 机器 / 系统 ===",
        f"系统：{release.get('PRETTY_NAME', '未知')}",
        f"内核：{platform.release() or '未知'}    架构：{platform.machine() or '未知'}",
        f"虚拟化：{_virt()}",
        f"CPU：{_cpu_model()}（{cores} 逻辑核心）",
        f"内存：总 {memory.get('MemTotal', '未知')} / 可用 {memory.get('MemAvailable', '未知')}",
        f"根分区：{disk_text}",
        f"运行时间：{_uptime()}    负载：{load}",
        f"TCP 拥塞控制：{_read('/proc/sys/net/ipv4/tcp_congestion_control') or '未知'}",
        f"默认队列：{_read('/proc/sys/net/core/default_qdisc') or '未知'}",
        "说明：这是只读信息，不代表 CPU 跑分或磁盘性能。",
    ]
    return "\n".join(lines)


def parse_ping(text):
    loss = re.search(r"(\d+(?:\.\d+)?)% packet loss", text)
    rtt = re.search(r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", text)
    if not loss:
        raise BenchFailure("无法解析 ping 丢包率")
    return {
        "loss": float(loss.group(1)),
        "min": float(rtt.group(1)) if rtt else None,
        "avg": float(rtt.group(2)) if rtt else None,
        "max": float(rtt.group(3)) if rtt else None,
    }


def ping_target(target, count=4):
    command = checks.find_command("ping")
    if not command:
        raise BenchFailure("未找到 ping；请安装 iputils-ping")
    result = _run((command, "-n", "-c", str(count), "-W", "2", target), timeout=count * 3 + 5)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise BenchFailure(f"{target} 探测失败：{detail[:200]}")
    return parse_ping(result.stdout)


def network_report():
    lines = ["=== 网络 / 延迟 ==="]
    ip = checks.find_command("ip")
    if ip:
        addr = _run((ip, "-brief", "address"), timeout=5)
        route = _run((ip, "route", "show", "default"), timeout=5)
        lines.append("接口：")
        lines.append(addr.stdout.strip() or "无输出")
        lines.append("默认路由：")
        lines.append(route.stdout.strip() or "无输出")
    else:
        lines.append("未找到 ip 命令。")
    try:
        dns = common.dns_status()
        lines.append("DNS：" + ("、".join(dns["nameservers"]) or "未配置"))
    except common.CommonFailure as exc:
        lines.append(f"DNS：未知（{exc}）")
    ss = checks.find_command("ss")
    if ss:
        summary = _run((ss, "-s"), timeout=5)
        lines.append("TCP/UDP 摘要：")
        lines.append(summary.stdout.strip()[:3000] or "无输出")
    lines.append("ICMP 延迟：")
    for target in PING_TARGETS:
        try:
            result = ping_target(target)
            rtt = f"平均 {result['avg']:.2f} ms" if result["avg"] is not None else "无 RTT"
            lines.append(f"  {target}: 丢包 {result['loss']:.0f}% / {rtt}")
        except BenchFailure as exc:
            lines.append(f"  {target}: 未知（{exc}）")
    lines.append("说明：ICMP 可能被服务商或目标限速；延迟不代表实际代理吞吐。")
    return "\n".join(lines)


def route_report():
    mtr = checks.find_command("mtr")
    if mtr:
        result = _run((mtr, "-rwzbc", "10", "1.1.1.1"), timeout=90)
        if result.returncode == 0:
            return "=== 线路追踪（mtr，1.1.1.1）===\n" + result.stdout.strip()[:12000]
        detail = (result.stderr or result.stdout or "").strip()[:300]
        return f"mtr 执行失败：{detail}\n可尝试安装 mtr-tiny 后重试。"
    traceroute = checks.find_command("traceroute")
    if traceroute:
        result = _run((traceroute, "-n", "-w", "2", "-q", "1", "-m", "20", "1.1.1.1"), timeout=90)
        if result.returncode == 0:
            return "=== 线路追踪（traceroute，1.1.1.1）===\n" + result.stdout.strip()[:12000]
        detail = (result.stderr or result.stdout or "").strip()[:300]
        return f"traceroute 执行失败：{detail}"
    return "未找到 mtr 或 traceroute；可在“系统软件 → 网络诊断工具”中安装。"


def parse_speed(text):
    fields = text.split()
    if len(fields) < 3:
        raise BenchFailure("无法解析 curl 测速输出")
    try:
        speed, size, seconds = float(fields[0]), float(fields[1]), float(fields[2])
    except ValueError as exc:
        raise BenchFailure("curl 测速输出格式无效") from exc
    if speed < 0 or size <= 0 or seconds <= 0:
        raise BenchFailure("curl 测速结果无效")
    return {"bytes_per_second": speed, "bytes": size, "seconds": seconds,
            "mbps": speed * 8 / 1_000_000, "mib_per_second": speed / 1024**2}


def bandwidth_report(size_mb=25):
    if type(size_mb) is not int or not 10 <= size_mb <= 100:
        raise BenchFailure("测速大小必须是 10–100 MiB 的整数")
    curl = checks.find_command("curl")
    if not curl:
        raise BenchFailure("未找到 curl；请先安装 curl")
    url = f"https://speed.cloudflare.com/__down?bytes={size_mb * 1024 * 1024}"
    started = time.monotonic()
    result = _run(
        (curl, "-fsSL", "--max-time", "120", "-o", "/dev/null", "-w",
         "%{speed_download} %{size_download} %{time_total}", url),
        timeout=130,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise BenchFailure(f"下载测速失败：{detail[:300]}")
    data = parse_speed(result.stdout)
    return "\n".join((
        "=== 带宽下载测试（Cloudflare，单线程）===",
        f"下载：{data['bytes'] / 1024**2:.1f} MiB / {data['seconds']:.2f} 秒",
        f"速度：{data['mbps']:.2f} Mbps（{data['mib_per_second']:.2f} MiB/s）",
        f"进程耗时：{time.monotonic() - started:.1f} 秒",
        "说明：单线程 HTTP 下载，受对端、线路、TCP 窗口和本地限速影响；不代表多线程或代理吞吐。",
    ))
