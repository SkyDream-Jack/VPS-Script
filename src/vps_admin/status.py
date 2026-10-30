"""只读状态收集与渲染。

状态查询只运行固定命令并读取固定文件；不探测公网、不读取面板凭据、
不显示 fail2ban 的封禁 IP 列表。每项结果都区分正常、注意和未知。
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import shutil

from . import bbr, checks, common, fail2ban, hy2, packages, panel, swap, tuning

SECTIONS = {
    "system": "系统概览",
    "packages": "系统更新与软件",
    "panel": "3x-ui 面板",
    "bbr": "BBR / fq",
    "tuning": "内核网络调优",
    "ssh": "SSH 登录",
    "ufw": "UFW 防火墙",
    "fail2ban": "Fail2ban",
    "hy2": "Hy2 跳跃端口",
    "swap": "Swap",
    "timezone": "时区",
    "dns": "DNS",
}
ALIASES = {
    "network": ("bbr", "tuning", "hy2"),
    "security": ("ssh", "ufw", "fail2ban"),
    "common": ("swap", "timezone", "dns"),
}
STATUS_LABELS = {"ok": "正常", "warn": "注意", "unknown": "未知", "info": "信息"}
SUMMARY_MAX_CHARS = 1800
SUMMARY_MAX_SECTIONS = 12


def _item(name, state, detail=""):
    return {"name": name, "state": state, "detail": detail}


def _result_item(name, result, ok_state="ok"):
    if result.state == "ok":
        return _item(name, ok_state, result.output)
    return _item(name, "unknown", result.output)


def _service_state(result):
    if result.state != "ok":
        return "unknown", {}
    fields = {}
    for line in result.output.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            fields[key.strip()] = value.strip()
    return fields.get("ActiveState", "unknown"), fields


def _read(path):
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return ""


def _system():
    release = checks.os_release()
    facts = {
        "系统": release.get("PRETTY_NAME", "未知"),
        "ID": release.get("ID", "未知"),
        "版本": release.get("VERSION_ID", "未知"),
        "架构": platform.machine() or "未知",
        "内核": platform.release() or "未知",
        "权限": "root" if hasattr(os, "geteuid") and os.geteuid() == 0 else "普通用户",
        "systemd": "运行中" if Path("/run/systemd/system").is_dir() else "未检测到",
        "时区": datetime.now().astimezone().tzname() or "未知",
    }
    items = []
    try:
        memory = {}
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            key, sep, value = line.partition(":")
            if sep and key in ("MemTotal", "MemAvailable"):
                memory[key] = value.strip()
        if memory:
            facts["内存"] = f"总 {memory.get('MemTotal', '未知')} / 可用 {memory.get('MemAvailable', '未知')}"
    except (OSError, UnicodeError):
        pass
    try:
        uptime = int(float(Path("/proc/uptime").read_text(encoding="ascii").split()[0]))
        days, rest = divmod(uptime, 86400)
        hours, rest = divmod(rest, 3600)
        facts["运行时间"] = f"{days} 天 {hours} 小时 {rest // 60} 分钟"
    except (OSError, UnicodeError, ValueError, IndexError):
        pass
    try:
        usage = shutil.disk_usage("/")
        facts["根分区"] = f"{usage.used / 1024**3:.1f} / {usage.total / 1024**3:.1f} GiB 已用"
    except OSError:
        pass
    items.append(_item("发行版支持", "info", "当前只把 Ubuntu / Debian 作为目标；其他系统只读展示。"))
    return {"name": "system", "title": SECTIONS["system"], "facts": facts, "items": items}


def _packages():
    origins, unreadable = packages.source_origins()
    facts = {
        "包管理器": "APT" if checks.find_command("apt-get") else "未找到 apt-get",
        "软件源数量": str(len(origins)),
        "软件源": "、".join(origins) if origins else "未识别",
    }
    items = []
    stamp_candidates = (
        Path("/var/lib/apt/periodic/update-success-stamp"),
        Path("/var/lib/apt/lists"),
    )
    stamp = None
    for candidate in stamp_candidates:
        try:
            stamp = candidate.stat().st_mtime
            break
        except OSError:
            continue
    if stamp:
        facts["最近索引更新"] = datetime.fromtimestamp(stamp).strftime("%Y-%m-%d %H:%M:%S")
    else:
        facts["最近索引更新"] = "未知"
    reboot_required = Path("/var/run/reboot-required")
    facts["需要重启"] = "是" if reboot_required.exists() else "未标记"
    if unreadable:
        items.append(_item("软件源读取", "warn", "至少一个源文件无法读取，来源列表不完整。"))
    elif not origins:
        items.append(_item("软件源读取", "warn", "未在默认源文件中识别到 HTTP(S) 来源；可能使用自定义源或非 HTTP 源。"))
    else:
        items.append(_item("软件源读取", "ok", "默认源文件中的 HTTP(S) 来源已读取；不包含代理和重定向。"))
    if reboot_required.exists():
        items.append(_item("重启标记", "warn", "/var/run/reboot-required 存在；请在合适窗口重启。"))
    else:
        items.append(_item("重启标记", "ok", "未发现 /var/run/reboot-required。"))
    return {"name": "packages", "title": SECTIONS["packages"], "facts": facts, "items": items}


def _panel():
    installed = panel.existing_installation()
    facts = {"安装路径": "、".join(installed) if installed else "未检测到"}
    items = []
    service = checks.run_check("xui_service")
    state, fields = _service_state(service)
    facts["服务"] = f"{state} / {fields.get('UnitFileState', 'unknown')}"
    if state == "active":
        items.append(_item("3x-ui 服务", "ok", "服务处于 active。"))
    elif state == "unknown":
        items.append(_item("3x-ui 服务", "unknown", service.output))
    else:
        items.append(_item("3x-ui 服务", "warn", f"服务状态为 {state}。"))
    settings = panel.read_settings()
    if settings:
        facts.update({key: value for key, value in settings.items()})
        port = settings.get("端口")
        if port and port.isdigit():
            listen = checks.run_check("listening")
            if listen.state == "ok" and re.search(rf":{re.escape(port)}\b", listen.output):
                items.append(_item("面板监听", "ok", f"检测到端口 {port} 的监听；未验证公网可达。"))
            elif listen.state == "ok":
                items.append(_item("面板监听", "warn", f"未在监听列表中看到端口 {port}。"))
            else:
                items.append(_item("面板监听", "unknown", listen.output))
    else:
        items.append(_item("面板设置", "unknown", "未读取到端口/路径；可能未安装或需要 root。"))
    items.append(_item("访问验证", "info", "服务运行和端口监听不等于公网可访问；云防火墙与 TLS 需单独检查。"))
    return {"name": "panel", "title": SECTIONS["panel"], "facts": facts, "items": items}


def _bbr():
    manager = bbr.BBRManager()
    facts = {}
    items = []
    try:
        live = manager.read_live()
        facts["TCP 拥塞控制"] = live[bbr.TCP]
        facts["默认队列"] = live[bbr.QDISC]
    except (bbr.BBRFailure, OSError) as exc:
        live = {}
        items.append(_item("运行时值", "unknown", str(exc)))
    try:
        facts["可用拥塞控制"] = " ".join(manager.available()) or "未知"
    except (bbr.BBRFailure, OSError) as exc:
        facts["可用拥塞控制"] = "未知"
        items.append(_item("可用算法", "unknown", str(exc)))
    facts["项目配置"] = "存在" if os.path.lexists(manager.config) else "不存在"
    facts["状态文件"] = "存在" if os.path.lexists(manager.state) else "不存在"
    facts["模块持久化"] = "存在" if os.path.lexists(manager.modules) else "不存在"
    if live:
        if live.get(bbr.TCP) == "bbr" and live.get(bbr.QDISC) == "fq":
            items.append(_item("运行时值", "ok", "当前为 bbr / fq。"))
        else:
            items.append(_item("运行时值", "warn", "当前不是 bbr / fq；可能未启用或被其他配置覆盖。"))
    if os.path.lexists(manager.config):
        try:
            if manager._read_regular(manager.config) == bbr.CONFIG:
                items.append(_item("项目配置", "ok", "90-vps-script.conf 内容符合预期。"))
            else:
                items.append(_item("项目配置", "warn", "项目配置文件被外部修改，恢复会停止。"))
        except bbr.BBRFailure as exc:
            items.append(_item("项目配置", "unknown", str(exc)))
    else:
        items.append(_item("项目配置", "info", "尚未启用项目 BBR 配置。"))
    module_loaded = Path("/sys/module/tcp_bbr").exists()
    facts["tcp_bbr 模块"] = "已加载" if module_loaded else "未加载或内建"
    try:
        conflicts = manager.conflicts()
    except bbr.BBRFailure as exc:
        conflicts = (str(exc),)
    if conflicts:
        items.append(_item("配置冲突", "warn", "\n".join(conflicts)))
    else:
        items.append(_item("配置冲突", "ok", "未发现其他 sysctl 文件设置不同的目标值。"))
    items.append(_item("Hy2 说明", "info", "TCP BBR 不是 Hy2/QUIC 的拥塞控制；需单独查看 Hy2 配置。"))
    return {"name": "bbr", "title": SECTIONS["bbr"], "facts": facts, "items": items}


def _parse_effective(text):
    values = {}
    for line in text.splitlines():
        fields = line.split(maxsplit=1)
        if len(fields) == 2:
            values.setdefault(fields[0].lower(), []).append(fields[1].strip())
    return values


def _ssh_ufw_item(text, ports):
    """Summarize explicit rules, without equating a port match to access.

    UFW's display omits some rule details, so source/destination constraints,
    ranges and possible earlier blocking rules require separate inspection.
    Only simple ALLOW IN rules for both families receive an OK summary.
    """
    allowed = {port: set() for port in ports}
    ambiguous = False
    blocked = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        rule = re.fullmatch(r"(.+?)\s+(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD)\s+(.+)", line)
        if not rule:
            if re.search(r"\b(?:ALLOW|DENY|REJECT|LIMIT)\b", line):
                ambiguous = True
            continue
        destination, action, direction, source = rule.groups()
        if direction != "IN":
            continue
        family = "IPv6" if destination.endswith(" (v6)") else "IPv4"
        destination = destination.removesuffix(" (v6)")
        relevant = destination in {f"{port}/tcp" for port in ports}
        if action != "ALLOW":
            # Even a differently labelled rule may precede and overlap an
            # allow rule (Anywhere, ranges, application profiles, etc.).
            ambiguous = True
            blocked = blocked or relevant
            continue
        expected_source = "Anywhere (v6)" if family == "IPv6" else "Anywhere"
        if not relevant or source != expected_source:
            ambiguous = True
            continue
        allowed[destination.removesuffix("/tcp")].add(family)
    evidence = "；".join(f"{port}/tcp：{'、'.join(sorted(families))} ALLOW IN"
                        for port, families in allowed.items() if families)
    if all(families == {"IPv4", "IPv6"} for families in allowed.values()) and not ambiguous:
        return _item("UFW 放行", "ok", evidence + "。仅为明确规则记录；不证明外部 SSH 可达。")
    if evidence:
        return _item("UFW 放行", "info", evidence + "。其他地址族、来源限制或规则顺序未确认，请独立验证连接。")
    detail = "存在该端口的限制/拒绝入站规则。" if blocked else "未确认覆盖该端口的无来源限制 ALLOW IN 规则。"
    return _item("UFW 放行", "warn", detail + "来源、地址族和规则顺序需单独检查；不据此推断连接可达。")


def _tuning():
    try:
        info = tuning.TuningManager().inspect()
    except (tuning.TuningFailure, bbr.BBRFailure, OSError) as exc:
        return {"name": "tuning", "title": SECTIONS["tuning"], "facts": {}, "items": [_item("调优", "unknown", str(exc))]}
    values = info["values"]
    state = info["state"]
    facts = {
        "档位": tuning.PROFILE_TITLES.get(state.get("profile"), "未应用") if state and not state.get("invalid") else "未应用或状态无效",
        "项目配置": "存在" if info["config_exists"] else "不存在",
        "状态文件": "存在" if state else "不存在",
        "配置内容": "匹配" if info["config_matches"] else ("未知" if info["config_exists"] else "不存在"),
        "内存": f"{tuning.read_ram_kb() // 1024} MiB",
    }
    labels = {
        "somaxconn": "net.core.somaxconn",
        "tcp_max_syn_backlog": "net.ipv4.tcp_max_syn_backlog",
        "ip_local_port_range": "net.ipv4.ip_local_port_range",
        "tcp_tw_reuse": "net.ipv4.tcp_tw_reuse",
        "tcp_fastopen": "net.ipv4.tcp_fastopen",
        "tcp_slow_start_after_idle": "net.ipv4.tcp_slow_start_after_idle",
        "tcp_notsent_lowat": "net.ipv4.tcp_notsent_lowat",
        "rmem_max": "net.core.rmem_max",
        "wmem_max": "net.core.wmem_max",
        "tcp_rmem": "net.ipv4.tcp_rmem",
        "tcp_wmem": "net.ipv4.tcp_wmem",
        "tcp_mem": "net.ipv4.tcp_mem",
        "nf_conntrack_max": "net.netfilter.nf_conntrack_max",
    }
    for label, key in labels.items():
        value = values.get(key)
        facts[label] = value if value else "未知/未加载"
    items = []
    if state and state.get("invalid"):
        items.append(_item("项目调优", "warn", "状态文件无法解析；不会自动恢复。"))
    elif state:
        items.append(_item("项目调优", "info", f"状态文件记录 {len(state['target'])} 项，档位 {tuning.PROFILE_TITLES.get(state['profile'], state['profile'])}；记录本身不证明所有参数已生效。"))
        if not info["config_matches"]:
            items.append(_item("配置一致性", "warn", "项目配置文件缺失或被外部修改；缺失时可按有效快照尝试恢复，内容或运行值被外部修改时会停止。"))
        if state.get("skipped"):
            items.append(_item("跳过的参数", "info", "、".join(state["skipped"])))
    else:
        items.append(_item("项目调优", "info", "尚未应用；系统使用当前内核/发行版默认值。"))
    if values.get("net.ipv4.tcp_tw_reuse") == "1" and values.get("net.ipv4.tcp_timestamps") != "1":
        items.append(_item("tcp_tw_reuse", "warn", "已开启 reuse，但 timestamps 不是 1；这种组合不安全。"))
    if values.get("net.ipv4.tcp_fastopen") == "3":
        items.append(_item("TCP Fast Open", "info", "已开启（客户端+服务端）；实际可用性取决于应用和中间设备。"))
    if not values.get("net.netfilter.nf_conntrack_max"):
        items.append(_item("Conntrack", "info", "未加载或不可读；不会设置 conntrack 上限。"))
    items.append(_item("BBR / qdisc", "info", "由 BBR 模块单独管理；本模块不改 tcp_congestion_control 和 default_qdisc。"))
    items.append(_item("性能结论", "info", "参数写入不等于实际提速；需同机、同对端 A/B 测试。"))
    return {"name": "tuning", "title": SECTIONS["tuning"], "facts": facts, "items": items}


def _ssh():
    facts = {}
    items = []
    for name, label in (("ssh_service", "ssh.service"), ("sshd_service", "sshd.service"), ("ssh_socket", "ssh.socket")):
        result = checks.run_check(name)
        state, _ = _service_state(result)
        facts[label] = state
        if state == "active":
            items.append(_item(label, "ok", "active。"))
        elif state == "unknown":
            items.append(_item(label, "unknown", result.output))
        else:
            items.append(_item(label, "info", state))
    effective_result = checks.run_check("sshd_config")
    if effective_result.state == "ok":
        values = _parse_effective(effective_result.output)
        ports = values.get("port", [])
        facts["有效端口"] = "、".join(ports) or "未知"
        for key, label in (
            ("passwordauthentication", "密码认证"),
            ("kbdinteractiveauthentication", "键盘交互认证"),
            ("pubkeyauthentication", "公钥认证"),
            ("permitrootlogin", "root 登录"),
            ("authenticationmethods", "认证方法"),
        ):
            if key in values:
                facts[label] = "、".join(values[key])
        password = values.get("passwordauthentication", [])
        kbd = values.get("kbdinteractiveauthentication", [])
        pubkey = values.get("pubkeyauthentication", [])
        methods = values.get("authenticationmethods", [])
        password_off = password == ["no"] and kbd == ["no"]
        password_switch_on = password == ["yes"] or kbd == ["yes"]
        key_only = password_off and pubkey == ["yes"] and methods == ["publickey"]
        if key_only:
            items.append(_item("仅公钥认证", "ok", "默认上下文明确要求 publickey，且密码和键盘交互认证已关闭；实际登录仍需验证。"))
        elif password_switch_on:
            items.append(_item("仅公钥认证", "warn", "密码或键盘交互认证开关仍开启；实际可用方式还受 AuthenticationMethods 等设置限制。"))
        elif password_off and pubkey == ["no"]:
            items.append(_item("仅公钥认证", "warn", "密码和键盘交互认证已关闭，但公钥认证也未启用；请检查实际认证方式。"))
        elif password_off:
            items.append(_item("仅公钥认证", "unknown", "密码和键盘交互认证已关闭，但仅公钥认证尚未确认；AuthenticationMethods=any 或字段缺失不能据此判定。"))
        else:
            items.append(_item("仅公钥认证", "unknown", "认证字段不完整或无法识别，仅公钥认证尚未确认。"))
        root_login = values.get("permitrootlogin", [])
        if root_login:
            policy = root_login[0]
            if policy == "yes" and key_only:
                items.append(_item("root 登录", "info",
                                   "PermitRootLogin 为 yes；默认上下文明确要求公钥，且密码/键盘交互已关闭；root 实际登录仍需验证。"))
            elif policy == "yes" and password_off:
                items.append(_item("root 登录", "unknown",
                                   "PermitRootLogin 为 yes；密码/键盘交互均已关闭，但 root 仅公钥认证尚未确认。"))
            elif policy == "yes" and password_switch_on:
                items.append(_item("root 登录", "warn",
                                   "PermitRootLogin 为 yes，且密码或键盘交互开关仍开启；实际可用方式还受 AuthenticationMethods 等设置限制。"))
            elif policy == "yes":
                items.append(_item("root 登录", "unknown",
                                   "PermitRootLogin 为 yes；认证字段不完整，无法确认 root 的认证方式。"))
            elif policy in ("prohibit-password", "without-password"):
                items.append(_item("root 登录", "info", "root 密码和键盘交互认证被禁止；是否仅公钥还需结合 AuthenticationMethods 等设置判断。"))
            elif policy == "no":
                items.append(_item("root 登录", "info", "root 登录已禁用；如需 root 请使用普通用户 + sudo。"))
            else:
                items.append(_item("root 登录", "info", f"当前策略：{policy}。"))
        # 检查 UFW 是否放行有效 SSH 端口。
        ufw = checks.run_check("ufw")
        if ufw.state == "ok" and "Status: active" in ufw.output and ports:
            items.append(_ssh_ufw_item(ufw.output, ports))
    else:
        items.append(_item("有效 SSH 配置", "unknown", effective_result.output))
    listen = checks.run_check("listening")
    if listen.state == "ok":
        facts["监听"] = "已读取（内容可能含 IP/进程名，分享前遮盖）"
    else:
        facts["监听"] = "未知"
    items.append(_item("公钥验证", "info", "配置值和公钥文件不能证明外部登录成功；需从第二个会话实测。"))
    return {"name": "ssh", "title": SECTIONS["ssh"], "facts": facts, "items": items}


def _ufw():
    result = checks.run_check("ufw")
    facts = {}
    items = []
    if result.state != "ok":
        facts["状态"] = "未知"
        items.append(_item("UFW", "unknown", result.output))
        facts["IPv6"] = _ufw_ipv6()
        return {"name": "ufw", "title": SECTIONS["ufw"], "facts": facts, "items": items}
    text = result.output
    active = "Status: active" in text
    facts["状态"] = "active" if active else "inactive"
    facts["IPv6"] = _ufw_ipv6()
    default_line = next((line for line in text.splitlines() if line.startswith("Default:")), "")
    if default_line:
        facts["默认策略"] = default_line.split(":", 1)[1].strip()
    facts["规则摘要"] = text[:4000] + ("\n……输出已截断" if len(text) > 4000 else "")
    if active:
        items.append(_item("UFW 状态", "ok", "防火墙已启用。"))
        if "deny (incoming)" not in default_line:
            items.append(_item("默认入站", "warn", "默认入站策略不是 deny；启用前应先确认。"))
        else:
            items.append(_item("默认入站", "ok", "默认拒绝入站。"))
    else:
        items.append(_item("UFW 状态", "warn", "防火墙未启用。"))
    if facts["IPv6"] == "no":
        items.append(_item("IPv6", "warn", "/etc/default/ufw 中 IPV6=no；IPv6 流量可能不受 UFW 管理。"))
    else:
        items.append(_item("IPv6", "info", f"IPV6={facts['IPv6']}；仍需确认内核和云防火墙。"))
    items.append(_item("云防火墙", "info", "本工具无法读取云厂商安全组；需在控制台单独检查。"))
    return {"name": "ufw", "title": SECTIONS["ufw"], "facts": facts, "items": items}


def _ufw_ipv6():
    text = _read("/etc/default/ufw")
    match = re.search(r"^IPV6\s*=\s*(\S+)", text, re.MULTILINE)
    return match.group(1).strip("\"'") if match else "未知"


def _parse_jail(text):
    result = {}
    for key in ("Currently banned", "Total banned", "Currently failed", "Total failed"):
        match = re.search(rf"^[\s|`+\-]*{re.escape(key)}:\s*(\d+)\s*$", text, re.MULTILINE)
        if match:
            result[key] = int(match.group(1))
    return result


def _fail2ban():
    service = checks.run_check("fail2ban_service")
    state, fields = _service_state(service)
    facts = {"服务": f"{state} / {fields.get('UnitFileState', 'unknown')}"}
    items = []
    if state == "active":
        items.append(_item("Fail2ban 服务", "ok", "active。"))
    elif state == "unknown":
        items.append(_item("Fail2ban 服务", "unknown", service.output))
    else:
        items.append(_item("Fail2ban 服务", "warn", f"状态为 {state}。"))
    status = checks.run_check("fail2ban")
    if status.state == "ok":
        try:
            jails = fail2ban.jail_names(status.output)
        except fail2ban.Fail2banFailure as exc:
            jails = ()
            items.append(_item("Jail 列表", "unknown", str(exc)))
        facts["Jail"] = "、".join(jails) if jails else "无"
        for name, label in ((fail2ban.JAIL, "项目 SSH jail"), ("sshd", "系统 SSH jail")):
            if name not in jails:
                items.append(_item(label, "info", "未启用。"))
                continue
            result = checks.run_check("fail2ban_managed" if name == fail2ban.JAIL else "fail2ban_ssh")
            if result.state == "ok":
                counts = _parse_jail(result.output)
                facts[label] = "、".join(f"{key} {value}" for key, value in counts.items()) or "已启用"
                items.append(_item(label, "ok", "已启用；封禁 IP 列表不在此显示。"))
            else:
                items.append(_item(label, "unknown", result.output))
    else:
        items.append(_item("Jail 列表", "unknown", status.output))
    items.append(_item("封禁动作", "info", "默认动作可能写入 nftables/iptables；与 UFW 的组合需单独检查。"))
    return {"name": "fail2ban", "title": SECTIONS["fail2ban"], "facts": facts, "items": items}


def _hy2():
    manager = hy2.Hy2Manager()
    facts = {}
    items = []
    for path, label in ((manager.config, "规则文件"), (manager.unit, "systemd 单元"), (manager.state, "状态文件")):
        facts[label] = "存在" if os.path.lexists(path) else "不存在"
    if not os.path.lexists(manager.state):
        items.append(_item("项目状态", "info", "尚未配置项目 Hy2 转发。"))
    else:
        try:
            spec, nft, digests = manager._load_state()
            facts.update({
                "接口": spec.interface,
                "跳跃范围": f"{spec.start}-{spec.end}",
                "目标端口": str(spec.target),
                "地址族": "、".join(spec.families),
                "已记录指纹": str(len(digests)),
            })
            items.append(_item("项目状态", "ok", "状态文件可读取。"))
        except (hy2.Hy2Failure, bbr.BBRFailure, OSError) as exc:
            items.append(_item("项目状态", "warn", str(exc)))
    service = checks.run_check("hy2_service")
    state, fields = _service_state(service)
    facts["服务"] = f"{state} / {fields.get('UnitFileState', 'unknown')}"
    if state == "active":
        items.append(_item("开机服务", "ok", "active。"))
    elif state == "unknown":
        items.append(_item("开机服务", "unknown", service.output))
    else:
        items.append(_item("开机服务", "warn", f"状态为 {state}。"))
    for family, key in (("ip", "hy2_ipv4"), ("ip6", "hy2_ipv6")):
        result = checks.run_check(key)
        if result.state == "ok":
            items.append(_item(f"{family} 规则表", "ok", "存在；规则内容需结合 nft 输出检查。"))
        else:
            items.append(_item(f"{family} 规则表", "info" if "No such file" in result.output or "not found" in result.output.lower() else "unknown", result.output))
    items.append(_item("防火墙", "warn", "Hy2 只管理 NAT；UFW 与云防火墙必须单独允许跳跃范围和目标 UDP 端口。"))
    items.append(_item("客户端验证", "info", "规则存在不等于客户端跳端口可用；需从外部网络实测。"))
    return {"name": "hy2", "title": SECTIONS["hy2"], "facts": facts, "items": items}


def _swap():
    try:
        state = swap.SwapManager().status()
    except (swap.SwapFailure, OSError) as exc:
        return {"name": "swap", "title": SECTIONS["swap"], "facts": {}, "items": [_item("Swap", "unknown", str(exc))]}
    facts = {
        "项目 swap": "active" if state["active"] else ("未启用" if state["file_exists"] else "不存在"),
        "大小": f"{state['active_bytes'] / 1024**2:.0f} MiB" if state["active_bytes"] else (
            f"{state['file_bytes'] / 1024**2:.0f} MiB" if state["file_bytes"] else "未知"),
        "fstab 条目": "存在" if state["fstab_managed"] else "不存在",
        "其他 swap": "、".join(f"{path} ({size // 1024**2} MiB)" for path, size in state["other_swaps"]) or "无",
    }
    items = []
    if state["active"]:
        items.append(_item("Swap", "ok", "项目 swap 已启用。"))
    elif state["file_exists"]:
        items.append(_item("Swap", "warn", "文件存在但未启用；检查 fstab 或手动 swapon。"))
    else:
        items.append(_item("Swap", "info", "未创建项目 swap。"))
    if state["fstab_managed"] and not state["active"]:
        items.append(_item("持久化", "warn", "fstab 有条目但当前未启用；重启后是否生效需验证。"))
    return {"name": "swap", "title": SECTIONS["swap"], "facts": facts, "items": items}


def _timezone():
    try:
        status = common.timezone_status()
    except common.CommonFailure as exc:
        return {"name": "timezone", "title": SECTIONS["timezone"], "facts": {}, "items": [_item("时区", "unknown", str(exc))]}
    return {
        "name": "timezone", "title": SECTIONS["timezone"],
        "facts": {"有效时区": status["effective"], "/etc/timezone": status["configured"]},
        "items": [_item("时区", "ok" if status["effective"] != "未知" else "unknown", "只读；修改时区需单独确认。")],
    }


def _dns():
    try:
        status = common.dns_status()
    except common.CommonFailure as exc:
        return {"name": "dns", "title": SECTIONS["dns"], "facts": {}, "items": [_item("DNS", "unknown", str(exc))]}
    return {
        "name": "dns", "title": SECTIONS["dns"],
        "facts": {
            "名称服务器": "、".join(status["nameservers"]) or "未配置",
            "搜索域": "、".join(status["search"]) or "未配置",
            "/etc/resolv.conf": "符号链接" if status["symlink"] else "普通文件",
        },
        "items": [_item("DNS", "info", "只读；不修改 DNS，避免覆盖 systemd-resolved 或云厂商配置。")],
    }


_COLLECTORS = {
    "system": _system,
    "packages": _packages,
    "panel": _panel,
    "bbr": _bbr,
    "tuning": _tuning,
    "ssh": _ssh,
    "ufw": _ufw,
    "fail2ban": _fail2ban,
    "hy2": _hy2,
    "swap": _swap,
    "timezone": _timezone,
    "dns": _dns,
}


def names_for(section):
    if section in ALIASES:
        return ALIASES[section]
    if section in _COLLECTORS:
        return (section,)
    if section == "all":
        return tuple(_COLLECTORS)
    raise KeyError(section)


def collect_selected(names, section="overview"):
    """Collect only explicitly selected sections, for cached menu summaries.

    This uses the same collectors and payload schema as public status commands.
    Menu grouping does not change the public section names or their aliases.
    """
    if isinstance(names, str):
        raise TypeError("names must contain section names, not a single string")
    selected = tuple(dict.fromkeys(names))
    for name in selected:
        if name not in _COLLECTORS:
            raise KeyError(name)
    sections = []
    for name in selected:
        try:
            sections.append(_COLLECTORS[name]())
        except Exception as exc:  # 状态查询不应因单项异常而整体崩溃
            sections.append({
                "name": name, "title": SECTIONS.get(name, name), "facts": {},
                "items": [_item("检查失败", "unknown", f"{type(exc).__name__}: {exc}")],
            })
    return {
        "schema": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "host": platform.node(),
        "section": section,
        "sections": sections,
    }


def collect_overview():
    return collect_selected(("system", "ssh", "ufw"))


def collect(section="all"):
    return collect_selected(names_for(section), section=section)


def _summary_text(value, limit=48):
    if value is None:
        return "未知"
    # Terminal control characters and multiline values must not alter the menu.
    text = " ".join("".join(char if char.isprintable() else " " for char in str(value)).split())
    if not text:
        return "未知"
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _summary_ports(value):
    text = str(value or "")
    if not re.fullmatch(r"[0-9、, ]+", text):
        return "未知"
    values = tuple(dict.fromkeys(part for part in re.split(r"[、, ]+", text) if part))
    if not values or any(len(part) > 5 or not 1 <= int(part) <= 65535 for part in values):
        return "未知"
    return "、".join(values[:8]) + ("…" if len(values) > 8 else "")


def _summary_service(value):
    text = str(value or "")
    return _summary_text(text, 40) if re.fullmatch(r"[A-Za-z-]+ / [A-Za-z-]+", text) else "未知"


def _summary_range(value):
    text = str(value or "")
    if not re.fullmatch(r"[0-9]{1,5}-[0-9]{1,5}", text):
        return "未知"
    start, end = map(int, text.split("-"))
    return text if 1 <= start <= end <= 65535 else "未知"


def render_summary(payload):
    """Render bounded, non-sensitive menu hints without running any checks.

    Never include hostnames, raw item details, addresses, full firewall rules,
    panel paths, or other unselected facts. Counts describe check items, not
    external connectivity or a successful application of configuration.
    """
    lines = ["状态快照：" + _summary_text(payload.get("generated_at"), 40)]
    sections = payload.get("sections", [])
    for section in sections[:SUMMARY_MAX_SECTIONS]:
        name = section.get("name")
        facts = section.get("facts", {})
        items = section.get("items", [])
        warnings = sum(item.get("state") == "warn" for item in items)
        unknowns = sum(item.get("state") not in ("ok", "warn", "info") for item in items)
        counts = f"注意项 {warnings} / 未知项 {unknowns}"
        if name == "system":
            detail = (f"系统 {_summary_text(facts.get('系统'), 40)}；"
                      f"内存 {_summary_text(facts.get('内存'), 48)}；"
                      f"磁盘 {_summary_text(facts.get('根分区'), 40)}")
        elif name == "ssh":
            auth = lambda key: facts.get(key) if facts.get(key) in ("yes", "no") else "未知"
            detail = (f"SSH 端口 {_summary_ports(facts.get('有效端口'))}；"
                      f"密码 {auth('密码认证')} / 交互 {auth('键盘交互认证')} / 公钥 {auth('公钥认证')}")
        elif name == "ufw":
            state = facts.get("状态") if facts.get("状态") in ("active", "inactive") else "未知"
            ipv6 = facts.get("IPv6") if facts.get("IPv6") in ("yes", "no") else "未知"
            detail = f"UFW {state}；IPv6 {ipv6}"
        elif name == "panel":
            detail = f"3x-ui {_summary_service(facts.get('服务'))}；端口 {_summary_ports(facts.get('端口'))}"
        elif name == "bbr":
            detail = f"TCP 拥塞控制 {_summary_text(facts.get('TCP 拥塞控制'), 20)}；默认队列 {_summary_text(facts.get('默认队列'), 20)}"
        elif name == "tuning":
            detail = f"调优 {_summary_text(facts.get('档位'), 32)}；配置 {_summary_text(facts.get('配置内容'), 16)}"
        elif name == "fail2ban":
            detail = f"Fail2ban {_summary_service(facts.get('服务'))}"
        elif name == "hy2":
            detail = (f"Hy2 转发 {_summary_service(facts.get('服务'))}；"
                      f"范围 {_summary_range(facts.get('跳跃范围'))} → {_summary_ports(facts.get('目标端口'))}")
        elif name == "swap":
            detail = f"Swap {_summary_text(facts.get('项目 swap'), 12)}；大小 {_summary_text(facts.get('大小'), 20)}"
        elif name == "timezone":
            detail = f"时区 {_summary_text(facts.get('有效时区'), 40)}"
        elif name == "packages":
            detail = f"软件 {_summary_text(facts.get('包管理器'), 16)}；需要重启 {_summary_text(facts.get('需要重启'), 12)}"
        elif name == "dns":
            servers = facts.get("名称服务器")
            count = "未知" if not servers or servers == "未知" else (0 if servers == "未配置" else len(str(servers).split("、")))
            detail = f"DNS 名称服务器数量 {count}"
        else:
            detail = SECTIONS.get(name, "其他检查")
        lines.append(f"{detail} ｜ {counts}")
    if len(sections) > SUMMARY_MAX_SECTIONS:
        lines.append("…其余检查请查看完整状态。")
    text = "\n".join(lines)
    if len(text) > SUMMARY_MAX_CHARS:
        text = text[:SUMMARY_MAX_CHARS - 15] + "\n…请查看完整状态。"
    return text


def render(payload):
    lines = [f"状态生成时间：{payload['generated_at']}；主机：{payload['host']}"]
    for section in payload["sections"]:
        lines.append(f"\n=== {section['title']} ===")
        for key, value in section["facts"].items():
            lines.append(f"{key}：{value}")
        for item in section["items"]:
            label = STATUS_LABELS.get(item["state"], item["state"])
            detail = f"：{item['detail']}" if item["detail"] else ""
            lines.append(f"[{label}] {item['name']}{detail}")
    return "\n".join(lines)


def dumps(payload):
    return json.dumps(payload, ensure_ascii=False, indent=2)
