"""六类终端菜单；复用统一状态接口和已有修改模块。"""

import argparse
import platform
import sys
from pathlib import Path

from . import __version__, bbr, bench, checks, common, external, fail2ban, firewall, hy2, packages, panel, ssh, status, swap, tuning

DEMO = """【演示数据：不是本机或 VPS 的真实状态】
系统：示例 Debian / Ubuntu
SSH：示例服务运行中；配置和外部登录状态未知
UFW：示例未检查；云防火墙未知
3x-ui：示例未检查
TCP 拥塞控制：示例值 bbr；Hy2 的拥塞控制未知
Swap：示例未检查；时区示例为 Asia/Shanghai
演示模式不会检查主机、联网或修改系统。"""

UPDATE_COMMAND = (
    'f=$(mktemp) && curl -fsSL '
    'https://raw.githubusercontent.com/SkyDream-Jack/VPS-Script/main/test-releases/latest/install.sh '
    '-o "$f" && bash "$f" && rm -f "$f"'
)


def show_status(name, demo: bool = False, summary: bool = False) -> None:
    if demo:
        print(DEMO)
        return
    payload = status.collect(name) if isinstance(name, str) else status.collect_selected(name, section="menu")
    print("\n" + (status.render_summary(payload) if summary else status.render(payload)))


def show_report(name: str) -> None:
    """Keep the existing network detail checks, within the shared status format."""
    if name != "network":
        show_status(name)
        return
    payload = status.collect_selected((), section="network-details")
    payload["sections"] = [{
        "name": "network", "title": "网络监听与实际队列", "facts": {},
        "items": [{"name": "详细检查", "state": "info", "detail": checks.network_report()}],
    }]
    print(status.render(payload))


def _require_modify(experimental: bool) -> bool:
    if experimental:
        return True
    print("当前为只读模式；请以 --experimental 启动，或在主菜单按 M 启用修改模式。")
    return False


def _ask_int(prompt: str):
    return int(input(prompt).strip())


def _mode(demo, experimental):
    return "演示模式" if demo else "修改模式（测试环境）" if experimental else "只读模式"


def _submenu(title, actions, *, demo=False, experimental=False, sections=None):
    """Actions are (label, callback, kind): nav/info/read/modify.

    Demo only allows navigation and static information. Mutation gating happens
    before parameter prompts; modules still perform their own preflight/confirm.
    """
    if sections:
        show_status(sections, demo=demo, summary=True)
    while True:
        print(f"\n{title} · {_mode(demo, experimental)}")
        for number, (label, _, kind) in enumerate(actions, 1):
            marker = " [修改]" if kind == "modify" else ""
            print(f"{number}. {label}{marker}")
        if sections:
            print("S. 查看当前详细状态（只读）")
        print("0. 返回")
        try:
            choice = input("请选择：").strip().lower()
            if choice in ("0", "q"):
                return
            if choice == "s" and sections:
                show_status(sections, demo=demo)
                continue
            if choice not in {str(n) for n in range(1, len(actions) + 1)}:
                print("无效选择，请重试。")
                continue
            label, run, kind = actions[int(choice) - 1]
            if demo and kind in ("read", "modify"):
                print(f"【演示】{label}；不会读取本机、联网或执行修改。")
            elif kind != "modify" or _require_modify(experimental):
                run()
        except EOFError:
            print("\n输入结束。")
            return
        except ValueError:
            print("输入无效，已取消。")
        except (bench.BenchFailure, external.ExternalFailure, firewall.FirewallFailure,
                bbr.BBRFailure, tuning.TuningFailure, OSError) as exc:
            print(f"操作未完成：{exc}")


def _change(run, section):
    if run() == 0:
        show_status(section)


def packages_menu(demo=False, experimental=False):
    names = ("update", "upgrade", "base", "network", "monitor", "security")
    actions = [(packages.ACTIONS[name].title,
                lambda name=name: _change(lambda: packages.run_action(name, experimental=experimental), "packages"),
                "modify") for name in names]
    _submenu("软件包与工具", actions, demo=demo, experimental=experimental, sections="packages")


def system_menu(demo=False, experimental=False):
    _submenu("系统与软件", [
        ("软件包与工具", lambda: packages_menu(demo=demo, experimental=experimental), "nav"),
        ("创建 swap", lambda: _change(lambda: swap.change(experimental=experimental), "swap"), "modify"),
        ("移除本项目 swap", lambda: _change(lambda: swap.change(remove=True, experimental=experimental), "swap"), "modify"),
        ("设置时区", lambda: _change(lambda: common.timezone_change(experimental=experimental), "timezone"), "modify"),
    ], demo=demo, experimental=experimental, sections=("system", "packages", "swap", "timezone"))


def common_menu(demo=False, experimental=False):
    # Retain the Python entry point for existing callers; CLI sections stay intact.
    system_menu(demo=demo, experimental=experimental)


def _ssh_port(remove, experimental):
    port = _ask_int("SSH 端口：")
    if remove:
        _change(lambda: ssh.change(remove_port=port, experimental=experimental), "ssh")
    else:
        allow = input("修改前尝试放行 UFW 新端口？输入 yes：").strip().lower() == "yes"
        _change(lambda: ssh.change(new_port=port, open_firewall=allow, experimental=experimental), "ssh")


def ssh_menu(demo=False, experimental=False):
    _submenu("SSH 登录", [
        ("新增 SSH 端口", lambda: _ssh_port(False, experimental), "modify"),
        ("关闭项目管理的旧 SSH 端口", lambda: _ssh_port(True, experimental), "modify"),
        ("仅允许公钥认证（保留 root 和当前端口）",
         lambda: _change(lambda: ssh.change(key_only=True, experimental=experimental), "ssh"), "modify"),
    ], demo=demo, experimental=experimental, sections="ssh")


def _ufw_rule(remove, experimental):
    error = packages.preflight(experimental)
    if error:
        print(error)
        return
    start = _ask_int("起始端口：")
    end_text = input("结束端口（单个端口留空）：").strip()
    end = int(end_text) if end_text else start
    protocol = input("协议（tcp / udp）：").strip().lower()
    if remove:
        if input("输入 YES 删除对应 allow 规则：").strip() != "YES":
            print("已取消。")
            return
        print(firewall.FirewallManager().delete(start, end, protocol))
        show_status("ufw")
    else:
        _change(lambda: firewall.allow(start, end, protocol, experimental=experimental), "ufw")


def ufw_menu(demo=False, experimental=False):
    _submenu("UFW 防火墙", [
        ("允许端口或范围", lambda: _ufw_rule(False, experimental), "modify"),
        ("启用 UFW", lambda: _change(lambda: firewall.enable(experimental=experimental), "ufw"), "modify"),
        ("删除允许规则", lambda: _ufw_rule(True, experimental), "modify"),
    ], demo=demo, experimental=experimental, sections="ufw")


def _unban(experimental):
    address = input("要解封的 IP（留空返回）：").strip()
    if address:
        _change(lambda: fail2ban.unban(address, experimental=experimental), "fail2ban")


def fail2ban_menu(demo=False, experimental=False):
    _submenu("Fail2ban", [
        ("配置 SSH jail", lambda: _change(lambda: fail2ban.configure(experimental=experimental), "fail2ban"), "modify"),
        ("解封 IP", lambda: _unban(experimental), "modify"),
    ], demo=demo, experimental=experimental, sections="fail2ban")


def security_menu(demo=False, experimental=False):
    _submenu("SSH 与安全", [
        ("SSH 登录", lambda: ssh_menu(demo=demo, experimental=experimental), "nav"),
        ("UFW 防火墙", lambda: ufw_menu(demo=demo, experimental=experimental), "nav"),
        ("Fail2ban", lambda: fail2ban_menu(demo=demo, experimental=experimental), "nav"),
    ], demo=demo, experimental=experimental, sections="security")


def panel_menu(demo=False, experimental=False):
    _submenu("3x-ui 管理", [
        (f"安装官方 3x-ui（固定版本 {panel.VERSION}）",
         lambda: _change(lambda: panel.install(experimental=experimental), "panel"), "modify"),
    ], demo=demo, experimental=experimental, sections="panel")


def _hy2_configure(experimental):
    interface = input("接收 UDP 的网络接口：").strip()
    start = _ask_int("跳跃范围起始端口：")
    end = _ask_int("跳跃范围结束端口：")
    target = _ask_int("Hy2 实际监听 UDP 端口：")
    family = input("地址族（4 / 6 / 46）：").strip()
    families = {"4": ("ip",), "6": ("ip6",), "46": ("ip", "ip6")}.get(family)
    if not families:
        raise ValueError("地址族无效")
    allow = input("应用成功后尝试放行 UFW UDP 范围？输入 yes：").strip().lower() == "yes"
    _change(lambda: hy2.change(hy2.HopSpec(interface, start, end, target, families),
                              allow_firewall=allow, experimental=experimental), "hy2")


def hy2_menu(demo=False, experimental=False):
    _submenu("Hy2 跳跃端口", [
        ("配置跳跃端口", lambda: _hy2_configure(experimental), "modify"),
        ("移除本项目转发", lambda: _change(lambda: hy2.change(remove=True, experimental=experimental), "hy2"), "modify"),
    ], demo=demo, experimental=experimental, sections="hy2")


def proxy_menu(demo=False, experimental=False):
    _submenu("代理服务", [
        ("3x-ui 管理", lambda: panel_menu(demo=demo, experimental=experimental), "nav"),
        ("Hy2 跳跃端口", lambda: hy2_menu(demo=demo, experimental=experimental), "nav"),
    ], demo=demo, experimental=experimental, sections=("panel", "hy2"))


def bbr_menu(demo=False, experimental=False):
    _submenu("BBR / fq", [
        ("配置 BBR / fq", lambda: _change(lambda: bbr.change(experimental=experimental), "bbr"), "modify"),
        ("恢复本项目记录的原值", lambda: _change(lambda: bbr.change(restore=True, experimental=experimental), "bbr"), "modify"),
    ], demo=demo, experimental=experimental, sections="bbr")


def _tuning_buffer(experimental):
    text = input("预期带宽 Mbps（留空按内存估算）：").strip()
    bandwidth = int(text) if text else None
    rtt_text = input("预期 RTT ms（默认 200）：").strip()
    rtt = int(rtt_text) if rtt_text else 200
    _change(lambda: tuning.change("buffer", bandwidth_mbps=bandwidth, rtt_ms=rtt,
                                 experimental=experimental), "tuning")


def tuning_menu(demo=False, experimental=False):
    _submenu("内核网络调优", [
        ("应用保守档（通用 Web / 面板）", lambda: _change(lambda: tuning.change("conservative", experimental=experimental), "tuning"), "modify"),
        ("应用代理 / 中转档", lambda: _change(lambda: tuning.change("proxy", experimental=experimental), "tuning"), "modify"),
        ("应用大带宽缓冲档", lambda: _tuning_buffer(experimental), "modify"),
        ("代理档 + TCP Fast Open", lambda: _change(lambda: tuning.change("proxy", fastopen=True, experimental=experimental), "tuning"), "modify"),
        ("恢复本项目调优", lambda: _change(lambda: tuning.change(restore=True, experimental=experimental), "tuning"), "modify"),
    ], demo=demo, experimental=experimental, sections="tuning")


def network_menu(demo=False, experimental=False):
    _submenu("网络与调优", [
        ("网络监听与实际队列（只读）", lambda: show_report("network"), "read"),
        ("DNS 详情（只读）", lambda: show_status("dns"), "read"),
        ("BBR / fq", lambda: bbr_menu(demo=demo, experimental=experimental), "nav"),
        ("内核网络调优", lambda: tuning_menu(demo=demo, experimental=experimental), "nav"),
    ], demo=demo, experimental=experimental, sections=("bbr", "tuning", "dns"))


def _bandwidth():
    text = input("下载大小 MiB（10–100，默认 25）：").strip()
    size = int(text) if text else 25
    if input("将从 Cloudflare 单线程下载并消耗流量（最长 120 秒），输入 YES 开始：").strip() != "YES":
        print("已取消。")
        return
    print(bench.bandwidth_report(size))


def _network_test():
    print("将顺序向 1.1.1.1、8.8.8.8、223.5.5.5 发送 ICMP 探测；不会修改网络配置。")
    print(bench.network_report())


def _route_test():
    print("将向 1.1.1.1 进行单目标线路追踪（最长 90 秒）；不会修改路由。")
    print(bench.route_report())


def _preview():
    key = input("输入 nq / tq / ipquality / netquality / yabs 预览：").strip().lower()
    if key in external.SPECS:
        external.preview(key)
    else:
        print("未知名称。" if key else "已取消。")


def external_menu(demo=False, experimental=False):
    actions = [(external.SPECS[key].title,
                lambda key=key: external.run(key, experimental=experimental), "modify")
               for key in ("nq", "tq", "ipquality", "netquality", "yabs")]
    actions.extend([
        ("下载预览第三方脚本（不执行）", _preview, "read"),
        ("查看官方命令", external.show_commands, "info"),
    ])
    _submenu("第三方测试", actions, demo=demo, experimental=experimental)


def test_menu(demo=False, experimental=False):
    _submenu("诊断与测试", [
        ("完整状态报告（只读）", lambda: status_menu(demo=demo), "nav"),
        ("机器 / 系统信息（本机只读）", lambda: print(bench.machine_report()), "read"),
        ("网络接口、DNS、延迟（主动探测）", _network_test, "read"),
        ("线路追踪（主动探测）", _route_test, "read"),
        ("带宽下载测试（消耗流量）", _bandwidth, "read"),
        ("第三方测试（NQ / TQ / IPQuality / NetQuality / YABS）",
         lambda: external_menu(demo=demo, experimental=experimental), "nav"),
    ], demo=demo, experimental=experimental)


def status_menu(demo=False):
    names = ("all", "system", "packages", "panel", "bbr", "ssh", "ufw", "fail2ban", "hy2", "common", "tuning")
    actions = [(status.SECTIONS.get(name, "全部状态" if name == "all" else "Swap / 时区 / DNS"),
                lambda name=name: show_status(name, demo=demo), "info") for name in names]
    _submenu("状态查询（只读）", actions, demo=demo)


def _installation_info():
    print(f"版本：{__version__}")
    print(f"程序目录：{Path('/opt/vps-script') if Path('/opt/vps-script').is_dir() else '未安装或不在默认路径'}")
    print(f"启动命令：{Path('/usr/local/bin/vps-script') if Path('/usr/local/bin/vps-script').exists() else '未安装'}")


def _upgrade_info():
    print("在 VPS 的 root SSH 终端运行以下命令安装或升级；保留 /etc、/var 中的配置：")
    print(UPDATE_COMMAND)
    print("升级前先运行 vps-script status，并保留一个 SSH 会话。")


def _uninstall_info():
    print("卸载程序不会恢复 SSH/UFW/Fail2ban/BBR/Hy2；请先处理各模块配置：")
    print("  rm -f /usr/local/bin/vps-script\n  rm -rf /opt/vps-script")


def _recovery_info():
    print("现有恢复能力（不是整机备份）：")
    print("SSH：变更前备份及定时回退；UFW：首次启用失败时尝试回退到 inactive，新增 allow 规则保留。")
    print("SSH/UFW 回退可能失败，且不保证跨重启；仍需保留第二会话和服务商控制台。")
    print("BBR / 调优：在“网络与调优”对应模块恢复记录的原值。")
    print("Hy2：在“代理服务”移除本项目转发；swap：在“系统与软件”移除本项目 swap。")
    print("安装器：升级失败恢复程序目录；不负责撤销系统配置。")
    print("APT / 3x-ui / 第三方脚本：无完整回滚；重大操作前使用服务商快照。")
    print("统一自动备份、恢复记录与恢复入口计划下一步实现；当前没有一键恢复整机。")


def maintenance_menu(demo=False, experimental=False):
    _submenu("工具维护与恢复", [
        ("查看版本与安装路径", _installation_info, "read"),
        ("查看安装 / 升级命令", _upgrade_info, "info"),
        ("查看卸载说明", _uninstall_info, "info"),
        ("查看现有恢复能力", _recovery_info, "info"),
    ], demo=demo, experimental=experimental)


def menu(demo=False, experimental=False) -> int:
    modify = experimental and not demo
    overview = None if demo else status.collect_overview()
    routes = (
        ("系统与软件", system_menu), ("SSH 与安全", security_menu),
        ("代理服务", proxy_menu), ("网络与调优", network_menu),
        ("诊断与测试", test_menu), ("工具维护与恢复", maintenance_menu),
    )
    while True:
        print("\nVPS 管理工具 · v" + __version__)
        print(f"【{_mode(demo, modify)}】")
        print(DEMO if demo else status.render_summary(overview))
        print("首页摘要为上次读取的快照；操作后可按 R 刷新。")
        for number, (label, _) in enumerate(routes, 1):
            print(f"{number}. {label}")
        print("M. 切换只读 / 修改模式\nR. 刷新首页状态（只读）\n0. 退出")
        try:
            choice = input("请选择：").strip().lower()
            if choice in ("0", "q"):
                return 0
            if choice == "r":
                if not demo:
                    overview = status.collect_overview()
            elif choice == "m":
                if demo:
                    print("【演示】不能启用真实修改。")
                elif modify:
                    modify = False
                    print("已切回只读模式。")
                else:
                    print("修改模式仅用于测试环境；各模块仍需单独确认。请确保有服务商控制台和备份。")
                    if input("输入 ENABLE 启用，其他内容取消：").strip() == "ENABLE":
                        modify = True
                        print("修改模式已启用。")
                    else:
                        print("已取消。")
            elif choice in {str(n) for n in range(1, 7)}:
                routes[int(choice) - 1][1](demo=demo, experimental=modify)
            else:
                print("无效选择，请重试。")
        except EOFError:
            print("\n输入结束。")
            return 0




def main(argv=None) -> int:
    sections = tuple(status.SECTIONS) + tuple(status.ALIASES) + ("all",)
    parser = argparse.ArgumentParser(prog="vps-admin", description="VPS 初始化与日常管理工具")
    parser.add_argument("action", nargs="?", choices=("menu", "status", "doctor", "version"), default="menu")
    parser.add_argument("section", nargs="?", choices=sections, default="all")
    parser.add_argument("--demo", action="store_true", help="展示虚构数据，不检查本机")
    parser.add_argument("--json", action="store_true", help="状态查询以 JSON 输出")
    parser.add_argument("--experimental", action="store_true", help="启用未通过真实 VPS 验证的系统修改")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    if args.action == "version":
        print(__version__)
        return 0
    if args.action == "menu" and args.section != "all":
        parser.error("菜单模式不接受检查分类")
    if args.json and args.action not in ("status", "doctor"):
        parser.error("--json 只能与 status 或 doctor 一起使用")
    if not args.demo and platform.system() != "Linux":
        print("真实状态查询和修改仅在 Linux 上可用；可用 --demo 查看界面。", file=sys.stderr)
        return 2
    if args.action == "menu":
        try:
            return menu(demo=args.demo, experimental=args.experimental)
        except KeyboardInterrupt:
            print("\n已退出。")
            return 130
    if args.action == "doctor":
        if args.demo:
            if args.json:
                print(status.dumps({"schema": 1, "demo": True, "section": "all", "sections": [
                    {"name": "all", "title": "演示", "facts": {},
                     "items": [{"name": "演示", "state": "info", "detail": DEMO}]},
                ]}))
            else:
                print(DEMO)
            return 0
        payload = status.collect("all")
        if not args.json:
            print("VPS-Script 诊断：以下检查均为只读；未知项不会冒充正常。")
        print(status.dumps(payload) if args.json else status.render(payload))
        return 0
    if args.demo:
        if args.json:
            print(status.dumps({
                "schema": 1, "demo": True, "section": args.section,
                "sections": [{"name": args.section, "title": status.SECTIONS.get(args.section, "演示"),
                              "facts": {}, "items": [{"name": "演示", "state": "info", "detail": DEMO}]}],
            }))
        else:
            print(DEMO)
        return 0
    payload = status.collect(args.section)
    print(status.dumps(payload) if args.json else status.render(payload))
    return 0
