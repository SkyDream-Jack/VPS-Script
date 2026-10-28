"""终端面板：只读状态、按需修改和常用工具。"""

import argparse
import platform
import sys
from pathlib import Path

from . import __version__, bbr, checks, common, fail2ban, firewall, hy2, packages, panel, ssh, status, swap, tuning

REPORTS = {
    "system": ("系统概览", checks.system_report),
    "network": ("网络与监听", checks.network_report),
    "security": ("SSH 与安全", checks.security_report),
    "panel": ("3x-ui", checks.panel_report),
}

DEMO = """【演示数据：不是本机或 VPS 的真实状态】
系统：示例 Debian / Ubuntu
SSH：示例服务运行中；配置和外部登录状态未知
UFW：示例未检查；云防火墙未知
3x-ui：示例未检查
TCP 拥塞控制：示例值 bbr；Hy2 的拥塞控制未知
Swap：示例未检查；时区示例为 Asia/Shanghai
演示模式不会安装软件或修改系统。"""

UPDATE_COMMAND = (
    'sudo bash -c "$(curl -fsSL '
    'https://raw.githubusercontent.com/SkyDream-Jack/VPS-Script/main/test-releases/latest/install.sh)"'
)


def show_report(name: str) -> None:
    title, collect = REPORTS[name]
    print(f"\n=== {title} ===")
    print(collect())


def show_status(name: str) -> None:
    print("\n" + status.render(status.collect(name)))


def _demo_status(name: str) -> None:
    print(f"\n=== {status.SECTIONS.get(name, name)} ===")
    print(DEMO)


def _require_modify(experimental: bool) -> bool:
    if experimental:
        return True
    print("当前为只读模式；请以 --experimental 启动，或在主菜单选择“启用修改模式”。")
    return False


def _ask_int(prompt: str):
    value = input(prompt).strip()
    return int(value)


def packages_menu(demo: bool = False, experimental: bool = False) -> None:
    choices = {"1": "update", "2": "upgrade", "3": "base", "4": "network", "5": "monitor", "6": "security"}
    while True:
        print("\n系统软件 · 试验功能")
        if demo:
            print("【演示模式：不会执行任何软件操作】")
        elif not experimental:
            print("尚未完成隔离 Linux 验证；默认只展示菜单，不执行修改。")
        print("1. 更新软件包索引\n2. 升级已安装软件包\n3. 安装基础工具\n4. 安装网络诊断工具\n5. 安装常用查看工具\n6. 安装安全工具")
        print("7. 查看软件源与重启状态\n8. 查看全部系统状态\n0. 返回")
        try:
            choice = input("请选择：").strip()
        except EOFError:
            print("\n输入结束。")
            return
        if choice in ("0", "q", "Q"):
            return
        if choice in ("7", "8"):
            _demo_status("packages") if demo else show_status("all" if choice == "8" else "packages")
            continue
        name = choices.get(choice)
        if not name:
            print("无效选择，请重试。")
        elif demo:
            action = packages.ACTIONS[name]
            print(f"【演示】{action.title}：{action.impact}")
            print("示例命令：" + " ".join(packages.apt_command(action)))
        else:
            result = packages.run_action(name, experimental=experimental)
            if result == 0:
                show_status("packages")


def panel_menu(demo: bool = False, experimental: bool = False) -> None:
    while True:
        print("\n3x-ui 管理")
        print("1. 查看服务、监听与面板设置\n2. 安装官方 3x-ui（试验功能）\n0. 返回")
        try:
            choice = input("请选择：").strip()
        except EOFError:
            print("\n输入结束。")
            return
        if choice in ("0", "q", "Q"):
            return
        if choice == "1":
            _demo_status("panel") if demo else show_status("panel")
        elif choice == "2":
            if demo:
                print(f"【演示】固定版本 {panel.VERSION}，不会下载或执行脚本。")
            else:
                result = panel.install(experimental=experimental)
                if result == 0:
                    show_status("panel")
        else:
            print("无效选择，请重试。")


def network_menu(demo: bool = False, experimental: bool = False) -> None:
    while True:
        print("\n网络设置")
        print("1. 查看网络与监听\n2. 配置 BBR / fq（试验功能）\n3. 恢复 BBR / fq 原值（试验功能）")
        print("4. 配置 Hy2 跳跃端口（试验功能）\n5. 移除本项目 Hy2 转发（试验功能）")
        print("6. 查看 BBR / fq 状态\n7. 查看 Hy2 状态\n8. 查看全部状态\n0. 返回")
        try:
            choice = input("请选择：").strip()
        except EOFError:
            print("\n输入结束。")
            return
        if choice in ("0", "q", "Q"):
            return
        if choice == "1":
            print(DEMO) if demo else show_report("network")
        elif choice in ("2", "3"):
            if demo:
                print("【演示】不会修改 BBR / fq 配置。")
            else:
                result = bbr.change(restore=choice == "3", experimental=experimental)
                if result == 0:
                    show_status("bbr")
        elif choice in ("4", "5"):
            if demo:
                print("【演示】不会创建或删除 UDP 转发规则。")
            elif choice == "5":
                result = hy2.change(remove=True, experimental=experimental)
                if result == 0:
                    show_status("hy2")
            elif not _require_modify(experimental):
                continue
            else:
                try:
                    interface = input("接收 UDP 的网络接口：").strip()
                    start = _ask_int("跳跃范围起始端口：")
                    end = _ask_int("跳跃范围结束端口：")
                    target = _ask_int("Hy2 实际监听 UDP 端口：")
                    family = input("地址族（4 / 6 / 46）：").strip()
                    families = {"4": ("ip",), "6": ("ip6",), "46": ("ip", "ip6")}.get(family, ())
                    if not families:
                        raise ValueError("地址族无效")
                    allow = input("应用成功后尝试放行 UFW UDP 范围？输入 yes：").strip().lower() == "yes"
                    result = hy2.change(hy2.HopSpec(interface, start, end, target, families),
                                        allow_firewall=allow, experimental=experimental)
                    if result == 0:
                        show_status("hy2")
                except (EOFError, ValueError):
                    print("输入无效，已取消。")
        elif choice == "6":
            _demo_status("bbr") if demo else show_status("bbr")
        elif choice == "7":
            _demo_status("hy2") if demo else show_status("hy2")
        elif choice == "8":
            _demo_status("all") if demo else show_status("all")
        else:
            print("无效选择，请重试。")


def security_menu(demo: bool = False, experimental: bool = False) -> None:
    while True:
        print("\nSSH 与安全")
        print("1. 查看 SSH / UFW / Fail2ban 状态\n2. 允许 UFW 端口或范围（试验功能）\n3. 启用 UFW（试验功能）")
        print("4. 配置 SSH Fail2ban jail（试验功能）\n5. 新增 SSH 端口（试验功能）\n6. 关闭项目管理的旧 SSH 端口（试验功能）")
        print("7. 只允许公钥认证（试验功能）\n8. 查看 UFW 详细状态\n9. 删除 UFW 允许规则（试验功能）")
        print("10. Fail2ban 状态与解封（试验功能）\n11. 查看 SSH 状态\n0. 返回")
        try:
            choice = input("请选择：").strip()
        except EOFError:
            print("\n输入结束。")
            return
        if choice in ("0", "q", "Q"):
            return
        if choice == "1":
            _demo_status("security") if demo else show_status("security")
        elif choice == "4":
            if demo:
                print("【演示】不会修改 Fail2ban。")
            else:
                result = fail2ban.configure(experimental=experimental)
                if result == 0:
                    show_status("fail2ban")
        elif choice in ("5", "6", "7"):
            if demo:
                print("【演示】不会修改 SSH。")
            elif not _require_modify(experimental):
                continue
            elif choice == "7":
                result = ssh.change(key_only=True, experimental=experimental)
                if result == 0:
                    show_status("ssh")
            else:
                try:
                    port = _ask_int("SSH 端口：")
                    if choice == "5":
                        allow = input("修改前尝试放行 UFW 新端口？输入 yes：").strip().lower() == "yes"
                        result = ssh.change(new_port=port, open_firewall=allow, experimental=experimental)
                    else:
                        result = ssh.change(remove_port=port, experimental=experimental)
                    if result == 0:
                        show_status("ssh")
                except (EOFError, ValueError):
                    print("输入无效，已取消。")
        elif choice in ("2", "3"):
            if demo:
                print("【演示】不会修改防火墙。")
            elif choice == "3":
                result = firewall.enable(experimental=experimental)
                if result == 0:
                    show_status("ufw")
            elif not _require_modify(experimental):
                continue
            else:
                try:
                    start = _ask_int("起始端口：")
                    end_text = input("结束端口（单个端口留空）：").strip()
                    end = int(end_text) if end_text else start
                    protocol = input("协议（tcp / udp）：").strip().lower()
                    result = firewall.allow(start, end, protocol, experimental=experimental)
                    if result == 0:
                        show_status("ufw")
                except (EOFError, ValueError):
                    print("输入无效，已取消。")
        elif choice == "8":
            _demo_status("ufw") if demo else show_status("ufw")
        elif choice == "9":
            if demo:
                print("【演示】不会删除防火墙规则。")
            elif not _require_modify(experimental):
                continue
            else:
                try:
                    start = _ask_int("起始端口：")
                    end_text = input("结束端口（单个端口留空）：").strip()
                    end = int(end_text) if end_text else start
                    protocol = input("协议（tcp / udp）：").strip().lower()
                    if input("输入 YES 删除对应 allow 规则：").strip() != "YES":
                        print("已取消。")
                        continue
                    print(firewall.FirewallManager().delete(start, end, protocol))
                    show_status("ufw")
                except (EOFError, ValueError, firewall.FirewallFailure, bbr.BBRFailure, OSError) as exc:
                    print(f"操作未完成：{exc}")
        elif choice == "10":
            if demo:
                print("【演示】不会查看或修改 Fail2ban。")
            else:
                show_status("fail2ban")
                try:
                    address = input("要解封的 IP（留空返回）：").strip()
                except EOFError:
                    return
                if address:
                    fail2ban.unban(address, experimental=experimental)
                    show_status("fail2ban")
        elif choice == "11":
            _demo_status("ssh") if demo else show_status("ssh")
        else:
            print("无效选择，请重试。")


def common_menu(demo: bool = False, experimental: bool = False) -> None:
    while True:
        print("\n常用工具")
        print("1. 查看系统概览\n2. 查看 swap\n3. 创建 swap（试验功能）\n4. 移除项目 swap（试验功能）")
        print("5. 查看时区\n6. 设置时区（试验功能）\n7. 查看 DNS\n0. 返回")
        try:
            choice = input("请选择：").strip()
        except EOFError:
            print("\n输入结束。")
            return
        if choice in ("0", "q", "Q"):
            return
        if choice == "1":
            _demo_status("system") if demo else show_status("system")
        elif choice == "2":
            _demo_status("swap") if demo else show_status("swap")
        elif choice in ("3", "4"):
            if demo:
                print("【演示】不会创建或删除 swap。")
            elif choice == "3":
                result = swap.change(experimental=experimental)
                if result == 0:
                    show_status("swap")
            else:
                result = swap.change(remove=True, experimental=experimental)
                if result == 0:
                    show_status("swap")
        elif choice == "5":
            _demo_status("timezone") if demo else show_status("timezone")
        elif choice == "6":
            if demo:
                print("【演示】不会修改时区。")
            else:
                result = common.timezone_change(experimental=experimental)
                if result == 0:
                    show_status("timezone")
        elif choice == "7":
            _demo_status("dns") if demo else show_status("dns")
        else:
            print("无效选择，请重试。")


def tuning_menu(demo: bool = False, experimental: bool = False) -> None:
    while True:
        print("\nVPS 优化 · 内核网络调优（试验功能）")
        print("1. 查看当前调优状态\n2. 应用保守档（通用 Web / 面板）\n3. 应用代理 / 中转档")
        print("4. 应用大带宽缓冲档（按预期带宽/RTT 估算）\n5. 代理档 + TCP Fast Open\n6. 恢复本项目调优")
        print("0. 返回")
        try:
            choice = input("请选择：").strip()
        except EOFError:
            print("\n输入结束。")
            return
        if choice in ("0", "q", "Q"):
            return
        if choice == "1":
            _demo_status("tuning") if demo else show_status("tuning")
            continue
        if demo:
            print("【演示】不会修改内核网络参数。")
            continue
        if choice in ("2", "3", "4", "5", "6") and not _require_modify(experimental):
            continue
        try:
            if choice == "2":
                result = tuning.change("conservative", experimental=experimental)
            elif choice == "3":
                result = tuning.change("proxy", experimental=experimental)
            elif choice == "4":
                text = input("预期带宽 Mbps（留空按内存估算）：").strip()
                bandwidth = int(text) if text else None
                rtt_text = input("预期 RTT ms（默认 200）：").strip()
                rtt = int(rtt_text) if rtt_text else 200
                result = tuning.change("buffer", bandwidth_mbps=bandwidth, rtt_ms=rtt,
                                       experimental=experimental)
            elif choice == "5":
                result = tuning.change("proxy", fastopen=True, experimental=experimental)
            elif choice == "6":
                result = tuning.change(restore=True, experimental=experimental)
            else:
                print("无效选择，请重试。")
                continue
            if result == 0:
                show_status("tuning")
        except (EOFError, ValueError):
            print("输入无效，已取消。")
        except (tuning.TuningFailure, bbr.BBRFailure, OSError) as exc:
            print(f"操作未完成：{exc}")


def status_menu(demo: bool = False) -> None:
    while True:
        print("\n状态查询（只读）")
        print("1. 全部状态\n2. 系统概览\n3. 软件与重启\n4. 3x-ui\n5. BBR / fq\n6. SSH\n7. UFW\n8. Fail2ban\n9. Hy2\n10. Swap / 时区 / DNS\n11. 内核网络调优\n0. 返回")
        try:
            choice = input("请选择：").strip()
        except EOFError:
            print("\n输入结束。")
            return
        if choice in ("0", "q", "Q"):
            return
        mapping = {
            "1": "all", "2": "system", "3": "packages", "4": "panel", "5": "bbr",
            "6": "ssh", "7": "ufw", "8": "fail2ban", "9": "hy2", "10": "common", "11": "tuning",
        }
        name = mapping.get(choice)
        if not name:
            print("无效选择，请重试。")
        else:
            _demo_status(name) if demo else show_status(name)


def maintenance_menu() -> None:
    while True:
        print("\n工具维护")
        print("1. 查看版本与安装路径\n2. 查看升级命令\n3. 查看卸载说明\n0. 返回")
        try:
            choice = input("请选择：").strip()
        except EOFError:
            print("\n输入结束。")
            return
        if choice in ("0", "q", "Q"):
            return
        if choice == "1":
            print(f"版本：{__version__}")
            print(f"程序目录：{Path('/opt/vps-script') if Path('/opt/vps-script').is_dir() else '未安装或不在默认路径'}")
            print(f"启动命令：{Path('/usr/local/bin/vps-script') if Path('/usr/local/bin/vps-script').exists() else '未安装'}")
        elif choice == "2":
            print("在 VPS 上重新运行以下命令即可升级（会保留 /etc、/var 中的系统配置）：")
            print(UPDATE_COMMAND)
            print("升级前请先运行 vps-script status，并保留一个 SSH 会话。")
        elif choice == "3":
            print("卸载程序（不会自动恢复 SSH/UFW/Fail2ban/BBR/Hy2 配置）：")
            print("  rm -f /usr/local/bin/vps-script")
            print("  rm -rf /opt/vps-script")
            print("系统配置请先用各模块的“恢复/移除”功能处理。")
        else:
            print("无效选择，请重试。")


def menu(demo: bool = False, experimental: bool = False) -> int:
    modify = experimental
    while True:
        print("\nVPS 管理工具 · v" + __version__)
        if demo:
            print("【演示模式：以下不是实际状态】")
        elif modify:
            print("【修改模式已启用：只用于可丢弃的测试环境】")
        else:
            print("【只读模式：不会修改系统】")
        print("1. 系统概览\n2. 网络设置\n3. SSH 与安全\n4. 3x-ui 管理\n5. 系统软件（试验功能）")
        print("6. 常用工具\n7. 状态查询（只读）\n8. 工具维护\n9. VPS 优化（内核网络调优）")
        if not modify:
            print("10. 启用修改模式")
        print("0. 退出")
        try:
            choice = input("请选择：").strip()
        except EOFError:
            print("\n输入结束。")
            return 0
        if choice in ("0", "q", "Q"):
            return 0
        if choice == "1":
            _demo_status("system") if demo else show_status("system")
        elif choice == "2":
            network_menu(demo=demo, experimental=modify)
        elif choice == "3":
            security_menu(demo=demo, experimental=modify)
        elif choice == "4":
            panel_menu(demo=demo, experimental=modify)
        elif choice == "5":
            packages_menu(demo=demo, experimental=modify)
        elif choice == "6":
            common_menu(demo=demo, experimental=modify)
        elif choice == "7":
            status_menu(demo=demo)
        elif choice == "8":
            maintenance_menu()
        elif choice == "9":
            tuning_menu(demo=demo, experimental=modify)
        elif choice == "10" and not modify and not demo:
            print("修改模式会启用 APT、3x-ui、BBR、内核调优、SSH、UFW、Fail2ban、Hy2、swap 和时区变更。")
            print("每项操作仍需单独确认；请确保有服务商控制台和备份。")
            if input("输入 ENABLE 启用，其他内容取消：").strip() == "ENABLE":
                modify = True
                print("修改模式已启用。")
        else:
            print("无效选择，请重试。")


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
            print(DEMO)
            return 0
        payload = status.collect("all")
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
