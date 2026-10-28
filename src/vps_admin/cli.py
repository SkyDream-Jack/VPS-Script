"""终端界面；系统修改默认关闭，开发功能需单独启用。"""

import argparse
import platform
import sys

from . import __version__, bbr, checks, fail2ban, firewall, hy2, packages, panel, ssh

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
演示模式不会安装软件或修改系统。"""


def show_report(name: str) -> None:
    title, collect = REPORTS[name]
    print(f"\n=== {title} ===")
    print(collect())


def packages_menu(demo: bool = False, experimental: bool = False) -> None:
    choices = {"1": "update", "2": "upgrade", "3": "base", "4": "network", "5": "monitor", "6": "security"}
    while True:
        print("\n系统软件 · 试验功能")
        if demo:
            print("【演示模式：不会执行任何软件操作】")
        elif not experimental:
            print("尚未完成隔离 Linux 验证；默认只展示菜单，不执行修改。")
        print("1. 更新软件包索引\n2. 升级已安装软件包\n3. 安装基础工具\n4. 安装网络诊断工具\n5. 安装常用查看工具\n6. 安装安全工具\n0. 返回")
        try:
            choice = input("请选择：").strip()
        except EOFError:
            print("\n输入结束。")
            return
        if choice in ("0", "q", "Q"):
            return
        name = choices.get(choice)
        if not name:
            print("无效选择，请重试。")
        elif demo:
            action = packages.ACTIONS[name]
            print(f"【演示】{action.title}：{action.impact}")
            print("示例命令：" + " ".join(packages.apt_command(action)))
        else:
            packages.run_action(name, experimental=experimental)


def panel_menu(demo: bool = False, experimental: bool = False) -> None:
    while True:
        print("\n3x-ui 管理")
        print("1. 查看服务与监听\n2. 安装官方 3x-ui（试验功能）\n0. 返回")
        try:
            choice = input("请选择：").strip()
        except EOFError:
            print("\n输入结束。")
            return
        if choice in ("0", "q", "Q"):
            return
        if choice == "1":
            print(DEMO) if demo else show_report("panel")
        elif choice == "2":
            if demo:
                print(f"【演示】固定版本 {panel.VERSION}，不会下载或执行脚本。")
            else:
                panel.install(experimental=experimental)
        else:
            print("无效选择，请重试。")


def network_menu(demo: bool = False, experimental: bool = False) -> None:
    while True:
        print("\n网络设置")
        print("1. 查看网络与监听\n2. 配置 BBR / fq（试验功能）\n3. 恢复 BBR / fq 原值（试验功能）\n4. 配置 Hy2 跳跃端口（试验功能）\n5. 移除本项目 Hy2 转发（试验功能）\n0. 返回")
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
                bbr.change(restore=choice == "3", experimental=experimental)
        elif choice in ("4", "5"):
            if demo:
                print("【演示】不会创建或删除 UDP 转发规则。")
            elif choice == "5":
                hy2.change(remove=True, experimental=experimental)
            elif not experimental:
                print("尚未完成 Linux 验证；默认不执行修改。")
            else:
                try:
                    interface = input("接收 UDP 的网络接口：").strip()
                    start = int(input("跳跃范围起始端口：").strip())
                    end = int(input("跳跃范围结束端口：").strip())
                    target = int(input("Hy2 实际监听 UDP 端口：").strip())
                    family = input("地址族（4 / 6 / 46）：").strip()
                    families = {"4": ("ip",), "6": ("ip6",), "46": ("ip", "ip6")}.get(family, ())
                    hy2.change(hy2.HopSpec(interface, start, end, target, families), experimental=experimental)
                except (EOFError, ValueError):
                    print("输入无效，已取消。")
        else:
            print("无效选择，请重试。")


def security_menu(demo: bool = False, experimental: bool = False) -> None:
    while True:
        print("\nSSH 与安全")
        print("1. 查看 SSH / UFW / Fail2ban 状态\n2. 允许 UFW 端口或范围（试验功能）\n3. 启用 UFW（试验功能）\n4. 配置 SSH Fail2ban jail（试验功能）\n5. 新增 SSH 端口（试验功能）\n6. 关闭项目管理的旧 SSH 端口（试验功能）\n7. 只允许公钥认证（试验功能）\n0. 返回")
        try:
            choice = input("请选择：").strip()
        except EOFError:
            print("\n输入结束。")
            return
        if choice in ("0", "q", "Q"):
            return
        if choice == "1":
            print(DEMO) if demo else show_report("security")
        elif choice == "4":
            if demo:
                print("【演示】不会修改 Fail2ban。")
            else:
                fail2ban.configure(experimental=experimental)
        elif choice in ("5", "6", "7"):
            if demo:
                print("【演示】不会修改 SSH。")
            elif not experimental:
                print("尚未完成 Linux 验证；默认不执行修改。")
            elif choice == "7":
                ssh.change(key_only=True, experimental=experimental)
            else:
                try:
                    port = int(input("SSH 端口：").strip())
                    if choice == "5":
                        ssh.change(new_port=port, experimental=experimental)
                    else:
                        ssh.change(remove_port=port, experimental=experimental)
                except (EOFError, ValueError):
                    print("输入无效，已取消。")
        elif choice in ("2", "3"):
            if demo:
                print("【演示】不会修改防火墙。")
            elif choice == "3":
                firewall.enable(experimental=experimental)
            elif not experimental:
                print("尚未完成 Linux 验证；默认不执行修改。")
            else:
                try:
                    start = int(input("起始端口：").strip())
                    end_text = input("结束端口（单个端口留空）：").strip()
                    end = int(end_text) if end_text else start
                    protocol = input("协议（tcp / udp）：").strip().lower()
                    firewall.allow(start, end, protocol, experimental=experimental)
                except (EOFError, ValueError):
                    print("输入无效，已取消。")
        else:
            print("无效选择，请重试。")


def menu(demo: bool = False, experimental: bool = False) -> int:
    while True:
        print("\nVPS 管理工具 · 开发原型")
        if demo:
            print("【演示模式：以下不是实际状态】")
        elif experimental:
            print("【试验功能已启用：只用于可丢弃的测试环境】")
        print("1. 系统概览\n2. 网络设置\n3. SSH 与安全\n4. 3x-ui 管理\n5. 系统软件（试验功能）\n0. 退出")
        try:
            choice = input("请选择：").strip()
        except EOFError:
            print("\n输入结束。")
            return 0
        if choice in ("0", "q", "Q"):
            return 0
        if choice == "5":
            packages_menu(demo=demo, experimental=experimental)
            continue
        if choice == "4":
            panel_menu(demo=demo, experimental=experimental)
            continue
        if choice == "2":
            network_menu(demo=demo, experimental=experimental)
            continue
        if choice == "3":
            security_menu(demo=demo, experimental=experimental)
            continue
        names = {"1": "system"}
        if choice not in names:
            print("无效选择，请重试。")
        elif demo:
            print(f"\n=== {REPORTS[names[choice]][0]} ===\n{DEMO}")
        else:
            show_report(names[choice])


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="vps-admin", description="VPS 管理工具的开发原型")
    parser.add_argument("action", nargs="?", choices=("menu", "status"), default="menu")
    parser.add_argument("section", nargs="?", choices=("all", *REPORTS), default="all")
    parser.add_argument("--demo", action="store_true", help="展示虚构数据，不检查本机")
    parser.add_argument("--experimental", action="store_true", help="启用未通过 Linux 验证的软件操作，仅供可丢弃测试环境")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    if args.action == "menu" and args.section != "all":
        parser.error("菜单模式不接受检查分类")
    if not args.demo and platform.system() != "Linux":
        print("当前只读原型仅在 Linux 上检查真实系统；可用 --demo 查看界面。", file=sys.stderr)
        return 2
    if args.action == "menu":
        try:
            return menu(demo=args.demo, experimental=args.experimental)
        except KeyboardInterrupt:
            print("\n已退出。")
            return 130
    if args.demo:
        print(DEMO)
        return 0
    for name in REPORTS if args.section == "all" else (args.section,):
        show_report(name)
    return 0
