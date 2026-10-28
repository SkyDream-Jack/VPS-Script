"""UFW 的试验性管理：单独开放端口，以及带超时保护的首次启用。"""

import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess

from . import bbr, checks, packages


class FirewallFailure(Exception):
    pass


def ssh_session_port(value):
    parts = value.split()
    if len(parts) != 4:
        raise FirewallFailure("需要从现有 SSH 终端运行，无法识别当前连接端口")
    try:
        ipaddress.ip_address(parts[0])
        ipaddress.ip_address(parts[2])
        client, server = int(parts[1]), int(parts[3])
    except ValueError as exc:
        raise FirewallFailure("SSH_CONNECTION 格式无效") from exc
    if not 1 <= client <= 65535 or not 1 <= server <= 65535:
        raise FirewallFailure("SSH_CONNECTION 端口无效")
    return server


def ufw_state(output):
    for line in output.splitlines():
        if line.strip() == "Status: active":
            return "active"
        if line.strip() == "Status: inactive":
            return "inactive"
    raise FirewallFailure("无法判断 UFW 当前状态")


def ufw_defaults(output):
    for line in output.splitlines():
        if line.startswith("Default:"):
            value = line.split(":", 1)[1]
            result = {}
            for part in value.split(","):
                part = part.strip()
                if "(" in part and part.endswith(")"):
                    policy, _, direction = part.partition("(")
                    result[direction.rstrip(")")] = policy.strip()
            return result
    raise FirewallFailure("无法读取 UFW 默认策略")


def port_rule(start, end, protocol):
    if any(type(value) is not int or not 1 <= value <= 65535 for value in (start, end)) or start > end:
        raise FirewallFailure("端口范围无效")
    if protocol not in ("tcp", "udp"):
        raise FirewallFailure("协议必须是 TCP 或 UDP")
    value = str(start) if start == end else f"{start}:{end}"
    return f"{value}/{protocol}"


class FirewallManager:
    def __init__(self, root=Path("/"), runner=None):
        self.root = Path(root)
        self.runner = runner or subprocess.run
        self.files = bbr.BBRManager(self.root)
        self.files.lock = self.root / "run/lock/vps-script-ufw.lock"

    def command(self, name):
        value = checks.find_command(name)
        if not value:
            raise FirewallFailure(f"未找到 {name}")
        return value

    def run(self, args, *, check=True, timeout=30):
        try:
            result = self.runner(args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False,
                                 env={"PATH": packages.SAFE_PATH, "LC_ALL": "C"})
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise FirewallFailure(f"无法运行 {args[0]}：{exc}") from exc
        if check and result.returncode != 0:
            raise FirewallFailure(f"{args[0]} 返回 {result.returncode}: {(result.stderr or '').strip()}")
        return result

    def status(self, ufw):
        return ufw_state(self.run((ufw, "status")).stdout)

    def verbose_status(self, ufw):
        return self.run((ufw, "status", "verbose")).stdout

    def defaults(self, ufw):
        return ufw_defaults(self.verbose_status(ufw))

    def ensure_no_competing_services(self, systemctl):
        for service in ("firewalld.service", "nftables.service", "docker.service", "fail2ban.service"):
            result = self.run((systemctl, "is-active", service), check=False)
            if result.returncode == 0 and result.stdout.strip() == "active":
                raise FirewallFailure(f"{service} 正在运行，暂不自动启用 UFW；请先检查规则兼容性")
            if result.returncode not in (3, 4) or result.stdout.strip() not in ("inactive", "failed", "unknown"):
                raise FirewallFailure(f"无法确认 {service} 状态")

    def ensure_no_foreign_rules(self):
        nft = self.command("nft")
        try:
            data = json.loads(self.run((nft, "-j", "list", "ruleset")).stdout)
            entries = data["nftables"]
            if not isinstance(entries, list):
                raise ValueError("invalid ruleset")
            for entry in entries:
                if not isinstance(entry, dict) or len(entry) != 1:
                    raise ValueError("invalid entry")
                kind, value = next(iter(entry.items()))
                if not isinstance(value, dict):
                    raise ValueError("invalid object")
                if kind == "rule":
                    # 不凭链名判断归属：已有规则可能属于其他管理器。
                    raise FirewallFailure("发现现有 nftables 规则，暂不自动启用 UFW")
                if kind == "chain" and ("hook" in value or "type" in value or "policy" in value):
                    # 即使没有规则，带 hook 的基链也可能以 drop 为默认策略。
                    raise FirewallFailure("发现现有 nftables 挂钩链，暂不自动启用 UFW")
                if kind not in ("metainfo", "table", "chain"):
                    raise FirewallFailure("发现未检查的 nftables 对象，暂不自动启用 UFW")
        except (ValueError, KeyError, TypeError) as exc:
            raise FirewallFailure("无法解析现有 nftables 规则") from exc
        for name in ("ip_tables_names", "ip6_tables_names"):
            path = self.root / "proc/net" / name
            try:
                if path.read_text(encoding="ascii").strip():
                    raise FirewallFailure("发现旧版 iptables 表，暂不自动启用 UFW")
            except FileNotFoundError:
                continue
            except (OSError, UnicodeError) as exc:
                raise FirewallFailure("无法检查旧版 iptables 状态") from exc

    def allow(self, start, end, protocol):
        rule = port_rule(start, end, protocol)
        with self.files.locked():
            ufw = self.command("ufw")
            current = self.status(ufw)
            result = self.run((ufw, "allow", rule))
            return f"UFW 当前为 {current}；添加规则命令已执行。\n{result.stdout.strip()}\n请独立检查 IPv4/IPv6 和云防火墙。"

    def delete(self, start, end, protocol):
        rule = port_rule(start, end, protocol)
        with self.files.locked():
            ufw = self.command("ufw")
            current = self.status(ufw)
            result = self.run((ufw, "delete", "allow", rule))
            return f"UFW 当前为 {current}；删除规则命令已执行。\n{result.stdout.strip()}\n请检查是否仍有其他规则放行该端口。"

    def enable(self, port, verify):
        if type(port) is not int or not 1 <= port <= 65535:
            raise FirewallFailure("SSH 端口无效")
        with self.files.locked():
            ufw = self.command("ufw")
            if self.status(ufw) == "active":
                return "UFW 已处于 active；没有改变现有规则或默认策略。"
            defaults = self.defaults(ufw)
            if defaults.get("incoming") != "deny":
                raise FirewallFailure("UFW 默认入站策略不是 deny；请先设置 ufw default deny incoming，避免启用后仍然放行全部入站")
            if defaults.get("outgoing") not in ("allow", "deny"):
                raise FirewallFailure("无法确认 UFW 默认出站策略")
            systemctl = self.command("systemctl")
            systemd_run = self.command("systemd-run")
            python = "/usr/bin/python3"
            if not (self.root / "run/systemd/system").is_dir() or not os.path.isfile(python):
                raise FirewallFailure("需要运行中的 systemd 与 /usr/bin/python3")
            self.ensure_no_competing_services(systemctl)
            self.ensure_no_foreign_rules()
            self.files._prepare_state_dir()
            base = self.files.state_dir / "ufw-transactions"
            base.mkdir(mode=0o700, exist_ok=True)
            if (base.is_symlink() or base.stat().st_mode & 0o077
                    or (self.root == Path("/") and base.stat().st_uid != 0)):
                raise FirewallFailure("UFW 事务目录不安全")
            tx_dir = base / secrets.token_hex(12)
            tx_dir.mkdir(mode=0o700)
            worker = tx_dir / "rollback.py"
            worker_source = Path(__file__).with_name("ufw_rollback.py").read_bytes()
            self.files._atomic_create(worker, worker_source, 0o600)
            unit = "vps-script-ufw-" + tx_dir.name
            # 先建立定时恢复，再修改防火墙。systemd-run 创建独立瞬态定时器。
            self.run((systemd_run, "--unit=" + unit, "--on-active=180s", python, "-I", "-B", str(worker), str(tx_dir), ufw))
            timer = unit + ".timer"
            active = self.run((systemctl, "is-active", timer), check=False)
            if active.returncode != 0 or active.stdout.strip() != "active":
                raise FirewallFailure("未能确认回滚定时器，未启用 UFW")
            try:
                lock_fd = os.open(tx_dir / "lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX)
                    if (tx_dir / "expired").exists() or (tx_dir / "rolled-back").exists():
                        raise FirewallFailure("回滚定时器已到期，未启用 UFW")
                    active = self.run((systemctl, "is-active", timer), check=False)
                    if active.returncode != 0 or active.stdout.strip() != "active":
                        raise FirewallFailure("回滚定时器不再活动，未启用 UFW")
                    # 定时器创建期间其他管理器仍可能发生变化；再次检查，但不能消除并发竞争。
                    self.ensure_no_competing_services(systemctl)
                    self.ensure_no_foreign_rules()
                    self.run((ufw, "allow", f"{port}/tcp"))
                    (tx_dir / "enable-started").write_text("1\n", encoding="ascii")
                    self.run((ufw, "--force", "enable"), timeout=60)
                    if self.status(ufw) != "active":
                        raise FirewallFailure("启用后 UFW 状态不是 active")
                    snapshot = self.run((ufw, "status", "verbose")).stdout.encode("utf-8")
                    (tx_dir / "expected-status.sha256").write_text(hashlib.sha256(snapshot).hexdigest() + "\n", encoding="ascii")
                finally:
                    os.close(lock_fd)
                print(f"UFW 已启用。保留本会话，并立即从另一终端通过端口 {port} 建立新的 SSH 连接。")
                print("180 秒定时器在启用前已经启动，剩余时间可能少于 180 秒。")
                print("新连接请使用 -o ControlMaster=no -o ControlPath=none，避免复用现有连接。")
                print("验证时核对服务器主机密钥；指纹出现未解释的变化时不要确认。")
                print("云防火墙与外部 SSH 连通性仍需独立检查；不要在这段时间重启。")
                verified = verify()
                if not verified:
                    raise FirewallFailure("未确认新的 SSH 会话，正在尝试恢复原状态")
                # 先停止定时器，再通过锁和标记处理与回滚任务的竞争。
                self.run((systemctl, "stop", timer), check=False)
                lock_fd = os.open(tx_dir / "lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX)
                    if any((tx_dir / name).exists() for name in ("rollback-started", "rolled-back", "expired")):
                        raise FirewallFailure("回滚已开始或发生；UFW 未保持启用")
                    (tx_dir / "confirmed").write_text("1\n", encoding="ascii")
                finally:
                    os.close(lock_fd)
            except BaseException:
                # 调用独立副本；若失败，已启动的定时器仍可继续尝试。
                result = self.run((python, "-I", "-B", str(worker), str(tx_dir), ufw), check=False, timeout=40)
                if result.returncode != 0:
                    print("立即恢复失败；定时器状态未知，请立即使用服务商控制台检查。")
                raise
            return "UFW 已启用并收到第二会话确认；仍需检查默认策略、IPv6、云防火墙和业务端口。"


def _confirm(prompt):
    try:
        return input(prompt).strip() == "YES"
    except EOFError:
        return False


def allow(start, end, protocol, experimental=False):
    error = packages.preflight(experimental)
    if error:
        print(f"未执行：{error}")
        return 2
    try:
        rule = port_rule(start, end, protocol)
        print(f"【试验功能】将允许任意来源访问 {rule}；UFW 未启用时规则会留待之后使用。")
        if not _confirm("输入 YES 继续，其他内容取消："):
            print("已取消。")
            return 0
        print(FirewallManager().allow(start, end, protocol))
        return 0
    except (FirewallFailure, bbr.BBRFailure, OSError) as exc:
        print(f"操作未完成：{exc}")
        return 1


def enable(experimental=False):
    error = packages.preflight(experimental)
    if error:
        print(f"未执行：{error}")
        return 2
    try:
        port = ssh_session_port(os.environ.get("SSH_CONNECTION", ""))
        print(f"【试验功能】将在启用前允许当前 SSH 端口 {port}/tcp。")
        print("如当前 UFW 未启用，建立 180 秒超时恢复尝试；允许规则即使恢复后也会保留。")
        print("启用期间中断、状态发生变化或恢复命令失败时，可能无法自动恢复。")
        print("此瞬态定时器不保证跨重启，且不影响云防火墙；请准备服务商控制台。")
        if not _confirm("输入 YES 继续，其他内容取消："):
            print("已取消。")
            return 0
        def verify():
            try:
                return input("第二个 SSH 会话已成功登录后输入 VERIFIED：").strip() == "VERIFIED"
            except EOFError:
                return False
        print(FirewallManager().enable(port, verify))
        return 0
    except (FirewallFailure, bbr.BBRFailure, OSError) as exc:
        print(f"操作未完成：{exc}")
        return 1
