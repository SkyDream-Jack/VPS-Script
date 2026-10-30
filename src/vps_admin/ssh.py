"""SSH 端口与仅公钥认证的受限试验流程。"""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shlex
import stat
import subprocess
import tempfile

from . import backup, bbr, checks, firewall, packages

HEADER = "# Managed by VPS-Script; do not edit while managed.\n"
AUTH = {"passwordauthentication": "no", "kbdinteractiveauthentication": "no",
        "pubkeyauthentication": "yes", "authenticationmethods": "publickey"}
USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}\$?$")


class SSHFailure(Exception):
    pass


def login_users():
    """列出可能使用交互式登录的账户；仅用于影响提示。"""
    users = []
    for entry in pwd.getpwall():
        shell = Path(entry.pw_shell).name
        if shell in ("nologin", "false", "sync", "shutdown", "halt"):
            continue
        if entry.pw_uid == 0 or entry.pw_uid >= 1000:
            users.append(entry.pw_name)
    return tuple(sorted(set(users)))


def read_managed(data):
    if data is None:
        return set(), False
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise SSHFailure("项目 SSH 配置编码无效") from exc
    if not text.startswith(HEADER):
        raise SSHFailure("目标 SSH 配置不属于本项目，拒绝覆盖")
    ports, auth = set(), {}
    for line in text[len(HEADER):].splitlines():
        fields = line.split()
        if not fields:
            continue
        if len(fields) != 2:
            raise SSHFailure("项目 SSH 配置存在未知内容")
        key, value = fields[0].lower(), fields[1].lower()
        if key == "port" and value.isdigit() and 1 <= int(value) <= 65535:
            ports.add(int(value))
        elif key in AUTH and value == AUTH[key] and key not in auth:
            auth[key] = value
        else:
            raise SSHFailure("项目 SSH 配置已被修改，拒绝覆盖")
    if auth and auth != AUTH:
        raise SSHFailure("项目 SSH 认证配置不完整")
    return ports, bool(auth)


def render_managed(ports, key_only):
    if any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise SSHFailure("SSH 端口无效")
    lines = [HEADER.rstrip("\n")]
    lines.extend(f"Port {port}" for port in sorted(ports))
    if key_only:
        lines.extend(("PasswordAuthentication no", "KbdInteractiveAuthentication no",
                      "PubkeyAuthentication yes", "AuthenticationMethods publickey"))
    return ("\n".join(lines) + "\n").encode("utf-8")


def parse_effective(text):
    result = {}
    for line in text.splitlines():
        fields = line.split(maxsplit=1)
        if len(fields) == 2:
            result.setdefault(fields[0].lower(), []).append(fields[1].strip().lower())
    ports = set()
    for value in result.get("port", []):
        if not value.isdigit() or not 1 <= int(value) <= 65535:
            raise SSHFailure("无法解析实际 SSH 端口")
        ports.add(int(value))
    if not ports:
        raise SSHFailure("未能取得 SSH 有效端口")
    return result, ports


def external_config(base, dropin_dir, managed):
    """只处理常见 Debian/Ubuntu Include 布局，其他布局拒绝自动修改。"""
    try:
        base_text = base.read_text(encoding="utf-8")
        files = sorted(dropin_dir.glob("*.conf"))
    except (OSError, UnicodeError) as exc:
        raise SSHFailure(f"无法读取 SSH 配置: {exc}") from exc
    include_seen = False
    external_ports = set()
    for path in (base, *files):
        if path == managed:
            continue
        try:
            if path.is_symlink() or not path.is_file():
                raise SSHFailure(f"SSH 配置不是普通文件: {path}")
            text = base_text if path == base else path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise SSHFailure(f"无法读取 {path}: {exc}") from exc
        for line in text.splitlines():
            try:
                parts = shlex.split(line, comments=True)
            except ValueError as exc:
                raise SSHFailure(f"无法解析 {path}") from exc
            if not parts:
                continue
            key = parts[0].lower()
            if key == "match":
                raise SSHFailure("检测到 Match 条件，暂不自动更改 SSH")
            if key == "include":
                if path != base or parts[1:] != ["/etc/ssh/sshd_config.d/*.conf"] or include_seen:
                    raise SSHFailure("检测到不支持的 SSH Include 布局")
                include_seen = True
            if key == "port":
                if len(parts) != 2 or not parts[1].isdigit() or not 1 <= int(parts[1]) <= 65535:
                    raise SSHFailure("检测到无法解析的 SSH Port 配置")
                external_ports.add(int(parts[1]))
    if not include_seen:
        raise SSHFailure("主配置未包含标准 sshd_config.d 目录")
    return external_ports


def listening_ports(text):
    ports = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5:
            raise SSHFailure("无法解析 TCP 监听列表")
        _, separator, value = parts[3].rpartition(":")
        if not separator or not value.isdigit():
            raise SSHFailure("无法解析 TCP 监听端口")
        ports.add(int(value))
    return ports


class SSHManager:
    def __init__(self, root=Path("/"), runner=None):
        self.root = Path(root)
        self.runner = runner or subprocess.run
        self.files = bbr.BBRManager(self.root)
        self.files.lock = self.root / "run/lock/vps-script-ssh.lock"
        self.base = self.root / "etc/ssh/sshd_config"
        self.dropins = self.root / "etc/ssh/sshd_config.d"
        self.target = self.dropins / "00-vps-script.conf"

    def command(self, name):
        result = checks.find_command(name)
        if not result:
            raise SSHFailure(f"未找到 {name}")
        return result

    def run(self, args, check=True):
        try:
            result = self.runner(args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30, check=False,
                                 env={"PATH": packages.SAFE_PATH, "LC_ALL": "C"})
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SSHFailure(f"无法执行 {args[0]}: {exc}") from exc
        if check and result.returncode != 0:
            raise SSHFailure(f"{args[0]} 返回 {result.returncode}: {(result.stderr or '').strip()}")
        return result

    def service(self, systemctl):
        for name in ("ssh.socket", "ssh.service", "sshd.service"):
            result = self.run((systemctl, "is-active", name), check=False)
            if result.returncode == 0 and result.stdout.strip() == "active":
                return name
            if result.returncode not in (3, 4) or result.stdout.strip() not in ("inactive", "failed", "unknown"):
                raise SSHFailure(f"无法判断 {name} 状态")
        raise SSHFailure("没有检测到活动的 SSH 服务或 socket")

    def effective(self, sshd, user, address):
        if not USER_RE.fullmatch(user):
            raise SSHFailure("无法识别当前 SSH 用户")
        result = self.run((sshd, "-T", "-C", f"user={user},host=localhost,addr={address}"))
        return parse_effective(result.stdout)

    def _read_before(self):
        if not os.path.lexists(self.target):
            return None, 0o644
        try:
            data = self.files._read_regular(self.target)
            info = os.lstat(self.target)
        except (bbr.BBRFailure, OSError) as exc:
            raise SSHFailure("无法安全读取项目 SSH 配置") from exc
        if (not stat.S_ISREG(info.st_mode)
                or (self.root == Path("/") and (info.st_uid != 0 or info.st_gid != 0))):
            raise SSHFailure("项目 SSH 配置不是可信的普通文件")
        return data, stat.S_IMODE(info.st_mode)

    def _replace(self, before, after, mode):
        current, _ = self._read_before()
        if current != before:
            raise SSHFailure("SSH 配置在操作期间发生变化")
        if after is None:
            if before is not None:
                os.unlink(self.target)
            return
        if before is None:
            self.files._atomic_create(self.target, after, mode)
            return
        temporary = None
        try:
            fd, temporary = tempfile.mkstemp(prefix=".vps-script-ssh-", dir=str(self.dropins))
            with os.fdopen(fd, "wb") as file:
                os.fchmod(file.fileno(), mode)
                file.write(after)
                file.flush()
                os.fsync(file.fileno())
            if self._read_before()[0] != before:
                raise SSHFailure("SSH 配置在写入时发生变化")
            os.replace(temporary, self.target)
            temporary = None
        finally:
            if temporary is not None:
                os.unlink(temporary)

    def restore_snapshot(self, expected, desired, mode, *, user, address, current_port, verify, precheck=None):
        """Restore only this project's drop-in using the normal guarded transaction."""
        if any(value is not None and not isinstance(value, bytes) for value in (expected, desired)):
            raise SSHFailure("历史 SSH 配置类型无效")
        if type(mode) is not int or mode < 0 or mode > 0o777 or mode & 0o022:
            raise SSHFailure("历史 SSH 配置权限无效")
        read_managed(expected)
        read_managed(desired)
        return self.change(user=user, address=address, current_port=current_port, verify=verify,
                           _restore=(expected, desired, mode), _restore_check=precheck)

    def change(self, *, user, address, current_port, new_port=None, remove_port=None, key_only=False, verify=None,
               _restore=None, _restore_check=None):
        restoring = _restore is not None
        if type(current_port) is not int or not 1 <= current_port <= 65535:
            raise SSHFailure("当前 SSH 端口无效")
        if new_port is not None and (type(new_port) is not int or not 1 <= new_port <= 65535):
            raise SSHFailure("新端口必须是 1–65535 的整数")
        if remove_port is not None and (type(remove_port) is not int or not 1 <= remove_port <= 65535):
            raise SSHFailure("旧端口必须是 1–65535 的整数")
        if sum((new_port is not None, remove_port is not None, bool(key_only), restoring)) != 1:
            raise SSHFailure("每次只能执行一项 SSH 变更")
        if remove_port == current_port:
            raise SSHFailure("不能关闭当前 SSH 会话使用的端口")
        with self.files.locked():
            if restoring and _restore_check is not None:
                _restore_check()
            if not (self.root / "run/systemd/system").is_dir():
                raise SSHFailure("需要运行中的 systemd")
            if not self.dropins.is_dir() or self.dropins.is_symlink():
                raise SSHFailure("SSH 配置目录不可用或为符号链接")
            info = os.lstat(self.dropins)
            if info.st_mode & 0o022 or (self.root == Path("/") and info.st_uid != 0):
                raise SSHFailure("SSH 配置目录权限不安全")
            sshd, ss, systemctl, systemd_run = (self.command(name) for name in ("sshd", "ss", "systemctl", "systemd-run"))
            if sshd != "/usr/sbin/sshd" or systemctl != "/usr/bin/systemctl":
                raise SSHFailure("当前 SSH 或 systemd 程序路径不受支持")
            external_ports = external_config(self.base, self.dropins, self.target)
            before, mode = self._read_before()
            if restoring and before != _restore[0]:
                raise SSHFailure("当前 SSH 配置与历史变更后的记录不一致，拒绝覆盖")
            _, was_key_only = read_managed(before)
            effective, old_ports = self.effective(sshd, user, address)
            if current_port not in old_ports:
                raise SSHFailure("当前会话端口与 SSH 有效配置不一致")
            if user == "root" and effective.get("permitrootlogin") not in (["yes"], ["prohibit-password"], ["without-password"]):
                raise SSHFailure("当前配置未明确允许 root 以公钥登录")
            listen = listening_ports(self.run((ss, "-H", "-l", "-t", "-n")).stdout)
            if current_port not in listen:
                raise SSHFailure("当前 SSH 端口未出现在监听列表")
            if new_port is not None and new_port in listen and new_port not in old_ports:
                raise SSHFailure("新端口已被其他服务监听")
            if remove_port is not None:
                if remove_port not in old_ports:
                    raise SSHFailure("旧端口不在当前 SSH 配置中")
                if remove_port in external_ports:
                    raise SSHFailure("旧端口由其他 SSH 配置文件管理，拒绝覆盖")
            if key_only:
                if effective.get("pubkeyauthentication") != ["yes"]:
                    raise SSHFailure("当前用户的公钥认证未启用")
                if effective.get("authenticationmethods", ["any"]) not in (["any"], ["publickey"]):
                    raise SSHFailure("已有多因素认证要求，拒绝自动覆盖")
            managed_ports = old_ports - external_ports
            if new_port is not None and new_port not in external_ports:
                managed_ports.add(new_port)
            if remove_port is not None:
                managed_ports.discard(remove_port)
            expected_key_only = was_key_only or key_only
            target_ports = None
            apply_mode = mode
            if restoring:
                after, apply_mode = _restore[1:]
                restored_ports, expected_key_only = read_managed(after)
                target_ports = restored_ports | external_ports
                if not target_ports:
                    target_ports = {22}
                if current_port not in target_ports:
                    raise SSHFailure("历史配置不保留当前 SSH 端口；请先从历史配置保留的端口重新登录后恢复")
                if (target_ports - old_ports) & listen:
                    raise SSHFailure("历史 SSH 端口已被其他服务监听，拒绝恢复")
            else:
                after = render_managed(managed_ports, expected_key_only)
            if after == before and apply_mode == mode:
                return "项目 SSH 配置已经包含所选设置；未修改。"
            service = self.service(systemctl)
            self.files._prepare_state_dir()
            parent = self.files.state_dir / "ssh-transactions"
            parent.mkdir(mode=0o700, exist_ok=True)
            if parent.is_symlink() or parent.stat().st_mode & 0o077 or (self.root == Path("/") and parent.stat().st_uid != 0):
                raise SSHFailure("SSH 事务目录不安全")
            tx_dir = parent / secrets.token_hex(12)
            tx_dir.mkdir(mode=0o700)
            worker = tx_dir / "rollback.py"
            self.files._atomic_create(worker, Path(__file__).with_name("ssh_rollback.py").read_bytes(), 0o600)
            if before is not None:
                self.files._atomic_create(tx_dir / "before", before, 0o600)
            state = {"schema": 1, "target": str(self.target), "service": service,
                     "before_exists": before is not None, "before_mode": mode,
                     "before_sha256": hashlib.sha256(before).hexdigest() if before is not None else None,
                     "after_exists": after is not None,
                     "after_sha256": hashlib.sha256(after).hexdigest() if after is not None else None}
            self.files._atomic_create(tx_dir / "state.json", (json.dumps(state) + "\n").encode(), 0o600)
            unit = "vps-script-ssh-" + tx_dir.name
            self.run((systemd_run, "--unit=" + unit, "--on-active=180s", "/usr/bin/python3", "-I", "-B", str(worker), str(tx_dir)))
            timer = unit + ".timer"
            active = self.run((systemctl, "is-active", timer), check=False)
            if active.returncode != 0 or active.stdout.strip() != "active":
                raise SSHFailure("未能确认 SSH 回滚定时器，未修改配置")
            try:
                lock = os.open(tx_dir / "lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX)
                    if (tx_dir / "expired").exists() or (tx_dir / "rolled-back").exists():
                        raise SSHFailure("回滚定时器已到期，未修改配置")
                    active = self.run((systemctl, "is-active", timer), check=False)
                    if active.returncode != 0 or active.stdout.strip() != "active":
                        raise SSHFailure("回滚定时器不再活动，未修改配置")
                    (tx_dir / "apply-started").write_text("1\n", encoding="ascii")
                    self._replace(before, after, apply_mode)
                    self.run((sshd, "-t"))
                    updated, updated_ports = self.effective(sshd, user, address)
                    expected_ports = target_ports if restoring else old_ports - ({remove_port} if remove_port is not None else set())
                    removed_ports = old_ports - target_ports if restoring else ({remove_port} if remove_port is not None else set())
                    if (not expected_ports.issubset(updated_ports)
                            or (new_port is not None and new_port not in updated_ports)
                            or removed_ports & updated_ports
                            or (restoring and updated_ports != target_ports)):
                        raise SSHFailure("SSH 有效端口与预期不一致")
                    if expected_key_only:
                        if any(updated.get(k) != [v] for k, v in AUTH.items()):
                            raise SSHFailure("仅公钥认证未按预期生效")
                    if restoring and user == "root" and updated.get("permitrootlogin") not in (["yes"], ["prohibit-password"], ["without-password"]):
                        raise SSHFailure("恢复后的配置未明确允许当前 root 公钥登录")
                    self.run((systemctl, "daemon-reload"))
                    self.run((systemctl, "restart" if service == "ssh.socket" else "reload", service))
                    actual = listening_ports(self.run((ss, "-H", "-l", "-t", "-n")).stdout)
                    if (not expected_ports.issubset(actual)
                            or (new_port is not None and new_port not in actual)
                            or removed_ports & actual):
                        raise SSHFailure("SSH 实际监听端口与预期不一致")
                finally:
                    os.close(lock)
                print("配置已应用，请保留此会话，立即从另一终端建立不复用的 SSH 连接。")
                print("180 秒定时器在应用前已经启动，剩余时间可能少于 180 秒。")
                print("新连接请使用 -o ControlMaster=no -o ControlPath=none，避免复用现有连接。")
                if new_port is not None:
                    print(f"请连接新 SSH 端口 {new_port}，不要用旧端口代替验证。")
                if key_only or (restoring and expected_key_only):
                    print("请再次强制使用公钥登录，并确认密码或键盘交互认证被拒绝。")
                print("验证时核对服务器主机密钥；指纹出现未解释的变化时不要确认。")
                if verify is None or not verify():
                    raise SSHFailure("未确认新 SSH 会话，正在尝试恢复")
                self.run((systemctl, "stop", timer), check=False)
                lock = os.open(tx_dir / "lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX)
                    if any((tx_dir / name).exists() for name in ("rollback-started", "rolled-back", "expired")):
                        raise SSHFailure("回滚已开始或发生，SSH 设置未保持")
                    (tx_dir / "confirmed").write_text("1\n", encoding="ascii")
                finally:
                    os.close(lock)
            except BaseException:
                result = self.run(("/usr/bin/python3", "-I", "-B", str(worker), str(tx_dir)), check=False)
                if result.returncode != 0:
                    print("SSH 立即恢复失败；请立即使用服务商控制台检查。")
                raise
            if restoring:
                return "历史 SSH 项目配置已恢复并收到第二会话确认；未恢复其他 SSH 配置或云防火墙。"
            detail = "项目管理的旧端口已移除。" if remove_port is not None else "旧端口仍保留。"
            return f"SSH 设置已应用并收到第二会话确认；{detail} 云防火墙需独立检查。"


def change(new_port=None, remove_port=None, key_only=False, open_firewall=False, experimental=False):
    error = packages.preflight(experimental)
    if error:
        print(f"未执行：{error}")
        return 2
    try:
        connection = os.environ.get("SSH_CONNECTION", "").split()
        current_port = firewall.ssh_session_port(" ".join(connection))
        user = os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name
        address = connection[0]
        print("【试验功能】SSH 修改尚未在真实 Linux / VPS 验证；请准备服务商控制台。")
        print("只处理标准 Debian/Ubuntu SSH 配置；出现 Match、非标准 Include 或无法判断的情况会停止。")
        print("设置 180 秒瞬态超时恢复，不能保证跨重启。")
        if new_port is not None:
            print(f"请先确保云防火墙允许新 TCP 端口 {new_port}；成功后旧端口仍保留。")
            if open_firewall:
                print(f"将在修改 SSH 前请求 UFW 允许 {new_port}/tcp；若 UFW 未安装会提示但不会阻止 SSH 变更。")
        if remove_port is not None:
            print(f"将关闭项目管理的 SSH 旧端口 {remove_port}；必须从其他已验证的端口运行本操作。")
        if key_only:
            users = login_users()
            print("这会禁用所有账户的密码和键盘交互认证，而不只是当前账户。")
            print("这不会修改 SSH 端口，也不会禁用 root 登录；root 仍可通过密钥登录。")
            print("检测到的可登录账户：" + ("、".join(users) if users else "未知"))
            print("当前只验证了目标账户的公钥登录；其他账户是否已配置公钥无法由本工具证明。")
            if input("输入 ALL USERS 确认影响范围，其他内容取消：").strip() != "ALL USERS":
                print("已取消。")
                return 0
            print("请先从第二终端禁用连接复用并强制使用公钥成功登录；存在多因素认证要求时不会覆盖。")
            print("SSH 客户端可使用 -o ControlMaster=no -o ControlPath=none -o PreferredAuthentications=publickey -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no。")
            print("修改后还需检查密码或键盘交互方式是否被拒绝；配置值和公钥登录成功本身不能证明这一点。")
            if input("已用公钥建立独立 SSH 连接后输入 VERIFIED：").strip() != "VERIFIED":
                print("已取消。")
                return 0
        if input("输入 YES 应用，其他内容取消：").strip() != "YES":
            print("已取消。")
            return 0
        if new_port is not None and open_firewall:
            try:
                print(backup.track("ufw", "allow-ssh-port",
                                   lambda: firewall.FirewallManager().allow(new_port, new_port, "tcp"),
                                   details={"action": f"allow {new_port}/tcp"}))
            except (backup.BackupFailure, firewall.FirewallFailure, bbr.BBRFailure, OSError) as exc:
                print(f"UFW 放行未完成：{exc}；请手动确认后再继续。")
                if input("输入 CONTINUE 跳过 UFW 放行继续，其他内容取消：").strip() != "CONTINUE":
                    print("已取消。")
                    return 0
        def verify():
            try:
                return input("第二个 SSH 会话已成功登录后输入 VERIFIED：").strip() == "VERIFIED"
            except EOFError:
                return False
        action = "key-only" if key_only else "add-port" if new_port is not None else "remove-port"
        result = backup.track("ssh", action,
                              lambda: SSHManager().change(user=user, address=address, current_port=current_port,
                                                          new_port=new_port, remove_port=remove_port,
                                                          key_only=key_only, verify=verify),
                              details={"action": f"{action}: {new_port or remove_port or 'all-users'}"})
        print(result)
        if key_only:
            print("SSH 端口和 root 登录策略保持原样；请确认 root 账号使用密钥登录，并确认密码/键盘交互被拒绝。")
        if new_port is not None or remove_port is not None:
            try:
                from . import fail2ban
                fail2ban.refresh_ports()
            except Exception as exc:
                # 端口已经变更；Fail2ban 刷新失败只提示，不影响 SSH 结果。
                print(f"Fail2ban 端口刷新未完成：{exc}")
        return 0
    except EOFError:
        print("已取消。")
        return 0
    except (backup.BackupFailure, SSHFailure, firewall.FirewallFailure, bbr.BBRFailure, OSError) as exc:
        print(f"操作未完成：{exc}")
        return 1
