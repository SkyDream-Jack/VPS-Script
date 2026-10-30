"""Local, read-only security evidence; never declare a machine malware-free."""

import base64
from datetime import datetime, timezone
import hashlib
import ipaddress
import os
from pathlib import Path
import pwd
import re
import stat

from . import access_transactions, backup, bounded, checks, firewall

STATES = {"pass": "本项符合检查条件", "info": "信息", "review": "需核实", "risk": "风险", "unknown": "未检查/未知"}
LIMITATIONS = ("这是本机当前可读证据，不是未入侵证明；内核/root 被控制时本机结果不可信。"
               "不探测外部主机、不上传日志、不安装工具、不更改服务。云防火墙、外部 SSH、"
               "未保留的日志、用户自定义认证/容器及业务程序仍需单独核实。")


def read_regular(root, relative, limit=256 * 1024):
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("路径不在检查范围")
    current = Path(root)
    for part in path.parts[:-1]:
        current /= part
        if not stat.S_ISDIR(current.lstat().st_mode):
            raise ValueError("不跟随目录符号链接")
    fd = os.open(Path(root) / path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("只读取普通文件")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("文件超过检查上限")
    return data, info


class Audit:
    def __init__(self, root=Path("/"), runner=None, commands=None):
        self.root = Path(root)
        self.run = runner or bounded.run
        self.commands = commands or checks.find_command
        self.items = []

    def add(self, key, category, state, summary, evidence=(), advice="", repair=None):
        item = {"id": key, "category": category, "state": state, "summary": summary,
                "evidence": [bounded.clean(value)[:2000] for value in evidence][:80],
                "advice": advice, "repair": repair}
        self.items.append(item)

    def command(self, name, *args, timeout=5):
        executable = self.commands(name)
        if not executable:
            return bounded.Result(reason=f"未安装 {name}")
        return self.run((executable, *args), timeout=timeout)

    def unknown(self, key, category, result):
        self.add(key, category, "unknown", result.reason or f"命令返回 {result.code}；未获得可靠结果",
                 advice="检查依赖、权限与对应服务；没有结果不能视为正常。")

    def access(self):
        try:
            rows = access_transactions.pending(self.root)
            self.add("pending", "访问防护", "risk" if rows else "pass",
                     "存在尚未结束的访问回滚事务" if rows else "没有发现未结束的项目访问事务",
                     [f"{row['module']}:{row['id']} {row['phase']}" for row in rows],
                     "未结束时保留会话、等待原定时器；失败或重启后从服务商控制台核实，不删除标记。")
        except (OSError, backup.BackupFailure):
            self.unknown("pending", "访问防护", bounded.Result(reason="无法安全读取旧访问事务"))
        connection = os.environ.get("SSH_CONNECTION", "").split()
        user = os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name
        context = None
        if len(connection) == 4 and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", user):
            try:
                firewall.ssh_session_port(" ".join(connection))
                ipaddress.ip_address(connection[0])
                ipaddress.ip_address(connection[2])
                context = f"user={user},addr={connection[0]},laddr={connection[2]},lport={connection[3]}"
            except (ValueError, firewall.FirewallFailure):
                pass
        result = self.command("sshd", "-T", *(("-C", context) if context else ()))
        if not result.complete or result.code != 0:
            self.unknown("ssh", "访问防护", result)
        else:
            values = {}
            for line in result.output.splitlines():
                key, _, value = line.partition(" ")
                if key in checks.SSH_CONFIG_KEYS:
                    values.setdefault(key, []).append(value.strip())
            auth = [values.get(key) for key in ("passwordauthentication", "kbdinteractiveauthentication", "pubkeyauthentication")]
            state = "unknown" if any(value not in (["yes"], ["no"]) for value in auth) else "risk" if ["yes"] in auth[:2] else "review" if auth[2] != ["yes"] else "pass"
            self.add("ssh", "访问防护", state, "SSH 有效认证配置" + ("（当前用户与会话地址）" if context else "（全局默认，缺少连接上下文）"),
                     [f"{key}={' '.join(value)}" for key, value in sorted(values.items())],
                     "Match Host/其他用户与地址可能不同；需独立验证公钥成功且密码/交互认证被拒绝。", "ssh-key-only")
        ufw = self.command("ufw", "status", "verbose")
        ufw_active = None
        if not ufw.complete or ufw.code != 0:
            self.unknown("ufw", "访问防护", ufw)
        else:
            try:
                ufw_active = firewall.ufw_state(ufw.output) == "active"
                defaults = firewall.ufw_defaults(ufw.output) if ufw_active else {}
                state = "pass" if ufw_active and defaults.get("incoming") in ("deny", "reject") else "review"
                self.add("ufw", "访问防护", state, "UFW 已启用" if ufw_active else "UFW 未启用",
                         ufw.output.splitlines(), "规则和云防火墙需分别检查，勿在未放行 SSH/业务端口时启用。", "ufw-enable")
            except firewall.FirewallFailure:
                self.unknown("ufw", "访问防护", bounded.Result(reason="无法识别 UFW 状态/策略"))
        jail = self.command("fail2ban-client", "status", "vps-script-sshd")
        if not jail.complete or jail.code != 0:
            self.unknown("fail2ban", "访问防护", jail)
            self.items[-1]["advice"] = "项目 jail 不可确认；可能使用系统 sshd 或其他 jail，请到 Fail2ban 状态单独核实。"
        else:
            actions = self.command("fail2ban-client", "get", "vps-script-sshd", "actions")
            if not actions.complete or actions.code != 0:
                self.unknown("fail2ban", "访问防护", actions)
            else:
                depends_ufw = bool(re.search(r"\bufw\b", actions.output))
                state = "risk" if depends_ufw and ufw_active is False else "unknown" if depends_ufw and ufw_active is None else "info"
                self.add("fail2ban", "访问防护", state, "项目 SSH jail 与封禁动作", [*jail.output.splitlines(), *actions.output.splitlines()],
                         "服务运行不证明日志匹配或实际封禁。ufw 动作要求 UFW 已启用；其他 jail 未逐项检查。", "fail2ban")

    def accounts(self):
        data, _ = read_regular(self.root, "etc/passwd")
        accounts = []
        for line in data.decode("utf-8").splitlines():
            parts = line.split(":")
            if len(parts) != 7 or not parts[2].isdigit():
                raise ValueError("账户文件结构无效")
            accounts.append(parts)
        uid_zero = [p[0] for p in accounts if p[2] == "0"]
        local = [p for p in accounts if p[6] and p[6].rsplit("/", 1)[-1] not in ("nologin", "false", "sync", "shutdown", "halt")]
        self.add("accounts", "账户与密钥", "risk" if uid_zero != ["root"] else "review", "本地特权与可登录账户",
                 ["UID 0: " + ", ".join(uid_zero), "可登录: " + ", ".join(p[0] for p in local)],
                 "核对是否均由你创建；系统服务账户不等于入侵。此项不枚举远程 NSS/LDAP 或解析全部 sudo 规则。")
        try:
            groups, _ = read_regular(self.root, "etc/group")
            selected = [line.split(":") for line in groups.decode("utf-8").splitlines()]
            self.add("sudo-groups", "账户与密钥", "review", "本地 sudo/wheel 组成员",
                     [f"{p[0]}: {p[3]}" for p in selected if len(p) == 4 and p[0] in ("sudo", "wheel")],
                     "也需核对自定义 sudoers 授权；组列表不是完整权限审计。")
        except (OSError, ValueError):
            self.unknown("sudo-groups", "账户与密钥", bounded.Result(reason="无法读取本地组"))
        evidence, risks, incomplete = [], False, len(local) > 16
        for entry in local[:16]:
            name, _, uid, _, _, home, _ = entry
            path = Path(home)
            if not path.is_absolute() or ".." in path.parts or path == Path("/"):
                incomplete = True
                continue
            relative = str(path).lstrip("/") + "/.ssh/authorized_keys"
            try:
                data, info = read_regular(self.root, relative)
                parent = (self.root / relative).parent.lstat()
                if info.st_uid not in (0, int(uid)) or info.st_mode & 0o022 or parent.st_uid not in (0, int(uid)) or parent.st_mode & 0o022:
                    risks = True
                    evidence.append(f"{name}: .ssh/authorized_keys 所有者或权限需检查")
                count = 0
                for line in data.decode("utf-8").splitlines():
                    if not line.strip() or line.lstrip().startswith("#"):
                        continue
                    tokens = line.split()
                    for index, token in enumerate(tokens[:-1]):
                        if token.startswith(("ssh-", "ecdsa-", "sk-")):
                            raw = base64.b64decode(tokens[index + 1], validate=True)
                            fingerprint = base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
                            if count < 8:
                                evidence.append(f"{name}: SHA256:{fingerprint}")
                            count += 1
                            break
                    else:
                        incomplete = True
                if count > 8:
                    incomplete = True
                evidence.append(f"{name}: {count} 个可解析公钥条目（不是可登录证明）")
            except FileNotFoundError:
                evidence.append(f"{name}: 未发现标准路径 authorized_keys；可能使用自定义密钥来源")
            except (OSError, ValueError):
                evidence.append(f"{name}: 公钥文件未完整检查")
                incomplete = True
        self.add("keys", "账户与密钥", "risk" if risks else "unknown" if incomplete or len(evidence) > 80 else "review", "标准 authorized_keys 权限与指纹",
                 evidence, "只显示公钥指纹，不读取私钥。核对陌生指纹；仅检查前 16 个本地登录账户、每账户显示前 8 个指纹。")

    def evidence_command(self, key, category, summary, name, args, *, timeout=5, advice=""):
        result = self.command(name, *args, timeout=timeout)
        if not result.complete or result.code != 0:
            self.unknown(key, category, result)
        else:
            lines = result.output.splitlines()
            self.add(key, category, "review" if len(lines) <= 80 else "unknown", summary,
                     lines[:80], advice + (" 输出超过 80 行，仅显示前 80 行，覆盖不完整。" if len(lines) > 80 else ""))

    def logins(self):
        self.evidence_command("logins", "登录记录", "最近最多 20 次登录（wtmp，可能未启用）", "last", ("-n", "20", "-F", "-i"),
                              advice="核对时间、账户和来源；日志可能被轮转或删除，记录空白不代表没有登录。")
        result = self.command("journalctl", "--no-pager", "-q", "_COMM=sshd", "--since=-24h", "-n", "300", "-o", "cat")
        if not result.complete or result.code != 0:
            self.unknown("auth-log", "登录记录", result)
        else:
            lines = result.output.splitlines()
            events = [line for line in lines if any(word in line for word in ("Accepted ", "Failed ", "Invalid user", "authentication failure"))]
            self.add("auth-log", "登录记录", "unknown" if not lines or len(lines) >= 300 else "review",
                     "过去 24 小时 SSH 日志样本（最多读取最近 300 行）",
                     ["样本内成功认证: " + str(sum("Accepted " in line for line in events)),
                      "样本内失败/无效用户: " + str(sum("Accepted " not in line for line in events))],
                     "样本计数不是总量；不打印原始认证日志。陌生成功登录比普通公网失败尝试更值得优先调查。")

    def network(self):
        self.evidence_command("listeners", "网络与进程", "本机监听端口和进程（含地址；不是公网可达证明）",
                              "ss", ("-H", "-lntup"), advice="核对 SSH、面板和代理业务；不要直接关闭不认识的端口。")
        self.evidence_command("processes", "网络与进程", "CPU 使用排序的进程名称（不读取命令行参数/环境变量）",
                              "ps", ("-eo", "pid,ppid,user,pcpu,pmem,comm", "--sort=-pcpu"),
                              advice="合法任务也可能高负载；名称可伪造，需要结合可执行文件来源核实。")
        paths, unreadable, count = [], 0, 0
        with os.scandir(self.root / "proc") as entries:
            for entry in entries:
                if not entry.name.isascii() or not entry.name.isdigit():
                    continue
                count += 1
                if count > 512:
                    unreadable += 1
                    break
                try:
                    executable = os.readlink(self.root / "proc" / entry.name / "exe")
                    if executable.endswith(" (deleted)") or executable.startswith(("/tmp/", "/var/tmp/", "/dev/shm/", "memfd:")):
                        paths.append(f"PID {entry.name}: {executable}")
                except OSError:
                    # Includes kernel threads, process exit and permission errors.
                    unreadable += 1
        self.add("executable-paths", "网络与进程", "unknown" if unreadable or len(paths) > 80 else "review" if paths else "info",
                 "临时目录、memfd 或已删除文件的进程可执行路径",
                 [f"最多检查 512 PID；本次枚举 {min(count, 512)}；无法读取/超过上限 {unreadable}", *paths],
                 "升级也会留下 deleted 进程；这里只给线索，不代表恶意，不停止进程。不读取进程参数、内存或环境变量。")

    def persistence(self):
        self.evidence_command("units", "启动与持久化", "已启用的系统服务和定时器", "systemctl",
                              ("list-unit-files", "--type=service", "--type=timer", "--state=enabled", "--no-pager", "--no-legend"),
                              advice="核对来源与用途；未枚举用户级服务、容器内部或临时服务。")
        evidence, incomplete = [], False
        for directory in ("etc/cron.d", "etc/cron.hourly", "etc/cron.daily", "etc/cron.weekly", "etc/cron.monthly", "var/spool/cron/crontabs"):
            path = self.root / directory
            try:
                if not stat.S_ISDIR(path.lstat().st_mode):
                    raise ValueError("目录不是普通目录")
                with os.scandir(path) as entries:
                    for count, entry in enumerate(entries):
                        if count >= 64:
                            incomplete = True
                            break
                        relative = directory + "/" + entry.name
                        try:
                            data, info = read_regular(self.root, relative)
                            evidence.append(f"/{relative} mode={stat.S_IMODE(info.st_mode):04o} sha256={hashlib.sha256(data).hexdigest()}")
                        except (OSError, ValueError):
                            incomplete = True
                            evidence.append(f"/{relative}: 未读取（链接/权限/类型/大小限制）")
            except FileNotFoundError:
                continue
            except (OSError, ValueError):
                incomplete = True
        for relative in ("etc/crontab", "etc/rc.local", "etc/ld.so.preload"):
            try:
                data, info = read_regular(self.root, relative)
                evidence.append(f"/{relative} mode={stat.S_IMODE(info.st_mode):04o} sha256={hashlib.sha256(data).hexdigest()}")
                if relative.endswith("ld.so.preload") and data.strip():
                    self.add("preload", "启动与持久化", "review", "存在 ld.so.preload 内容", advice="可能来自合法监控，也可能是持久化；核对安装来源，不直接删除。")
            except FileNotFoundError:
                continue
            except (OSError, ValueError):
                incomplete = True
        self.add("persistence-files", "启动与持久化", "unknown" if incomplete or len(evidence) > 80 else "review", "常见持久化文件的元数据和摘要",
                 evidence, "不展示脚本正文或执行其中命令；摘要没有可信基线时不能用于判恶意。每目录最多 64 项，总显示最多 80 项。")

    def collect(self):
        for name, category in (("access", "访问防护"), ("accounts", "账户与密钥"), ("logins", "登录记录"),
                               ("network", "网络与进程"), ("persistence", "启动与持久化")):
            try:
                getattr(self, name)()
            except (OSError, ValueError, backup.BackupFailure) as exc:
                self.unknown(name + "-coverage", category, bounded.Result(reason=f"本组检查未完成：{type(exc).__name__}"))
        self.add("deep", "检查覆盖", "unknown", "未执行病毒扫描、全盘文件校验或离线取证",
                 advice="可单独选择限范围 ClamAV 扫描或软件包完整性检查；不自动下载、不自动清理。")
        return {"schema": 1, "kind": "security-audit", "demo": False,
                "generated_at": datetime.now(timezone.utc).isoformat(), "limitations": LIMITATIONS,
                "counts": {state: sum(item["state"] == state for item in self.items) for state in STATES}, "items": self.items}


def collect(*, demo=False):
    if demo:
        return {"schema": 1, "kind": "security-audit", "demo": True, "limitations": LIMITATIONS,
                "counts": {"info": 1}, "items": [{"id": "demo", "category": "演示", "state": "info",
                  "summary": "虚构演示；未读取本机或执行扫描", "evidence": [], "advice": "", "repair": None}]}
    return Audit().collect()


def render(report):
    lines = ["VPS 安全体检（只读）", report["limitations"]]
    for item in report["items"]:
        lines.append(f"\n[{STATES[item['state']]}] {item['category']} · {item['summary']}")
        lines.extend("  " + value for value in item["evidence"])
        if item["advice"]:
            lines.append("  建议：" + item["advice"])
    lines.append("\n检查计数：" + "，".join(f"{STATES[key]} {value}" for key, value in report["counts"].items()))
    return bounded.clean("\n".join(lines))
