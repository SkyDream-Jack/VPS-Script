"""Hy2 端口跳跃的 nftables 试验实现。

不修改 UFW、云防火墙或客户端；只管理独立表及专属 systemd 单元。
"""

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from . import backup, bbr, checks, firewall, packages

TABLE = "vps_script_hy2"
IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
UNIT_NAME = "vps-script-hy2.service"


class Hy2Failure(Exception):
    pass


@dataclass(frozen=True)
class HopSpec:
    interface: str
    start: int
    end: int
    target: int
    families: tuple

    def validate(self):
        if not IFACE_RE.fullmatch(self.interface) or self.interface in (".", ".."):
            raise Hy2Failure("网络接口名称无效")
        if any(type(p) is not int or p < 1 or p > 65535 for p in (self.start, self.end, self.target)):
            raise Hy2Failure("端口必须是 1–65535 的整数")
        if self.start > self.end:
            raise Hy2Failure("起始端口不能大于结束端口")
        if not self.families or len(set(self.families)) != len(self.families) or any(f not in ("ip", "ip6") for f in self.families):
            raise Hy2Failure("IP 地址族无效")


def nft_config(spec):
    spec.validate()
    blocks = ["# Managed by VPS-Script; do not edit while managed."]
    ports = str(spec.start) if spec.start == spec.end else f"{spec.start}-{spec.end}"
    for family in spec.families:
        blocks.extend((
            f"table {family} {TABLE} {{",
            "  chain prerouting {",
            "    type nat hook prerouting priority dstnat; policy accept;",
            f'    iifname "{spec.interface}" udp dport {ports} counter redirect to :{spec.target}',
            "  }",
            "}",
        ))
    return ("\n".join(blocks) + "\n").encode("utf-8")


def service_unit(spec, nft_path):
    spec.validate()
    if nft_path not in ("/usr/sbin/nft", "/usr/bin/nft", "/sbin/nft", "/bin/nft"):
        raise Hy2Failure("nft 程序路径不在允许范围")
    lines = [
        "[Unit]", "Description=VPS-Script Hy2 UDP port redirect",
        "Wants=network-pre.target", "Before=network-pre.target", "",
        "[Service]", "Type=oneshot", f"ExecStart={nft_path} -f /etc/vps-script/hy2.nft",
    ]
    lines.extend(f"ExecStop=-{nft_path} delete table {family} {TABLE}" for family in spec.families)
    lines.extend(("RemainAfterExit=yes", "", "[Install]", "WantedBy=multi-user.target", ""))
    return "\n".join(lines).encode("utf-8")


def parse_ss(text):
    """解析 ss -H -l -u -n 的本地端点；无法确认时不猜。"""
    result = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 5:
            raise Hy2Failure("无法解析 UDP 监听信息")
        address, sep, port = fields[3].rpartition(":")
        if not sep or not port.isdigit():
            raise Hy2Failure("UDP 监听包含无法识别的端口")
        result.append((address.strip("[]").split("%", 1)[0], int(port)))
    return result


def inspect_listeners(spec, family, listeners, interface_addresses):
    spec.validate()
    allowed = set(interface_addresses) | ({"0.0.0.0", "*"} if family == "ip" else {"::", "*"})
    if not any(port == spec.target and addr in allowed for addr, port in listeners):
        raise Hy2Failure(f"{family} 未确认目标 UDP 端口在所选接口可接收")
    occupied = sorted({port for _, port in listeners if spec.start <= port <= spec.end and port != spec.target})
    if occupied:
        raise Hy2Failure(f"{family} 跳跃范围与其他 UDP 监听端口冲突：{occupied}")


def nat_conflicts(document, families):
    """检测其他非空 NAT prerouting 链；不试图推断复杂规则是否兼容。"""
    entries = document.get("nftables") if isinstance(document, dict) else None
    if not isinstance(entries, list):
        raise Hy2Failure("无法解析 nftables 规则集")
    relevant = set(families) | {"inet"}
    chains = set()
    own = False
    for entry in entries:
        if not isinstance(entry, dict):
            raise Hy2Failure("nftables 规则集格式未知")
        table = entry.get("table")
        if isinstance(table, dict) and table.get("name") == TABLE and table.get("family") in relevant:
            own = True
        chain = entry.get("chain")
        if isinstance(chain, dict) and chain.get("family") in relevant and chain.get("type") == "nat" and chain.get("hook") == "prerouting":
            chains.add((chain.get("family"), chain.get("table"), chain.get("name")))
    conflicts = set()
    for entry in entries:
        rule = entry.get("rule")
        if isinstance(rule, dict):
            key = (rule.get("family"), rule.get("table"), rule.get("chain"))
            if key in chains and rule.get("table") != TABLE:
                conflicts.add("/".join(str(part) for part in key))
    return own, tuple(sorted(conflicts))


def normalize_nft(value):
    """保留结构和匹配条件，忽略动态计数器和内核句柄。"""
    if isinstance(value, list):
        return [normalize_nft(item) for item in value if not (isinstance(item, dict) and "metainfo" in item)]
    if isinstance(value, dict):
        return {key: ({} if key == "counter" and isinstance(val, dict) else normalize_nft(val))
                for key, val in value.items() if key not in ("handle", "index")}
    return value


def fingerprint(document):
    data = json.dumps(normalize_nft(document), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


class Hy2Manager:
    def __init__(self, root=Path("/"), runner=None):
        self.root = Path(root)
        self.runner = runner or subprocess.run
        self.files = bbr.BBRManager(self.root)
        self.files.lock = self.root / "run/lock/vps-script-hy2.lock"
        self.state = self.root / "var/lib/vps-script/hy2-state.json"
        self.config = self.root / "etc/vps-script/hy2.nft"
        self.unit = self.root / "etc/systemd/system" / UNIT_NAME

    def run(self, command, *, input_text=None, check=True):
        try:
            result = self.runner(command, input=input_text, capture_output=True, text=True, encoding="utf-8", errors="replace",
                                 timeout=20, check=False, env={"PATH": packages.SAFE_PATH, "LC_ALL": "C"})
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Hy2Failure(f"无法运行 {command[0]}: {exc}") from exc
        if check and result.returncode != 0:
            raise Hy2Failure(f"{command[0]} 返回 {result.returncode}: {(result.stderr or '').strip()}")
        return result.stdout if check else result

    def command(self, name):
        value = checks.find_command(name)
        if not value:
            raise Hy2Failure(f"未找到 {name}")
        return value

    def ruleset(self, nft):
        try:
            return json.loads(self.run((nft, "-j", "list", "ruleset")))
        except ValueError as exc:
            raise Hy2Failure("nftables 输出不是有效 JSON") from exc

    def table_digest(self, nft, family):
        try:
            document = json.loads(self.run((nft, "-j", "list", "table", family, TABLE)))
        except ValueError as exc:
            raise Hy2Failure("项目规则表输出不是有效 JSON") from exc
        return fingerprint(document)

    def addresses(self, ip, spec, family):
        try:
            data = json.loads(self.run((ip, "-j", "address", "show", "dev", spec.interface)))
            if not isinstance(data, list) or len(data) != 1 or data[0].get("ifname") != spec.interface:
                raise ValueError("interface mismatch")
            wanted = "inet" if family == "ip" else "inet6"
            values = set()
            for item in data[0].get("addr_info", []):
                if item.get("family") == wanted:
                    values.add(str(ipaddress.ip_address(item["local"])))
            return values
        except (ValueError, KeyError, TypeError) as exc:
            raise Hy2Failure("无法读取所选接口地址") from exc

    def check_legacy_nat(self, family):
        path = self.root / ("proc/net/ip_tables_names" if family == "ip" else "proc/net/ip6_tables_names")
        try:
            names = path.read_text(encoding="ascii").split()
        except FileNotFoundError:
            # 模块未加载时路径可能不存在；无法证明宿主网络命名空间以外的状态。
            return
        except (OSError, UnicodeError) as exc:
            raise Hy2Failure(f"无法检查旧版 iptables NAT: {exc}") from exc
        if "nat" in names:
            raise Hy2Failure(f"检测到 {family} 的旧版 iptables NAT 表，暂不自动修改")

    def inspect(self, spec):
        spec.validate()
        nft, ip, ss = (self.command(name) for name in ("nft", "ip", "ss"))
        if nft not in ("/usr/sbin/nft", "/usr/bin/nft", "/sbin/nft", "/bin/nft"):
            raise Hy2Failure("nft 路径不受支持")
        own, conflicts = nat_conflicts(self.ruleset(nft), spec.families)
        if own:
            raise Hy2Failure("项目规则表已存在；拒绝覆盖")
        if conflicts:
            raise Hy2Failure("存在其他 NAT prerouting 规则，无法可靠判断执行顺序：" + ", ".join(conflicts))
        for family in spec.families:
            self.check_legacy_nat(family)
            addresses = self.addresses(ip, spec, family)
            flag = "-4" if family == "ip" else "-6"
            listeners = parse_ss(self.run((ss, "-H", "-l", "-u", "-n", flag)))
            inspect_listeners(spec, family, listeners, addresses)
        return nft

    def check_services(self, systemctl):
        for service in ("docker.service", "firewalld.service", "nftables.service"):
            active = self.run((systemctl, "is-active", service), check=False)
            if active.returncode == 0 and active.stdout.strip() == "active":
                raise Hy2Failure(f"{service} 正在运行，暂不自动管理 NAT")
            if active.returncode not in (3, 4) or active.stdout.strip() not in ("inactive", "failed", "unknown"):
                raise Hy2Failure(f"无法判断 {service} 状态")
        enabled = self.run((systemctl, "is-enabled", "nftables.service"), check=False)
        if enabled.returncode != 1 or enabled.stdout.strip() not in ("disabled", "not-found"):
            raise Hy2Failure("nftables.service 可能在开机时重置规则，暂不自动管理 NAT")

    def _state_bytes(self, spec, nft, fingerprints=None):
        return (json.dumps({"schema": 1, "interface": spec.interface, "start": spec.start, "end": spec.end,
                            "target": spec.target, "families": list(spec.families), "nft": nft,
                            "fingerprints": fingerprints or {}}, sort_keys=True) + "\n").encode("utf-8")

    def _load_state(self):
        try:
            data = json.loads(self.files._read_regular(self.state).decode("utf-8"))
            if data.get("schema") != 1:
                raise ValueError("unknown schema")
            spec = HopSpec(data["interface"], data["start"], data["end"], data["target"], tuple(data["families"]))
            spec.validate()
            nft = data["nft"]
            service_unit(spec, nft)
            fingerprints = data["fingerprints"]
            if not isinstance(fingerprints, dict):
                raise ValueError("invalid fingerprints")
            return spec, nft, fingerprints
        except (ValueError, KeyError, TypeError, UnicodeError, bbr.BBRFailure) as exc:
            raise Hy2Failure("项目状态文件无效或无法读取") from exc

    def _prepare(self):
        self.files._prepare_state_dir()
        try:
            self.config.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            info = os.lstat(self.config.parent)
        except OSError as exc:
            raise Hy2Failure(f"无法准备项目配置目录: {exc}") from exc
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022 or (self.root == Path("/") and info.st_uid != 0):
            raise Hy2Failure("项目配置目录不安全")

    def _replace_state(self, old, new):
        if self.files._read_regular(self.state) != old:
            raise Hy2Failure("状态文件已被外部修改")
        temp = None
        try:
            fd, temp = tempfile.mkstemp(prefix=".hy2-state-", dir=str(self.state.parent))
            with os.fdopen(fd, "wb") as file:
                os.fchmod(file.fileno(), 0o600)
                file.write(new)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temp, self.state)
            temp = None
        finally:
            if temp is not None:
                os.unlink(temp)

    def _cleanup_apply(self, nft, spec):
        """应用失败时只清理本项目已创建的对象；无法确认时保留状态供人工恢复。"""
        systemctl = checks.find_command("systemctl")
        if systemctl:
            self.run((systemctl, "disable", "--now", UNIT_NAME), check=False)
        for family in spec.families:
            self.run((nft, "delete", "table", family, TABLE), check=False)
        for path in (self.config, self.unit):
            if os.path.lexists(path):
                try:
                    os.unlink(path)
                except OSError:
                    pass
        if systemctl:
            self.run((systemctl, "daemon-reload"), check=False)
        own = True
        try:
            own, _ = nat_conflicts(self.ruleset(nft), spec.families)
        except (Hy2Failure, bbr.BBRFailure, OSError):
            own = True
        if not own and not os.path.lexists(self.config) and not os.path.lexists(self.unit):
            if os.path.lexists(self.state):
                try:
                    os.unlink(self.state)
                except OSError:
                    pass

    def apply(self, spec):
        spec.validate()
        with self.files.locked():
            for path in (self.state, self.config, self.unit):
                if os.path.lexists(path):
                    raise Hy2Failure(f"项目文件已存在，拒绝覆盖：{path}")
            nft = self.inspect(spec)
            systemctl = self.command("systemctl")
            self.check_services(systemctl)
            self._prepare()
            initial = self._state_bytes(spec, nft)
            try:
                self.files._atomic_create(self.state, initial, 0o600)
                self.files._atomic_create(self.config, nft_config(spec), 0o644)
                self.files._atomic_create(self.unit, service_unit(spec, nft), 0o644)
                self.run((nft, "-c", "-f", str(self.config)))
                # 应用前重新检查，降低交互期间出现规则冲突的风险。
                self.inspect(spec)
                self.check_services(systemctl)
                self.run((systemctl, "daemon-reload"))
                self.run((systemctl, "enable", "--now", UNIT_NAME))
                digests = {family: self.table_digest(nft, family) for family in spec.families}
                self._replace_state(initial, self._state_bytes(spec, nft, digests))
            except (Hy2Failure, bbr.BBRFailure, OSError) as exc:
                if any(os.path.lexists(path) for path in (self.state, self.config, self.unit)):
                    self._cleanup_apply(nft, spec)
                raise Hy2Failure(f"应用未完成；已尝试清理项目文件和规则：{exc}") from exc
            return "项目转发规则和开机服务已创建；重启持久化与公网客户端连接仍需独立验证。"

    def remove(self):
        with self.files.locked():
            spec, nft, digests = self._load_state()
            for path, expected in ((self.config, nft_config(spec)), (self.unit, service_unit(spec, nft))):
                if os.path.lexists(path) and self.files._read_regular(path) != expected:
                    raise Hy2Failure(f"{path} 已变更，拒绝覆盖")
            document = self.ruleset(nft)
            existing = {item["table"].get("family") for item in document.get("nftables", [])
                        if isinstance(item, dict) and isinstance(item.get("table"), dict)
                        and item["table"].get("name") == TABLE}
            if existing - set(spec.families):
                raise Hy2Failure("出现未知地址族的同名表，拒绝删除")
            if existing and set(digests) != set(spec.families):
                raise Hy2Failure("上次操作未完整记录实时规则，不能自动删除；请先人工检查")
            for family in existing:
                if self.table_digest(nft, family) != digests[family]:
                    raise Hy2Failure(f"{family} 项目规则表已被外部修改，拒绝删除")
            systemctl = self.command("systemctl")
            if os.path.lexists(self.unit):
                self.run((systemctl, "disable", "--now", UNIT_NAME))
            own, _ = nat_conflicts(self.ruleset(nft), spec.families)
            if own:
                raise Hy2Failure("服务停止后规则表仍存在；保留配置以供检查")
            for path in (self.config, self.unit):
                if os.path.lexists(path):
                    os.unlink(path)
            os.unlink(self.state)
            self.run((systemctl, "daemon-reload"))
            return "已移除本项目的转发和开机服务；未改动 UFW 或云防火墙。"


def allow_ufw(spec):
    """在 UFW 已启用时放行跳跃范围和目标 UDP 端口；失败只提示。"""
    try:
        manager = firewall.FirewallManager()
        ufw = manager.command("ufw")
        if manager.status(ufw) != "active":
            return "UFW 未启用；没有添加规则。启用 UFW 前请先规划 SSH 和业务端口。"
        messages = [
            backup.track("ufw", "allow", lambda: manager.allow(spec.start, spec.end, "udp"),
                         details={"action": "Hy2 UDP 跳跃范围放行"}),
            backup.track("ufw", "allow", lambda: manager.allow(spec.target, spec.target, "udp"),
                         details={"action": "Hy2 UDP 目标端口放行"}),
        ]
        return "UFW 已添加 UDP 跳跃范围和目标端口规则；云防火墙仍需单独放行。\n" + "\n".join(messages)
    except (firewall.FirewallFailure, bbr.BBRFailure, backup.BackupFailure, OSError) as exc:
        return f"UFW 放行未全部完成：{exc}；此前成功的规则保留并单独记录，请检查 UDP {spec.start}-{spec.end} 和目标 {spec.target}。"


def change(spec=None, remove=False, allow_firewall=False, experimental=False):
    error = packages.preflight(experimental)
    if error:
        print(f"未执行：{error}")
        return 2
    if not (Path("/run/systemd/system").is_dir()):
        print("未检测到运行中的 systemd。")
        return 2
    print("\n【试验功能】Hy2 转发尚未在真实 Linux / VPS 验证。")
    if remove:
        print("将移除本项目的 NAT 和开机服务；现有连接可能中断。")
    else:
        try:
            spec.validate()
        except Hy2Failure as exc:
            print(f"参数无效：{exc}")
            return 2
        print(f"接口 {spec.interface}：UDP {spec.start}-{spec.end} 转发到 {spec.target}；地址族 {', '.join(spec.families)}。")
        print("只创建项目专用 nftables 表和 systemd 服务；不会修改云防火墙或客户端。")
        if allow_firewall:
            print("应用成功后会尝试在 UFW 中放行跳跃范围和目标 UDP 端口。")
        else:
            print("不会自动修改 UFW；请自行确认主机防火墙放行。")
        print("请先确认云防火墙允许跳跃范围，主机防火墙允许转发后的目标 UDP 端口，且客户端支持并使用该范围。")
        print("遇到其他 NAT prerouting 规则、旧版 NAT 表或监听冲突时将停止。")
    try:
        confirmed = input("输入 YES 继续，其他内容取消：").strip() == "YES"
    except EOFError:
        confirmed = False
    if not confirmed:
        print("已取消。")
        return 0
    try:
        manager = Hy2Manager()
        operation = manager.remove if remove else lambda: manager.apply(spec)
        result = backup.track("hy2", "remove" if remove else "apply", operation)
        print(result)
        if not remove and allow_firewall:
            print(allow_ufw(spec))
        if remove:
            print("UFW 中此前为 Hy2 添加的规则不会自动删除；如需要请手动检查。")
        return 0
    except (Hy2Failure, bbr.BBRFailure, backup.BackupFailure, OSError) as exc:
        print(f"操作未完成：{exc}")
        return 1
