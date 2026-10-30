"""项目专属的内核网络调优。

只管理 ``/etc/sysctl.d/91-vps-script-tuning.conf`` 和
``/var/lib/vps-script/tuning-state.json``；不碰 BBR 的
``tcp_congestion_control`` / ``default_qdisc``，不覆盖 /etc/sysctl.conf。

参数分为保守、代理/中转、大带宽缓冲三档。缓冲区按内存和用户给出的
预期带宽/RTT 估算，不把固定值当成“加速”。
"""

import json
import os
from pathlib import Path
import re
import subprocess

from . import bbr, checks, packages

HEADER = "# Managed by VPS-Script; do not edit while managed.\n"
CONFIG_NAME = "91-vps-script-tuning.conf"
KEY_RE = re.compile(r"^[a-z0-9_.]{3,96}$")
VALUE_RE = re.compile(r"^[0-9A-Za-z_.: -]{1,128}$")
PROFILES = ("conservative", "proxy", "buffer")
PROFILE_TITLES = {
    "conservative": "保守（通用 Web / 面板 / 轻量应用）",
    "proxy": "代理 / 中转（长连接、较高并发）",
    "buffer": "大带宽缓冲（按预期带宽和 RTT 估算）",
}

# 通用安全基线。tcp_tw_reuse 依赖 timestamps，因此同时确保 timestamps=1。
CONSERVATIVE = {
    "net.core.somaxconn": "4096",
    "net.core.netdev_max_backlog": "4096",
    "net.ipv4.tcp_max_syn_backlog": "8192",
    "net.ipv4.ip_local_port_range": "10240 65535",
    "net.ipv4.tcp_fin_timeout": "15",
    "net.ipv4.tcp_keepalive_time": "600",
    "net.ipv4.tcp_keepalive_intvl": "30",
    "net.ipv4.tcp_keepalive_probes": "5",
    "net.ipv4.tcp_mtu_probing": "1",
    "net.ipv4.tcp_sack": "1",
    "net.ipv4.tcp_timestamps": "1",
    "net.ipv4.tcp_window_scaling": "1",
    "net.ipv4.tcp_tw_reuse": "1",
    "net.ipv4.tcp_syncookies": "1",
}

PROXY = {
    "net.core.somaxconn": "8192",
    "net.core.netdev_max_backlog": "16384",
    "net.ipv4.tcp_max_syn_backlog": "16384",
    "net.ipv4.ip_local_port_range": "1024 65535",
    "net.ipv4.tcp_slow_start_after_idle": "0",
    "net.ipv4.tcp_notsent_lowat": "16384",
    "net.ipv4.tcp_fin_timeout": "10",
    "net.ipv4.tcp_keepalive_time": "300",
}

BUFFER_QUEUE = {
    "net.core.somaxconn": "8192",
    "net.core.netdev_max_backlog": "16384",
    "net.ipv4.tcp_max_syn_backlog": "16384",
    "net.ipv4.ip_local_port_range": "1024 65535",
    "net.ipv4.tcp_adv_win_scale": "1",
    "net.ipv4.tcp_moderate_rcvbuf": "1",
}

STATUS_KEYS = (
    "net.core.somaxconn",
    "net.core.netdev_max_backlog",
    "net.ipv4.tcp_max_syn_backlog",
    "net.ipv4.ip_local_port_range",
    "net.ipv4.tcp_tw_reuse",
    "net.ipv4.tcp_timestamps",
    "net.ipv4.tcp_slow_start_after_idle",
    "net.ipv4.tcp_notsent_lowat",
    "net.ipv4.tcp_fastopen",
    "net.core.rmem_max",
    "net.core.wmem_max",
    "net.ipv4.tcp_rmem",
    "net.ipv4.tcp_wmem",
    "net.ipv4.tcp_mem",
    "net.netfilter.nf_conntrack_max",
)

MIB = 1024 * 1024
MAX_BANDWIDTH = 100_000
MAX_RTT = 2_000


class TuningFailure(Exception):
    pass


def _norm(value):
    return " ".join(str(value).split())


def read_ram_kb(root=Path("/")):
    try:
        for line in (Path(root) / "proc/meminfo").read_text(encoding="ascii").splitlines():
            key, sep, value = line.partition(":")
            if sep and key == "MemTotal":
                fields = value.split()
                if fields and fields[0].isdigit() and int(fields[0]) > 0:
                    return int(fields[0])
    except (OSError, UnicodeError):
        pass
    return 1024 * 1024


def buffer_values(ram_kb, bandwidth_mbps=None, rtt_ms=200):
    if type(rtt_ms) is not int or not 1 <= rtt_ms <= MAX_RTT:
        raise TuningFailure(f"RTT 必须是 1–{MAX_RTT} 的整数")
    if bandwidth_mbps is not None:
        if type(bandwidth_mbps) is not int or not 1 <= bandwidth_mbps <= MAX_BANDWIDTH:
            raise TuningFailure(f"带宽必须是 1–{MAX_BANDWIDTH} Mbps 的整数")
    ram_bytes = max(ram_kb, 128 * 1024) * 1024
    cap = min(128 * MIB, max(4 * MIB, ram_bytes // 8))
    if bandwidth_mbps is None:
        target = ram_bytes // 16
        hard_cap = 64 * MIB
    else:
        bdp = bandwidth_mbps * rtt_ms * 125
        target = max(2 * bdp, 4 * MIB)
        hard_cap = 128 * MIB
    buf_max = min(max(target, 4 * MIB), cap, hard_cap)
    buf_max = max(4 * MIB, (buf_max // 4096) * 4096)
    buf_default = min(max(256 * 1024, buf_max // 16), 1 * MIB, buf_max)
    buf_default = max(4096, (buf_default // 4096) * 4096)
    ram_pages = max(4096, ram_kb // 4)
    low = max(1, ram_pages // 32)
    pressure = max(low + 1, ram_pages // 16)
    high = max(pressure + 1, ram_pages // 8)
    return {
        "net.core.rmem_max": str(buf_max),
        "net.core.wmem_max": str(buf_max),
        "net.ipv4.tcp_rmem": f"4096 {buf_default} {buf_max}",
        "net.ipv4.tcp_wmem": f"4096 {buf_default} {buf_max}",
        "net.ipv4.tcp_mem": f"{low} {pressure} {high}",
    }


def target_values(profile, ram_kb, bandwidth_mbps=None, rtt_ms=200,
                  fastopen=False, conntrack=False):
    if profile not in PROFILES:
        raise TuningFailure("未知调优档位")
    values = dict(CONSERVATIVE)
    if profile == "proxy":
        values.update(PROXY)
        if conntrack:
            values["net.netfilter.nf_conntrack_max"] = str(min(max(65536, ram_kb // 16), 262144))
    elif profile == "buffer":
        values.update(BUFFER_QUEUE)
        values.update(buffer_values(ram_kb, bandwidth_mbps, rtt_ms))
        if conntrack:
            values["net.netfilter.nf_conntrack_max"] = str(min(max(65536, ram_kb // 16), 262144))
    if fastopen:
        values["net.ipv4.tcp_fastopen"] = "3"
    for key, value in values.items():
        if not KEY_RE.fullmatch(key) or not VALUE_RE.fullmatch(value):
            raise TuningFailure("调优参数包含无法安全识别的字符")
    return dict(sorted(values.items()))


class TuningManager:
    def __init__(self, root=Path("/"), runner=None):
        self.root = Path(root)
        self.runner = runner or subprocess.run
        self.files = bbr.BBRManager(self.root)
        self.files.lock = self.root / "run/lock/vps-script-tuning.lock"
        self.config = self.root / "etc/sysctl.d" / CONFIG_NAME
        self.state = self.root / "var/lib/vps-script/tuning-state.json"

    def _command(self):
        command = checks.find_command("sysctl")
        if not command:
            raise TuningFailure("未找到 sysctl")
        return command

    def _sysctl(self, key):
        if not KEY_RE.fullmatch(key):
            raise TuningFailure("无效的 sysctl 键")
        result = self.runner(
            (self._command(), "-n", key), capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=3, check=False,
            env={"PATH": packages.SAFE_PATH, "LC_ALL": "C"},
        )
        if result.returncode != 0:
            raise TuningFailure(f"无法读取 {key}")
        value = result.stdout.strip()
        if not value or len(value) > 128 or "\n" in value:
            raise TuningFailure(f"{key} 的值无法安全识别")
        return _norm(value)

    def _write(self, key, value):
        if not KEY_RE.fullmatch(key) or not VALUE_RE.fullmatch(value):
            raise TuningFailure("拒绝写入无法识别的 sysctl 参数")
        result = self.runner(
            (self._command(), "-w", f"{key}={value}"), capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=10, check=False,
            env={"PATH": packages.SAFE_PATH, "LC_ALL": "C"},
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            raise TuningFailure(f"写入 {key} 失败：{detail[:200]}")

    def key_exists(self, key):
        try:
            self._sysctl(key)
            return True
        except TuningFailure:
            return False

    def read_live(self, keys):
        return {key: self._sysctl(key) for key in keys}

    def inspect(self):
        values = {}
        for key in STATUS_KEYS:
            try:
                values[key] = self._sysctl(key)
            except TuningFailure:
                values[key] = None
        state = None
        if os.path.lexists(self.state):
            try:
                state = self.load_state()
            except TuningFailure:
                state = {"invalid": True}
        config_exists = os.path.lexists(self.config)
        config_matches = False
        if config_exists and state and not state.get("invalid"):
            try:
                config_matches = self.files._read_regular(self.config) == self._render(state["profile"], state["target"])
            except (OSError, bbr.BBRFailure):
                config_matches = False
        return {
            "values": values,
            "state": state,
            "config_exists": config_exists,
            "config_matches": config_matches,
        }

    def conflicts(self, target):
        locations = [self.root / "etc/sysctl.conf"]
        for folder in ("etc/sysctl.d", "run/sysctl.d", "usr/local/lib/sysctl.d", "usr/lib/sysctl.d", "lib/sysctl.d"):
            try:
                locations.extend(sorted((self.root / folder).glob("*.conf")))
            except OSError as exc:
                raise TuningFailure(f"无法检查 {folder}: {exc}") from exc
        conflicts = []
        seen = set()
        for path in locations:
            if path == self.config or not os.path.lexists(path):
                continue
            try:
                resolved = path.resolve(strict=True)
                if resolved in seen:
                    continue
                seen.add(resolved)
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                raise TuningFailure(f"无法读取 {path}: {exc}") from exc
            for raw in text.splitlines():
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                match = re.match(r"^-?\s*([a-z0-9_.]+)\s*(?:=|\s)\s*(.+)$", line)
                if not match:
                    continue
                key = match.group(1).replace("/", ".")
                value = _norm(match.group(2))
                if key in target and value != _norm(target[key]):
                    conflicts.append(f"{path}: {key} = {value}")
        return conflicts

    def _render(self, profile, target):
        lines = [HEADER.rstrip("\n"), f"# profile: {profile}"]
        lines.extend(f"{key} = {value}" for key, value in sorted(target.items()))
        return ("\n".join(lines) + "\n").encode("utf-8")

    def load_state(self):
        try:
            data = json.loads(self.files._read_regular(self.state).decode("utf-8"))
        except (ValueError, UnicodeError, bbr.BBRFailure) as exc:
            raise TuningFailure("调优状态文件无效或无法读取") from exc
        if not isinstance(data, dict) or data.get("schema") != 1:
            raise TuningFailure("调优状态文件格式无效")
        profile = data.get("profile")
        target = data.get("target")
        before = data.get("before")
        if profile not in PROFILES or not isinstance(target, dict) or not isinstance(before, dict):
            raise TuningFailure("调优状态文件字段无效")
        if set(target) != set(before) or not target:
            raise TuningFailure("调优状态文件目标/原值不匹配")
        for key, value in target.items():
            if not KEY_RE.fullmatch(key) or not isinstance(value, str) or not VALUE_RE.fullmatch(value):
                raise TuningFailure("调优状态文件包含无效目标值")
        for key, value in before.items():
            if not KEY_RE.fullmatch(key) or not isinstance(value, str) or not VALUE_RE.fullmatch(value):
                raise TuningFailure("调优状态文件包含无效原值")
        if not isinstance(data.get("fastopen"), bool):
            raise TuningFailure("调优状态文件缺少 Fast Open 字段")
        return data

    def apply(self, profile, bandwidth_mbps=None, rtt_ms=200, fastopen=False):
        with self.files.locked():
            if os.path.lexists(self.state):
                state = self.load_state()
                requested = (profile, bandwidth_mbps, rtt_ms, bool(fastopen))
                recorded = (state["profile"], state.get("bandwidth_mbps"),
                            state.get("rtt_ms", 200), state["fastopen"])
                if requested != recorded:
                    raise TuningFailure("本次档位或参数与已有调优不同，请先恢复原值，再应用新的调优")
                expected = self._render(state["profile"], state["target"])
                if (os.path.lexists(self.config)
                        and self.files._read_regular(self.config) == expected
                        and self.read_live(state["target"]) == state["target"]):
                    return "项目调优配置与运行时值已经一致。"
                raise TuningFailure("发现未完成或不一致的旧调优，请先检查并恢复")
            if os.path.lexists(self.config):
                raise TuningFailure("项目调优配置文件已存在，拒绝覆盖")
            conntrack = self.key_exists("net.netfilter.nf_conntrack_max")
            target = target_values(profile, read_ram_kb(self.root), bandwidth_mbps, rtt_ms, fastopen, conntrack)
            if fastopen and "net.ipv4.tcp_fastopen" not in target:
                raise TuningFailure("TCP Fast Open 参数不可用")
            conflicts = self.conflicts(target)
            if conflicts:
                raise TuningFailure("发现其他 sysctl 配置冲突：\n" + "\n".join(conflicts))

            before = {}
            skipped = []
            for key in target:
                try:
                    before[key] = self._sysctl(key)
                except TuningFailure:
                    skipped.append(key)
            target = {key: value for key, value in target.items() if key in before}
            if not target:
                raise TuningFailure("当前内核没有可应用的目标参数")
            if fastopen and "net.ipv4.tcp_fastopen" not in target:
                raise TuningFailure("当前内核不支持 TCP Fast Open 参数")
            state = {
                "schema": 1,
                "profile": profile,
                "target": target,
                "before": before,
                "fastopen": bool(fastopen),
                "bandwidth_mbps": bandwidth_mbps,
                "rtt_ms": rtt_ms,
                "skipped": skipped,
            }
            self.files._prepare_state_dir()
            initial = json.dumps(state, sort_keys=True).encode("utf-8") + b"\n"
            self.files._atomic_create(self.state, initial, 0o600)
            config_created = False
            try:
                for key, value in target.items():
                    if before[key] != value:
                        self._write(key, value)
                if self.read_live(target) != target:
                    raise TuningFailure("部分 sysctl 参数未按预期生效")
                self.files._atomic_create(self.config, self._render(profile, target), 0o644)
                config_created = True
            except BaseException as exc:
                errors = self._rollback(before, target)
                if config_created and os.path.lexists(self.config):
                    try:
                        if self.files._read_regular(self.config) == self._render(profile, target):
                            os.unlink(self.config)
                    except (OSError, bbr.BBRFailure):
                        pass
                if not errors:
                    try:
                        os.unlink(self.state)
                    except OSError:
                        pass
                else:
                    print("自动恢复未完成：" + "；".join(errors) + "；保留状态文件供检查。")
                raise TuningFailure(f"调优未完成：{exc}") from exc
            detail = f"已应用 {PROFILE_TITLES[profile]}，共 {len(target)} 项"
            if skipped:
                detail += f"；跳过不支持的键 {len(skipped)} 项"
            if fastopen:
                detail += "；已请求 TCP Fast Open"
            return detail + "。重启后的实际效果尚未验证。"

    def _rollback(self, before, target):
        errors = []
        for key in reversed(tuple(target)):
            try:
                current = self._sysctl(key)
                if current not in (before[key], target[key]):
                    raise TuningFailure(f"{key} 已被其他操作改为 {current}，拒绝覆盖")
                if current != before[key]:
                    self._write(key, before[key])
                if self._sysctl(key) != before[key]:
                    errors.append(f"{key} 未恢复")
            except (TuningFailure, OSError, subprocess.TimeoutExpired) as exc:
                errors.append(str(exc))
        return errors

    def restore(self):
        with self.files.locked():
            if not os.path.lexists(self.state):
                raise TuningFailure("没有找到本项目记录的调优原值")
            state = self.load_state()
            expected = self._render(state["profile"], state["target"])
            # State is persisted before live writes, while config is created
            # only afterwards. Interrupted applications may legitimately have
            # no config; a valid snapshot and unchanged live values suffice.
            if os.path.lexists(self.config) and self.files._read_regular(self.config) != expected:
                raise TuningFailure("项目调优配置被外部修改，拒绝覆盖或恢复")
            live = self.read_live(state["target"])
            for key, value in live.items():
                if value not in (state["before"][key], state["target"][key]):
                    raise TuningFailure(f"{key} 已被其他操作改为 {value}，拒绝覆盖")
            errors = self._rollback(state["before"], state["target"])
            if errors:
                raise TuningFailure("恢复未完全生效：" + "；".join(errors))
            if self.read_live(state["target"]) != state["before"]:
                raise TuningFailure("恢复后的运行时值与原值不一致；状态文件保留")
            if os.path.lexists(self.config):
                if self.files._read_regular(self.config) != expected:
                    raise TuningFailure("项目调优配置在恢复期间发生变化，拒绝删除")
                os.unlink(self.config)
            os.unlink(self.state)
            return "已恢复运行时值并移除项目调优配置；其他 sysctl 文件未被改写。"


def change(profile="conservative", restore=False, bandwidth_mbps=None, rtt_ms=200,
           fastopen=False, experimental=False):
    error = packages.preflight(experimental)
    if error:
        print(f"未执行：{error}")
        return 2
    if profile not in PROFILES:
        print("未知调优档位。")
        return 2
    manager = TuningManager()
    print("\n【试验功能】VPS 内核网络调优；尚未完成真实 VPS A/B 验证。")
    print("只管理 /etc/sysctl.d/91-vps-script-tuning.conf 和项目状态文件。")
    print("不改 BBR/default_qdisc、不改内核、不做 qdisc 整形、不改 DNS/转发/RPS/MSS。")
    print("参数改变内核行为，不保证吞吐或延迟一定改善；请先快照并准备回滚。")
    try:
        if restore:
            print("将按本项目记录的原值恢复；配置或运行值被外部修改时会停止。")
            if input("输入 YES 继续，其他内容取消：").strip() != "YES":
                print("已取消。")
                return 0
            print(manager.restore())
            return 0
        target = target_values(profile, read_ram_kb(), bandwidth_mbps, rtt_ms, fastopen)
        print(f"档位：{PROFILE_TITLES[profile]}")
        if profile == "buffer":
            print("缓冲区按预期带宽/RTT 或内存估算，不是实测结果；上限仍受 tcp_mem 和内存约束。")
        if fastopen:
            print("TCP Fast Open 可能被中间设备丢弃，且不是所有应用都使用。")
        print("将写入以下参数（已有冲突会停止）：")
        for key, value in target.items():
            print(f"  {key} = {value}")
        if input("输入 YES 应用，其他内容取消：").strip() != "YES":
            print("已取消。")
            return 0
        print(manager.apply(profile, bandwidth_mbps, rtt_ms, fastopen))
        return 0
    except EOFError:
        print("已取消。")
        return 0
    except (TuningFailure, bbr.BBRFailure, OSError) as exc:
        print(f"操作未完成：{exc}")
        return 1
