"""Bounded history adapters for the project's network and system settings.

Snapshots contain fixed configuration paths and semantic runtime values. They
never contain swap data, arbitrary commands, or a whole nftables ruleset.
"""

import fnmatch
import json
import os
from pathlib import Path
import re
import stat

from . import backup, bbr, checks, common, hy2, swap, tuning


def _fail(message):
    raise backup.BackupFailure(message)


def _files(snapshot, paths):
    files = snapshot.get("files")
    if not isinstance(files, dict) or set(files) != set(paths):
        _fail("历史文件集合不符合模块白名单")
    return {path: backup.decode_file(files[path]) for path in paths}


def _sysctl_context(root, keys, own_config):
    """Record only relevant foreign assignments, including matching globs."""
    root = Path(root).resolve(strict=True)
    locations = [root / "etc/sysctl.conf"]
    for folder in ("etc/sysctl.d", "run/sysctl.d", "usr/local/lib/sysctl.d", "usr/lib/sysctl.d", "lib/sysctl.d"):
        locations.extend(sorted((root / folder).glob("*.conf")))
    result, seen = {}, set()
    for path in locations:
        if path == root / own_config or not os.path.lexists(path):
            continue
        current = root
        for part in path.relative_to(root).parts:
            current /= part
            info = current.lstat()
            if (info.st_uid != backup._owner(root)
                    or (not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022)):
                _fail("其他 sysctl 配置路径可被其他用户修改")
        resolved = path.resolve(strict=True)
        try:
            resolved.relative_to(root)
        except ValueError:
            _fail("其他 sysctl 配置链接超出允许的根目录")
        # Distribution aliases (e.g. 99-sysctl.conf -> ../sysctl.conf) are
        # readable, but the resolved target must remain a trusted normal file.
        if not backup._directories(root, resolved.parent):
            _fail("其他 sysctl 配置目录不存在")
        if resolved == root / "dev/null" and path.is_symlink():
            info = resolved.lstat()
            if stat.S_ISCHR(info.st_mode) and info.st_uid == backup._owner(root):
                # A root-owned /dev/null alias is the standard sysctl.d mask.
                # Record its path but never open the device.
                result[path.relative_to(root).as_posix()] = []
                continue
        if resolved in seen:
            continue
        seen.add(resolved)
        data, _ = backup._read(resolved, root, backup.MAX_FILE_BYTES)
        assignments = []
        for raw in data.decode("utf-8").splitlines():
            line = raw.split("#", 1)[0].split(";", 1)[0].strip()
            match = re.fullmatch(r"-?\s*([a-zA-Z0-9_./*?\[\]-]+)\s*(?:=|\s)\s*(.+)", line)
            if match:
                key = match.group(1).replace("/", ".")
                affected = [candidate for candidate in keys if fnmatch.fnmatchcase(candidate, key)]
                if affected:
                    assignments.append({"keys": affected, "value": " ".join(match.group(2).split())})
        if assignments:
            result[path.relative_to(root).as_posix()] = assignments
    return result


def _check_context(context, target):
    for entries in context.values():
        for entry in entries:
            for key in entry["keys"]:
                if target.get(key) is not None and entry["value"] != target[key]:
                    _fail(f"其他 sysctl 配置与恢复目标 {key} 冲突，未执行")


class _Adapter:
    def __init__(self, root=Path("/")):
        self.root = Path(root)

    def _current(self, after):
        if self.capture() != after:
            _fail("当前配置或运行状态与该历史操作后的快照不一致，拒绝覆盖外部修改")

    def _verified(self, before):
        if self.capture() != before:
            _fail("恢复后的状态与目标快照不一致；请保留本次恢复记录并检查")

    def recovery_reason(self, before, after):
        if before == after:
            return None
        try:
            self._validate(before)
            self._validate(after)
        except (backup.BackupFailure, ValueError, TypeError, KeyError, AttributeError, UnicodeError) as exc:
            return str(exc)
        if "context" in before and before.get("context") != after.get("context"):
            return "原操作期间其他 sysctl 配置已变化，只保留备份供人工检查"
        return None

    def _ready(self, before, after):
        self._current(after)
        reason = self.recovery_reason(before, after)
        if reason:
            _fail(reason)
        return before != after


class BBRAdapter(_Adapter):
    paths = ("etc/sysctl.d/90-vps-script.conf", "etc/modules-load.d/vps-script-bbr.conf",
             "var/lib/vps-script/bbr-state.json")
    scope = "BBR/fq 运行值和本项目三个配置/状态文件"
    limitations = "不会卸载已加载的内核模块，不恢复接口当前 qdisc 或其他 sysctl 文件。"

    def __init__(self, root=Path("/"), manager=None):
        super().__init__(root)
        self.manager = manager or bbr.BBRManager(self.root)

    def capture(self):
        return {"files": backup.snapshot_files(self.root, self.paths), "live": self.manager.read_live(),
                "context": _sysctl_context(self.root, bbr.TARGET, self.paths[0])}

    def _validate(self, snapshot):
        files = _files(snapshot, self.paths)
        live = snapshot.get("live")
        if (not isinstance(live, dict) or set(live) != set(bbr.TARGET)
                or any(not isinstance(value, str) or not bbr.VALUE_RE.fullmatch(value) for value in live.values())):
            _fail("BBR 历史运行值无效")
        for path, content in ((self.paths[0], bbr.CONFIG), (self.paths[1], bbr.MODULES)):
            if files[path] is not None and files[path] != content:
                _fail("BBR 历史文件不是项目标准配置，只保留备份供人工检查")
        if files[self.paths[2]] is not None:
            state = json.loads(files[self.paths[2]])
            old = state.get("before")
            if (state.get("schema") != 1 or not isinstance(old, dict) or set(old) != set(bbr.TARGET)
                    or any(not isinstance(value, str) or not bbr.VALUE_RE.fullmatch(value) for value in old.values())):
                _fail("BBR 历史状态文件无效")
        elif files[self.paths[0]] is not None:
            _fail("BBR 配置缺少对应项目状态，只保留备份供人工检查")

    def restore(self, before, after):
        with self.manager.locked():
            if not self._ready(before, after):
                return "BBR 状态没有变化，无需恢复。"
            _check_context(_sysctl_context(self.root, bbr.TARGET, self.paths[0]), before["live"])
            if before["live"][bbr.TCP] not in self.manager.available():
                _fail("历史 TCP 算法当前不可用；不会为了恢复自动加载内核模块")
            for key in bbr.TARGET:
                if before["live"][key] != after["live"][key]:
                    self.manager.write_live(key, before["live"][key])
            backup.restore_files(self.root, before["files"], after["files"], self.paths)
            self._verified(before)
            return "已恢复所选操作前的 BBR/fq 值与项目文件；已加载模块不会卸载。"


TUNING_KEYS = tuple(sorted(set(tuning.CONSERVATIVE) | set(tuning.PROXY) | set(tuning.BUFFER_QUEUE)
                           | set(tuning.buffer_values(1024 * 1024))
                           | {"net.ipv4.tcp_fastopen", "net.netfilter.nf_conntrack_max"}))


class TuningAdapter(_Adapter):
    paths = ("etc/sysctl.d/91-vps-script-tuning.conf", "var/lib/vps-script/tuning-state.json")
    scope = "本项目支持的固定 sysctl 参数及调优配置/状态文件"
    limitations = "不重算历史带宽缓冲区，不恢复其他 sysctl 文件、内核或实际网络性能。"

    def __init__(self, root=Path("/"), manager=None):
        super().__init__(root)
        self.manager = manager or tuning.TuningManager(self.root)

    def capture(self):
        live = {}
        for key in TUNING_KEYS:
            try:
                live[key] = self.manager._sysctl(key)
            except tuning.TuningFailure:
                # An optional kernel key may genuinely be absent. A failure to
                # read an existing key must not discard its pre-change value.
                try:
                    (self.root / "proc/sys" / key.replace(".", "/")).stat()
                except FileNotFoundError:
                    live[key] = None
                else:
                    raise
        return {"files": backup.snapshot_files(self.root, self.paths), "live": live,
                "context": _sysctl_context(self.root, TUNING_KEYS, self.paths[0])}

    def _validate(self, snapshot):
        files = _files(snapshot, self.paths)
        live = snapshot.get("live")
        if not isinstance(live, dict) or set(live) != set(TUNING_KEYS):
            _fail("调优历史参数不符合固定白名单")
        if any(value is not None and (not isinstance(value, str) or not tuning.VALUE_RE.fullmatch(value))
               for value in live.values()):
            _fail("调优历史参数值无效")
        state_bytes = files[self.paths[1]]
        if state_bytes is None:
            if files[self.paths[0]] is not None:
                _fail("调优配置缺少对应项目状态，只保留备份供人工检查")
            return
        state = json.loads(state_bytes)
        target, original = state.get("target"), state.get("before")
        if (state.get("schema") != 1 or state.get("profile") not in tuning.PROFILES
                or not isinstance(target, dict) or not isinstance(original, dict)
                or not target or set(target) != set(original) or not set(target).issubset(TUNING_KEYS)):
            _fail("调优历史状态不符合固定白名单")
        if any(not isinstance(value, str) or not tuning.VALUE_RE.fullmatch(value)
               for value in (*target.values(), *original.values())):
            _fail("调优历史状态包含无效值")
        expected = self.manager._render(state["profile"], target)
        if files[self.paths[0]] is not None and files[self.paths[0]] != expected:
            _fail("调优历史配置与项目状态不匹配")

    def recovery_reason(self, before, after):
        reason = super().recovery_reason(before, after)
        if reason or before == after:
            return reason
        if any((before["live"][key] is None) != (after["live"][key] is None) for key in TUNING_KEYS):
            return "调优参数可读性发生变化，无法自动恢复未知的运行值"
        return None

    def restore(self, before, after):
        with self.manager.files.locked():
            if not self._ready(before, after):
                return "调优状态没有变化，无需恢复。"
            _check_context(_sysctl_context(self.root, TUNING_KEYS, self.paths[0]), before["live"])
            for key in reversed(TUNING_KEYS):
                if before["live"][key] != after["live"][key]:
                    self.manager._write(key, before["live"][key])
            backup.restore_files(self.root, before["files"], after["files"], self.paths)
            self._verified(before)
            return "已恢复所选操作前的调优运行值和项目文件。"


class Hy2Adapter(_Adapter):
    paths = ("etc/vps-script/hy2.nft", "etc/systemd/system/vps-script-hy2.service",
             "var/lib/vps-script/hy2-state.json")
    scope = "本项目 Hy2 NAT 表、固定服务和三个项目文件"
    limitations = "只自动恢复完整活动配置与未配置状态；UFW 放行是独立历史，不恢复云防火墙或客户端。"

    def __init__(self, root=Path("/"), manager=None):
        super().__init__(root)
        self.manager = manager or hy2.Hy2Manager(self.root)

    def capture(self):
        nft, systemctl = self.manager.command("nft"), self.manager.command("systemctl")
        document = self.manager.ruleset(nft)
        if not isinstance(document.get("nftables"), list):
            _fail("无法读取 nftables 规则集")
        families = {entry["table"].get("family") for entry in document["nftables"]
                    if isinstance(entry, dict) and isinstance(entry.get("table"), dict)
                    and entry["table"].get("name") == hy2.TABLE}
        if not families.issubset({"ip", "ip6"}):
            _fail("同名 Hy2 表出现未知地址族")
        active = self.manager.run((systemctl, "is-active", hy2.UNIT_NAME), check=False)
        enabled = self.manager.run((systemctl, "is-enabled", hy2.UNIT_NAME), check=False)
        if active.returncode == 0 and active.stdout.strip() == "active":
            service = "active"
        elif active.returncode in (3, 4) and active.stdout.strip() in ("inactive", "failed", "unknown"):
            service = "inactive" if active.stdout.strip() == "unknown" and not self.manager.unit.exists() else active.stdout.strip()
        else:
            _fail("无法确认项目 Hy2 服务状态")
        if enabled.returncode == 0 and enabled.stdout.strip() == "enabled":
            boot = True
        elif enabled.returncode in (1, 4) and (enabled.stdout.strip() in ("disabled", "not-found")
                                              or (not self.manager.unit.exists() and enabled.returncode == 4)):
            boot = False
        else:
            _fail("无法确认项目 Hy2 开机状态")
        return {"files": backup.snapshot_files(self.root, self.paths), "service": service, "enabled": boot,
                "tables": {family: self.manager.table_digest(nft, family) for family in sorted(families)}}

    def _spec(self, snapshot):
        files = _files(snapshot, self.paths)
        if all(value is None for value in files.values()):
            if snapshot.get("tables") or snapshot.get("enabled") is not False or snapshot.get("service") != "inactive":
                _fail("Hy2 无文件但运行状态仍存在，不能自动猜测恢复")
            return None
        if any(value is None for value in files.values()):
            _fail("Hy2 项目文件不完整，只保留备份供人工检查")
        data = json.loads(files[self.paths[2]])
        spec = hy2.HopSpec(data["interface"], data["start"], data["end"], data["target"], tuple(data["families"]))
        spec.validate()
        if (data.get("schema") != 1 or files[self.paths[0]] != hy2.nft_config(spec)
                or files[self.paths[1]] != hy2.service_unit(spec, data["nft"])
                or data.get("fingerprints") != snapshot.get("tables")
                or set(snapshot["tables"]) != set(spec.families)
                or snapshot.get("service") != "active" or snapshot.get("enabled") is not True):
            _fail("Hy2 不是可完整恢复的项目活动状态")
        return spec

    def _validate(self, snapshot):
        self._spec(snapshot)

    def recovery_reason(self, before, after):
        try:
            reason = super().recovery_reason(before, after)
            if reason or before == after:
                return reason
            if self._spec(before) is not None and self._spec(after) is not None:
                return "两个活动 Hy2 配置之间不支持直接替换；请先独立移除并检查"
            return None
        except hy2.Hy2Failure as exc:
            return str(exc)

    def restore(self, before, after):
        if not self._ready(before, after):
            return "Hy2 状态没有变化，无需恢复。"
        previous, current = self._spec(before), self._spec(after)
        if previous is not None and current is not None:
            _fail("两个活动 Hy2 配置之间不支持直接替换；请先独立移除并检查")
        if previous is None:
            self.manager.remove()
        else:
            saved_nft = json.loads(_files(before, self.paths)[self.paths[2]])["nft"]
            if self.manager.command("nft") != saved_nft:
                _fail("nft 程序路径已变化，不能安全恢复旧的开机服务")
            self.manager.apply(previous)
            actual = self.capture()
            if actual["tables"] != before["tables"] or actual["service"] != "active" or actual["enabled"] is not True:
                _fail("重建 Hy2 后的规则或服务与历史配置不一致")
            # Re-created files must be canonical before restoring saved metadata.
            actual_spec = self._spec(actual)
            if actual_spec != previous:
                _fail("重建 Hy2 配置与目标不一致")
            backup.restore_files(self.root, before["files"], actual["files"], self.paths)
        self._verified(before)
        return "已恢复所选操作前的项目 Hy2 转发；UFW 和云防火墙未改动。"


class SwapAdapter(_Adapter):
    paths = ("etc/fstab",)
    scope = "项目 swap 的配置、大小及启用状态；fstab 只回退本次项目变更"
    limitations = "不保存交换数据；仅自动恢复完整活动项目 swap 与未配置状态，不处理其他 swap 或异常条目。"

    def __init__(self, root=Path("/"), manager=None):
        super().__init__(root)
        self.manager = manager or swap.SwapManager(self.root)

    def capture(self):
        # Do not use status()'s empty fallback if /proc/swaps cannot be read.
        text = self.manager.proc_swaps.read_text(encoding="ascii")
        if not text.splitlines() or text.splitlines()[0].split() != ["Filename", "Type", "Size", "Used", "Priority"]:
            _fail("无法确认 /proc/swaps 的完整状态")
        entries = swap.parse_swaps(text)
        own = {swap.SWAP_PATH, str(self.manager.swap)}
        active = next((size for path, size in entries if path in own), None)
        info = None
        if os.path.lexists(self.manager.swap):
            value = self.manager.swap.lstat()
            if not stat.S_ISREG(value.st_mode):
                _fail("项目 swap 路径不是普通文件；不会读取或备份其内容")
            info = {"bytes": value.st_size, "mode": stat.S_IMODE(value.st_mode), "uid": value.st_uid, "gid": value.st_gid}
        return {"files": backup.snapshot_files(self.root, self.paths), "swap": info, "active_bytes": active,
                "other_swaps": [[path, size] for path, size in entries if path not in own]}

    def _validate(self, snapshot):
        files = _files(snapshot, self.paths)
        if files[self.paths[0]] is None:
            _fail("没有 fstab 备份，无法自动恢复 swap")
        text = files[self.paths[0]].decode("utf-8")
        if snapshot.get("other_swaps"):
            _fail("存在其他 swap，只保留备份供人工检查")
        info = snapshot.get("swap")
        if info is None:
            if snapshot.get("active_bytes") is not None or swap.SWAP_PATH in text:
                _fail("未配置 swap 的文件、启用状态与 fstab 不一致")
            return
        if (not isinstance(info, dict) or set(info) != {"bytes", "mode", "uid", "gid"}
                or type(info["bytes"]) is not int or info["bytes"] % (1024 * 1024)
                or not swap.MIN_MB <= info["bytes"] // (1024 * 1024) <= swap.MAX_MB
                or info["mode"] != 0o600 or info["uid"] != os.geteuid()
                or type(info["gid"]) is not int or not 0 <= info["gid"] < 2**32
                or type(snapshot.get("active_bytes")) is not int
                or not 0 < snapshot["active_bytes"] <= info["bytes"]
                or len(swap._fstab_managed_lines(text)) != 1):
            _fail("只支持恢复大小合法、权限 0600、带独立标记且处于活动状态的项目 swap")

    def recovery_reason(self, before, after):
        reason = super().recovery_reason(before, after)
        if reason or before == after:
            return reason
        if before["swap"] is not None and after["swap"] is not None:
            return "两个活动 swap 配置之间不支持直接替换"
        return None

    def restore(self, before, after):
        if not self._ready(before, after):
            return "Swap 状态没有变化，无需恢复。"
        after_files = _files(after, self.paths)
        if before["swap"] is not None and after["swap"] is not None:
            _fail("两个活动 swap 配置之间不支持直接替换")
        after_text = after_files[self.paths[0]].decode("utf-8")
        if before["swap"] is None:
            self.manager.remove()
            expected_text = swap._without_managed_fstab_lines(after_text)
        else:
            self.manager.create(before["swap"]["bytes"] // (1024 * 1024))
            expected_text = after_text + ("\n" if after_text and not after_text.endswith("\n") else "") + swap.FSTAB_LINE
        actual = self.capture()
        if backup.decode_file(actual["files"][self.paths[0]]) != expected_text.encode("utf-8"):
            _fail("恢复期间 fstab 出现其他修改，拒绝覆盖")
        backup.restore_files(self.root, before["files"], actual["files"], self.paths)
        self._verified(before)
        return "已恢复项目 swap 的配置与启用状态；交换数据未备份或恢复。"


class TimezoneAdapter(_Adapter):
    scope = "timedatectl 确认的有效时区"
    limitations = "恢复时区语义，不复制 /etc/localtime，不恢复时钟、NTP 或文件布局。"

    def capture(self):
        command = checks.find_command("timedatectl")
        if not command:
            _fail("未找到 timedatectl，无法备份有效时区")
        result = common._run((command, "show", "--property=Timezone", "--value"), timeout=5)
        value = result.stdout.strip()
        if result.returncode != 0 or not common.TIMEZONE_RE.fullmatch(value):
            _fail("无法确认有效时区；不会用配置文件猜测备份")
        return {"timezone": value}

    def _validate(self, snapshot):
        if set(snapshot) != {"timezone"} or not isinstance(snapshot["timezone"], str) or not common.TIMEZONE_RE.fullmatch(snapshot["timezone"]):
            _fail("历史时区值无效")

    def restore(self, before, after):
        if not self._ready(before, after):
            return "时区没有变化，无需恢复。"
        common.set_timezone(before["timezone"])
        self._verified(before)
        return "已恢复所选操作前的有效时区；未改动时钟或 NTP 设置。"


def get_adapter(module, root=Path("/")):
    adapters = {"bbr": BBRAdapter, "tuning": TuningAdapter, "hy2": Hy2Adapter,
                "swap": SwapAdapter, "timezone": TimezoneAdapter}
    if module not in adapters:
        _fail(f"没有对应的网络/系统备份适配器：{module}")
    return adapters[module](root)
