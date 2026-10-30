"""Bounded local change journal and fixed-adapter recovery; never a system image.

Snapshots contain only adapter-selected configuration, not arbitrary commands or
paths supplied by a record. Browsing never creates storage or runs collectors.
"""

import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import tempfile

from . import __version__

MAX_FILE_BYTES = 256 * 1024
MAX_RECORD_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_RECORDS = 100
ID_RE = re.compile(r"^[0-9a-f]{32}$")
MODULES = frozenset(("ssh", "ufw", "fail2ban", "bbr", "tuning", "hy2", "swap", "timezone",
                     "packages", "panel", "external"))
STATES = {
    "prepared": "已备份，尚未开始", "running": "执行中或中断后结果待核实",
    "completed": "命令完成（业务仍需验证）", "no_change": "未发现状态变化",
    "failed": "执行失败，需检查", "interrupted": "执行中断，需检查",
    "restored": "已有完成的恢复记录", "invalid": "记录损坏或不可读取",
}
DETAIL_KEYS = frozenset(("version", "script_sha256", "source", "action", "external_snapshot",
                         "limitation", "source_record"))


class BackupFailure(RuntimeError):
    pass


def _now():
    return datetime.now(timezone.utc).isoformat()


def _json(data):
    try:
        return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise BackupFailure("备份数据不能安全序列化") from exc


def _owner(root):
    return 0 if Path(root) == Path("/") else os.geteuid()


def _directories(root, directory, *, create=False, mode=0o700):
    root, directory = Path(root).absolute(), Path(directory).absolute()
    try:
        relative = directory.relative_to(root)
    except ValueError as exc:
        raise BackupFailure("路径不在允许的根目录内") from exc
    if ".." in relative.parts:
        raise BackupFailure("目录含非法路径")
    current = root
    for part in (None, *relative.parts):
        if part is not None:
            current /= part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            if not create:
                return False
            os.mkdir(current, mode)
            # A durable record also requires every newly created directory
            # entry to survive a crash, not only the final record.json fsync.
            _fsync_directory(current.parent)
            _fsync_directory(current)
            info = os.lstat(current)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != _owner(root)
                or info.st_mode & 0o022):
            raise BackupFailure(f"目录不可信或可被其他用户写入：{current}")
    return True


def _relative_path(name):
    if not isinstance(name, str) or not name or "\\" in name:
        raise BackupFailure("备份路径无效")
    path = PurePosixPath(name)
    if path.is_absolute() or any(p in (".", "..") for p in path.parts) or str(path) != name:
        raise BackupFailure("备份路径必须是明确的相对路径")
    return path


def _read(path, root, limit, *, private=False):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as file:
            info = os.fstat(file.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != _owner(root) or info.st_mode & 0o7022
                    or (private and info.st_mode & 0o077)):
                raise BackupFailure(f"不是可信的普通文件：{path}")
            data = file.read(limit + 1)
            final = os.fstat(file.fileno())
            if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
                    final.st_size, final.st_mtime_ns, final.st_ctime_ns):
                raise BackupFailure("读取备份时文件发生变化")
        if len(data) > limit:
            raise BackupFailure(f"文件超过备份大小限制：{path}")
        return data, info
    except OSError as exc:
        raise BackupFailure(f"无法安全读取文件：{path}（{type(exc).__name__}）") from exc


def decode_file(snapshot):
    if not isinstance(snapshot, dict) or type(snapshot.get("exists")) is not bool:
        raise BackupFailure("文件快照格式无效")
    if snapshot == {"exists": False}:
        return None
    if set(snapshot) != {"exists", "data", "sha256", "mode", "uid", "gid"} or not snapshot["exists"]:
        raise BackupFailure("文件快照字段无效")
    if (any(type(snapshot[key]) is not int for key in ("mode", "uid", "gid"))
            or not 0 <= snapshot["mode"] <= 0o777 or snapshot["mode"] & 0o022
            or any(not 0 <= snapshot[key] < 2**32 for key in ("uid", "gid"))
            or not isinstance(snapshot["data"], str) or len(snapshot["data"]) > (MAX_FILE_BYTES + 2) // 3 * 4
            or not isinstance(snapshot["sha256"], str)):
        raise BackupFailure("文件快照元数据无效")
    try:
        data = base64.b64decode(snapshot["data"], validate=True)
    except (ValueError, UnicodeError) as exc:
        raise BackupFailure("文件快照编码无效") from exc
    if len(data) > MAX_FILE_BYTES or hashlib.sha256(data).hexdigest() != snapshot["sha256"]:
        raise BackupFailure("文件快照摘要不匹配或过大")
    return data


def snapshot_files(root, paths):
    root = Path(root).absolute()
    snapshots = {}
    for name in paths:
        relative = _relative_path(name)
        path = root / relative
        if not _directories(root, path.parent) or not os.path.lexists(path):
            snapshots[name] = {"exists": False}
            continue
        data, info = _read(path, root, MAX_FILE_BYTES)
        snapshots[name] = {"exists": True, "data": base64.b64encode(data).decode("ascii"),
                           "sha256": hashlib.sha256(data).hexdigest(), "mode": stat.S_IMODE(info.st_mode),
                           "uid": info.st_uid, "gid": info.st_gid}
    return snapshots


def _fsync_directory(directory):
    fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic(path, data, mode=0o600, *, owner=None, create=False):
    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".vps-backup-", dir=str(path.parent))
        with os.fdopen(fd, "wb") as file:
            if owner is not None:
                os.fchown(file.fileno(), *owner)
            os.fchmod(file.fileno(), mode)
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        if create:
            os.link(temporary, path)
            os.unlink(temporary)
        else:
            os.replace(temporary, path)
        temporary = None
        _fsync_directory(path.parent)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def restore_files(root, before_files, after_files, paths):
    """Only restore fixed adapter paths, never paths selected by saved data."""
    root, paths = Path(root).absolute(), tuple(paths)
    if not isinstance(before_files, dict) or not isinstance(after_files, dict):
        raise BackupFailure("文件快照集合无效")
    if set(before_files) != set(paths) or set(after_files) != set(paths):
        raise BackupFailure("文件快照超出模块允许范围")
    for name in paths:
        _relative_path(name)
        decode_file(after_files[name])
        decode_file(before_files[name])
        if before_files[name]["exists"] and before_files[name]["uid"] != _owner(root):
            raise BackupFailure("拒绝恢复非预期属主的配置")
    if snapshot_files(root, paths) != after_files:
        raise BackupFailure("当前文件已被后续操作修改，拒绝覆盖")
    for name in paths:
        if before_files[name] == after_files[name]:
            continue
        path = root / name
        _directories(root, path.parent, create=True, mode=0o755)
        if snapshot_files(root, (name,))[name] != after_files[name]:
            raise BackupFailure("恢复期间文件发生变化，已停止")
        data = decode_file(before_files[name])
        if data is None:
            os.unlink(path)
            _fsync_directory(path.parent)
        else:
            saved = before_files[name]
            _atomic(path, data, saved["mode"], owner=(saved["uid"], saved["gid"]),
                    create=not after_files[name]["exists"])
    if snapshot_files(root, paths) != before_files:
        raise BackupFailure("文件恢复后的校验不一致；请保留历史记录")


def _text(value, limit=220):
    text = " ".join("".join(char if char.isprintable() else " " for char in str(value)).split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _details(value):
    if value is None:
        return {}
    if not isinstance(value, dict) or not set(value) <= DETAIL_KEYS:
        raise BackupFailure("记录附加字段不在允许范围内")
    if any(type(v) not in (str, int, bool) or len(str(v)) > 300 for v in value.values()):
        raise BackupFailure("记录附加字段无效或过长")
    return dict(value)


class Store:
    def __init__(self, root=Path("/")):
        self.root = Path(root).absolute()
        self.directory = self.root / "var/lib/vps-script/backups"

    def _base(self, create=False):
        if not _directories(self.root, self.directory, create=create):
            return False
        if os.lstat(self.directory).st_mode & 0o077:
            raise BackupFailure("备份目录必须仅属主可访问（0700）")
        return True

    def _path(self, identifier):
        if not isinstance(identifier, str) or not ID_RE.fullmatch(identifier):
            raise BackupFailure("记录 ID 无效；不能输入文件路径")
        return self.directory / identifier

    @contextmanager
    def locked(self):
        self._base(create=True)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(self.directory / ".lock", flags, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != _owner(self.root) or info.st_mode & 0o077):
                raise BackupFailure("备份操作锁不可信")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise BackupFailure("另一个配置变更或恢复正在运行，请稍后再试") from exc
            yield
        finally:
            os.close(fd)

    def _usage(self):
        count, size = 0, 0
        for entry in self.directory.iterdir():
            if entry.name == ".lock":
                continue
            if not ID_RE.fullmatch(entry.name):
                raise BackupFailure("备份目录含未知内容，请先人工检查")
            if not _directories(self.root, entry) or os.lstat(entry).st_mode & 0o077:
                raise BackupFailure("备份记录目录不可信")
            count += 1
            for item in entry.iterdir():
                if item.name != "record.json":
                    raise BackupFailure("发现未完成写入材料，请先检查；不会自动删除")
                data, _ = _read(item, self.root, MAX_RECORD_BYTES, private=True)
                size += len(data)
        return count, size

    def _capacity(self):
        count, size = self._usage()
        if count >= MAX_RECORDS or size + MAX_RECORD_BYTES > MAX_TOTAL_BYTES:
            raise BackupFailure("备份记录达到容量限制；先查看并明确删除不再需要的已完成记录")

    def _write(self, record, *, create=False):
        _validate_record(record)
        encoded = _json(record)
        envelope = _json({"sha256": hashlib.sha256(encoded).hexdigest(), "record": record}) + b"\n"
        if len(envelope) > MAX_RECORD_BYTES:
            raise BackupFailure("单条备份记录超过 2 MiB；未覆盖旧记录")
        directory = self._path(record["id"])
        if create:
            os.mkdir(directory, 0o700)
            _fsync_directory(self.directory)
        if not _directories(self.root, directory) or os.lstat(directory).st_mode & 0o077:
            raise BackupFailure("备份记录目录不可信")
        target = directory / "record.json"
        if not create:
            _read(target, self.root, MAX_RECORD_BYTES, private=True)
        _atomic(target, envelope, create=create)

    def read(self, identifier):
        directory = self._path(identifier)
        if not self._base() or not _directories(self.root, directory):
            raise BackupFailure("未找到该备份记录")
        if os.lstat(directory).st_mode & 0o077:
            raise BackupFailure("备份记录目录权限过宽")
        data, _ = _read(directory / "record.json", self.root, MAX_RECORD_BYTES, private=True)
        try:
            envelope = json.loads(data)
            if (not isinstance(envelope, dict) or set(envelope) != {"sha256", "record"}
                    or hashlib.sha256(_json(envelope["record"])).hexdigest() != envelope["sha256"]):
                raise BackupFailure("记录摘要不匹配")
            record = envelope["record"]
            _validate_record(record)
            if record["id"] != identifier:
                raise BackupFailure("目录和记录 ID 不一致")
            return record
        except (ValueError, TypeError, KeyError, RecursionError) as exc:
            raise BackupFailure("备份记录格式损坏") from exc

    def list(self):
        if not self._base():
            return []
        entries = sorted(self.directory.iterdir(), key=lambda path: path.name)
        if len(entries) > MAX_RECORDS + 1:
            raise BackupFailure("目录条目超过限制，请先人工检查")
        rows = []
        for entry in entries:
            if entry.name == ".lock":
                continue
            if not ID_RE.fullmatch(entry.name):
                raise BackupFailure("备份目录含未知条目，请先人工检查")
            try:
                rows.append(public_record(self.read(entry.name)))
            except BackupFailure:
                rows.append({"id": entry.name, "state": "invalid", "module": "未知",
                             "action": "记录损坏或权限异常", "created_at": "未知",
                             "restore_supported": False, "reason": "需人工检查；未执行恢复"})
        return sorted(rows, key=lambda row: (row["created_at"], row["id"]), reverse=True)

    def delete(self, identifier):
        with self.locked():
            record = self.read(identifier)
            if record["state"] not in ("completed", "no_change", "restored"):
                raise BackupFailure("失败、中断或未完成记录不能通过菜单删除，请先人工核查")
            directory = self._path(identifier)
            if {path.name for path in directory.iterdir()} != {"record.json"}:
                raise BackupFailure("记录目录含其他材料，拒绝删除")
            os.unlink(directory / "record.json")
            os.rmdir(directory)
            _fsync_directory(self.directory)


def _validate_record(record):
    fields = {"schema", "id", "module", "action", "created_at", "updated_at", "version", "state",
              "scope", "limitations", "restore_supported", "reason", "details", "before", "after",
              "restores", "restored_by", "error_type"}
    if not isinstance(record, dict) or set(record) != fields or type(record["schema"]) is not int or record["schema"] != 1:
        raise BackupFailure("未知或损坏的备份记录 schema")
    if (not isinstance(record["id"], str) or not ID_RE.fullmatch(record["id"])
            or record["module"] not in MODULES or record["state"] not in STATES
            or type(record["restore_supported"]) is not bool
            or not isinstance(record["before"], dict)
            or (record["after"] is not None and not isinstance(record["after"], dict))):
        raise BackupFailure("备份记录字段无效")
    for key in ("action", "created_at", "updated_at", "version", "scope", "limitations", "reason", "error_type"):
        if not isinstance(record[key], str) or len(record[key]) > 1000:
            raise BackupFailure("备份记录文本字段无效")
    for key in ("restores", "restored_by"):
        if record[key] is not None and (not isinstance(record[key], str) or not ID_RE.fullmatch(record[key])):
            raise BackupFailure("恢复关联记录 ID 无效")
    _details(record["details"])


class _ExternalAdapter:
    scope = "操作记录；不包含可用于完整撤销安装/升级的系统备份"
    limitations = "需要服务商快照或人工恢复；本工具未核实外部快照是否存在或可恢复。"

    def capture(self):
        return {"kind": "external_snapshot_required"}

    def recovery_reason(self, before, after):
        return self.limitations


def get_adapter(module, root=Path("/")):
    if module in ("packages", "panel", "external"):
        return _ExternalAdapter()
    if module in ("ssh", "ufw", "fail2ban"):
        from . import backup_access
        return backup_access.get_adapter(module, root=root)
    if module in ("bbr", "tuning", "hy2", "swap", "timezone"):
        from . import backup_network
        return backup_network.get_adapter(module, root=root)
    raise BackupFailure("该模块没有受支持的备份适配器")


def _capture(adapter):
    captured = adapter.capture()
    if not isinstance(captured, dict) or len(_json(captured)) > MAX_RECORD_BYTES // 2 - 8192:
        raise BackupFailure("备份快照无效或超过大小限制")
    # Detach from mutable adapter state before invoking the operation.
    return json.loads(_json(captured))


def _execute_locked(store, module, action, operation, adapter, details, restore_supported, restores=None):
    if module not in MODULES or not isinstance(action, str) or not 1 <= len(action) <= 120:
        raise BackupFailure("备份操作名称无效")
    details = _details(details)
    store._capacity()
    before = _capture(adapter)
    identifier, timestamp = secrets.token_hex(16), _now()
    record = {"schema": 1, "id": identifier, "module": module, "action": action,
              "created_at": timestamp, "updated_at": timestamp, "version": __version__, "state": "prepared",
              "scope": str(getattr(adapter, "scope", "本项目管理的配置和运行参数")),
              "limitations": str(getattr(adapter, "limitations", "不包含整机、应用数据或云防火墙。")),
              "restore_supported": False, "reason": "操作尚未完成，暂不能自动恢复", "details": details,
              "before": before, "after": None, "restores": restores, "restored_by": None, "error_type": ""}
    store._write(record, create=True)
    record["state"] = "running"
    record["updated_at"] = _now()
    store._write(record)
    print(f"变更前记录已保存：{identifier}；范围：{record['scope']}")
    try:
        # Persisting the record can take time. Do not operate on a stale before
        # snapshot if another administrator changed the managed state meanwhile.
        if _capture(adapter) != before:
            raise BackupFailure("写入备份期间当前状态发生变化，已停止执行修改")
        result = operation()
        code = result if type(result) is int else getattr(result, "returncode", 0)
        if code not in (0, None):
            raise BackupFailure(f"操作返回非零退出码 {code}；可能已部分执行")
        record["after"] = _capture(adapter)
        record["state"] = "completed"
        if not restore_supported:
            reason = details.get("limitation", "该操作只保留备份/执行记录，需要人工或外部快照恢复")
        else:
            reason = (adapter.recovery_reason(before, record["after"])
                      if hasattr(adapter, "recovery_reason") else None)
        # Audit-only adapters intentionally have identical before/after facts.
        if before == record["after"] and restore_supported:
            record["state"] = "no_change"
            reason = "未检测到受管理状态变化，无需恢复"
        record["restore_supported"] = record["state"] == "completed" and reason is None
        record["reason"] = str(reason or "可请求恢复；执行前仍需核对当前状态与恢复条件")
    except BaseException as exc:
        record["state"] = "interrupted" if not isinstance(exc, Exception) else "failed"
        record["error_type"] = type(exc).__name__
        record["reason"] = "结果未确认；先检查原模块的回退结果，保留材料供人工恢复"
        try:
            record["after"] = _capture(adapter)
        except Exception:
            record["after"] = None
        record["updated_at"] = _now()
        try:
            store._write(record)
        except Exception as write_error:
            raise BackupFailure(f"操作可能已部分执行，且历史更新失败（{type(write_error).__name__}）；"
                                f"请保留 {identifier} 的变更前备份，不要自动重试") from exc
        if not isinstance(exc, Exception):
            raise
        raise BackupFailure(f"操作未完成，记录 {identifier} 已保留：{exc}") from exc
    record["updated_at"] = _now()
    try:
        store._write(record)
    except Exception as exc:
        raise BackupFailure(f"操作已执行，但完成记录写入失败；请检查 {identifier}，不要重复执行") from exc
    print(f"记录 {identifier}：{STATES[record['state']]}；{record['reason']}")
    return result, record


def track(module, action, operation, *, adapter=None, details=None, restore_supported=True, store=None):
    store = store or Store()
    try:
        adapter = adapter or get_adapter(module, root=store.root)
        with store.locked():
            result, _ = _execute_locked(store, module, action, operation, adapter, details, restore_supported)
            return result
    except BackupFailure:
        raise
    except Exception as exc:
        raise BackupFailure(f"无法准备或完成备份事务（{type(exc).__name__}）：{exc}") from exc


def restore_record(identifier, *, store=None, adapter=None):
    """Low-level transaction; interactive entry does root/mode/TTY/confirmation."""
    store = store or Store()
    try:
        with store.locked():
            source = store.read(identifier)
            if source["state"] != "completed" or not source["restore_supported"] or source["after"] is None:
                raise BackupFailure("该记录不支持自动恢复：" + source["reason"])
            adapter = adapter or get_adapter(source["module"], root=store.root)
            current = _capture(adapter)
            if current != source["after"]:
                raise BackupFailure("当前配置/运行态与操作后快照不同；可能有后续变更，拒绝覆盖")
            reason = (adapter.recovery_reason(source["before"], source["after"])
                      if hasattr(adapter, "recovery_reason") else None)
            if reason:
                raise BackupFailure("当前版本不能自动恢复此记录：" + reason)
            result, restored = _execute_locked(
                store, source["module"], "restore:" + source["action"][:100],
                lambda: adapter.restore(source["before"], source["after"]), adapter,
                {"source_record": identifier}, True, restores=identifier)
            source["state"], source["restored_by"] = "restored", restored["id"]
            source["restore_supported"] = False
            source["reason"] = "已执行恢复；实际结果与范围见关联恢复记录"
            source["updated_at"] = _now()
            try:
                store._write(source)
            except Exception as exc:
                raise BackupFailure(f"恢复已执行且保存为 {restored['id']}，但原记录标记失败；不要重复恢复") from exc
            return result
    except BackupFailure:
        raise
    except Exception as exc:
        raise BackupFailure(f"恢复未完成（{type(exc).__name__}）：{exc}") from exc


def public_record(record, *, detail=False):
    """A redacted view; never include config bytes, commands, or error stdout."""
    keys = ("id", "module", "action", "created_at", "updated_at", "version", "state", "scope",
            "limitations", "restore_supported", "reason", "restores", "restored_by", "error_type")
    output = {key: record[key] for key in keys}
    if detail:
        output["details"] = dict(record["details"])
        output["snapshots"] = {
            stage: {"available": record[stage] is not None,
                    "bytes": len(_json(record[stage])) if record[stage] is not None else 0,
                    "sha256": hashlib.sha256(_json(record[stage])).hexdigest() if record[stage] is not None else None}
            for stage in ("before", "after")}
    return output


def history(identifier=None, *, store=None):
    store = store or Store()
    return {"schema": 1, "storage": str(store.directory),
            "records": [public_record(store.read(identifier), detail=True)] if identifier else store.list()}


def render_history(payload):
    lines = ["变更备份与恢复记录（仅本机；不代表整机快照）"]
    if not payload["records"]:
        return "\n".join(lines + ["暂无记录。只读查看不会创建备份目录。"])
    for record in payload["records"]:
        ability = "可请求恢复" if record["restore_supported"] else "不可自动恢复"
        lines.extend((f"\n{record['id']}  {_text(record['created_at'], 40)}",
                      f"{_text(record['module'], 30)} / {_text(record['action'], 120)} · {STATES[record['state']]} · {ability}",
                      _text(record.get("reason", ""), 300)))
        if "snapshots" in record:
            lines.append("范围：" + _text(record.get("scope", ""), 500))
            lines.append("限制：" + _text(record.get("limitations", ""), 500))
            for stage, label in (("before", "操作前"), ("after", "操作后")):
                snapshot = record["snapshots"][stage]
                lines.append(f"{label}：" + (f"{snapshot['bytes']} bytes / SHA-256 {snapshot['sha256']}"
                                            if snapshot["available"] else "未取得完整快照"))
            if record.get("restored_by"):
                lines.append("恢复记录：" + record["restored_by"])
            if record.get("restores"):
                lines.append("恢复来源：" + record["restores"])
            for key, value in record.get("details", {}).items():
                lines.append(f"{_text(key, 30)}：{_text(value, 300)}")
    lines.append("完整备份仅 root 可读；终端/JSON 不输出配置正文。")
    return "\n".join(lines)


def confirm_external_snapshot():
    print("此操作不能通过本工具完整撤销。请先准备服务商快照或独立备份及恢复方式。")
    print("输入 SNAPSHOT 仅记录你的声明，本工具不会核实外部快照是否存在或可恢复。")
    try:
        return input("已准备可用备份后输入 SNAPSHOT，其他内容取消：").strip() == "SNAPSHOT"
    except EOFError:
        return False


def restore(identifier, experimental=False):
    from . import packages
    error = packages.preflight(experimental)
    if error:
        print("未执行恢复：" + error)
        return 2
    try:
        record = Store().read(identifier)
        print(render_history({"records": [public_record(record, detail=True)]}))
        if not record["restore_supported"] or record["state"] != "completed":
            raise BackupFailure("此记录不可自动恢复：" + record["reason"])
        print("恢复会改变当前系统配置，可能重新启用历史认证/防护策略；SSH 仍需第二会话验证。")
        if input(f"输入 RESTORE {identifier} 继续：").strip() != f"RESTORE {identifier}":
            print("已取消。")
            return 0
        print(restore_record(identifier))
        if record["module"] == "ssh":
            # Separate transaction after releasing the global journal lock.
            from . import fail2ban
            if fail2ban.refresh_ports() != 0:
                print("SSH 恢复命令完成，但 Fail2ban 端口刷新未完成；请检查其独立记录和实际防护范围。")
        return 0
    except EOFError:
        print("已取消。")
        return 0
    except (BackupFailure, OSError) as exc:
        print(f"恢复未完成：{exc}")
        return 1


def delete(identifier, experimental=False):
    from . import packages
    error = packages.preflight(experimental)
    if error:
        print("未删除记录：" + error)
        return 2
    try:
        store = Store()
        print(render_history({"records": [public_record(store.read(identifier), detail=True)]}))
        print("删除后不能再用这条记录恢复；不会修改对应系统配置。失败/未完成记录不在此清理。")
        if input(f"输入 DELETE {identifier} 确认永久删除：").strip() != f"DELETE {identifier}":
            print("已取消。")
            return 0
        store.delete(identifier)
        print("该记录已删除。")
        return 0
    except EOFError:
        print("已取消。")
        return 0
    except (BackupFailure, OSError) as exc:
        print(f"记录未删除：{exc}")
        return 1
