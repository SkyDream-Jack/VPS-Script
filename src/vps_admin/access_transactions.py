"""Read-only gate for unfinished SSH/UFW rollback workers, including old copies."""

import os
from pathlib import Path
import re
import stat

from . import backup


def pending(root=Path("/")):
    root = Path(root)
    rows = []
    for module, started in (("ssh", "apply-started"), ("ufw", "enable-started")):
        parent = root / "var/lib/vps-script" / (module + "-transactions")
        try:
            parent.lstat()
        except FileNotFoundError:
            continue
        backup._directories(root, parent)
        entries = []
        with os.scandir(parent) as iterator:
            for entry in iterator:
                entries.append(entry.name)
                if len(entries) > 1024:
                    raise backup.BackupFailure("访问事务目录过大，无法确认所有回滚状态")
        for name in sorted(entries):
            if not re.fullmatch(r"[0-9a-f]{24}", name):
                raise backup.BackupFailure("访问事务目录含无法识别的条目")
            directory = parent / name
            backup._directories(root, directory)
            markers = set()
            for marker in ("confirmed", "rolled-back", "expired", started, "rollback-started"):
                path = directory / marker
                try:
                    info = path.lstat()
                except FileNotFoundError:
                    continue
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022
                        or info.st_uid != backup._owner(root)):
                    raise backup.BackupFailure("访问事务标记不安全，无法确认回滚状态")
                markers.add(marker)
            if "confirmed" in markers or "rolled-back" in markers:
                continue
            if "expired" in markers and started not in markers:
                continue
            rows.append({"module": module, "id": name,
                         "phase": "回退已开始但未完成" if "rollback-started" in markers else "尚未确认或回退"})
    return rows


def require_settled(root=Path("/"), failure=backup.BackupFailure):
    try:
        rows = pending(root)
    except (backup.BackupFailure, OSError) as exc:
        raise failure(f"无法确认旧访问事务是否结束：{exc}") from exc
    if rows:
        detail = "; ".join(f"{row['module']}:{row['id']} ({row['phase']})" for row in rows[:5])
        raise failure("存在未结束的 SSH/UFW 回滚事务，拒绝继续访问配置变更：" + detail
                      + "。请保留当前会话并等待原定时器；失败或重启后请从服务商控制台核实。"
                        "可用 audit 查看；不要删除事务标记来绕过检查。")
