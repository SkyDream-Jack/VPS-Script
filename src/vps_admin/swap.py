"""项目专属 swap 文件的管理。

只创建或删除固定路径的 ``/swapfile-vps-script``，并在 ``/etc/fstab``
中维护带标记的一行。不会修改已有 swap、其他 fstab 行或内核 swap 参数。
"""

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import shutil
import stat
import subprocess

from . import checks, packages

SWAP_PATH = "/swapfile-vps-script"
FSTAB_LINE = "/swapfile-vps-script none swap sw 0 0 # Managed by VPS-Script\n"
MARKER = "# Managed by VPS-Script"
MIN_MB = 256
MAX_MB = 8192


class SwapFailure(Exception):
    pass


def parse_swaps(text):
    """解析 /proc/swaps；返回 (路径, 大小字节) 列表。"""
    entries = []
    for line in text.splitlines():
        fields = line.split()
        if not fields or fields[0] == "Filename":
            continue
        if len(fields) < 3 or not fields[2].isdigit():
            raise SwapFailure("无法解析 /proc/swaps")
        entries.append((fields[0], int(fields[2]) * 1024))
    return tuple(entries)


def validate_size(size_mb):
    if type(size_mb) is not int or not MIN_MB <= size_mb <= MAX_MB:
        raise SwapFailure(f"swap 大小必须是 {MIN_MB}–{MAX_MB} MiB 的整数")
    return size_mb


def _fstab_managed_lines(text):
    return tuple(
        line for line in text.splitlines()
        if line.strip().endswith(MARKER) and SWAP_PATH in line.split()
    )


class SwapManager:
    def __init__(self, root=Path("/"), runner=None):
        self.root = Path(root)
        self.runner = runner or subprocess.run
        self.swap = self.root / SWAP_PATH.lstrip("/")
        self.fstab = self.root / "etc/fstab"
        self.proc_swaps = self.root / "proc/swaps"
        self.lock_path = self.root / "run/lock/vps-script-swap.lock"

    def _run(self, args, *, timeout=60):
        try:
            return self.runner(
                args, capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=timeout, check=False, env={"PATH": packages.SAFE_PATH, "LC_ALL": "C"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SwapFailure(f"无法运行 {args[0]}：{exc}") from exc

    def _require(self, args):
        result = self._run(args)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            raise SwapFailure(f"{args[0]} 返回 {result.returncode}：{detail}")
        return result

    @contextmanager
    def locked(self):
        try:
            fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except OSError as exc:
            raise SwapFailure(f"无法创建 swap 操作锁：{exc}") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or (self.root == Path("/") and info.st_uid != 0):
                raise SwapFailure("swap 操作锁不是可信的普通文件")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise SwapFailure("另一个 swap 操作正在运行") from exc
            yield
        finally:
            os.close(fd)

    def _fstab_text(self):
        try:
            return self.fstab.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise SwapFailure(f"无法读取 {self.fstab}：{exc}") from exc

    def _write_fstab(self, text):
        temporary = None
        try:
            fd, temporary = self._mkstemp(self.fstab.parent)
            with os.fdopen(fd, "w", encoding="utf-8") as file:
                os.fchmod(file.fileno(), 0o644)
                file.write(text)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary, self.fstab)
            temporary = None
        except OSError as exc:
            raise SwapFailure(f"无法更新 {self.fstab}：{exc}") from exc
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass

    @staticmethod
    def _mkstemp(directory):
        import tempfile
        return tempfile.mkstemp(prefix=".vps-script-fstab-", dir=str(directory))

    def status(self):
        try:
            text = self.proc_swaps.read_text(encoding="ascii")
        except (OSError, UnicodeError):
            text = ""
        entries = parse_swaps(text) if text else ()
        own_paths = {SWAP_PATH, str(self.swap)}
        active = next((size for path, size in entries if path in own_paths), None)
        fstab_text = ""
        try:
            fstab_text = self.fstab.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            pass
        file_size = None
        try:
            info = os.lstat(self.swap)
            if stat.S_ISREG(info.st_mode):
                file_size = info.st_size
        except OSError:
            pass
        return {
            "active": active is not None,
            "active_bytes": active,
            "file_exists": file_size is not None,
            "file_bytes": file_size,
            "fstab_managed": bool(_fstab_managed_lines(fstab_text)),
            "other_swaps": tuple((path, size) for path, size in entries if path not in own_paths),
        }

    def create(self, size_mb):
        validate_size(size_mb)
        with self.locked():
            state = self.status()
            if state["other_swaps"]:
                raise SwapFailure("系统中已有其他 swap；本项目不会叠加或修改它们")
            if state["file_exists"] or os.path.lexists(self.swap):
                raise SwapFailure("项目 swap 文件已存在，拒绝覆盖")
            if state["fstab_managed"]:
                raise SwapFailure("fstab 中已有项目 swap 条目，拒绝重复添加")
            if not self.fstab.is_file() or self.fstab.is_symlink():
                raise SwapFailure("/etc/fstab 不是可用的普通文件")
            try:
                free = shutil.disk_usage(self.swap.parent).free
            except OSError as exc:
                raise SwapFailure(f"无法检查磁盘空间：{exc}") from exc
            required = size_mb * 1024 * 1024
            if free < required + 256 * 1024 * 1024:
                raise SwapFailure("磁盘剩余空间不足（至少需要 swap 大小再加 256 MiB）")

            added_fstab = False
            try:
                self._make_file(size_mb)
                os.chmod(self.swap, 0o600)
                self._require(("mkswap", str(self.swap)))
                self._require(("swapon", str(self.swap)))
                fstab_text = self._fstab_text()
                if fstab_text and not fstab_text.endswith("\n"):
                    fstab_text += "\n"
                with self.fstab.open("a", encoding="utf-8") as file:
                    file.write(FSTAB_LINE)
                    file.flush()
                    os.fsync(file.fileno())
                added_fstab = True
                if not self.status()["active"]:
                    raise SwapFailure("swapon 返回成功，但 /proc/swaps 未显示项目 swap")
            except BaseException:
                self._cleanup_after_failure(added_fstab)
                raise
            return f"已创建 {size_mb} MiB swap 并写入 fstab；重启后的自动启用仍需验证。"

    def _make_file(self, size_mb):
        try:
            result = self._run(("fallocate", "-l", f"{size_mb}M", str(self.swap)))
        except SwapFailure:
            result = None
        if result is not None and result.returncode == 0:
            return
        # 某些文件系统不支持 fallocate，或系统没有该命令；退回 dd，仍在固定路径上。
        self._require(("dd", "if=/dev/zero", f"of={self.swap}", "bs=1M", f"count={size_mb}", "status=none"))

    def _cleanup_after_failure(self, added_fstab):
        try:
            if self.status()["active"]:
                self._run(("swapoff", str(self.swap)))
        except SwapFailure:
            pass
        if added_fstab:
            try:
                text = self._fstab_text()
                self._write_fstab("\n".join(
                    line for line in text.splitlines()
                    if not (line.strip().endswith(MARKER) and SWAP_PATH in line.split())
                ) + ("\n" if text.endswith("\n") else ""))
            except SwapFailure:
                pass
        try:
            if os.path.lexists(self.swap):
                os.unlink(self.swap)
        except OSError:
            pass

    def remove(self):
        with self.locked():
            state = self.status()
            if not state["file_exists"] and not state["active"] and not state["fstab_managed"]:
                raise SwapFailure("没有找到本项目的 swap 文件或 fstab 条目")
            if not state["fstab_managed"]:
                raise SwapFailure("fstab 中没有项目标记，拒绝删除可能属于他人的 swap")
            if state["active"]:
                self._require(("swapoff", str(self.swap)))
            text = self._fstab_text()
            if not _fstab_managed_lines(text):
                raise SwapFailure("fstab 条目在操作期间发生变化，拒绝删除")
            new_text = "\n".join(
                line for line in text.splitlines()
                if not (line.strip().endswith(MARKER) and SWAP_PATH in line.split())
            )
            if text.endswith("\n"):
                new_text += "\n"
            self._write_fstab(new_text)
            if os.path.lexists(self.swap):
                if self.swap.is_symlink() or not self.swap.is_file():
                    raise SwapFailure("项目 swap 路径不是普通文件，拒绝删除")
                os.unlink(self.swap)
            return "已移除项目 swap 文件和 fstab 条目；其他 swap 未改动。"


def change(remove=False, size_mb=None, experimental=False):
    error = packages.preflight(experimental)
    if error:
        print(f"未执行：{error}")
        return 2
    manager = SwapManager()
    try:
        current = manager.status()
        if remove:
            print("\n【试验功能】移除项目 swap；不会修改其他 swap 或 fstab 行。")
            if not current["fstab_managed"]:
                print("未找到项目管理的 swap；未执行。")
                return 0
            if input("输入 YES 继续，其他内容取消：").strip() != "YES":
                print("已取消。")
                return 0
            print(manager.remove())
            return 0
        print("\n【试验功能】创建项目 swap 文件；不会修改其他 swap 或 fstab 行。")
        print("已有其他 swap 时会停止；创建后写入 fstab，重启自动启用尚未验证。")
        if size_mb is None:
            try:
                size_mb = int(input("swap 大小（MiB，256–8192）：").strip())
            except (EOFError, ValueError):
                print("输入无效，已取消。")
                return 0
        validate_size(size_mb)
        if input("输入 YES 继续，其他内容取消：").strip() != "YES":
            print("已取消。")
            return 0
        print(manager.create(size_mb))
        return 0
    except (SwapFailure, OSError) as exc:
        print(f"操作未完成：{exc}")
        return 1
    except EOFError:
        print("已取消。")
        return 0
