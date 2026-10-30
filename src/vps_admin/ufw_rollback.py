"""独立的 UFW 超时恢复程序，复制到受限目录后由 systemd 调用。"""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

CONFIG_PATHS = ("etc/default/ufw", "etc/ufw/ufw.conf", "etc/ufw/user.rules", "etc/ufw/user6.rules",
                "etc/ufw/before.rules", "etc/ufw/before6.rules", "etc/ufw/after.rules", "etc/ufw/after6.rules",
                "etc/ufw/sysctl.conf", "etc/ufw/before.init", "etc/ufw/after.init")


def config_fingerprint(root=Path("/")):
    """Fixed UFW inputs; normalize only the documented enable toggle.

    Kept in this standalone file so a scheduled worker survives an upgrade.
    Missing required files or any untrusted input fails closed.
    """
    root = Path(root)
    expected_uid = 0 if root == Path("/") else os.geteuid()
    values = {}
    for relative in CONFIG_PATHS:
        path = root / relative
        current = root
        for part in Path(relative).parts[:-1]:
            current = current / part
            info = current.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid or info.st_mode & 0o022:
                raise ValueError("UFW 配置目录不可信")
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            if relative in ("etc/default/ufw", "etc/ufw/ufw.conf", "etc/ufw/user.rules"):
                raise ValueError("缺少 UFW 恢复所需配置") from None
            values[relative] = None
            continue
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != expected_uid
                    or info.st_mode & 0o022):
                raise ValueError("UFW 配置文件不可信")
            data = stream.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError("UFW 配置文件过大")
        if relative == "etc/ufw/ufw.conf":
            if len(re.findall(rb"(?m)^\s*ENABLED\s*=", data)) != 1:
                raise ValueError("无法识别 UFW ENABLED 配置")
            data, count = re.subn(rb"(?m)^ENABLED=(?:yes|no)\r?$", b"ENABLED=<toggle>", data)
            if count != 1:
                raise ValueError("不支持的 UFW ENABLED 配置")
        values[relative] = [stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid, hashlib.sha256(data).hexdigest()]
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode("ascii")).hexdigest()


def run(tx_dir, ufw="/usr/sbin/ufw", runner=subprocess.run, *, root=Path("/")):
    tx_dir = Path(tx_dir)
    if ufw not in ("/usr/sbin/ufw", "/usr/bin/ufw", "/sbin/ufw", "/bin/ufw"):
        return 2
    lock_fd = os.open(tx_dir / "lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        if (tx_dir / "confirmed").exists() or (tx_dir / "rolled-back").exists():
            return 0
        if not (tx_dir / "enable-started").exists():
            (tx_dir / "expired").write_text("1\n", encoding="ascii")
            return 0
        (tx_dir / "rollback-started").write_text("1\n", encoding="ascii")
        status = runner((ufw, "status"), check=False, timeout=30, capture_output=True, text=True,
                        encoding="utf-8", errors="replace",
                        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        if status.returncode != 0:
            return 1
        if "Status: inactive" in status.stdout.splitlines():
            (tx_dir / "rolled-back").write_text("UFW was already inactive\n", encoding="ascii")
            return 0
        if "Status: active" not in status.stdout.splitlines():
            return 1
        before_enable = tx_dir / "before-enable.sha256"
        has_fingerprint = before_enable.is_file() and not before_enable.is_symlink()
        if has_fingerprint:
            try:
                if config_fingerprint(root) != before_enable.read_text(encoding="ascii").strip():
                    return 1
            except (OSError, ValueError):
                return 1
        expected = tx_dir / "expected-status.sha256"
        if expected.is_symlink():
            return 1
        if expected.is_file():
            verbose = runner((ufw, "status", "verbose"), check=False, timeout=30, capture_output=True, text=True,
                             encoding="utf-8", errors="replace",
                             env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
            if verbose.returncode != 0 or hashlib.sha256(verbose.stdout.encode("utf-8")).hexdigest() != expected.read_text(encoding="ascii").strip():
                return 1
        elif not has_fingerprint:
            # Old transactions without either piece of evidence remain unresolved.
            return 1
        result = runner((ufw, "--force", "disable"), check=False, timeout=30,
                        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        if result.returncode != 0:
            return 1
        verify = runner((ufw, "status"), check=False, timeout=30, capture_output=True, text=True,
                        encoding="utf-8", errors="replace",
                        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        if verify.returncode != 0 or "Status: inactive" not in verify.stdout.splitlines():
            return 1
        (tx_dir / "rolled-back").write_text("UFW restored to previously inactive state\n", encoding="ascii")
        return 0
    finally:
        os.close(lock_fd)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(2)
    try:
        raise SystemExit(run(sys.argv[1], sys.argv[2]))
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise SystemExit(1)
