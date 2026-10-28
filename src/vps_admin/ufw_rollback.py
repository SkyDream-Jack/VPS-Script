"""独立的 UFW 超时恢复程序，复制到受限目录后由 systemd 调用。"""

import fcntl
import hashlib
import os
from pathlib import Path
import subprocess
import sys


def run(tx_dir, ufw="/usr/sbin/ufw", runner=subprocess.run):
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
        status = runner((ufw, "status", "verbose"), check=False, timeout=30, capture_output=True, text=True,
                        encoding="utf-8", errors="replace",
                        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        if status.returncode != 0:
            return 1
        if "Status: inactive" in status.stdout.splitlines():
            (tx_dir / "rolled-back").write_text("UFW was already inactive\n", encoding="ascii")
            return 0
        expected = tx_dir / "expected-status.sha256"
        if not expected.is_file() or expected.is_symlink():
            return 1
        digest = hashlib.sha256(status.stdout.encode("utf-8")).hexdigest()
        if digest != expected.read_text(encoding="ascii").strip():
            return 1
        result = runner((ufw, "--force", "disable"), check=False, timeout=30,
                        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        if result.returncode != 0:
            return 1
        (tx_dir / "rolled-back").write_text("UFW restored to previously inactive state\n", encoding="ascii")
        return 0
    finally:
        os.close(lock_fd)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(2)
    raise SystemExit(run(sys.argv[1], sys.argv[2]))
