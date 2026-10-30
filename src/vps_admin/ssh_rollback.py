"""独立 SSH 恢复程序；由 systemd 瞬态定时器执行。"""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

TARGET = "/etc/ssh/sshd_config.d/00-vps-script.conf"
SERVICES = {"ssh.socket", "ssh.service", "sshd.service"}


def _read(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as file:
        return file.read(65_537)


def run(tx_dir, *, target_override=None, runner=subprocess.run):
    tx_dir = Path(tx_dir)
    target = Path(target_override or TARGET)
    lock = os.open(tx_dir / "lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if (tx_dir / "confirmed").exists() or (tx_dir / "rolled-back").exists():
            return 0
        if not (tx_dir / "apply-started").exists():
            (tx_dir / "expired").write_text("1\n", encoding="ascii")
            return 0
        (tx_dir / "rollback-started").write_text("1\n", encoding="ascii")
        state = json.loads(_read(tx_dir / "state.json").decode("utf-8"))
        if state.get("schema") != 1 or state.get("service") not in SERVICES or state.get("target") != str(target):
            return 2
        before_exists = state.get("before_exists")
        if type(before_exists) is not bool or not isinstance(state.get("before_mode"), int):
            return 2
        before = _read(tx_dir / "before") if before_exists else None
        if before is not None and hashlib.sha256(before).hexdigest() != state.get("before_sha256"):
            return 2
        current = _read(target) if os.path.lexists(target) else None
        if current is not None and len(current) > 65_536:
            return 2
        expected_hash = state.get("after_sha256")
        after_exists = state.get("after_exists", True)  # Old transaction copies always wrote a file.
        if type(after_exists) is not bool or (not after_exists and expected_hash is not None):
            return 2
        matches_after = ((after_exists and current is not None and hashlib.sha256(current).hexdigest() == expected_hash)
                         or (not after_exists and current is None))
        if matches_after:
            if before is None:
                if current is not None:
                    os.unlink(target)
            else:
                fd, temporary = tempfile.mkstemp(prefix=".vps-script-rollback-", dir=str(target.parent))
                try:
                    with os.fdopen(fd, "wb") as file:
                        os.fchmod(file.fileno(), state["before_mode"] & 0o777)
                        file.write(before)
                        file.flush()
                        os.fsync(file.fileno())
                    os.replace(temporary, target)
                    temporary = None
                finally:
                    if temporary is not None:
                        os.unlink(temporary)
        elif current != before:
            # 不覆盖用户在事务期间做出的其他修改。
            return 1
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
        check = runner(("/usr/sbin/sshd", "-t"), check=False, timeout=20, env=env)
        if check.returncode != 0:
            return 1
        reload_systemd = runner(("/usr/bin/systemctl", "daemon-reload"), check=False, timeout=20, env=env)
        if reload_systemd.returncode != 0:
            return 1
        action = "restart" if state["service"] == "ssh.socket" else "reload"
        reloaded = runner(("/usr/bin/systemctl", action, state["service"]), check=False, timeout=30, env=env)
        if reloaded.returncode != 0:
            return 1
        (tx_dir / "rolled-back").write_text("SSH configuration restored\n", encoding="ascii")
        return 0
    finally:
        os.close(lock)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(2)
    try:
        raise SystemExit(run(sys.argv[1]))
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise SystemExit(1)
