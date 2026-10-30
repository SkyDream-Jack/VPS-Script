"""Install checkout-built packages only on disposable GitHub Ubuntu runners.

This helper is not part of the release and must never be run on a user's VPS.
The current package and the historical baseline both come from the checkout;
published download smoke tests are a separate workflow step.
"""

import argparse
import ast
import errno
import hashlib
import os
from pathlib import Path
import platform
import pty
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
import bootstrap
from release import build_release

DESTINATION = Path("/opt/vps-script")
LAUNCHER = Path("/usr/local/bin/vps-script")
BASELINE_VERSION = "v0.5.1-dev"
BASELINE_SHA256 = "6d97b408be62147b305e4f6db87e5375953f032defba4040d1c37d46bb5e6b54"
INSTALLED_FILES = tuple(name for name in build_release.FILES if name not in ("install-local.sh", "bootstrap.py"))
SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "TERM": "xterm", "LC_ALL": "C.UTF-8"}


def validate_ci_environment():
    if (platform.system() != "Linux" or os.geteuid() != 0
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise RuntimeError("Installer integration requires a disposable GitHub-hosted Linux runner and root")
    workspace = os.environ.get("GITHUB_WORKSPACE", "")
    if not workspace or Path(workspace).resolve() != PROJECT:
        raise RuntimeError("The checkout must match GITHUB_WORKSPACE")
    for path in (DESTINATION, LAUNCHER):
        if os.path.lexists(path):
            raise RuntimeError(f"Refusing to use a runner with an existing installation: {path}")


def prepare_runner_paths():
    # Called only after validate_ci_environment(); these are disposable VM paths.
    for path in (Path("/opt"), Path("/usr/local/bin")):
        path.mkdir(mode=0o755, parents=True, exist_ok=True)
        if path.is_symlink() or not path.is_dir():
            raise RuntimeError(f"Unsafe installation parent: {path}")
        os.chown(path, 0, 0)
        path.chmod(0o755)


def source_version(source):
    tree = ast.parse((Path(source) / "src/vps_admin/__init__.py").read_text(encoding="utf-8"))
    values = [node.value.value for node in tree.body
              if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets)
              and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)]
    if len(values) != 1 or not build_release.VERSION_RE.fullmatch("v" + values[0]):
        raise RuntimeError("Missing or invalid source version")
    return values[0]


def verify_tree(source, installed, names=INSTALLED_FILES):
    source, installed = Path(source), Path(installed)
    actual = set()
    for path in installed.rglob("*"):
        if path.is_symlink():
            raise RuntimeError(f"Installed symlink: {path}")
        if path.is_file():
            actual.add(path.relative_to(installed).as_posix())
    if actual != set(names):
        raise RuntimeError(f"Installed file set differs: missing={set(names) - actual}, extra={actual - set(names)}")
    for name in names:
        if (installed / name).read_bytes() != (source / name).read_bytes():
            raise RuntimeError(f"Installed bytes differ from checkout/package: {name}")
    if source_version(installed) != source_version(source):
        raise RuntimeError("Installed source version differs")


def run_tty(command, answers, timeout=90):
    """Give the unmodified installer/menu a TTY and bounded scripted input."""
    master, slave = pty.openpty()
    process = None
    output = bytearray()
    try:
        process = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave,
                                   cwd="/", env=SAFE_ENV, start_new_session=True)
        os.close(slave)
        slave = None
        os.write(master, answers.encode("utf-8"))
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError(f"TTY command timed out: {command}")
            ready, _, _ = select.select([master], [], [], min(1, remaining))
            if not ready:
                continue
            try:
                chunk = os.read(master, 65_536)
            except OSError as exc:
                if exc.errno != errno.EIO:
                    raise
                break
            if not chunk:
                break
            output.extend(chunk)
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
            if len(output) > 1_000_000:
                raise RuntimeError("TTY output exceeded 1 MB")
        if process.wait(timeout=5) != 0:
            raise RuntimeError(f"TTY command failed ({process.returncode}): {command}")
        return output.decode("utf-8", errors="replace")
    finally:
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        if slave is not None:
            os.close(slave)
        os.close(master)


def verify_installed(source):
    verify_tree(source, DESTINATION)
    info = LAUNCHER.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or not os.access(LAUNCHER, os.X_OK):
        raise RuntimeError("Installed launcher is not a trusted root-owned executable")
    result = subprocess.run((str(LAUNCHER), "--version"), capture_output=True, text=True,
                            check=True, timeout=15, cwd="/", env=SAFE_ENV)
    if result.stdout.strip() != source_version(source):
        raise RuntimeError("Launcher reported a different installed version")


def run_scenario(scenario):
    validate_ci_environment()
    prepare_runner_paths()
    version = source_version(PROJECT)
    with tempfile.TemporaryDirectory(prefix="vps-script-ci-") as directory:
        temporary = Path(directory)
        current_asset, digest = build_release.build("v" + version, temporary / "package", source=PROJECT)
        current = bootstrap.unpack(current_asset.read_bytes(), temporary / "current")
        if scenario == "upgrade":
            baseline_asset = PROJECT / "test-releases" / BASELINE_VERSION / f"vps-script-{BASELINE_VERSION}.tar.gz"
            data = baseline_asset.read_bytes()
            if hashlib.sha256(data).hexdigest() != BASELINE_SHA256:
                raise RuntimeError("Historical baseline archive differs from its pinned digest")
            baseline = bootstrap.unpack(data, temporary / "baseline")
            if source_version(baseline) != BASELINE_VERSION.removeprefix("v"):
                raise RuntimeError("Historical baseline has the wrong runtime version")
            run_tty(("/bin/bash", str(baseline / "install-local.sh")), "YES\n")
            verify_installed(baseline)
            # A successful replacement must remove obsolete program files too.
            (DESTINATION / "ci-obsolete-marker").write_text("old installation\n", encoding="ascii")
        command = ("/bin/bash", str(current / "install-local.sh"))
        if scenario == "upgrade":
            command += ("--upgrade",)
        run_tty(command, "YES\n")
        # Compare against the checkout, not merely the package or a version label.
        verify_installed(PROJECT)
        menu = run_tty((str(LAUNCHER),), "0\n", timeout=30)
        if "v" + version not in menu:
            raise RuntimeError("The installed menu did not display the current version")
        subprocess.run((str(LAUNCHER), "status", "system"), check=True, timeout=30, cwd="/", env=SAFE_ENV)
        print(f"Verified {scenario}: checkout version={version}, package sha256={digest}, installed files={len(INSTALLED_FILES)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=("fresh", "upgrade"))
    args = parser.parse_args()
    try:
        run_scenario(args.scenario)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"Installer integration failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
