#!/bin/bash
set -euo pipefail

# 本地源码安装/升级入口。不会下载文件；--upgrade 会替换程序目录，
# 但不会修改 /etc、/var 中的系统配置。
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
script_path=${BASH_SOURCE[0]}
case "$script_path" in
  */*) script_dir=${script_path%/*}; [[ -n "$script_dir" ]] || script_dir=/ ;;
  *) script_dir=. ;;
esac
source_dir=$(CDPATH= cd -- "$script_dir" && pwd -P)
destination=/opt/vps-script
launcher=/usr/local/bin/vps-script

upgrade=0
case ${1:-} in
  --preview)
    if [[ $# != 1 ]]; then
      printf '%s\n' '用法：install-local.sh [--preview | --upgrade]' >&2
      exit 2
    fi
    printf '本地源码：%s\n安装目录：%s\n启动命令：%s\n' "$source_dir" "$destination" "$launcher"
    printf '%s\n' '预览不会下载、安装或修改系统。已有目标时安装会停止；--upgrade 会替换程序目录。'
    exit 0
    ;;
  --upgrade)
    upgrade=1
    shift
    ;;
esac
if [[ $# != 0 ]]; then
  printf '%s\n' '用法：install-local.sh [--preview | --upgrade]' >&2
  exit 2
fi
if [[ $(uname -s) != Linux || $EUID -ne 0 || ! -t 0 || ! -t 1 ]]; then
  printf '%s\n' '安装需要 Linux、root 和交互式终端；未执行任何修改。' >&2
  exit 2
fi
python_bin=''
for candidate in /usr/bin/python3 /usr/local/bin/python3; do
  if [[ -x "$candidate" && -f "$candidate" ]]; then python_bin=$candidate; break; fi
done
if [[ -z "$python_bin" ]]; then
  printf '%s\n' '需要系统 Python 3；本安装器不会自动访问软件源。' >&2
  exit 2
fi
if ! "$python_bin" -I -B -c 'import pathlib,shlex,sys
try:
    values={}
    for line in pathlib.Path("/etc/os-release").read_text().splitlines():
        key,sep,value=line.partition("=")
        if sep and key=="ID":
            parts=shlex.split(value)
            if len(parts)==1: values[key]=parts[0]
    sys.exit(0 if values.get("ID") in ("ubuntu","debian") else 1)
except (OSError,ValueError): sys.exit(1)'; then
  printf '%s\n' '未识别为 Ubuntu 或 Debian，已停止。' >&2
  exit 2
fi

if [[ -e "$destination" || -L "$destination" ]]; then
  if (( ! upgrade )); then
    printf '%s\n' '安装目录已存在，拒绝覆盖；升级请使用 --upgrade。' >&2
    exit 2
  fi
  if [[ -L "$destination" || ! -d "$destination" ]]; then
    printf '%s\n' '安装目录不是可信的普通目录，拒绝升级。' >&2
    exit 2
  fi
else
  upgrade=0
fi
if [[ -e "$launcher" || -L "$launcher" ]]; then
  if (( ! upgrade )); then
    printf '%s\n' '启动命令已存在，拒绝覆盖；升级请使用 --upgrade。' >&2
    exit 2
  fi
  if [[ -L "$launcher" || ! -f "$launcher" ]]; then
    printf '%s\n' '启动命令不是可信的普通文件，拒绝升级。' >&2
    exit 2
  fi
fi

secure_dir() {
  local directory=$1 allow_group_write=${2:-0} owner group mode
  [[ -d "$directory" && ! -L "$directory" ]] || return 1
  owner=$(/usr/bin/stat -c '%u' -- "$directory") || return 1
  mode=$(/usr/bin/stat -c '%a' -- "$directory") || return 1
  [[ "$owner" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
  # 任何用户可写一律拒绝；组可写只对启动器目录、且组为 root/staff 时放行。
  (( (8#$mode & 8#002) == 0 )) || return 1
  if (( (8#$mode & 8#020) != 0 )); then
    (( allow_group_write )) || return 1
    group=$(/usr/bin/stat -c '%G' -- "$directory") || return 1
    [[ "$group" == "root" || "$group" == "staff" ]] || return 1
  fi
  return 0
}

if [[ ! -e /opt && ! -L /opt ]]; then
  if ! mkdir -m 0755 /opt; then
    printf '%s\n' '无法创建 /opt，已停止。' >&2
    exit 2
  fi
fi
if ! secure_dir /opt; then
  printf '%s\n' '/opt 不存在、不是普通目录、不是 root 所有或可被其他用户写入，已停止。' >&2
  exit 2
fi
if ! secure_dir /usr/local/bin 1; then
  printf '%s\n' '/usr/local/bin 不存在、不是普通目录、不是 root 所有或可被其他用户写入，已停止。' >&2
  exit 2
fi
launcher_dir_mode=$(/usr/bin/stat -c '%a' -- /usr/local/bin) || exit 2
if (( (8#$launcher_dir_mode & 8#020) != 0 )); then
  launcher_dir_group=$(/usr/bin/stat -c '%G' -- /usr/local/bin) || exit 2
  printf '提示：/usr/local/bin 对 %s 组可写；将只创建 root 所有、0755 的启动器，请确认该组成员可信。\n' "$launcher_dir_group"
fi

modules=(__init__.py __main__.py checks.py cli.py packages.py panel.py bbr.py hy2.py firewall.py ufw_rollback.py fail2ban.py ssh.py ssh_rollback.py status.py swap.py common.py tuning.py bench.py external.py backup.py backup_access.py backup_network.py wizard.py)
documents=(PLAN.md DEVELOPMENT.md 3X-UI-AUDIT.md INSTALLATION.md TESTING.md REVIEW.md OPTIMIZATION.md TESTING-TOOLS.md)
for directory in "$source_dir/src" "$source_dir/src/vps_admin" "$source_dir/docs"; do
  if [[ ! -d "$directory" || -L "$directory" ]]; then
    printf '源码目录不可用或为符号链接：%s\n' "$directory" >&2
    exit 2
  fi
done
for file in vps-admin README.md "${modules[@]/#/src/vps_admin/}" "${documents[@]/#/docs/}"; do
  if [[ ! -f "$source_dir/$file" || -L "$source_dir/$file" ]]; then
    printf '缺少普通源码文件：%s\n' "$file" >&2
    exit 2
  fi
done

if (( upgrade )); then
  printf '%s\n' '【试验升级】尚未通过 Linux/VPS 全功能验证，只能用于可丢弃测试环境。'
  printf '将替换程序目录 %s，并保留 /etc、/var 中的系统配置。\n' "$destination"
else
  printf '%s\n' '【试验安装】尚未通过 Linux/VPS 全功能验证，只能用于可丢弃测试环境。'
  printf '将复制项目到 %s，并创建 %s。\n' "$destination" "$launcher"
fi
printf '%s\n' '默认菜单只读；系统修改功能需要另外启用修改模式并逐项确认。'
read -r -p '输入 YES 继续，其他内容取消：' answer || answer=''
if [[ "$answer" != YES ]]; then
  printf '%s\n' '已取消。'
  exit 1
fi

# The transaction is stdlib Python so every failure path shares one rollback.
# Paths are fixed above; there is no environment override for installation targets.
"$python_bin" -I -B - "$source_dir" "$destination" "$launcher" "$upgrade" \
  vps-admin README.md "${modules[@]/#/src/vps_admin/}" "${documents[@]/#/docs/}" <<'INSTALL_TRANSACTION_PY'
import ctypes
import fcntl
import os
from pathlib import Path
import shutil
import signal
import stat
import sys
import tempfile


class InstallFailure(Exception):
    pass


def identity(path):
    try:
        value = path.lstat()
    except FileNotFoundError:
        return None
    return value.st_dev, value.st_ino


def trusted_target(path, directory=False):
    value = path.lstat()
    valid_type = stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode)
    if not valid_type or value.st_uid != os.geteuid() or value.st_mode & 0o022:
        raise InstallFailure(f"目标类型、所有者或写入权限已变化，拒绝覆盖：{path}")
    return value.st_dev, value.st_ino


def move_absent(source, target):
    # Never replace an unexpected path, even an empty directory created after a
    # precheck. Linux uses renameat2(RENAME_NOREPLACE); macOS supports rootless
    # fixture tests through renamex_np(RENAME_EXCL). Other platforms fail closed.
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform.startswith("linux") and hasattr(library, "renameat2"):
        rename = library.renameat2
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        result = rename(-100, os.fsencode(source), -100, os.fsencode(target), 1)
    elif sys.platform == "darwin" and hasattr(library, "renamex_np"):
        rename = library.renamex_np
        rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        result = rename(os.fsencode(source), os.fsencode(target), 4)
    else:
        raise InstallFailure("系统缺少禁止覆盖的原子重命名操作，已停止。")
    if result != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(target))


def install_transaction(source, destination, launcher, upgrade, files):
    source, destination, launcher = Path(source), Path(destination), Path(launcher)
    lock_path = destination.parent / ".vps-script.install.lock"
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+b") as lock:
        info = os.fstat(lock.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o022
                or identity(lock_path) != (info.st_dev, info.st_ino)):
            raise InstallFailure("安装锁文件不可信，已停止。")
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise InstallFailure("另一个安装/升级正在运行，已停止。") from exc
        # Do not unlink the flock file: another process may already hold its fd.
        return perform_install(source, destination, launcher, bool(upgrade), files)


def perform_install(source, destination, launcher, upgrade, files):
    old_id = trusted_target(destination, directory=True) if upgrade else None
    if not upgrade and identity(destination) is not None:
        raise InstallFailure("安装目录在确认期间出现，拒绝覆盖。")
    old_launcher_id = trusted_target(launcher) if identity(launcher) is not None else None
    if not upgrade and old_launcher_id is not None:
        raise InstallFailure("启动命令在确认期间出现，拒绝覆盖。")
    workspace = Path(tempfile.mkdtemp(prefix=".vps-script-transaction.", dir=destination.parent))
    workspace_id = identity(workspace)
    stage, previous, failed = workspace / "new", workspace / "previous", workspace / "failed"
    launcher_tmp = launcher_backup = None
    launcher_tmp_id = launcher_backup_id = new_id = None
    committed = False
    # Never delete recovery material until commit or rollback is confirmed.
    cleanup_allowed = False
    try:
        stage.mkdir()
        for name in files:
            relative = Path(name)
            if relative.is_absolute() or ".." in relative.parts:
                raise InstallFailure("安装文件清单包含无效路径。")
            original, target = source / relative, stage / relative
            if original.is_symlink() or not original.is_file():
                raise InstallFailure(f"源码文件已变化：{name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with original.open("rb") as reader, target.open("xb") as writer:
                shutil.copyfileobj(reader, writer)
            target.chmod(0o755 if name == "vps-admin" else 0o644)
        for directory, _, _ in os.walk(stage):
            Path(directory).chmod(0o755)
        new_id = identity(stage)
        # Prepare both launcher files before touching the installed program.
        descriptor, name = tempfile.mkstemp(prefix=".vps-script-new.", dir=launcher.parent)
        launcher_tmp = Path(name)
        launcher_tmp_id = identity(launcher_tmp)
        with os.fdopen(descriptor, "wb") as writer:
            writer.write(b'#!/bin/bash\nexec /opt/vps-script/vps-admin "$@"\n')
            writer.flush()
            os.fsync(writer.fileno())
            os.fchmod(writer.fileno(), 0o755)
        if old_launcher_id is not None:
            descriptor, name = tempfile.mkstemp(prefix=".vps-script-previous.", dir=launcher.parent)
            launcher_backup = Path(name)
            launcher_backup_id = identity(launcher_backup)
            with os.fdopen(descriptor, "wb") as writer, launcher.open("rb") as reader:
                info = os.fstat(reader.fileno())
                if (info.st_dev, info.st_ino) != old_launcher_id:
                    raise InstallFailure("启动命令在安装期间变化，已停止。")
                shutil.copyfileobj(reader, writer)
                writer.flush()
                os.fsync(writer.fileno())
                os.fchown(writer.fileno(), info.st_uid, info.st_gid)
                os.fchmod(writer.fileno(), stat.S_IMODE(info.st_mode))
        if identity(destination) != old_id or identity(launcher) != old_launcher_id:
            raise InstallFailure("安装目标在准备期间变化，未覆盖。")
        if upgrade:
            move_absent(destination, previous)
        move_absent(stage, destination)
        if identity(launcher) != old_launcher_id:
            raise InstallFailure("启动命令在切换程序目录后变化，未覆盖。")
        if old_launcher_id is None:
            os.link(launcher_tmp, launcher)  # Atomic no-clobber creation.
        else:
            os.replace(launcher_tmp, launcher)
        if identity(destination) != new_id or identity(launcher) != launcher_tmp_id:
            raise InstallFailure("安装目标在提交前变化，已停止。")
        committed = True
    except BaseException as exc:
        # Keep recovery indivisible with respect to ordinary termination signals.
        # Unexpected Python exceptions also preserve backups because cleanup is
        # still disabled until all restoration checks have completed.
        old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGHUP})
        try:
            errors = []
            try:
                current_launcher = identity(launcher)
                if current_launcher == launcher_tmp_id and launcher_tmp_id is not None:
                    if old_launcher_id is None:
                        launcher.unlink()
                    else:
                        if identity(launcher_backup) != launcher_backup_id:
                            raise InstallFailure("启动命令备份已变化")
                        os.replace(launcher_backup, launcher)
                elif current_launcher != old_launcher_id:
                    raise InstallFailure("启动命令被外部修改，保留原样")
            except (OSError, InstallFailure) as error:
                errors.append(str(error))
            try:
                if new_id is not None and identity(destination) == new_id:
                    move_absent(destination, failed)
                if old_id is not None and identity(previous) == old_id:
                    move_absent(previous, destination)
                elif identity(destination) != old_id:
                    raise InstallFailure("程序目录被外部修改，保留原样")
            except (OSError, InstallFailure) as error:
                errors.append(str(error))
            if errors:
                recovery = f"；启动命令备份：{launcher_backup}" if launcher_backup else ""
                raise InstallFailure(f"安装/升级失败：{exc}；自动恢复未完成：{'；'.join(errors)}。"
                                     f"保留事务目录：{workspace}{recovery}") from exc
            cleanup_allowed = True
            raise InstallFailure(f"安装/升级失败：{exc}；程序目录和启动命令已恢复到操作前状态。") from exc
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
    else:
        cleanup_allowed = True
    finally:
        if cleanup_allowed:
            for path, expected in ((launcher_tmp, launcher_tmp_id), (launcher_backup, launcher_backup_id)):
                if path is not None and identity(path) == expected:
                    try:
                        path.unlink()
                    except OSError as error:
                        print(f"临时文件未能删除，保留供检查：{path}（{error}）", file=sys.stderr)
            if identity(workspace) == workspace_id:
                try:
                    shutil.rmtree(workspace)
                except OSError as error:
                    print(f"事务目录未能删除，保留供检查：{workspace}（{error}）", file=sys.stderr)
        else:
            print(f"尚未确认提交或完整恢复，保留事务目录：{workspace}；"
                  f"启动命令备份：{launcher_backup or '未创建'}。请人工检查。", file=sys.stderr)
    if committed:
        print("试验升级完成。" if upgrade else "本地试验安装完成。")
        print("运行 vps-script 打开菜单；系统配置未被替换。真实 Linux/VPS 全功能验证尚未完成。")


def interrupted(signum, frame):
    # Further termination signals must not interrupt the recovery attempt.
    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, signal.SIG_IGN)
    raise InterruptedError(f"收到信号 {signum}")


if __name__ == "__main__":
    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, interrupted)
    try:
        install_transaction(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] == "1", sys.argv[5:])
    except (InstallFailure, OSError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
INSTALL_TRANSACTION_PY
