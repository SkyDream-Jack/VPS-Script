"""BBR/fq 的试验性配置：仅管理独立文件，并记录可恢复的原始值。"""

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from . import checks, packages

TCP = "net.ipv4.tcp_congestion_control"
QDISC = "net.core.default_qdisc"
TARGET = {TCP: "bbr", QDISC: "fq"}
CONFIG = b"# Managed by VPS-Script; do not edit while managed.\nnet.ipv4.tcp_congestion_control = bbr\nnet.core.default_qdisc = fq\n"
VALUE_RE = re.compile(r"^[A-Za-z0-9_-]+$")
ASSIGNMENT_RE = re.compile(r"^\s*-?\s*(net[./]ipv4[./]tcp_congestion_control|net[./]core[./]default_qdisc)\s*(?:=|\s)\s*([^\s#;]+)")


class BBRFailure(Exception):
    pass


class BBRManager:
    def __init__(self, root=Path("/"), runner=None):
        self.root = Path(root)
        self.runner = runner or subprocess.run
        self.config = self.root / "etc/sysctl.d/90-vps-script.conf"
        self.state_dir = self.root / "var/lib/vps-script"
        self.state = self.state_dir / "bbr-state.json"
        self.lock = self.root / "run/lock/vps-script-bbr.lock"

    def _proc(self, name):
        return self.root / "proc/sys" / name.replace(".", "/")

    def read_live(self):
        values = {}
        for key in TARGET:
            try:
                value = self._proc(key).read_text(encoding="ascii").strip()
            except (OSError, UnicodeError) as exc:
                raise BBRFailure(f"无法读取 {key}: {exc}") from exc
            if not VALUE_RE.fullmatch(value):
                raise BBRFailure(f"{key} 的当前值无法安全识别")
            values[key] = value
        return values

    def available(self):
        try:
            return self._proc("net.ipv4.tcp_available_congestion_control").read_text(encoding="ascii").split()
        except (OSError, UnicodeError) as exc:
            raise BBRFailure(f"无法检查可用的 TCP 算法: {exc}") from exc

    def conflicts(self):
        locations = [self.root / "etc/sysctl.conf"]
        for folder in ("etc/sysctl.d", "run/sysctl.d", "usr/local/lib/sysctl.d", "usr/lib/sysctl.d", "lib/sysctl.d"):
            try:
                locations.extend(sorted((self.root / folder).glob("*.conf")))
            except OSError as exc:
                raise BBRFailure(f"无法检查 sysctl 配置目录: {exc}") from exc
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
                raise BBRFailure(f"无法检查 {path}: {exc}") from exc
            for line in text.splitlines():
                match = ASSIGNMENT_RE.match(line)
                if match:
                    key = match.group(1).replace("/", ".")
                    if match.group(2) != TARGET[key]:
                        conflicts.append(f"{path}: {key} = {match.group(2)}")
        return conflicts

    @contextmanager
    def locked(self):
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.lock, flags, 0o600)
        except OSError as exc:
            raise BBRFailure(f"无法创建操作锁: {exc}") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or (self.root == Path("/") and info.st_uid != 0):
                raise BBRFailure("操作锁不是可信的普通文件")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise BBRFailure("另一个 BBR 操作正在运行") from exc
            yield
        finally:
            os.close(fd)

    def _prepare_state_dir(self):
        try:
            self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            info = os.lstat(self.state_dir)
        except OSError as exc:
            raise BBRFailure(f"无法准备状态目录: {exc}") from exc
        if not stat.S_ISDIR(info.st_mode) or (self.root == Path("/") and info.st_uid != 0):
            raise BBRFailure("状态目录不是可信目录")
        if info.st_mode & 0o077:
            raise BBRFailure("状态目录权限过宽，拒绝写入")

    @staticmethod
    def _atomic_create(path, data, mode):
        temp_path = None
        try:
            fd, temp_path = tempfile.mkstemp(prefix=".vps-script-", dir=str(path.parent))
            with os.fdopen(fd, "wb") as file:
                os.fchmod(file.fileno(), mode)
                file.write(data)
                file.flush()
                os.fsync(file.fileno())
            # link 保证目标存在时不覆盖；临时文件与目标必须处于同一目录。
            os.link(temp_path, path)
        except OSError as exc:
            raise BBRFailure(f"无法创建 {path}: {exc}") from exc
        finally:
            if temp_path is not None:
                try:
                    os.unlink(temp_path)
                except FileNotFoundError:
                    pass

    @staticmethod
    def _read_regular(path):
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
            with os.fdopen(fd, "rb") as file:
                info = os.fstat(file.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise BBRFailure(f"{path} 不是普通文件")
                data = file.read(16_385)
            if len(data) > 16_384:
                raise BBRFailure(f"{path} 过大")
            return data
        except OSError as exc:
            raise BBRFailure(f"无法安全读取 {path}: {exc}") from exc

    def load_state(self):
        try:
            data = json.loads(self._read_regular(self.state).decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise BBRFailure("BBR 状态文件无效") from exc
        if not isinstance(data, dict) or data.get("schema") != 1 or not isinstance(data.get("before"), dict):
            raise BBRFailure("BBR 状态文件格式无效")
        before = data["before"]
        if set(before) != set(TARGET) or any(not isinstance(v, str) or not VALUE_RE.fullmatch(v) for v in before.values()):
            raise BBRFailure("BBR 状态文件中的原值无效")
        return before

    def write_live(self, key, value):
        if key not in TARGET or not VALUE_RE.fullmatch(value):
            raise BBRFailure("无效的 sysctl 参数")
        command = checks.find_command("sysctl")
        if not command:
            raise BBRFailure("未找到 sysctl")
        try:
            result = self.runner((command, "-w", f"{key}={value}"), capture_output=True,
                                 text=True, encoding="utf-8", errors="replace", timeout=10, check=False,
                                 env={"PATH": packages.SAFE_PATH, "LC_ALL": "C"})
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BBRFailure(f"写入 {key} 失败: {exc}") from exc
        if result.returncode != 0:
            raise BBRFailure(f"写入 {key} 失败: {(result.stderr or '').strip()}")

    def _restore_locked(self, before):
        if os.path.lexists(self.config) and self._read_regular(self.config) != CONFIG:
            raise BBRFailure("项目配置已被外部修改，拒绝覆盖或恢复")
        live = self.read_live()
        for key in TARGET:
            if live[key] not in (before[key], TARGET[key]):
                raise BBRFailure(f"{key} 已被其他操作改为 {live[key]}，拒绝覆盖")
        for key in reversed(tuple(TARGET)):
            if live[key] != before[key]:
                self.write_live(key, before[key])
        if self.read_live() != before:
            raise BBRFailure("运行时恢复未完全生效；状态文件保留供检查")
        if os.path.lexists(self.config):
            if self._read_regular(self.config) != CONFIG:
                raise BBRFailure("配置文件在恢复时发生变化，拒绝删除")
            os.unlink(self.config)
        os.unlink(self.state)

    def apply(self, load_module=False):
        with self.locked():
            if os.path.lexists(self.state):
                before = self.load_state()
                if os.path.lexists(self.config) and self._read_regular(self.config) == CONFIG and self.read_live() == TARGET:
                    return "配置与运行时值已经一致。"
                raise BBRFailure("发现未完成或不一致的旧操作，请先检查并恢复")
            if os.path.lexists(self.config):
                raise BBRFailure("目标配置文件已存在，拒绝覆盖")
            conflicts = self.conflicts()
            if conflicts:
                raise BBRFailure("发现其他 sysctl 配置冲突：\n" + "\n".join(conflicts))
            if "bbr" not in self.available():
                if not load_module:
                    raise BBRFailure("当前内核未列出 bbr；没有授权加载内核模块")
                modprobe = checks.find_command("modprobe")
                if not modprobe:
                    raise BBRFailure("未找到 modprobe，无法加载 tcp_bbr")
                try:
                    result = self.runner((modprobe, "tcp_bbr"), capture_output=True, text=True,
                                         encoding="utf-8", errors="replace", timeout=15, check=False,
                                         env={"PATH": packages.SAFE_PATH, "LC_ALL": "C"})
                except (OSError, subprocess.TimeoutExpired) as exc:
                    raise BBRFailure(f"无法加载 tcp_bbr: {exc}") from exc
                if result.returncode != 0 or "bbr" not in self.available():
                    raise BBRFailure("tcp_bbr 未能加载或当前环境不支持；不会卸载可能正在使用的模块")
            before = self.read_live()
            self._prepare_state_dir()
            state = json.dumps({"schema": 1, "before": before}, sort_keys=True).encode("utf-8") + b"\n"
            self._atomic_create(self.state, state, 0o600)
            try:
                for key, value in TARGET.items():
                    if before[key] != value:
                        self.write_live(key, value)
                if self.read_live() != TARGET:
                    raise BBRFailure("运行时配置未全部生效")
                self._atomic_create(self.config, CONFIG, 0o644)
            except BaseException:
                try:
                    self._restore_locked(before)
                except Exception as rollback_error:
                    print(f"自动恢复未完成：{rollback_error}；请保留状态文件并人工检查。")
                raise
            return "运行时值已读取为 bbr / fq，项目配置已写入；重启后的结果尚未验证。"

    def restore(self):
        with self.locked():
            if not os.path.lexists(self.state):
                raise BBRFailure("没有找到本项目记录的 BBR 原值")
            self._restore_locked(self.load_state())
            return "已恢复记录的运行时值并移除本项目配置；其他 sysctl 文件未被改写。"


def change(restore=False, experimental=False):
    error = packages.preflight(experimental)
    if error:
        print(f"未执行：{error}")
        return 2
    print("\n【试验功能】BBR / fq 尚未在真实 Linux 或 VPS 验证。")
    print("只管理 /etc/sysctl.d/90-vps-script.conf；若发现冲突或已有文件会停止。")
    print("TCP BBR 不代表 Hy2 的拥塞控制，默认 fq 也不保证每个接口正在使用 fq。")
    manager = BBRManager()
    try:
        need_module = not restore and "bbr" not in manager.available()
    except BBRFailure as exc:
        print(f"无法检查 BBR：{exc}")
        return 1
    if need_module:
        print("当前未列出 bbr；确认后会尝试加载 tcp_bbr 内核模块。模块可能被其他连接使用，不会自动卸载。")
    print("不会改写其他 sysctl 配置。")
    print("将恢复本项目记录的原值。" if restore else "将设置 TCP bbr、默认队列 fq，并保存原值。")
    try:
        confirmed = input("输入 YES 继续，其他内容取消：").strip() == "YES"
    except EOFError:
        confirmed = False
    if not confirmed:
        print("已取消。")
        return 0
    try:
        print(manager.restore() if restore else manager.apply(load_module=need_module))
        return 0
    except (BBRFailure, OSError) as exc:
        print(f"操作未完成：{exc}")
        return 1
