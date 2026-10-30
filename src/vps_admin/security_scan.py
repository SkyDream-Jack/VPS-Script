"""Explicit, bounded supplementary checks; findings never trigger deletion."""

import fcntl
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

from . import audit, bounded, checks

SCOPES = {
    "temporary": ("临时目录", ("/tmp", "/var/tmp")),
    "programs": ("本地程序目录", ("/usr/local/bin", "/usr/local/sbin", "/opt")),
    "web": ("网站文件目录", ("/var/www",)),
}
MAX_FILES = 2000
MAX_BYTES = 256 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_MEMORY = 3 * 1024 * 1024 * 1024
# Fixed wrapper limits the scanner, not the menu process. No input is code.
LIMIT_WRAPPER = ("import os,resource,sys; "
                 f"resource.setrlimit(resource.RLIMIT_AS,({MAX_MEMORY},{MAX_MEMORY})); "
                 "resource.setrlimit(resource.RLIMIT_CPU,(300,300)); "
                 "resource.setrlimit(resource.RLIMIT_FSIZE,(134217728,134217728)); "
                 "os.nice(10); os.execv(sys.argv[1],sys.argv[1:])")


def inventory(scope, root=Path("/")):
    if scope not in SCOPES:
        raise ValueError("未知扫描范围")
    root = Path(root)
    files, skipped, total, seen = [], {}, 0, 0
    def skip(reason):
        skipped[reason] = skipped.get(reason, 0) + 1
    for name in SCOPES[scope][1]:
        start = root / name.lstrip("/")
        try:
            # Do not follow a symlink supplied as a top-level directory either.
            current = root
            for part in Path(name).parts[1:]:
                current /= part
                if not stat.S_ISDIR(current.lstat().st_mode):
                    raise ValueError("链接或非目录")
            device = start.stat().st_dev
        except (OSError, ValueError):
            skip("缺失/无权限/不安全的范围目录")
            continue
        stack = [(start, 0)]
        while stack:
            directory, depth = stack.pop()
            if depth > 8:
                skip("目录深度超过 8")
                continue
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        seen += 1
                        if seen > 5000:
                            skip("达到 5000 项枚举上限，剩余数量未知")
                            return files, skipped, total
                        info = entry.stat(follow_symlinks=False)
                        if info.st_dev != device:
                            skip("跨文件系统")
                        elif stat.S_ISDIR(info.st_mode):
                            stack.append((Path(entry.path), depth + 1))
                        elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                            skip("链接/特殊文件/多硬链接")
                        elif any(not c.isprintable() for c in entry.path):
                            skip("文件名含控制字符")
                        elif info.st_size > MAX_FILE_BYTES:
                            skip("文件大于 16 MiB")
                        elif len(files) >= MAX_FILES or total + info.st_size > MAX_BYTES:
                            skip("达到 2000 文件或 256 MiB 总量上限，剩余数量未知")
                            return files, skipped, total
                        else:
                            files.append(entry.path)
                            total += info.st_size
            except OSError:
                skip("枚举期间权限不足/文件变化")
    return files, skipped, total


def classify(result):
    findings = [line for line in result.output.splitlines() if line.endswith(" FOUND")]
    errors = bool(re.search(r"(?im)(?:^.*(?:ERROR|WARNING):|^Total errors:\s*[1-9]|.* ERROR$)", result.output))
    limited = any(token in result.output for token in ("Heuristics.Limits.Exceeded", "Heuristics.Encrypted"))
    return {"state": "risk" if findings or result.code == 1 else "review" if result.complete and result.code == 0 and not errors else "unknown",
            "findings": findings[:40], "complete": result.complete and result.code in (0, 1) and not errors and not limited,
            "reason": result.reason or (f"扫描器返回 {result.code}；请核对工具、病毒库和文件权限" if result.code not in (0, 1)
                                         else "引擎报告错误、扫描限制或加密内容，需进一步核实" if errors or limited else ""),
            "exit_code": result.code}


def scan(scope="temporary", *, root=Path("/"), runner=None, commands=None):
    runner, commands, root = runner or bounded.run, commands or checks.find_command, Path(root)
    report = {"schema": 1, "kind": "malware-scan", "scope": scope, "state": "unknown", "complete": False,
              "limitations": "只扫描所选范围的部分普通文件；跳过、资源限制、运行中变化和病毒库覆盖均限制结论。命中可能误报，不自动删除/隔离/停止服务。",
              "selected_files": 0, "selected_bytes": 0, "skipped": {}, "findings": [], "reason": "", "exit_code": None}
    if scope not in SCOPES:
        raise ValueError("未知扫描范围")
    executable = commands("clamscan")
    if not executable:
        report["reason"] = "未安装 clamscan；请单独选择安装，扫描不会自动安装或联网。"
        return report
    try:
        memory, _ = audit.read_regular(root, "proc/meminfo")
        available = re.search(rb"(?m)^MemAvailable:\s+(\d+)\s+kB$", memory)
        if not available or int(available[1]) * 1024 < MAX_MEMORY + 256 * 1024 * 1024:
            report["reason"] = "可用内存不足 3.25 GiB 或未知；为保护 VPS 业务，不启动 ClamAV。小内存 VPS 可先做体检/文件校验，必要时在隔离副本扫描。"
            return report
    except (OSError, ValueError):
        report["reason"] = "无法确认可用内存，未启动扫描。"
        return report
    help_result = runner((executable, "--help"), timeout=5)
    if not help_result.complete or help_result.code != 0 or "--fail-if-cvd-older-than" not in help_result.output:
        report["reason"] = "扫描器未通过兼容性检查；需要支持病毒库过期检查的 clamscan。"
        return report
    files, skipped, total = inventory(scope, root)
    report.update(selected_files=len(files), selected_bytes=total, skipped=skipped)
    if not files:
        report["reason"] = "范围内没有可扫描文件；这不是无病毒结论。"
        return report
    # This is temporary scanner work space, not a system configuration backup.
    # A private, root-owned /run lock prevents concurrent scans of this tool.
    lock_directory = root / "run/vps-script-security"
    from . import backup
    try:
        if not backup._directories(root, lock_directory, create=True):
            raise ValueError("缺少可信运行目录")
        lock = os.open(lock_directory / "vps-script-security-scan.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    except (OSError, ValueError, backup.BackupFailure):
        report["reason"] = "无法建立安全的扫描锁；从 root 终端运行并检查 /run。"
        return report
    try:
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != backup._owner(root) or info.st_mode & 0o077:
            report["reason"] = "扫描锁不安全，未启动。"
            return report
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            report["reason"] = "已有扫描正在执行；本次未启动。"
            return report
        with tempfile.TemporaryDirectory(prefix="vps-script-scan-", dir=lock_directory) as directory:
            manifest = Path(directory) / "files"
            manifest.write_text("\n".join(files) + "\n", encoding="utf-8")
            manifest.chmod(0o600)
            result = runner((sys.executable, "-I", "-B", "-c", LIMIT_WRAPPER, executable,
                             "--stdout", "--suppress-ok-results", "--official-db-only=yes", "--fail-if-cvd-older-than=7",
                             "--follow-dir-symlinks=0", "--follow-file-symlinks=0", "--cross-fs=no", "--recursive=no",
                             "--max-filesize=16M", "--max-scansize=64M", "--max-files=1000", "--max-recursion=8",
                             "--max-scantime=15000", "--alert-exceeds-max=yes", "--alert-encrypted=yes",
                             "--tempdir=" + directory, "--file-list=" + str(manifest)), timeout=600, limit=128 * 1024)
        report.update(classify(result))
        count = re.search(r"(?m)^Scanned files:\s*(\d+)\s*$", result.output)
        report["scanned_files"] = int(count[1]) if count else None
        report["complete"] = report["complete"] and not skipped and count is not None and int(count[1]) >= len(files)
        report["summary"] = "发现引擎命中，需人工核实" if report["state"] == "risk" else "选定文件内未报告命中，仍有覆盖限制" if report["state"] == "review" else "扫描未完成或结果未知"
        if not report["complete"] and report["state"] != "risk":
            report["state"] = "unknown"
        return report
    except (OSError, ValueError) as exc:
        report["reason"] = f"扫描未完成：{type(exc).__name__}"
        return report
    finally:
        os.close(lock)


def render(report):
    lines = ["ClamAV 限范围扫描", report["limitations"], report.get("summary", report["reason"]),
             f"所选范围: {report['scope']}；已选 {report['selected_files']} 文件 / {report['selected_bytes']} 字节",
             "范围内检查完整: " + ("引擎完成；仍不保证检出全部威胁" if report["complete"] else "否/未知")]
    if report["reason"]:
        lines.append(report["reason"])
    lines.extend(f"跳过 {key}: {value}" for key, value in report["skipped"].items())
    lines.extend(report["findings"])
    lines.append("若发现可疑项：先保留路径、摘要和日志，核实来源；不要直接删除。确认 root 入侵时优先用可信镜像重建并轮换受影响凭据。")
    return bounded.clean("\n".join(lines))


def interactive(scope="temporary"):
    print("将使用已安装的 ClamAV 扫描所选范围；单进程、最多 10 分钟、2000 文件/256 MiB，CPU 时间 300 秒、虚拟内存上限 3 GiB。")
    print("只使用本地病毒库，不联网；扫描可能产生负载和临时文件，可 Ctrl-C 中断。范围：" + ", ".join(SCOPES[scope][1]))
    try:
        if input("输入 SCAN 开始，其他内容取消：").strip() != "SCAN":
            return 0
        report = scan(scope)
        print(render(report))
        return 0 if report["complete"] and report["state"] != "risk" else 1
    except EOFError:
        return 0


def package_integrity():
    print("只读核对 dpkg 保存的文件摘要；最多 60 秒。不修复/重装，配置文件差异也可能是正常修改。")
    print("本地软件包数据库并非独立可信基线，不覆盖自行下载的程序或内存驻留威胁。")
    executable = checks.find_command("dpkg")
    if not executable:
        print("未找到 dpkg，未检查。")
        return 1
    result = bounded.run((executable, "--verify"), timeout=60)
    print(result.output or "没有文件差异输出；这不证明系统未被入侵。")
    if not result.complete or result.code != 0:
        print(result.reason or f"检查返回 {result.code}，结果不完整。")
        return 1
    return 0
