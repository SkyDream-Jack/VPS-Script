#!/usr/bin/python3 -I
"""固定版本及摘要的试验下载入口；发布前不能用于生产。"""

import argparse
import gzip
import hashlib
import hmac
import io
import os
from pathlib import Path, PurePosixPath
import platform
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request

VERSION_RE = re.compile(r"^v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:-[A-Za-z0-9.-]{1,32})?$")
SHA_RE = re.compile(r"^[a-f0-9]{64}$")
ALLOWED_HOSTS = frozenset({"raw.githubusercontent.com"})
MAX_ARCHIVE = 5_000_000
MAX_EXPANDED = 2_000_000
MAX_TAR_BYTES = 2_500_000
FILES = frozenset({
    "README.md", "vps-admin", "install-local.sh", "bootstrap.py",
    "docs/PLAN.md", "docs/DEVELOPMENT.md", "docs/3X-UI-AUDIT.md", "docs/INSTALLATION.md", "docs/TESTING.md",
    "src/vps_admin/__init__.py", "src/vps_admin/__main__.py", "src/vps_admin/checks.py", "src/vps_admin/cli.py",
    "src/vps_admin/packages.py", "src/vps_admin/panel.py", "src/vps_admin/bbr.py", "src/vps_admin/hy2.py",
    "src/vps_admin/firewall.py", "src/vps_admin/ufw_rollback.py", "src/vps_admin/fail2ban.py",
    "src/vps_admin/ssh.py", "src/vps_admin/ssh_rollback.py",
})
EXECUTABLE = frozenset({"vps-admin", "install-local.sh", "bootstrap.py"})


def asset_url(version):
    if not VERSION_RE.fullmatch(version):
        raise ValueError("版本格式无效")
    return f"https://raw.githubusercontent.com/SkyDream-Jack/VPS-Script/main/test-releases/{version}/vps-script-{version}.tar.gz"


class ReleaseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        url = urllib.parse.urlsplit(newurl)
        if url.scheme != "https" or url.hostname not in ALLOWED_HOSTS or url.username is not None or url.port not in (None, 443):
            raise ValueError("发布包重定向到了不允许的地址")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(version, expected):
    if not SHA_RE.fullmatch(expected):
        raise ValueError("必须提供 64 位小写 SHA-256")
    opener = urllib.request.build_opener(ReleaseRedirect())
    request = urllib.request.Request(asset_url(version), headers={"User-Agent": "VPS-Script-development"})
    chunks, size = [], 0
    deadline = time.monotonic() + 90
    with opener.open(request, timeout=20) as response:
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError("下载超过总时间限制")
            chunk = response.read(min(65_536, MAX_ARCHIVE + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_ARCHIVE:
                raise ValueError("发布包超过大小限制")
    data = b"".join(chunks)
    actual = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise ValueError("发布包 SHA-256 不匹配")
    return data


def unpack(data, destination):
    """只提取白名单普通文件，不接受符号链接、重复或路径穿越。"""
    destination = Path(destination)
    seen, total = set(), 0
    # 先限制解压出的 tar 字节数，避免 getmembers 解析压缩炸弹时消耗无限资源。
    with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as zipped:
        raw = zipped.read(MAX_TAR_BYTES + 1)
    if len(raw) > MAX_TAR_BYTES:
        raise ValueError("发布包解压后的 tar 超过大小限制")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        members = archive.getmembers()
        if len(members) != len(FILES):
            raise ValueError("发布包文件数量不符合预期")
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or not path.parts or path.parts[0] != "vps-script" or ".." in path.parts:
                raise ValueError("发布包包含无效路径")
            name = "/".join(path.parts[1:])
            if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or name not in FILES or name in seen:
                raise ValueError("发布包包含非预期文件、链接或重复路径")
            seen.add(name)
            total += member.size
            if member.size < 0 or total > MAX_EXPANDED:
                raise ValueError("发布包解压后超过大小限制")
        if seen != FILES:
            raise ValueError("发布包缺少必需文件")
        for member in members:
            name = "/".join(PurePosixPath(member.name).parts[1:])
            target = destination / "vps-script" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("无法读取发布包文件")
            with source, target.open("xb") as file:
                data = source.read(member.size + 1)
                if len(data) != member.size:
                    raise ValueError("发布包文件长度异常")
                file.write(data)
                os.fchmod(file.fileno(), 0o755 if name in EXECUTABLE else 0o644)
    return destination / "vps-script"


def main(argv=None):
    parser = argparse.ArgumentParser(description="固定版本的 VPS-Script 下载入口（开发中）")
    parser.add_argument("version")
    parser.add_argument("sha256")
    parser.add_argument("--preview", action="store_true", help="仅查看来源，不下载")
    parser.add_argument("--start-menu", action="store_true", help="安装成功后打开试验菜单")
    args = parser.parse_args(argv)
    try:
        url = asset_url(args.version)
        if not SHA_RE.fullmatch(args.sha256):
            raise ValueError("必须提供 64 位小写 SHA-256")
    except ValueError as exc:
        parser.error(str(exc))
    print(f"发布包：{url}\n预期 SHA-256：{args.sha256}")
    print("发布包仅请求 raw.githubusercontent.com，单连接下载；单次连接/读取超时 20 秒，总检查限时约 90 秒，最大 5 MB。")
    print("摘要必须从独立可信渠道获取；下载入口自身也需先校验，不能仅凭同源摘要证明来源安全。")
    if args.preview:
        print("预览模式：没有下载或安装。")
        return 0
    if platform.system() != "Linux" or not hasattr(os, "geteuid") or os.geteuid() != 0 or not sys.stdin.isatty() or not sys.stdout.isatty():
        print("需要 Linux、root 和交互式终端；未下载。", file=sys.stderr)
        return 2
    print("该功能尚未经过真实 Linux/VPS 验证，只能用于可丢弃测试环境。")
    if args.start_menu:
        print("安装成功后将打开试验菜单；各项修改仍需选择并单独确认。")
    try:
        if input("输入 YES 下载，其他内容取消：").strip() != "YES":
            print("已取消。")
            return 0
        data = download(args.version, args.sha256)
        with tempfile.TemporaryDirectory(prefix="vps-script-release-") as directory:
            root = unpack(data, directory)
            env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root"}
            for key in ("TERM", "LANG", "LC_ALL", "SSH_CONNECTION", "SUDO_USER"):
                if key in os.environ:
                    env[key] = os.environ[key]
            result = subprocess.run(("/bin/bash", str(root / "install-local.sh")), env=env, check=False)
            if result.returncode != 0:
                return result.returncode if result.returncode >= 0 else 1
            if args.start_menu:
                launcher = Path("/usr/local/bin/vps-script")
                installed = Path("/opt/vps-script/vps-admin")
                # 安装器返回成功后仍检查目标是否存在。
                if not launcher.is_file() or not installed.is_file():
                    print("未检测到已完成的安装；不会启动菜单。")
                    return 0
                print("\n安装完成，打开试验菜单；系统修改仍需要逐项选择并确认。", flush=True)
                menu = subprocess.run((str(launcher), "--experimental"), env=env, check=False)
                return menu.returncode if menu.returncode >= 0 else 1
            return 0
    except EOFError:
        print("已取消。")
        return 0
    except (OSError, ValueError, tarfile.TarError, TimeoutError) as exc:
        print(f"下载或安装未完成：{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
