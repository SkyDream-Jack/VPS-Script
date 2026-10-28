"""从明确列出的源码生成可复现的试验发布包，不包含本机配置和秘密。"""

import argparse
import gzip
import hashlib
import io
from pathlib import Path
import re
import tarfile

ROOT = Path(__file__).resolve().parents[1]
VERSION_RE = re.compile(r"^v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:-[A-Za-z0-9.-]{1,32})?$")
FILES = (
    "README.md", "vps-admin", "install-local.sh", "bootstrap.py",
    "docs/PLAN.md", "docs/DEVELOPMENT.md", "docs/3X-UI-AUDIT.md", "docs/INSTALLATION.md", "docs/TESTING.md", "docs/REVIEW.md", "docs/OPTIMIZATION.md",
    "src/vps_admin/__init__.py", "src/vps_admin/__main__.py", "src/vps_admin/checks.py", "src/vps_admin/cli.py",
    "src/vps_admin/packages.py", "src/vps_admin/panel.py", "src/vps_admin/bbr.py", "src/vps_admin/hy2.py",
    "src/vps_admin/firewall.py", "src/vps_admin/ufw_rollback.py", "src/vps_admin/fail2ban.py",
    "src/vps_admin/ssh.py", "src/vps_admin/ssh_rollback.py", "src/vps_admin/status.py",
    "src/vps_admin/swap.py", "src/vps_admin/common.py", "src/vps_admin/tuning.py",
)
EXECUTABLE = frozenset({"vps-admin", "install-local.sh", "bootstrap.py"})


def build(version, output, source=ROOT):
    if not VERSION_RE.fullmatch(version):
        raise ValueError("版本必须形如 v1.2.3 或 v1.2.3-dev")
    source, output = Path(source), Path(output)
    contents = []
    for name in sorted(FILES):
        path = source / name
        if (path.is_symlink() or not path.is_file()
                or any((source / parent).is_symlink() for parent in Path(name).parents if str(parent) != ".")):
            raise ValueError(f"缺少普通源码文件: {name}")
        contents.append((name, path.read_bytes()))
    if sum(len(data) for _, data in contents) > 2_000_000:
        raise ValueError("源码总大小超过限制")
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", filename="", mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, data in contents:
                info = tarfile.TarInfo("vps-script/" + name)
                info.size = len(data)
                info.mode = 0o755 if name in EXECUTABLE else 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mtime = 0
                archive.addfile(info, io.BytesIO(data))
    payload = buffer.getvalue()
    output.mkdir(parents=True, exist_ok=True)
    asset = output / f"vps-script-{version}.tar.gz"
    checksum = output / (asset.name + ".sha256")
    if asset.exists() or checksum.exists():
        raise FileExistsError("发布文件已存在，拒绝覆盖")
    digest = hashlib.sha256(payload).hexdigest()
    # 试验产物只写新文件；意外中断后保留文件供检查，不自动覆盖。
    with asset.open("xb") as file:
        file.write(payload)
    with checksum.open("x", encoding="ascii") as file:
        file.write(f"{digest}  {asset.name}\n")
    return asset, digest


def main():
    parser = argparse.ArgumentParser(description="生成本地试验发布包")
    parser.add_argument("version")
    parser.add_argument("--output", default="dist")
    args = parser.parse_args()
    try:
        asset, digest = build(args.version, args.output)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"生成失败：{exc}\n")
    print(f"发布包：{asset}\nSHA-256：{digest}")
    print("该摘要需通过独立可信渠道提供；仅与同源文件比对不能证明发布源可信。")


if __name__ == "__main__":
    main()
