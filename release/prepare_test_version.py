"""生成可审查的本地测试包、短安装入口和固定摘要说明；不会上传或连接网络。"""

import argparse
import hashlib
from pathlib import Path

from . import build_release


ROOT = Path(__file__).resolve().parents[1]
RELEASE_ROOT = "https://raw.githubusercontent.com/SkyDream-Jack/VPS-Script/main/test-releases"
LATEST_ROOT = RELEASE_ROOT + "/latest"


def command_for(version, bootstrap_digest, archive_digest):
    """保留可审查的 Python 单行入口；新入口优先使用 install.sh。"""
    if not build_release.VERSION_RE.fullmatch(version):
        raise ValueError("版本格式无效")
    for digest in (bootstrap_digest, archive_digest):
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError("摘要格式无效")
    code = (
        'import os,sys,hashlib,urllib.request; '
        'sys.platform.startswith("linux") and os.geteuid()==0 and sys.stdin.isatty() and sys.stdout.isatty() '
        'or sys.exit("请在测试 VPS 的交互式 root SSH 终端运行"); '
        f'u="{RELEASE_ROOT}/{version}/bootstrap.py"; '
        'h=type("NoRedirect",(urllib.request.HTTPRedirectHandler,),{"redirect_request":lambda *a,**k:None}); '
        'd=urllib.request.build_opener(h()).open(u,timeout=20).read(200001); '
        f'len(d)<=200000 and hashlib.sha256(d).hexdigest()=="{bootstrap_digest}" '
        'or sys.exit("下载入口校验失败"); '
        'exec(compile(d,u,"exec"))'
    )
    return f"/usr/bin/python3 -I -c '{code}' {version} {archive_digest} --upgrade --start-menu"


def short_command(url):
    # 先下载到私有临时文件，避免 curl 失败时 bash -c "" 静默返回成功，
    # 也避免把 stdin 管道消耗掉导致后续交互确认读到 EOF。
    # 文档入口要求 root SSH；不再依赖精简系统可能没有的 sudo，也不丢失 SSH_CONNECTION。
    return f'f=$(mktemp) && curl -fsSL {url} -o "$f" && bash "$f" && rm -f "$f"'


def install_script_for(version, bootstrap_digest, archive_digest):
    if not build_release.VERSION_RE.fullmatch(version):
        raise ValueError("版本格式无效")
    for digest in (bootstrap_digest, archive_digest):
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError("摘要格式无效")
    base = f"{RELEASE_ROOT}/{version}"
    return f"""#!/bin/bash
set -euo pipefail

VERSION='{version}'
BOOTSTRAP_SHA='{bootstrap_digest}'
ARCHIVE_SHA='{archive_digest}'
BASE='{base}'

if [[ $(uname -s) != Linux ]]; then
  printf '%s\\n' '只支持 Linux。' >&2
  exit 2
fi
if [[ ${{EUID:-$(id -u)}} -ne 0 ]]; then
  printf '%s\\n' '请用 root 运行（或使用 sudo）。' >&2
  exit 2
fi
if [[ ! -t 0 || ! -t 1 ]]; then
  printf '%s\\n' '需要交互式终端；请从 SSH 终端运行。' >&2
  exit 2
fi

python_bin=''
for candidate in /usr/bin/python3 /usr/local/bin/python3; do
  if [[ -x "$candidate" && -f "$candidate" ]]; then python_bin=$candidate; break; fi
done
if [[ -z "$python_bin" ]]; then
  printf '%s\\n' '需要系统 Python 3；请先用系统包管理器安装 python3。' >&2
  exit 2
fi

tmp=$(mktemp)
trap 'rm -f -- "$tmp"' EXIT
if command -v curl > /dev/null 2>&1; then
  curl -fsSL --max-time 20 "$BASE/bootstrap.py" -o "$tmp"
elif command -v wget > /dev/null 2>&1; then
  wget -q -T 20 -O "$tmp" "$BASE/bootstrap.py"
else
  printf '%s\\n' '需要 curl 或 wget 下载入口。' >&2
  exit 2
fi
actual=$("$python_bin" -I -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$tmp")
if [[ "$actual" != "$BOOTSTRAP_SHA" ]]; then
  printf '%s\\n' '下载入口 SHA-256 不匹配，已拒绝执行。' >&2
  exit 1
fi
"$python_bin" -I "$tmp" "$VERSION" "$ARCHIVE_SHA" --upgrade --start-menu
"""


def document_for(version, install_command, bootstrap_digest, archive_digest, install_digest, long_command=""):
    extra = ""
    if long_command:
        extra = f"""
<details>
<summary>可审查的 Python 单行命令（已固定入口和测试包摘要）</summary>

```bash
{long_command}
```

</details>
"""
    return f"""# VPS-Script {version} 测试版

**仅用于可丢弃的 Ubuntu / Debian 测试 VPS。** 尚未完成真实 Linux、SSH、防火墙或 Hy2 端到端验证，不可用于生产。请先准备服务商控制台恢复途径和两个独立 SSH 会话。

在测试 VPS 的 **root SSH 终端**粘贴下面一条命令。需要系统自带 Python 3 和能访问 GitHub；安装器会要求确认下载与安装。成功后自动进入菜单，各项系统修改仍需逐项选择和确认。

```bash
{install_command}
```

该命令从 `raw.githubusercontent.com` 下载短入口，入口再下载并校验 `bootstrap.py` 和测试包；入口和测试包都固定 SHA-256。短入口本身未在命令中固定摘要，建议先打开 URL 审查内容，或使用下方的可审查单行命令。程序之后的 APT、3x-ui 等功能会分别说明其他网络访问与影响。
{extra}
升级：再次运行同一命令即可；会替换 `/opt/vps-script`，保留 `/etc`、`/var` 中的系统配置。安装路径为 `/opt/vps-script`，启动命令为 `/usr/local/bin/vps-script`。之后以 root 运行 `vps-script --experimental` 打开修改菜单；`vps-script` 默认只读。更新与卸载系统配置仍需使用各模块自己的恢复/移除功能。

初始化向导：安装后在首页按 `I`，或运行 `vps-script init --experimental`。先选择步骤，再按 `E` 进入单项确认，`N` 进入下一步，`S` 跳过，`H` 查看记录/恢复；步骤选择处 `Q`/`0` 退出。参数确认过程中可 Ctrl+C 退出。已经执行的修改与记录保留，再次进入重新检查，不自动续跑；只读规划使用 `vps-script init`，演示使用 `vps-script init --demo`。

安全检查：先运行 `vps-script audit` 或 `vps-script audit --json`（只读、不联网）。菜单 `2 → 4` 提供可选文件校验、限范围 ClamAV 和逐项加固。扫描需单独确认，不自动清理；缺少工具、病毒库过期或可用内存不足 3.25 GiB 时不会开始。报告不证明 VPS 未入侵；SSH/UFW 修改及真实业务仍需独立验收。

入口 SHA-256：`{bootstrap_digest}`

测试包 SHA-256：`{archive_digest}`

短入口 SHA-256：`{install_digest}`
"""


def prepare(version, latest=False):
    if not build_release.VERSION_RE.fullmatch(version):
        raise ValueError("版本格式无效")
    output = ROOT / "test-releases" / version
    if output.exists():
        raise FileExistsError("测试版本目录已存在，拒绝覆盖")
    asset, digest = build_release.build(version, output)
    bootstrap_data = (ROOT / "bootstrap.py").read_bytes()
    bootstrap_digest = hashlib.sha256(bootstrap_data).hexdigest()
    with (output / "bootstrap.py").open("xb") as file:
        file.write(bootstrap_data)
    install_data = install_script_for(version, bootstrap_digest, digest).encode("utf-8")
    install_digest = hashlib.sha256(install_data).hexdigest()
    with (output / "install.sh").open("xb") as file:
        file.write(install_data)
    (output / "install.sh").chmod(0o755)
    version_url = f"{RELEASE_ROOT}/{version}/install.sh"
    install_command = short_command(version_url)
    long_command = command_for(version, bootstrap_digest, digest)
    document = document_for(version, install_command, bootstrap_digest, digest, install_digest, long_command)
    (output / "INSTALL.md").write_text(document, encoding="utf-8")
    if latest:
        latest_dir = ROOT / "test-releases" / "latest"
        latest_dir.mkdir(parents=True, exist_ok=True)
        (latest_dir / "install.sh").write_bytes(install_data)
        (latest_dir / "install.sh").chmod(0o755)
        latest_document = document_for(version, short_command(f"{LATEST_ROOT}/install.sh"),
                                        bootstrap_digest, digest, install_digest, long_command)
        (latest_dir / "INSTALL.md").write_text(latest_document, encoding="utf-8")
    return asset, digest, install_command


def main():
    parser = argparse.ArgumentParser(description="生成固定摘要的 VPS 测试入口")
    parser.add_argument("version")
    parser.add_argument("--latest", action="store_true", help="同时更新 test-releases/latest")
    args = parser.parse_args()
    try:
        asset, digest, command = prepare(args.version, latest=args.latest)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"生成失败：{exc}\n")
    print(f"测试包：{asset}\nSHA-256：{digest}")
    print(f"试用说明：{asset.parent / 'INSTALL.md'}")
    print(f"一行命令：{command}")
    print("仅完成本地准备；必须上传并验证远端内容后才能使用。")


if __name__ == "__main__":
    main()
