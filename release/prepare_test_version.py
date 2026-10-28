"""生成可审查的本地测试包和固定摘要入口；不会上传或连接网络。"""

import argparse
import hashlib
from pathlib import Path

from . import build_release


ROOT = Path(__file__).resolve().parents[1]
RELEASE_ROOT = "https://raw.githubusercontent.com/SkyDream-Jack/VPS-Script/main/test-releases"


def command_for(version, bootstrap_digest, archive_digest):
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
    return f"/usr/bin/python3 -I -c '{code}' {version} {archive_digest} --start-menu"


def prepare(version):
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
    command = command_for(version, bootstrap_digest, digest)
    document = f"""# VPS-Script {version} 测试版

**仅用于可丢弃的 Ubuntu / Debian 测试 VPS。** 尚未完成真实 Linux、SSH、防火墙或 Hy2 端到端验证，不可用于生产。请先准备服务商控制台恢复途径和两个独立 SSH 会话。

在测试 VPS 的 **root SSH 终端**粘贴下面一条命令。需要系统自带 Python 3 和能访问 GitHub；安装器会分别要求确认下载与安装。成功后自动进入试验菜单，各项系统修改仍需单独选择和确认。

```bash
{command}
```

该命令只从 `raw.githubusercontent.com` 下载入口及指定版本测试包，依次校验各自的 SHA-256；入口下载单次超时 20 秒且限 200 KB，测试包最多 5 MB。程序之后的 APT、3x-ui 等功能会分别说明其他网络访问与影响。命令和摘要来自同一个仓库时，校验只能检测与命令中固定值不一致的内容，不能单独证明仓库未被入侵。

安装路径为 `/opt/vps-script`，启动命令为 `/usr/local/bin/vps-script`，不覆盖已有安装。之后以 root 运行 `vps-script --experimental` 打开试验菜单；`vps-script` 默认只读。保留 SSH 连接及控制台恢复途径，回滚定时器可能失败或无法跨重启。更新与卸载尚未实现。

入口 SHA-256：`{bootstrap_digest}`  
测试包 SHA-256：`{digest}`
"""
    (output / "INSTALL.md").write_text(document, encoding="utf-8")
    return asset, digest, command


def main():
    parser = argparse.ArgumentParser(description="生成固定摘要的 VPS 测试入口")
    parser.add_argument("version")
    args = parser.parse_args()
    try:
        asset, digest, _ = prepare(args.version)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"生成失败：{exc}\n")
    print(f"测试包：{asset}\nSHA-256：{digest}")
    print(f"试用说明：{asset.parent / 'INSTALL.md'}")
    print("仅完成本地准备；必须上传并验证远端内容后才能使用。")


if __name__ == "__main__":
    main()
