"""外部测试脚本的白名单运行器。

这些脚本不是本项目代码，按各自许可证分发和运行：
- NodeQuality / IPQuality / NetQuality：AGPL-3.0
- TcpQuality：GPL-3.0
- YABS：WTFPL

只在用户明确确认后下载并执行；不把远程内容管道进 bash，不固定上游摘要，
下载后显示本次 SHA-256 供审查。测试可能安装软件、创建临时文件、访问大量
第三方节点并上传 IP/结果，必须在测试 VPS 上使用。
"""

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request

from . import packages

MAX_SCRIPT = 2_000_000
ALLOWED_REDIRECT_HOSTS = frozenset({"raw.githubusercontent.com"})


@dataclass(frozen=True)
class ExternalTest:
    key: str
    title: str
    url: str
    license: str
    source: str
    official: str
    note: str


SPECS = {
    "nq": ExternalTest(
        "nq", "NodeQuality（NQ）综合测试", "https://run.NodeQuality.com",
        "AGPL-3.0", "https://github.com/LloydAsp/NodeQuality",
        "bash <(curl -sL https://run.NodeQuality.com)",
        "在临时 chroot 中运行 YABS/IP 质量/网络质量等组合测试，并可能上传结果到 nodequality.com。",
    ),
    "tq": ExternalTest(
        "tq", "TcpQuality（TQ）TCP 质量", "https://raw.githubusercontent.com/ibsgss/TcpQuality/main/runTcpQuality.sh",
        "GPL-3.0", "https://github.com/ibsgss/TcpQuality",
        "bash <(curl -fsSL https://raw.githubusercontent.com/ibsgss/TcpQuality/main/runTcpQuality.sh)",
        "探测全国三网 TCP 质量、国际互联和单线程测速；会向大量节点发包并可能上传结果。",
    ),
    "ipquality": ExternalTest(
        "ipquality", "IPQuality IP 质量", "https://IP.Check.Place",
        "AGPL-3.0", "https://github.com/xykt/IPQuality",
        "bash <(curl -Ls https://IP.Check.Place)",
        "查询 IP 类型、风险库、流媒体解锁和邮局连通性；会向多个第三方 API 发送服务器 IP。",
    ),
    "netquality": ExternalTest(
        "netquality", "NetQuality 网络质量", "https://Net.Check.Place",
        "AGPL-3.0", "https://github.com/xykt/NetQuality",
        "bash <(curl -Ls https://Net.Check.Place)",
        "检测 BGP/接入、三网延迟与回程、国内/国际测速；流量和耗时较高。",
    ),
    "yabs": ExternalTest(
        "yabs", "YABS 机器跑分", "https://yabs.sh",
        "WTFPL", "https://github.com/masonr/yet-another-bench-script",
        "curl -sL https://yabs.sh | bash",
        "运行 fio 磁盘、iperf3 网络和 Geekbench CPU/内存测试；可能下载便携二进制。",
    ),
}


class ExternalFailure(Exception):
    pass


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if (parsed.scheme != "https" or parsed.hostname not in ALLOWED_REDIRECT_HOSTS
                or parsed.username is not None or parsed.port not in (None, 443)):
            raise ExternalFailure("外部测试脚本重定向到了不允许的地址")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(key):
    spec = SPECS.get(key)
    if spec is None:
        raise ExternalFailure("未知的外部测试")
    opener = urllib.request.build_opener(SafeRedirect())
    request = urllib.request.Request(spec.url, headers={"User-Agent": "VPS-Script-development"})
    chunks, size = [], 0
    deadline = time.monotonic() + 60
    try:
        with opener.open(request, timeout=20) as response:
            while True:
                if time.monotonic() > deadline:
                    raise ExternalFailure("下载外部测试脚本超过总时间限制")
                chunk = response.read(min(65536, MAX_SCRIPT + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > MAX_SCRIPT:
                    raise ExternalFailure("外部测试脚本超过 2 MB 限制")
    except ExternalFailure:
        raise
    except (OSError, ValueError) as exc:
        raise ExternalFailure(f"下载外部测试脚本失败：{exc}") from exc
    data = b"".join(chunks)
    if not data:
        raise ExternalFailure("外部测试脚本为空")
    return spec, data, hashlib.sha256(data).hexdigest()


def preview(key):
    spec, data, digest = download(key)
    print(f"名称：{spec.title}")
    print(f"来源：{spec.source}")
    print(f"许可证：{spec.license}")
    print(f"URL：{spec.url}")
    print(f"官方命令：{spec.official}")
    print(f"本次下载 SHA-256：{digest}（未固定，上游更新会变化）")
    print(f"大小：{len(data)} 字节；说明：{spec.note}")
    print("\n--- 脚本前 120 行，仅用于审查 ---")
    text = data.decode("utf-8", errors="replace")
    for line in text.splitlines()[:120]:
        print(line)
    print("--- 预览结束，没有执行 ---")


def run(key, experimental=False):
    spec = SPECS.get(key)
    if spec is None:
        print("未知的外部测试。")
        return 2
    if not experimental:
        print("外部测试脚本会以 root 执行并可能安装软件/上传数据；请先启用修改模式（--experimental）。")
        return 2
    error = packages.preflight(experimental)
    if error:
        print(f"未执行：{error}")
        return 2
    try:
        spec, data, digest = download(key)
    except ExternalFailure as exc:
        print(f"下载失败：{exc}")
        return 1
    print(f"\n【外部测试】{spec.title}")
    print(f"来源：{spec.source}\n许可证：{spec.license}\nURL：{spec.url}")
    print(f"本次 SHA-256：{digest}（上游未固定，下载后才可知）")
    print(spec.note)
    print("这不是本项目代码；可能安装软件、创建临时文件、访问大量第三方节点并上传 IP/结果。")
    print("建议只在可丢弃测试 VPS 上运行；运行前可先用“预览脚本”查看入口内容。")
    if input("输入 RUN 执行，其他内容取消：").strip() != "RUN":
        print("已取消。")
        return 0
    path = None
    try:
        with tempfile.NamedTemporaryFile(prefix="vps-script-external-", suffix=".sh",
                                         dir="/run" if Path("/run").is_dir() else "/tmp",
                                         delete=False) as script:
            path = script.name
            os.fchmod(script.fileno(), 0o600)
            script.write(data)
            script.flush()
            os.fsync(script.fileno())
        env = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": "/root", "LC_ALL": "C",
        }
        for name in ("TERM", "LANG", "LC_ALL"):
            if name in os.environ:
                env[name] = os.environ[name]
        print(f"\n开始执行 {spec.title}；按 Ctrl-C 可中断。\n", flush=True)
        result = subprocess.run(("/bin/bash", path), cwd="/", env=env, check=False)
        if result.returncode != 0:
            print(f"\n外部测试退出码 {result.returncode}；可能只完成部分测试。")
            return result.returncode if result.returncode > 0 else 1
        print("\n外部测试退出码为 0；结果仅代表本次网络/机器状态。")
        return 0
    except OSError as exc:
        print(f"无法执行外部测试：{exc}")
        return 1
    finally:
        if path is not None:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass


def show_commands():
    print("外部测试官方命令（复制到终端执行；本项目不会自动运行）：")
    for spec in SPECS.values():
        print(f"\n{spec.title}")
        print(f"  来源：{spec.source}")
        print(f"  许可证：{spec.license}")
        print(f"  命令：{spec.official}")
        print(f"  说明：{spec.note}")
    print("\n注意：这些命令会把远程脚本直接交给 bash；本项目菜单里的“运行”会先下载到临时文件并显示 SHA-256。")
