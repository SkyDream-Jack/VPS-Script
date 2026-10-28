"""固定版本 3x-ui 的试验性安装入口。"""

import hashlib
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import urllib.parse
import urllib.request

from . import packages

VERSION = "v3.11.0"
COMMIT = "c621ba9014a6aa21fd7c9ecf45655e44e24ebf13"
SHA256 = "9684bae4f769b2127fcceceb4f200045657381311867529e6ba76c6b58e2825d"
INSTALLER_URL = f"https://raw.githubusercontent.com/MHSanaei/3x-ui/{COMMIT}/install.sh"
MAX_SCRIPT_BYTES = 200_000
EXISTING_PATHS = (
    "/usr/local/x-ui", "/usr/bin/x-ui", "/etc/x-ui", "/etc/systemd/system/x-ui.service",
    "/usr/lib/systemd/system/x-ui.service", "/lib/systemd/system/x-ui.service",
    "/usr/local/x-ui-linux-amd64.tar.gz", "/usr/local/x-ui-linux-arm64.tar.gz",
)
SUPPORTED_ARCHES = {"x86_64", "amd64", "aarch64", "arm64"}
IP_SERVICES = (
    "api4.ipify.org", "ipv4.icanhazip.com", "v4.api.ipinfo.io",
    "ipv4.myexternalip.com", "4.ident.me", "check-host.net",
)


class SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if (parsed.scheme != "https" or parsed.hostname != "raw.githubusercontent.com"
                or parsed.username is not None or parsed.port not in (None, 443)):
            raise ValueError("安装脚本重定向到了不允许的地址")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def existing_installation(paths=EXISTING_PATHS):
    return tuple(path for path in paths if os.path.lexists(path))


def check_environment(experimental):
    error = packages.preflight(experimental)
    if error:
        return error
    if platform.machine().lower() not in SUPPORTED_ARCHES:
        return "此试验入口仅考虑 x86_64 / arm64；其他架构尚未检查。"
    if not Path("/run/systemd/system").is_dir():
        return "没有检测到运行中的 systemd；已停止。"
    found = existing_installation()
    if found:
        return "检测到可能的现有 3x-ui 文件，拒绝覆盖：" + ", ".join(found)
    return None


def download_installer():
    """读取有限大小的固定文件，拒绝跨来源重定向并核对本地固定摘要。"""
    opener = urllib.request.build_opener(SameOriginRedirect())
    request = urllib.request.Request(INSTALLER_URL, headers={"User-Agent": "VPS-Script-development"})
    with opener.open(request, timeout=20) as response:
        body = response.read(MAX_SCRIPT_BYTES + 1)
    if len(body) > MAX_SCRIPT_BYTES:
        raise ValueError("安装脚本超过大小限制")
    if hashlib.sha256(body).hexdigest() != SHA256:
        raise ValueError("安装脚本 SHA-256 不符合固定版本，已拒绝执行")
    return body


def installer_env():
    # 不继承 XUI_*、LD_PRELOAD、BASH_ENV 等可改变上游行为的变量。
    env = packages.apt_env()
    env.pop("APT_CONFIG", None)
    env.update({"XUI_ENABLE_FAIL2BAN": "false", "XUI_NONINTERACTIVE": "0"})
    return env


def _confirm(prompt):
    try:
        return input(prompt).strip() == "YES"
    except EOFError:
        return False


def install(experimental=False):
    error = check_environment(experimental)
    if error:
        print(f"未执行：{error}")
        return 2
    print(f"\n【试验功能】安装官方 3x-ui {VERSION}，尚未通过 Linux / VPS 验证。")
    print("先下载固定提交的安装脚本，最长 20 秒、最多 200 KB；通过 SHA-256 检查后才允许执行。")
    print(f"脚本来源：{INSTALLER_URL}")
    print("安装时还会访问 GitHub 下载程序和依赖，并通过现有 APT 源获取软件包。")
    print("上游会依次尝试以下公网 IP 查询服务，每次最多 3 秒，成功后停止：")
    print("  " + "、".join(IP_SERVICES))
    print("上游交互中选择证书或 PostgreSQL 时，可能访问其他网站、运行额外代码或新增软件源。")
    print("安装脚本以 root 执行，安装 cron 等软件并启动服务；自动 Fail2ban 配置已禁用。")
    print("请提前准备控制台和快照。不要在未配置 TLS 的公网面板输入凭据。")
    print("上游 ACME 端口占用检测存在疑点；签发前请独立检查端口。")
    if not _confirm("输入 YES 下载脚本，其他内容取消："):
        print("已取消；没有下载或执行脚本。")
        return 0
    try:
        body = download_installer()
    except Exception as exc:
        print(f"下载或完整性检查失败，未执行脚本：{exc}")
        return 1
    print(f"固定脚本 SHA-256 已匹配：{SHA256}")
    print("此摘要只固定安装脚本本身；上游随后下载的组件及可选脚本具有各自的信任边界。")
    if not _confirm("输入 YES 运行上游安装程序，其他内容取消："):
        print("已取消；没有运行安装程序。")
        return 0
    # 下载到临时文件之后再次检测，避免交互期间新增的安装被覆盖。
    error = check_environment(experimental)
    if error:
        print(f"环境已变化，未执行：{error}")
        return 2
    path = None
    try:
        with tempfile.NamedTemporaryFile(prefix="vps-admin-xui-", dir="/run", delete=False) as script:
            path = script.name
            os.fchmod(script.fileno(), 0o600)
            script.write(body)
            script.flush()
            os.fsync(script.fileno())
        result = subprocess.run(("/bin/bash", path, VERSION), env=installer_env(), check=False)
    except OSError as exc:
        print(f"无法启动安装程序：{exc}")
        return 1
    finally:
        if path is not None:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
    if result.returncode != 0:
        print(f"安装程序退出码 {result.returncode}；可能已部分修改，请检查上游输出。")
        return result.returncode if result.returncode > 0 else 1
    print("安装程序退出码为 0。请分别检查服务、TLS、管理端口、云防火墙与实际访问。")
    return 0
