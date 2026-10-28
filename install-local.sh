#!/bin/bash
set -euo pipefail

# 本地源码安装入口。不会下载文件，也不会覆盖已有安装。
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
script_path=${BASH_SOURCE[0]}
case "$script_path" in
  */*) script_dir=${script_path%/*}; [[ -n "$script_dir" ]] || script_dir=/ ;;
  *) script_dir=. ;;
esac
source_dir=$(CDPATH= cd -- "$script_dir" && pwd -P)
destination=/opt/vps-script
launcher=/usr/local/bin/vps-script

if [[ ${1:-} == --preview && $# == 1 ]]; then
  printf '本地源码：%s\n安装目录：%s\n启动命令：%s\n' "$source_dir" "$destination" "$launcher"
  printf '%s\n' '预览不会下载、安装或修改系统。已有目标时安装会停止。'
  exit 0
fi
if [[ $# != 0 ]]; then
  printf '%s\n' '用法：install-local.sh [--preview]' >&2
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
if [[ -e "$destination" || -L "$destination" || -e "$launcher" || -L "$launcher" ]]; then
  printf '%s\n' '安装目录或启动命令已存在，拒绝覆盖。更新与卸载流程尚未完成。' >&2
  exit 2
fi

secure_dir() {
  local directory=$1 owner mode
  [[ -d "$directory" && ! -L "$directory" ]] || return 1
  owner=$(/usr/bin/stat -c '%u' -- "$directory") || return 1
  mode=$(/usr/bin/stat -c '%a' -- "$directory") || return 1
  [[ "$owner" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
  (( (8#$mode & 8#022) == 0 ))
}

if ! secure_dir /opt || ! secure_dir /usr/local/bin; then
  printf '%s\n' '/opt 或 /usr/local/bin 不存在、不是 root 所有或可被其他用户写入，已停止。' >&2
  exit 2
fi

modules=(__init__.py __main__.py checks.py cli.py packages.py panel.py bbr.py hy2.py firewall.py ufw_rollback.py fail2ban.py ssh.py ssh_rollback.py)
documents=(PLAN.md DEVELOPMENT.md 3X-UI-AUDIT.md INSTALLATION.md TESTING.md)
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

printf '%s\n' '【试验安装】本地代码尚未通过 Linux/VPS 验证，只能用于可丢弃测试环境。'
printf '将复制项目到 %s，并创建 %s。\n' "$destination" "$launcher"
printf '%s\n' '默认菜单只读；系统修改功能需要另外启用试验模式并逐项确认。'
read -r -p '输入 YES 安装，其他内容取消：' answer || answer=''
if [[ "$answer" != YES ]]; then
  printf '%s\n' '已取消。'
  # 避免上层启动器把取消误认为安装成功。
  exit 1
fi

stage=$(mktemp -d /opt/.vps-script.XXXXXXXX)
launcher_tmp=''
cleanup() {
  [[ -z "$stage" || ! -d "$stage" ]] || rm -rf -- "$stage"
  [[ -z "$launcher_tmp" || ! -e "$launcher_tmp" ]] || rm -f -- "$launcher_tmp"
}
trap cleanup EXIT
mkdir -p "$stage/src/vps_admin" "$stage/docs"
/usr/bin/install -m 0755 "$source_dir/vps-admin" "$stage/vps-admin"
/usr/bin/install -m 0644 "$source_dir/README.md" "$stage/README.md"
for file in "${modules[@]}"; do
  /usr/bin/install -m 0644 "$source_dir/src/vps_admin/$file" "$stage/src/vps_admin/$file"
done
for file in "${documents[@]}"; do
  /usr/bin/install -m 0644 "$source_dir/docs/$file" "$stage/docs/$file"
done
chmod 0755 "$stage" "$stage/src" "$stage/src/vps_admin" "$stage/docs"
mv -T -n -- "$stage" "$destination"
if [[ -d "$stage" ]]; then
  printf '%s\n' '目标目录在安装期间出现；已停止且未覆盖。' >&2
  exit 1
fi
stage=''
launcher_tmp=$(mktemp /usr/local/bin/.vps-script.XXXXXXXX)
printf '%s\n' '#!/bin/bash' 'exec /opt/vps-script/vps-admin "$@"' > "$launcher_tmp"
chmod 0755 "$launcher_tmp"
if ! ln -- "$launcher_tmp" "$launcher"; then
  printf '启动命令创建失败；源码保留在 %s，请检查后手动处理。\n' "$destination" >&2
  exit 1
fi
printf '%s\n' '本地试验安装完成。运行 vps-script 打开菜单；真实 Linux/VPS 验证尚未完成。'
