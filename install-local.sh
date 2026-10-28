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

modules=(__init__.py __main__.py checks.py cli.py packages.py panel.py bbr.py hy2.py firewall.py ufw_rollback.py fail2ban.py ssh.py ssh_rollback.py status.py swap.py common.py)
documents=(PLAN.md DEVELOPMENT.md 3X-UI-AUDIT.md INSTALLATION.md TESTING.md REVIEW.md)
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

stage=$(mktemp -d /opt/.vps-script.XXXXXXXX)
launcher_tmp=''
backup=''
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

if (( upgrade )); then
  backup=/opt/.vps-script.previous.$$
  if [[ -e "$backup" || -L "$backup" ]]; then
    printf '升级备份路径已存在，已停止：%s\n' "$backup" >&2
    exit 1
  fi
  if ! mv -T -- "$destination" "$backup"; then
    printf '%s\n' '无法暂存旧程序目录，升级未开始。' >&2
    exit 1
  fi
fi

restore_upgrade() {
  if (( upgrade )) && [[ -n "$backup" && -d "$backup" ]]; then
    if ! mv -T -- "$backup" "$destination"; then
      printf '升级失败，且旧目录未能自动恢复；保留在 %s，请人工检查。\n' "$backup" >&2
    else
      backup=''
    fi
  fi
}

if ! mv -T -n -- "$stage" "$destination"; then
  restore_upgrade
  printf '%s\n' '无法写入安装目录，升级/安装未完成。' >&2
  exit 1
fi
if [[ -d "$stage" ]]; then
  restore_upgrade
  printf '%s\n' '目标目录在安装期间出现；已停止且未覆盖。' >&2
  exit 1
fi
stage=''

launcher_tmp=$(mktemp /usr/local/bin/.vps-script.XXXXXXXX)
printf '%s\n' '#!/bin/bash' 'exec /opt/vps-script/vps-admin "$@"' > "$launcher_tmp"
chmod 0755 "$launcher_tmp"
if (( upgrade )); then
  if ! mv -T -f -- "$launcher_tmp" "$launcher"; then
    restore_upgrade
    printf '启动命令更新失败；程序目录已恢复，请检查 %s。\n' "$launcher" >&2
    exit 1
  fi
  launcher_tmp=''
else
  if ! ln -- "$launcher_tmp" "$launcher"; then
    restore_upgrade
    printf '启动命令创建失败；源码保留在 %s，请检查后手动处理。\n' "$destination" >&2
    exit 1
  fi
fi
if (( upgrade )); then
  rm -rf -- "$backup"
  backup=''
  printf '%s\n' '试验升级完成。运行 vps-script 打开菜单；系统配置未被替换。'
else
  printf '%s\n' '本地试验安装完成。运行 vps-script 打开菜单；真实 Linux/VPS 验证尚未完成。'
fi
