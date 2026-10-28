#!/bin/bash
set -euo pipefail

VERSION='v0.3.0-dev'
BOOTSTRAP_SHA='8b8f2e17313f23c4f7160c5241476cc4ca15f69925e89d8d037de5e02e4dffd1'
ARCHIVE_SHA='5935e90bbb6bb4f6287ce8164cc1e9193d5c9a2b3dd073c5cf686b169a09b775'
BASE='https://raw.githubusercontent.com/SkyDream-Jack/VPS-Script/main/test-releases/v0.3.0-dev'

if [[ $(uname -s) != Linux ]]; then
  printf '%s\n' '只支持 Linux。' >&2
  exit 2
fi
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  printf '%s\n' '请用 root 运行（或使用 sudo）。' >&2
  exit 2
fi
if [[ ! -t 0 || ! -t 1 ]]; then
  printf '%s\n' '需要交互式终端；请从 SSH 终端运行。' >&2
  exit 2
fi

python_bin=''
for candidate in /usr/bin/python3 /usr/local/bin/python3; do
  if [[ -x "$candidate" && -f "$candidate" ]]; then python_bin=$candidate; break; fi
done
if [[ -z "$python_bin" ]]; then
  printf '%s\n' '需要系统 Python 3；请先用系统包管理器安装 python3。' >&2
  exit 2
fi

tmp=$(mktemp)
trap 'rm -f -- "$tmp"' EXIT
if command -v curl > /dev/null 2>&1; then
  curl -fsSL --max-time 20 "$BASE/bootstrap.py" -o "$tmp"
elif command -v wget > /dev/null 2>&1; then
  wget -q -T 20 -O "$tmp" "$BASE/bootstrap.py"
else
  printf '%s\n' '需要 curl 或 wget 下载入口。' >&2
  exit 2
fi
actual=$("$python_bin" -I -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$tmp")
if [[ "$actual" != "$BOOTSTRAP_SHA" ]]; then
  printf '%s\n' '下载入口 SHA-256 不匹配，已拒绝执行。' >&2
  exit 1
fi
"$python_bin" -I "$tmp" "$VERSION" "$ARCHIVE_SHA" --upgrade --start-menu
