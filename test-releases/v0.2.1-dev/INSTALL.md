# VPS-Script v0.2.1-dev 测试版

**仅用于可丢弃的 Ubuntu / Debian 测试 VPS。** 尚未完成真实 Linux、SSH、防火墙或 Hy2 端到端验证，不可用于生产。请先准备服务商控制台恢复途径和两个独立 SSH 会话。

在测试 VPS 的 **root SSH 终端**粘贴下面一条命令。需要系统自带 Python 3 和能访问 GitHub；安装器会分别要求确认下载与安装。成功后自动进入试验菜单，各项系统修改仍需单独选择和确认。

```bash
/usr/bin/python3 -I -c 'import os,sys,hashlib,urllib.request; sys.platform.startswith("linux") and os.geteuid()==0 and sys.stdin.isatty() and sys.stdout.isatty() or sys.exit("请在测试 VPS 的交互式 root SSH 终端运行"); u="https://raw.githubusercontent.com/SkyDream-Jack/VPS-Script/main/test-releases/v0.2.1-dev/bootstrap.py"; h=type("NoRedirect",(urllib.request.HTTPRedirectHandler,),{"redirect_request":lambda *a,**k:None}); d=urllib.request.build_opener(h()).open(u,timeout=20).read(200001); len(d)<=200000 and hashlib.sha256(d).hexdigest()=="3fcb29593aa02c6519f2ff58362696bc5750f3bc7620e48f0fef07c44cfc3a06" or sys.exit("下载入口校验失败"); exec(compile(d,u,"exec"))' v0.2.1-dev 2d4ed9e14280b897a9f15fa168dd7d30c0ec24c6f5e3dc846a0cdd30818f1230 --start-menu
```

该命令只从 `raw.githubusercontent.com` 下载入口及指定版本测试包，依次校验各自的 SHA-256；入口下载单次超时 20 秒且限 200 KB，测试包最多 5 MB。程序之后的 APT、3x-ui 等功能会分别说明其他网络访问与影响。命令和摘要来自同一个仓库时，校验只能检测与命令中固定值不一致的内容，不能单独证明仓库未被入侵。

安装路径为 `/opt/vps-script`，启动命令为 `/usr/local/bin/vps-script`，不覆盖已有安装。之后以 root 运行 `vps-script --experimental` 打开试验菜单；`vps-script` 默认只读。保留 SSH 连接及控制台恢复途径，回滚定时器可能失败或无法跨重启。更新与卸载尚未实现。

入口 SHA-256：`3fcb29593aa02c6519f2ff58362696bc5750f3bc7620e48f0fef07c44cfc3a06`  
测试包 SHA-256：`2d4ed9e14280b897a9f15fa168dd7d30c0ec24c6f5e3dc846a0cdd30818f1230`
