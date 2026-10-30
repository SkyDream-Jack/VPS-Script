# VPS-Script v0.6.0-dev 测试版

**仅用于可丢弃的 Ubuntu / Debian 测试 VPS。** 尚未完成真实 Linux、SSH、防火墙或 Hy2 端到端验证，不可用于生产。请先准备服务商控制台恢复途径和两个独立 SSH 会话。

在测试 VPS 的 **root SSH 终端**粘贴下面一条命令。需要系统自带 Python 3 和能访问 GitHub；安装器会要求确认下载与安装。成功后自动进入菜单，各项系统修改仍需逐项选择和确认。

```bash
f=$(mktemp) && curl -fsSL https://raw.githubusercontent.com/SkyDream-Jack/VPS-Script/main/test-releases/latest/install.sh -o "$f" && bash "$f" && rm -f "$f"
```

该命令从 `raw.githubusercontent.com` 下载短入口，入口再下载并校验 `bootstrap.py` 和测试包；入口和测试包都固定 SHA-256。短入口本身未在命令中固定摘要，建议先打开 URL 审查内容，或使用下方的可审查单行命令。程序之后的 APT、3x-ui 等功能会分别说明其他网络访问与影响。

<details>
<summary>可审查的 Python 单行命令（已固定入口和测试包摘要）</summary>

```bash
/usr/bin/python3 -I -c 'import os,sys,hashlib,urllib.request; sys.platform.startswith("linux") and os.geteuid()==0 and sys.stdin.isatty() and sys.stdout.isatty() or sys.exit("请在测试 VPS 的交互式 root SSH 终端运行"); u="https://raw.githubusercontent.com/SkyDream-Jack/VPS-Script/main/test-releases/v0.6.0-dev/bootstrap.py"; h=type("NoRedirect",(urllib.request.HTTPRedirectHandler,),{"redirect_request":lambda *a,**k:None}); d=urllib.request.build_opener(h()).open(u,timeout=20).read(200001); len(d)<=200000 and hashlib.sha256(d).hexdigest()=="964d399076628353a30b573f8a3aa18d9f326cd71289ac9c0f031c967ddd61a7" or sys.exit("下载入口校验失败"); exec(compile(d,u,"exec"))' v0.6.0-dev adcb6298989093f771d15eddebc344f9a628d9fb0af5ff31fe29365962acf4e1 --upgrade --start-menu
```

</details>

升级：再次运行同一命令即可；会替换 `/opt/vps-script`，保留 `/etc`、`/var` 中的系统配置。安装路径为 `/opt/vps-script`，启动命令为 `/usr/local/bin/vps-script`。之后以 root 运行 `vps-script --experimental` 打开修改菜单；`vps-script` 默认只读。更新与卸载系统配置仍需使用各模块自己的恢复/移除功能。

入口 SHA-256：`964d399076628353a30b573f8a3aa18d9f326cd71289ac9c0f031c967ddd61a7`

测试包 SHA-256：`adcb6298989093f771d15eddebc344f9a628d9fb0af5ff31fe29365962acf4e1`

短入口 SHA-256：`88060d87bac43a32187a307319b5e5c4cc202e2d7f8efac282eaad0e96889f22`
