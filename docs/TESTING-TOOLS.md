# 测试与体检功能调研

> 状态：v0.5.0-dev。外部脚本按各自许可证运行，不合并进本项目源码。

## 1. NQ / TQ 是什么

| 简称 | 项目 | 做什么 | 许可证 |
| --- | --- | --- | --- |
| **NQ** | [LloydAsp/NodeQuality](https://github.com/LloydAsp/NodeQuality) | 在临时 chroot 的 BenchOS 中组合运行 YABS、IP 质量、网络质量、融合怪部分功能，自动排版并上传结果 | AGPL-3.0 |
| **TQ** | [ibsgss/TcpQuality](https://github.com/ibsgss/TcpQuality) | 全国三网 TCP 大包回程、国际互联、单线程测速 | GPL-3.0 |
| IP 质量 | [xykt/IPQuality](https://github.com/xykt/IPQuality) | IP 类型、风险库、流媒体/AI 解锁、邮局连通性 | AGPL-3.0 |
| 网络质量 | [xykt/NetQuality](https://github.com/xykt/NetQuality) | BGP/接入、三网延迟与回程、国内/国际测速 | AGPL-3.0 |
| YABS | [masonr/yet-another-bench-script](https://github.com/masonr/yet-another-bench-script) | fio 磁盘、iperf3 网络、Geekbench CPU/内存 | WTFPL |

NQ 本质上不是“另一个测速脚本”，而是 xykt 的 IP/网络质量 + YABS + 融合怪片段的**沙箱封装和后处理**。它的优点是测试痕迹少、排版好、结果可分享；代价是要下载 BenchOS rootfs、使用 chroot、上传结果到 nodequality.com。

TQ 的重点是 **TCP 质量/回程**，不是通用带宽测速；它会向大量国内节点发包，耗时和流量都不低。

## 2. 可信度评估

**可以借鉴/使用的部分：**

- 都是公开仓库，NQ/TQ/IPQuality/NetQuality/YABS 均有明确许可证；
- NQ 使用 chroot 隔离测试环境，测试后清理，减少对宿主系统的污染；
- IPQuality/NetQuality 的测试维度比“ping 一下”完整得多；
- YABS 是机器跑分领域的事实标准之一。

**必须保留的疑虑：**

- **供应链**：都是远程脚本/远程 rootfs/便携二进制，运行即信任上游；官方短域名还会 302 到 GitHub raw，内容会变化。
- **数据外发**：IP 质量会向多个第三方 API 发送服务器 IP；NQ 会把结果上传到 nodequality.com；TQ 会向大量节点发包；YABS 会下载 Geekbench/fio/iperf3 二进制。
- **权限**：NQ/TQ 需要 root/chroot/网络能力；测试脚本可能安装软件、改临时网络命名空间或留下缓存。
- **许可证**：AGPL/GPL 不适合把代码直接复制进本项目；我们只做**外部程序调用**，不打包、不改写、不声称合并。
- **结果可比性**：测试结果受时间、对端、运营商、云厂商限速影响；不能拿一次结果证明“优化有效”。

## 3. 本项目的做法

### 3.1 内置轻量测试（不下载第三方脚本）

菜单“测试与体检”中的 1–4 项：

- 机器/系统信息：发行版、内核、CPU、内存、磁盘、虚拟化、TCP 拥塞控制；
- 网络接口、默认路由、DNS、`ss -s`、到 1.1.1.1 / 8.8.8.8 / 223.5.5.5 的 ICMP 延迟；
- 线路追踪：优先 `mtr -rwzbc 10`，否则 `traceroute`；
- 带宽下载：Cloudflare `__down` 单线程下载，10–100 MiB 可选，明确提示消耗流量，只代表单线程 HTTP 下载。

这些功能不安装软件、不执行远程代码；缺少命令时显示未知/安装提示。

### 3.2 外部测试（白名单、预览、确认）

菜单 5–9 对应 NQ/TQ/IPQuality/NetQuality/YABS。运行流程：

1. 固定 URL 白名单，HTTPS only，重定向只允许 `raw.githubusercontent.com`；
2. 下载到私有临时文件，限制 2 MB、20 秒连接、60 秒总时长；
3. 显示来源、许可证、官方命令、本次 SHA-256 和前 120 行预览；
4. 要求修改模式（`--experimental`）并输入 `RUN`；
5. `bash 临时文件` 执行，**不使用 `curl | bash`**；
6. 执行后删除临时文件；不捕获/上传输出到本项目服务器。

菜单 10 可以只预览或查看官方命令，不执行。

### 3.3 不做什么

- 不把 NQ/TQ/IPQuality/NetQuality/YABS 的代码复制进仓库；
- 不自动运行、不在安装时运行、不在只读模式运行；
- 不固定上游 SHA（脚本会更新），但每次显示本次下载摘要；
- 不解析/保存测试结果为结构化数据（首版直接看终端输出）；
- 不自动安装 `mtr`/`nexttrace`/`speedtest` 等测试工具；内置功能缺少命令时提示；
- 不把 NQ 和 YABS/IPQuality/NetQuality 同时跑一遍，避免重复流量和重复结果。

## 4. 官方命令

```bash
# NQ：NodeQuality
bash <(curl -sL https://run.NodeQuality.com)

# TQ：TcpQuality
bash <(curl -fsSL https://raw.githubusercontent.com/ibsgss/TcpQuality/main/runTcpQuality.sh)

# IP 质量
bash <(curl -Ls https://IP.Check.Place)

# 网络质量
bash <(curl -Ls https://Net.Check.Place)

# YABS
curl -sL https://yabs.sh | bash
```

这些命令来自各自 README；本项目菜单里的“运行”会先下载到临时文件，效果相同但多一步审查。

## 5. 使用建议

- 新机器先跑内置 1–4，确认系统/网络没有明显异常；
- 要看 IP 风险/流媒体解锁，跑 IPQuality；
- 要看三网回程/国内测速，跑 NetQuality 或 TQ；
- 要综合报告/分享，跑 NQ（它已包含 IP/网络/YABS 的主要部分）；
- 要纯机器跑分，跑 YABS；
- 同一天、同一对端、同一时段做前后对比；不要拿不同脚本的结果直接比较；
- 测试完检查是否有残留进程/临时目录；外部脚本可能会留下缓存。

## 6. 后续

- 可选：保存外部测试输出的本地日志（root-only，明确路径和清理）；
- 可选：把内置测试结果输出 JSON，便于前后对比；
- 可选：增加 `speedtest`/`librespeed` 检测，但必须先说明第三方端点；
- 不建议首版自动解析 NQ/TQ 网页结果或自动上传。
