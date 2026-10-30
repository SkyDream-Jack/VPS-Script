# VPS 优化功能调研与实施计划

> 状态：v0.4.0-dev 计划与实现记录。所有参数调整仍是测试功能，需要真实 VPS A/B 验证。
>
> 备份点：Git 标签 `backup/pre-tuning-2026-10-28`；本地 `dist/vps-script-backup-2026-10-28.tar.gz`。

v0.7.0-dev 补充：当前入口为 `4 网络与调优 → 3 BBR/fq / 4 高级调优`。应用和原模块恢复操作现在都会先记录统一历史，可从 `6 工具维护与恢复 → 5 变更备份与恢复` 选择符合条件的记录撤销。历史恢复使用当时保存的固定白名单运行值与项目配置，不重新计算历史缓冲目标；当前状态必须严格匹配该记录的操作后状态，外部相关 sysctl 配置须保持一致且无冲突。BBR 恢复不卸载已加载的模块，也不还原接口实际 qdisc。本次没有改变下面的参数算法；历史与本地快照都不是整机快照，也不能证明性能提升。

## 1. 调研对象

| 项目 | 做法 | 可借鉴 | 不照搬 |
| --- | --- | --- | --- |
| [Kylin010/tcpfit](https://github.com/Kylin010/tcpfit) | 按每台机器实测 BDP、限速器拐点，动态算缓冲区；带快照、存档、回滚、qdisc 整形、initcwnd | 动态缓冲区、先快照再改、逐项读回、可回滚；不套固定参数 | 不引入 iperf3 依赖、不做 HTB 整形、不改 initcwnd、不写 PPP/networkd 钩子；4.5k 行脚本超出当前维护范围 |
| [sanmussh/vps-netpilot](https://github.com/sanmussh/vps-netpilot) | 保守调优 / 中转增强两档；BBR+FQ、conntrack、UDP、RPS、DNS、MSS | 场景分档、修改前快照、逐项验证、保守默认 | 不自动开 IP 转发/MSS Clamp，不自动改 DNS，不默认 RPS |
| [Madhatter2099/TCP-Optimize](https://github.com/Madhatter2099/TCP-Optimize) | 4 种工作负载模板、RPS/MSS 持久化、基准测试、回退 | 工作负载模板、状态/回退、明确 BBR 版本说明 | 不采用激进缓冲区固定值，不自动 RPS/MSS，不把“模板”当性能保证 |
| [DsTansice/sh（KEJILION.SH）](https://github.com/DsTansice/sh) | 大而全的 Linux 管理面板，覆盖 Docker/LNMP/监控/测试 | 菜单组织、状态展示、中文交互 | 不学单体巨型脚本、不执行未固定版本的远程代码、不把几十种应用塞进首版 |
| [ike-sh/bbrv3-lite](https://github.com/ike-sh/bbrv3-lite) | 安装 XanMod/BBRv3、DNS、IPv6、测速 | 说明 BBRv3 不是主线内核默认 | 不替换内核、不引入第三方内核源；供应链和回滚成本过高 |
| [ylx2016/Linux-NetSpeed](https://github.com/ylx2016/Linux-NetSpeed) | 锐速/BBR 内核切换、tcpx 优化 | 历史脚本的兼容性处理 | 不安装闭源/魔改内核，不做不可审计的“加速”承诺 |

参考：[Linux 内核 ip-sysctl 文档](https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt)。

### 关于 tcpfit / TCP-FIT

- 用户提到的 **tcpfit** 目前可对应到 [Kylin010/tcpfit](https://github.com/Kylin010/tcpfit)：一个 MIT 许可的 TCP 调优工具，不是内核拥塞控制算法。
- 另一个同名概念 **TCP-FIT** 是研究型拥塞控制算法，并不是 Linux 主线默认提供的 `tcp_congestion_control` 选项；本工具不会承诺或安装它。
- 因此首版只做 **可审计的 sysctl/缓冲区调优**，并把 BBR/FQ 继续留在已有的 `bbr` 模块，避免两个模块同时写同一批键。

## 2. 设计原则

1. **不追求“一键拉满”。** 先给保守档，代理/中转档单独选择；大带宽缓冲区需要用户输入预期带宽和 RTT，并明确这是估算而不是实测。
2. **只写项目文件。** `/etc/sysctl.d/91-vps-script-tuning.conf`、`/var/lib/vps-script/tuning-state.json`；不覆盖 `/etc/sysctl.conf`，不接管其他 sysctl 文件。
3. **先快照、再逐项写、逐项读回。** 失败时按快照回滚；恢复时发现外部修改就停止。
4. **冲突即停止。** 其他 sysctl 文件对同一键设置了不同值时拒绝应用，不猜测优先级。
5. **不碰高风险项。** 不改内核、不装第三方内核、不做 qdisc/HTB 整形、不改 initcwnd、不自动 RPS/MSS、不改 DNS、不自动开 IP 转发。
6. **所有状态可查询。** 新增 `status tuning`，显示档位、关键值、配置/状态文件和实际队列；执行后自动回显。
7. **真实 VPS 前不宣称提升。** 参数只代表内核行为改变，不代表实际吞吐/延迟一定改善。

## 3. 首版参数

所有档位都包含安全基线：`tcp_syncookies=1`、`tcp_sack=1`、`tcp_timestamps=1`、`tcp_window_scaling=1`、`tcp_tw_reuse=1`、`tcp_mtu_probing=1`。`tcp_tw_reuse` 依赖时间戳，基线中同时确保 `tcp_timestamps=1`。

### 保守档（通用 Web/面板/轻量应用）

| 键 | 值 | 说明 |
| --- | --- | --- |
| `net.core.somaxconn` | 4096 | 提高 listen 队列上限 |
| `net.ipv4.tcp_max_syn_backlog` | 8192 | SYN 队列 |
| `net.core.netdev_max_backlog` | 4096 | 网卡收包队列 |
| `net.ipv4.ip_local_port_range` | 10240 65535 | 扩大临时端口 |
| `net.ipv4.tcp_fin_timeout` | 15 | FIN_WAIT_2 超时 |
| `net.ipv4.tcp_keepalive_time` | 600 | keepalive |
| `net.ipv4.tcp_keepalive_intvl` | 30 | keepalive 间隔 |
| `net.ipv4.tcp_keepalive_probes` | 5 | keepalive 次数 |

### 代理/中转档

在保守档基础上：

| 键 | 值 | 说明 |
| --- | --- | --- |
| `net.core.somaxconn` | 8192 | 更高并发 |
| `net.ipv4.tcp_max_syn_backlog` | 16384 | 更高并发 |
| `net.core.netdev_max_backlog` | 16384 | 更高收包队列 |
| `net.ipv4.ip_local_port_range` | 1024 65535 | 更大端口池 |
| `net.ipv4.tcp_slow_start_after_idle` | 0 | 长连接空闲后不重置 cwnd；可能增加突发 |
| `net.ipv4.tcp_notsent_lowat` | 16384 | 降低未发送数据滞留；可能影响大上传吞吐 |
| `net.ipv4.tcp_fin_timeout` | 10 | 更快回收 |
| `net.ipv4.tcp_keepalive_time` | 300 | 更快发现死连接 |
| `net.netfilter.nf_conntrack_max` | RAM/16，最低 65536 | 仅在 conntrack 已存在时设置 |

### 大带宽缓冲档

在保守档基础上增加：

| 键 | 计算 |
| --- | --- |
| `net.core.rmem_max` / `wmem_max` | `buf_max` |
| `net.ipv4.tcp_rmem` | `4096 buf_default buf_max` |
| `net.ipv4.tcp_wmem` | `4096 buf_default buf_max` |
| `net.ipv4.tcp_adv_win_scale` | 1 |
| `net.ipv4.tcp_moderate_rcvbuf` | 1 |
| `net.ipv4.tcp_mem` | RAM 的 1/32、1/16、1/8（页） |

`buf_max` 计算：

```text
BDP = 预期带宽(Mbps) × RTT(ms) × 125 字节
目标 = max(2 × BDP, 4 MiB)
上限 = min(128 MiB, max(4 MiB, RAM / 8))
buf_max = min(目标, 上限)，按 4 KiB 对齐
buf_default = min(max(256 KiB, buf_max / 16), 1 MiB, buf_max)
```

不填带宽时按 RAM/16 估算，最高 64 MiB。所有值都是“上限/初始值”，不是预分配；仍受 `tcp_mem` 和实际内存约束。

### 可选 TCP Fast Open

单独选项 `tcp_fastopen=3`（客户端+服务端）。它可能被中间设备丢弃，且不是所有应用都使用；默认不启用。

## 4. 实施阶段

| 阶段 | 内容 | 验收 |
| --- | --- | --- |
| 0. 备份 | Git tag + 本地 tar | 可回到 v0.3.0-dev |
| 1. 调优模块 | `tuning.py`：保守/代理/缓冲档、状态文件、冲突检测、回滚、Fast Open 选项 | 单元测试覆盖重复执行、失败回滚、外部修改、冲突、恢复 |
| 2. 状态与菜单 | `status tuning`、主菜单“VPS 优化”、执行后回显 | 只读查询不修改；未知项不冒充正常 |
| 3. 发布 | v0.4.0-dev、文档、CI、latest 入口 | CI 全绿；一键安装/升级仍可用 |
| 4. 真实验收 | Ubuntu 24.04 / Debian 12 上用 iperf3/mtr 做前后对比；记录内存、CPU、重传、RTT | 未通过前保持“测试功能”，不写“加速 X 倍” |

## 5. 后续候选（不纳入首版）

- `limits.d` / systemd `LimitNOFILE`：需要逐服务验证，先只做状态。
- RPS/RFS：依赖网卡队列和 softirq 压力，自动写容易适得其反；先做只读检测。
- MSS Clamp / IP 转发：只对中转/路由场景有意义，需与 UFW/nftables 组合验证。
- qdisc/HTB 整形、initcwnd：需要实测和对端，失败影响面大。
- BBRv3/XanMod、锐速、闭源内核：暂不引入。
- DNS 切换：与 systemd-resolved、NetworkManager、云厂商冲突太多，保持只读。

## 6. 验证与回滚

- 应用前必须确认：Ubuntu/Debian、root、交互终端、`sysctl` 可用、目标键可读、无冲突。
- 应用失败：逐项恢复 `before`，删除项目配置/状态；恢复失败时保留状态并提示手动检查。
- 恢复：配置内容或运行值被外部修改时停止，不覆盖他人的调优。
- 重启后：sysctl.d 是否生效需单独验证；本工具不会自动重启。
- 性能结论：只能由同一机器、同一对端、同一时间窗的 A/B 测试支持；不以“参数已写入”作为性能提升证据。
