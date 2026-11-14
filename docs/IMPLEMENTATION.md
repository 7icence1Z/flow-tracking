# 实现细节

本文件记录 [README](../README.md) 之外的实现事实：资源占用、数据来源与自检方式。数值与结论均可由仓库内的脚本复现。

## 资源占用

常态（0.5 秒一帧）下不启动任何子进程：进程表、端口归属、网卡地址与网关均直接读取内核表，网关探活使用 ICMP 而非 `ping.exe`。原有实现保留为内部兜底（`_ps_table_wmi` / `_listen_map_netstat` / `_addrs_netsh` / `_gateway_ping`），内核表不可读时自动退回，行为不变。

| 一次操作 | 改动前 | 改动后 |
|---|---|---|
| 稳态子进程 | 约 20 次/分 | 0 次/分（60 秒实测 0 次） |
| 进程表（本机模式每 8 秒） | 0.9～1.0 s（PowerShell + WMI） | 17 ms（Toolhelp32） |
| 网卡地址与网关（每 20 秒） | 133 ms（`netsh`） | 10 ms（`GetAdaptersAddresses`） |
| 网关探活（每 15 秒两次） | 71 ms（`ping.exe`，含进程启动） | 8 ms（`IcmpSendEcho`） |
| 端口归属与连接表（每 15 秒 / 每帧） | 85 ms + 约 1.8 ms（新建 TCP） | 2 ms + 0.6～1.0 ms（长连接） |

采集器自身 CPU 与内存与改动前基本持平（约 2 % 单核、约 49 MB；打开一块面板约 51 MB）。节省的是子进程创建开销及其占用的 CPU，这部分原本计入 `powershell` / `netsh` / `ping` 等进程；本机模式下仅进程表一项，原实现即占用单核一成以上。

## 数据来源

| 事实 | 来源 |
|---|---|
| 系统代理开关与地址 | 注册表 `Internet Settings` 的 `ProxyEnable` / `ProxyServer` |
| 客户端身份与控制器位置 | `GetExtendedTcpTable` 端口归属 + 进程表（Toolhelp32，WMI 兜底）；控制器自动发现 |
| 模式 / TUN / 节点表 | 控制器 `/configs`、`/version` 与内核命令行指向的配置 |
| 每条连接是否经代理 | `/connections` 的 `chains`（`DIRECT` 表示直连） |
| 域名速率（Clash）/ 经代理（v2rayN） | 累计字节差分：前者按 `metadata.host` 归并，后者读取 `stats.outbound[tag]` |
| 网卡总量 / 不走代理 | `GetIfTable2` 的 `InOctets` / `OutOctets`；不走代理 = 总量 − 经代理（**差值估算**，仅在存在统计接口时） |
| 连接关系与端口归属 | `GetExtendedTcpTable(OWNER_PID_ALL)` v4 + v6，按进程归并，剔除回环 |
| 每进程速率（管理员）/ 进客户端字节 | `GetPerTcpConnectionEStats` 的 `DataBytesIn/Out` 差分；后者为「应用 → 本地代理口」回环 TCP 的入口字节 |
| 出口 IP 与网卡 | 经代理口请求 `ip-api.com`（120 秒）/ 绕过代理（300 秒）；`connect()` 询问内核选取源地址后反查网卡 |
| 地址、网关、Wi-Fi 与探活 | `GetAdaptersAddresses`（`netsh` 兜底）；信道与频段经 `netsh wlan` 读取；`IcmpSendEcho`（退回 `ping -n 1 -w 900`）与直连 UDP 查询 `223.5.5.5` 比对 DNS；异常归类为 DNS / 拒绝 / 重置 / 超时 / 不可达 / TLS / 绑定网卡失败 |

## 自检

| 脚本 | 内容 |
|---|---|
| `tools/test_diag.py` | 诊断判定 41 项，覆盖各层失败与灰色情形 |
| `tools/test_xray.py` | v2rayN 适配：配置解析、节点表、假统计接口 |
| `tools/test_estats.py` | 普通权限下 eStats 返回 5 的降级路径 |
| `tools/check_js.py` | 面板 JS 语法检查 |
| `tools/mock_state.py` | 生成演示数据（README 截图即由此产生） |

运行方式：`python tools/test_diag.py`，其余同理；全部仅依赖标准库。
