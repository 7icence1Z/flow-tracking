# FLOW · 流量出口监看

<p align="center">
  <a href="https://github.com/7icence1Z/flow-tracking/releases"><img alt="release" src="https://img.shields.io/github/v/release/7icence1Z/flow-tracking?style=flat-square&label=release&labelColor=14171c&color=d99a4e"></a>
  <a href="https://www.npmjs.com/package/@7icence1z/flow-tracking"><img alt="npm" src="https://img.shields.io/npm/v/@7icence1z/flow-tracking?style=flat-square&label=npm&labelColor=14171c&color=cb3837"></a>
  <img alt="platform" src="https://img.shields.io/badge/platform-Windows%2010%2F11-5fada5?style=flat-square&labelColor=14171c">
  <img alt="python" src="https://img.shields.io/badge/python-3.10%2B-5fada5?style=flat-square&labelColor=14171c">
  <img alt="deps" src="https://img.shields.io/badge/deps-0%20%C2%B7%20stdlib-2f6f6b?style=flat-square&labelColor=14171c">
  <img alt="telemetry" src="https://img.shields.io/badge/telemetry-none-2f6f6b?style=flat-square&labelColor=14171c">
</p>

一个只在本机跑的小面板：**这一刻的流量走直连还是走 VPN、走的哪块网卡、从哪个 IP 出去。**

两条路一起数（网卡总量 / 经代理 / 不走代理），站点按实际出口染色；没开 VPN 也按网卡和进程继续数。
Windows 10/11 · Python 标准库 · 零依赖 · 无遥测 · 当前 **v0.1.2**（[CHANGELOG](CHANGELOG.md)）

## 安装

```powershell
npm i -g @7icence1z/flow-tracking     # 需要 Node 16+（只负责搬运）
flow                                   # 起采集器 + 打开面板
```

| 命令 | 作用 |
|---|---|
| `flow` / `flow stop` | 起 / 停采集器 |
| `flow admin` | 以管理员打开 —— **只有管理员**才看得见每进程速率；`flow` 本身不提权 |
| `flow --port 7718` | 换端口（默认 7717） |
| `npx @7icence1z/flow-tracking` | 不装全局，跑一次 |

不想用 npm 就直接跑（连 Node 都不需要）：

```powershell
powershell -ExecutionPolicy Bypass -File .\start.ps1        # 或者双击 start.cmd
powershell -ExecutionPolicy Bypass -File .\start.ps1 -Stop
```

前提：Python 3.10+（只用标准库）、装了 Edge 或 Chrome。窗口是 `--app=` 模式（没有地址栏和标签页），
用独立 profile，不碰你日常浏览器；已经开着时不会再开第二扇。
`start.ps1` 另有 `-Port` / `-Width` / `-Height` / `-DefaultProfile`。

**想要每进程速率**：`flow stop` 之后 `flow admin`（或右键 `start.cmd` → 以管理员身份运行）。
已经有个非管理员采集器在跑时，提权那次不会接管它 —— 必须先停。原因见[「没开 VPN 的时候」](#没开-vpn-的时候)。

![FLOW 面板](docs/panel.png)

> 图里数据全是编的（`192.168.1.x` / `203.0.113.x` / `HomeNet-5G` / `Clash Verge`），由 `tools/mock_state.py` 生成，可复现。

## 面板上有什么

- **顶部判定**：走 VPN / 部分走 VPN / 直连 / 本机直连 / 隧道读不到；副标题是节点 + 隧道出口 IP，小字写判定依据（系统代理注册表、控制器模式、客户端身份）
- **两条泳道**：本机 IP → 网卡 → 节点 → 出口。网卡按内核路由判（拿目标地址 `connect()` 看它给的源地址），不是按网卡名猜；右侧挂实时速率和 `承载 17 条 · rule · TUN 关`
- **实时吞吐 + 分账**：1 秒一帧、120 秒曲线。大盘是**网卡总量**（`GetIfTable2`），旁边写 `经代理 121 KB/s · 不走代理 8.5 KB/s` —— 后者是差值**估算**（含 UDP/QUIC 帧开销）
- **通道探测**：代理 / 直连打同一个目标 + 国内对照点；失败直接给病因（DNS / 拒绝 / 重置 / 超时 / TLS），最近 96 次刻度
- **诊断结论**：右上角那句话是由证据算出来的，不是标题；鼠标停上去看支撑它的那几条
- **站点**：按域名归并的 ↓↑，颜色跟实际出口（琥珀=隧道、青=直连）；底部「＋ 域名」可直接加，写回 `config.json`

## 没开 VPN 的时候

检测不到代理客户端就自动切**本机模式**（判定写 `本机直连`）：网卡总量、连接数、谁在连谁（按进程归并 TCP 连接，剔掉回环）。

![本机模式](docs/panel-host.png)

**权限决定粒度** —— 这是唯一需要你做选择的地方：

| | 普通权限 | 管理员 |
|---|---|---|
| 网卡总量 / 连接数 / 谁在连谁 | ✅ | ✅ |
| 每进程 ↓↑ 与曲线 | ❌ 只数连接 | ✅ 内核 eStats 差分（只数 TCP 净荷） |
| 页脚 | `普通权限：只数连接` | `管理员：逐进程速率` |

![本机模式 · 管理员](docs/panel-host-admin.png)

eStats 在普通权限下返回 5 就**立刻**退回只数连接，不重试不编数字（`tools/test_estats.py` 覆盖）；UDP/QUIC 不进进程行。
"客户端在跑但没连节点"也归到这里，理由写"读不到它的流量"—— 不再红着喊隧道坏了。

## 适配哪些客户端

自动发现，不用配：`netstat` 端口归属 → 探 `GET /version` 认 Clash API → 从内核命令行找配置 → 解析节点表 → 每步带存活校验；客户端退出后身份会被清掉。

| 客户端 | 判定 | 节点名 | 逐条连接 | 字节 |
|---|---|---|---|---|
| Clash Verge / Mihomo Party / FlClash / mihomo / 机场定制 | ✅ | ✅ | ✅ | ✅ 按域名 |
| sing-box（开 `clash_api`） | ✅ | ✅ | ✅ | ✅ 按域名 |
| v2rayN（Xray 内核） | ✅ | ✅ 读 `guiNDB.db` | ❌ | ✅ 按出口 |
| 其它 Xray 壳 / WireGuard / OpenVPN / Tailscale | ✅ | 认不到就显示地址 | ❌ | 网卡 + 出口 |
| 什么都没开 | ✅ 本机直连 | — | ✅ 按进程 | 网卡总量 |

四种可见度如实标注：**连接级**（按域名）/ **出口级**（v2rayN 从它自己写的 `metrics.listen` 打 `/debug/vars` 差分，只有"经代理 / 直连"两行）/ **只有网卡** / **本机级**。没有逐域名数据就说没有，不拿总数凑。

![v2rayN 结构](docs/panel-xray.png)

## 一句话结论怎么算的

排除法：从底层往上排，越底层越先报。**红色只留给"说在用、但用不了"**，"现在没在用隧道"一律中性灰。

| 结论 | 依据 | 该干什么 |
|---|---|---|
| 链路正常 | 对照 / 直连 / 代理三条全通 | 没事 |
| 目标被墙，代理正常 | 对照和代理通、只有直连目标不通 | 正常现象 |
| 目标需要进出隧道 | TUN 已接管，直连探测其实也走隧道 | 不用管 |
| ⟨网卡⟩ 链路不通 | 连对照都打不开，且网关 ping 不回 | 查网线 / Wi-Fi |
| DNS 解析有问题 | 网关通、对照域名解析不出来 | 换 DNS |
| 链路通、外面不通 | 网关通、域名也解析得出，对照照样连不上 | 运营商 / 站点 |
| VPN 本地代理口没开 | `127.0.0.1:7890` 拒绝或超时 | 客户端没启动 / 没开系统代理 |
| 代理口被占，不是客户端 | 端口能连但不转发，也没找到客户端 | 换端口 |
| VPN 没连上节点（灰） | 代理口通、客户端在，隧道里 0 条连接 | 选节点 / 点连接 |
| VPN 拒绝连接 | 端口开着、客户端也在，但拒了 | 客户端没准备好 |
| ⟨隧道网卡⟩ 链路不通 | 代理通道失败 + 隧道网卡网关不响应 | 先修链路 |
| 代理侧 DNS 失败 | 请求到隧道了，域名在隧道里解析不出来 | 看节点 DNS |
| VPN 隧道/节点异常 | 链路、代理口、连接都正常，经隧道还是打不通 | 换节点 / 看订阅 |
| 只看本机流量（灰） | 读不到客户端，或压根没检测到 | 按网卡继续数 |

## 数据从哪来

| 事实 | 来源 |
|---|---|
| 系统代理开关 / 地址 | 注册表 `Internet Settings` 的 `ProxyEnable` / `ProxyServer` |
| 客户端是谁、控制器在哪 | `netstat` 端口归属 + WMI；控制器自动发现，`config.json` 只当提示 |
| 模式 / TUN / 节点表 | 控制器 `/configs`、`/version` + 内核命令行指向的配置 |
| 每条连接走没走代理 | `/connections` 的 `chains`（`DIRECT` = 直连） |
| 域名速率（Clash 系） | 连接累计字节 1 Hz 差分，按 `metadata.host` 归并 |
| 经代理 / 直连（v2rayN） | `GET /debug/vars` → `stats.outbound[tag]`，同样差分 |
| 网卡总量 | `GetIfTable2` 的 `InOctets` / `OutOctets`，1 Hz 差分，一直采 |
| 不走代理 | 网卡总量 − 经代理（**差值估算**） |
| 谁在连谁 | `GetExtendedTcpTable(OWNER_PID_ALL)`，按进程归并，剔回环 |
| 每进程速率（管理员） | `SetPerTcpConnectionEStats` / `GetPerTcpConnectionEStats` → `DataBytesIn/Out` 差分 |
| 出口 IP | 经代理口打 `ip-api.com`（120s 一次）/ 绕过代理（300s 一次） |
| 走哪块网卡 | `connect()` 问内核选哪个源地址，再反查成网卡 |
| Wi-Fi 细节 / 网关 / 度量 | `netsh wlan show interfaces`、`netsh interface ipv4 show addresses` |
| 网关通不通 | `ping -n 1 -w 900`，只看退出码（不解析输出，中英文系统都稳） |
| DNS 对不对 | 系统解析一次 + 直接 UDP 问 `223.5.5.5`，不一致标"疑似污染" |
| 某块网卡单独通不通 | 把源地址绑到那块网卡再 `connect()` 目标 443 |
| 连不上的原因 | 异常归类成 DNS / 拒绝 / 重置 / 超时 / 不可达 / TLS / 绑不上网卡 |

## 配置（`config.json`）

| 键 | 默认 | 说明 |
|---|---|---|
| `port` | `7717` | 面板端口，只绑 `127.0.0.1` |
| `controller` | `127.0.0.1:7892` | Clash 控制器；留空就完全自动发现 |
| `mixed_port` | `127.0.0.1:7890` | 出口 IP 探测和"代理通道"走它；v2rayN 会从自己配置里读，这个只兜底 |
| `sites` | `["chatgpt.com","openai.com"]` | 单独盯速率的域名，后缀匹配；「＋ 域名」改的就是这里 |
| `probe_interval` | `10` | 探测间隔秒，最小 5 |
| `probe_target` / `control_target` | chatgpt / baidu | 双通道探测目标 / 直连泳道里的对照目标 |

环境变量：`FLOW_PORT`、`FLOW_CONTROLLER`。改完重启采集器生效。

## HTTP 接口

`/`（面板）、`/api/state`（快照 JSON）、`/api/stream`（SSE，每秒一帧）、`/?poll=1`（退化成轮询）、
`POST /api/sites`（`{"action":"add"|"remove","domain":"github.com"}`）。快照关键字段：

| 字段 | 内容 |
|---|---|
| `flow` | `""`（Clash 系，连接级）/ `xray`（出口级）/ `host`（本机模式） |
| `path` | `{active, reason, sysproxy}`，`active` = `vpn` / `mixed` / `direct` / `down` |
| `diag` | `{state, label, why, evidence}` |
| `split` | `{nic, proxy, direct}`；本机模式下后两项为 `null` |
| `host` | `{nic, conns, cum, estats, elevated, procs}` |
| 其它 | `tunnel` / `client` / `iface` / `route` / `node` / `egress` / `probes` / `sites` / `extras` / `hist` |

`tools/peek.py` 是这套接口的命令行查看器，排障时比开面板快。

## 隐私

只监听 `127.0.0.1`（局域网里的别人连不上）；只读本机状态（注册表、进程表、网卡统计、配置文件，SQLite 只读打开）；
外网请求只有出口 IP 探测和通道探测，不带任何身份；不写日志、不收集、不上传；面板不引任何外链（无 CDN / 字体 / 统计脚本）。

## 目录结构

```
server.py             采集 + HTTP/SSE（标准库，单文件）
providers.py          客户端发现 / 配置解析 / 订阅感知 / Xray 统计口
hostflow.py           本机模式：GetIfTable2 + GetExtendedTcpTable + 管理员 eStats（纯 ctypes）
diag.py               网关 / DNS 对比 / 按网卡握手 / 错误归类
web/index.html        面板（单文件，内联 CSS/JS，手写 SVG）
start.ps1, start.cmd  启动器 / 双击入口
package.json, bin/flow.js  npm 包装（flow 只把参数翻译给 start.ps1）
config.json           配置
docs/                 四张示意图（Clash / v2rayN / 本机 / 本机+管理员）
tools/                peek.py 看快照 · mock_state.py 造假数据出图 · test_diag / test_xray / test_estats 自检
```

## 排障

| 现象 | 怎么办 |
|---|---|
| 面板说"本地控制器没有响应" | 客户端没开，或没开 REST API（Clash 系勾"外部控制"） |
| 关了节点一直说隧道坏了 | 不会了，回落本机模式；软件关掉后连客户端名都不再显示 |
| 进程卡只有连接数、没速率 | 普通权限。`flow stop` → `flow admin`，或右键 `start.cmd` 提权 |
| 判定是"部分走 VPN" | 客户端在跑但系统代理没开 —— 只有显式配了代理的程序走隧道 |
| 站点一直 `0 B/s` | 这秒没流量，或它走的是直连（Clash 系不计直连流量） |
| 面板不刷新 | SSE 被拦，用 `http://127.0.0.1:7717/?poll=1` |
| 中文乱码 / 启动器报语法错 | `.ps1` 必须是 UTF-8 **带 BOM**（仓库里带着，编辑后别把它存丢了） |
| 诊断说"⟨网卡⟩ 链路不通"可网是好的 | 有些路由器不回 ICMP；看同时刻"直连对照"，它通就说明诊断判不了 |

## 边界

- **只看得到客户端说它转发了多少**：系统代理关掉、程序又不认代理的流量不在连接表里，这时判定显示"部分走 VPN"；但网卡总量始终是真数，差额由"不走代理"暴露
- **本机模式的粒度取决于权限**：逐进程 / 逐域名的字节数要内核 eStats 或 DNS 缓存，两者都要管理员（实测非管理员 `SetPerTcpConnectionEStats` 回 5、`ipconfig /displaydns` 直接要提升）；eStats 只数 **TCP 净荷**，UDP/QUIC 只体现在网卡总量；`GetExtendedTcpTable` 只给 TCP，数不到 UDP 会话
- **精度**：不走去代理是**差值**（含帧开销、丢包、两个时钟的抖动）；粒度取决于客户端 —— Clash 到域名、Xray 到出口、WireGuard 只有网卡和出口 IP，**不拿总数摊到域名上冒充精确**
- **诊断是排除法，不是抓包**：能分"链路 / DNS / 隧道 / 目标"四层，分不清"网线松了还是路由器坏了"；一轮 15 秒、与对照同频，证据是快照不是连续记录；公共 DNS 固定 `223.5.5.5`
- **适配**：v2rayN 依据它生成配置的格式（构造样本 + 假统计口验证，没覆盖所有版本；`guiNDB.db` 结构变了只退回显示地址）；客户端没连节点时分不清"没连"还是"连了但不通"，按最可能的解释报灰
- **只读**：不改系统代理、不改路由、不动客户端配置，杀掉采集器什么都不影响
- **只有 Windows**：依赖注册表、WMI、`netsh`、`GetIfTable2`

## 版本与自检

语义化版本，当前 **v0.1.2**（[CHANGELOG](CHANGELOG.md)）。
v0.1.2 = 诊断结论 + 本机模式（含管理员逐进程速率）+ 分账；v0.1.1 = 多客户端发现 / 节点名 / 订阅 / 界面重做；v0.1.0 = 只认 mihomo。

```powershell
python -X utf8 tools\test_diag.py     # 14 组构造证据 + 9 组异常分类
python -X utf8 tools\test_xray.py     # v2rayN 适配（假配置 + 假统计口）
python -X utf8 tools\test_estats.py   # eStats 结构体 + 普通权限退化
```
