<h1 align="center">FLOW · 流量出口监看</h1>

<p align="center"><sub>直连还是经隧道 · 经由哪块网卡 · 从哪个公网 IP 出口</sub></p>

<p align="center">
  <a href="https://github.com/7icence1Z/flow-tracking/releases"><img alt="release" src="https://img.shields.io/github/v/release/7icence1Z/flow-tracking?style=flat-square&label=release&labelColor=14171c&color=d99a4e"></a>
  <a href="https://www.npmjs.com/package/@7icence1z/flow-tracking"><img alt="npm" src="https://img.shields.io/npm/v/@7icence1z/flow-tracking?style=flat-square&label=npm&labelColor=14171c&color=cb3837"></a>
  <a href="LICENSE"><img alt="license" src="https://img.shields.io/badge/license-MIT-5fada5?style=flat-square&labelColor=14171c"></a>
  <img alt="platform" src="https://img.shields.io/badge/platform-Windows%2010%2F11-5fada5?style=flat-square&labelColor=14171c">
  <img alt="python" src="https://img.shields.io/badge/python-3.10%2B-5fada5?style=flat-square&labelColor=14171c">
  <img alt="deps" src="https://img.shields.io/badge/deps-0%20%C2%B7%20stdlib-2f6f6b?style=flat-square&labelColor=14171c">
  <img alt="telemetry" src="https://img.shields.io/badge/telemetry-none-2f6f6b?style=flat-square&labelColor=14171c">
</p>

<p align="center">
  <a href="README.en.md">English</a> · <a href="CHANGELOG.md">变更记录</a>
</p>

<p align="center"><img src="docs/demo.gif" width="780" alt="FLOW 面板演示"></p>
<p align="center"><sub>13 秒循环，真实界面渲染；图中的数据均为虚构值，由 <code>tools/mock_state.py</code> 生成，可复现。<br><a href="https://github.com/7icence1Z/flow-tracking/releases/latest">2K 完整版（25 秒，含本机模式与逐进程速率）</a></sub></p>

## 概述

本程序是仅在本机运行的小型监控面板，用于回答一个问题：**当前时刻的流量是直连还是经隧道转发、经由哪块网卡、从哪个公网 IP 出口。**它同时统计三条数据线 —— 网卡总量、经代理、不经代理 —— 并按实际出口为站点着色；未启用客户端时依据网卡与进程继续统计，客户端未提供统计接口时从其本地代理端口取样。适用于 Windows 10/11，仅使用 Python 标准库，无第三方依赖，无遥测。当前版本 **v0.1.4**（2026-11-13），变更详见 [CHANGELOG](CHANGELOG.md)。

## 安装

```powershell
npm i -g @7icence1z/flow-tracking     # 需要 Node 16+，仅负责调度
flow                                   # 启动采集器并打开面板
```

| 命令 | 作用 |
|---|---|
| `flow` / `flow stop` | 启动 / 停止采集器 |
| `flow status`（`flow stat`） | 一屏显示模式、判定、诊断、分账与出口，不打开面板；采集器未运行时以状态码 1 退出 |
| `flow admin` | 以管理员身份启动。仅管理员可见每进程速率，`flow` 本身不请求提权 |
| `flow --port 7718` / `-h` / `-v` | 指定端口（`flow status -p 7718` 同样可用）/ 用法 / 版本 |
| `npx @7icence1z/flow-tracking@latest` | 不安装直接运行；省略 `@latest` 会使用 npx 缓存中的旧版本 |

运行前提为 Python 3.10 及以上（仅使用标准库）与 Edge 或 Chrome；窗口以 `--app=` 模式启动，独立 profile，已启动时不重复打开，`start.ps1` 另支持 `-Port` / `-Width` / `-Height` / `-DefaultProfile`。不使用 npm 时无需 Node：

```powershell
powershell -ExecutionPolicy Bypass -File .\start.ps1     # 亦可双击 start.cmd；-Stop 停止
```

更新由包管理器完成，不提供 `flow update`：全局安装执行 `npm i -g @7icence1z/flow-tracking@latest`，git 副本执行 `git pull`。

**每进程速率需要管理员权限**：先 `flow stop`，再 `flow admin`（或右键以管理员身份运行 `start.cmd`）。普通权限的采集器不会被提权实例接管，必须先停止；原因见[本机模式](#未启用客户端时本机模式)。

## 面板

- **顶部判定**：经隧道 / 部分经隧道 / 直连 / 本机直连 / 隧道统计不可读。副标题显示节点名与隧道出口 IP，小字标注判定依据（系统代理注册表、控制器模式、客户端身份）
- **两条数据泳道**：本机 IP → 网卡 → 节点 → 出口。网卡由内核路由判定（对目标执行 `connect()` 并读回源地址），不依网卡名推测；右侧为实时速率与 `承载 17 条 · rule · TUN 关`
- **吞吐与分账**：0.5 秒一帧、120 秒曲线（本机模式枚举连接，为 1 秒一帧）。总量取自网卡累计字节（`GetIfTable2`）；`经代理 121 KB/s · 不经代理 8.5 KB/s` 中后者为差值**估算**。曲线按各采样点当时的判定着色：关闭 VPN 后琥珀段既不消失也不增长，只随窗口左移滑出
- **通道探测**：代理与直连分别请求同一目标，另设国内对照点；失败归因为 DNS / 拒绝 / 重置 / 超时 / TLS，并显示最近 96 次结果刻度。卡头 ✎ 可改探测目标、对照目标与间隔（5～120 秒），保存即生效
- **诊断结论**：右上角结论由证据计算得出，悬停可查看支撑证据
- **站点**：按域名归并的 ↓↑ 速率，颜色对应实际出口（琥珀 = 隧道，青色 = 直连）；「＋ 域名」写入 `config.json`
- **语言与连接状态**：顶栏 中 / EN 切换（英文采用英式拼写，记于浏览器本地，亦支持 `?lang=en`）；连续 6 秒无新帧时显示 `采集器未连接 · 最后 21:03:10`，读数变淡表示为旧帧

## 未启用客户端时（本机模式）

未检测到客户端时自动切换为**本机模式**：统计网卡总量、连接数以及按进程归并的 TCP 连接关系（剔除回环）。客户端在运行但字节数不可读时（典型为 v2rayN 关闭统计接口），区分三种情形：

- 系统代理指向客户端自身开放的本地端口 → 判定 `部分经隧道`，副标题「在转发 · 字节数不可读」。此时已能证明其在转发，故不表述为「未在走隧道」
- **管理员权限下**沿「应用 → 本地端口」的回环 TCP 读取**进入客户端**的字节（`split.client`），改述为「客户端在转发（经本地口计数）」，副标题「经它的本地口计数，隧道份额未知」。入口字节不等于隧道流量，该值仅为上限
- 无法证明时，判定 `本机直连`，理由仅表述为「读不到它的流量」，不对其行为作出断言

<p align="center">
  <img src="docs/panel-host.png" width="49%" alt="本机模式">
  <img src="docs/panel-host-admin.png" width="49%" alt="本机模式（管理员）">
</p>

**权限决定统计粒度**，这是唯一需要选择之处：

| 项目 | 普通权限 | 管理员 |
|---|---|---|
| 网卡总量 / 连接数 / 谁在连谁 | ✅ | ✅ |
| 每进程 ↓↑ 与曲线 | ❌ 仅统计连接 | ✅ 内核 eStats 差分（仅 TCP 净荷） |
| 经代理 / 不走代理分账 | ❌（客户端接口提供的另计） | ❌ 需客户端统计接口；可得者为下一行 |
| 进客户端的字节（经本地口） | ❌ | ✅ 回环代理口 eStats 差分，仅系统代理模式；**入口 ≠ 隧道** |
| 页脚 | `普通权限 · 仅统计连接` | `管理员：逐进程速率`，系统代理模式下加 `+ 经客户端字节` |

eStats 在普通权限下返回 5 时立即退回仅统计连接，不重试、不推测（覆盖见 `tools/test_estats.py`）；UDP/QUIC 不计入进程行。客户端在运行但未连接节点亦归入此类。

## 支持的客户端

客户端自动发现，无需配置：端口归属（`GetExtendedTcpTable`）→ `GET /version` 识别 Clash API → 依内核命令行定位配置 → 解析节点表，每一步均带存活校验；客户端退出后身份信息一并清除。

| 客户端 | 判定 | 节点名 | 逐条连接 | 字节 |
|---|---|---|---|---|
| Clash Verge / Mihomo Party / FlClash / mihomo / 机场定制 | ✅ | ✅ | ✅ | ✅ 按域名 |
| sing-box（开启 `clash_api`） | ✅ | ✅ | ✅ | ✅ 按域名 |
| v2rayN（Xray 内核） | ✅ | ✅ 读取 `guiNDB.db` | ❌ | ✅ 按出口 |
| 其它 Xray 壳 / WireGuard / OpenVPN / Tailscale | ✅ | 无法识别时显示地址 | ❌ | 网卡 + 出口 |
| 未运行任何客户端 | ✅ 本机直连 | — | ✅ 按进程 | 网卡总量 |

可见度如实标注为**连接级**（按域名）、**出口级**（v2rayN 读其 `metrics.listen` 的 `/debug/vars` 做差分，仅有「经代理 / 直连」两行）、**仅网卡**与**本机级**；无逐域名数据时如实说明，不以总量代填。

<p align="center"><img src="docs/panel-xray.png" width="780" alt="v2rayN（出口级可见度）"></p>

## 诊断

采用排除法：自底层向上逐层判定，层级越低者优先报出。**红色仅用于「声称在用但不可用」的情形**，「当前确实未在使用隧道」一律以中性灰表示。

共 15 种结论：链路正常 · 目标被墙而代理正常 · 目标需要进出隧道 · ⟨网卡⟩ 链路不通 · DNS 解析有问题 · 链路通但外面不通 · VPN 本地代理口未开启 · 代理口被其他程序占用 · VPN 未连接节点（灰）· VPN 拒绝连接 · ⟨隧道网卡⟩ 链路不通 · 代理侧 DNS 失败 · VPN 隧道或节点异常 · 客户端在转发但读不到字节数（灰）· 仅统计本机流量（灰）。悬停结论可查看支撑证据，`flow status` 输出同一结论。

## 与同类工具的关系

| 工具 | 每进程流量 | 区分经隧道 / 直连 | 网卡与出口 IP | 客户端未运行时 |
|---|---|---|---|---|
| [GlassWire](https://www.glasswire.com/userguide/) / [NetLimiter](https://netlimiter.com/docs/using-with-vpns)（商业） | ✅ | ❌ 经隧道的流量计入客户端进程，重复计量 | ❌ | ❌ |
| [TrafficMonitor](https://github.com/zhongyang219/TrafficMonitor)（含每进程插件） | ✅ | ❌ | ❌ | ✅ 仅速率 |
| [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev) 连接页 | 逐条连接 | 逐条连接可见策略链 | ❌ | ❌ |
| [proxytop](https://www.npmjs.com/package/proxytop)（macOS 终端） | ✅ | ✅ | ✅ 接口级 | ❌ 仅 macOS |
| **本程序** | ✅ 需管理员 | ✅ 网卡总量 − 统计接口 | ✅ | ✅ 本机模式 |

差异不在界面，而在分账（不经代理的字节由网卡总量与经代理之差得出，客户端无统计接口时以本地代理入口字节兜底并标注为上限）、出口归属（同时给出网卡与公网出口 IP）与客户端缺席时的可用性（覆盖未安装、未启动、未开 API、未开 TUN 四种情形）。本程序不替代上述工具：Clash 面板给出逐条连接，本程序给出按进程的分账与出口，二者互补。

## 实现细节

资源占用、数据来源与自检方式记录于 [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md)：常态下不启动任何子进程，进程表、端口归属与网卡数据均直读内核表。

## 配置与接口

| 键 | 默认值 | 说明 |
|---|---|---|
| `port` | `7717` | 面板端口，仅绑定 `127.0.0.1` |
| `controller` | `127.0.0.1:7892` | Clash 控制器地址；留空则完全自动发现 |
| `mixed_port` | `127.0.0.1:7890` | 出口 IP 探测与「代理通道」所用端口；v2rayN 读自身配置，此项仅作兜底 |
| `sites` | `["chatgpt.com","openai.com"]` | 单独监控速率的域名（后缀匹配），「＋ 域名」修改此项 |
| `probe_interval` | `10` | 探测间隔（秒），取值 5～120 |
| `probe_target` / `control_target` | chatgpt / baidu | 双通道探测目标 / 直连泳道的对照目标；仅接受 http(s)，不可指向本机 |

环境变量：`FLOW_PORT`、`FLOW_CONTROLLER`。修改后需重启采集器；探测三项为例外，经卡头 ✎ 修改后立即生效。

接口：`/`（面板）、`/api/state`（快照 JSON）、`/api/stream`（SSE，0.5 秒一帧）、`/?poll=1`（退化为轮询）、`POST /api/sites`（`{"action":"add"|"remove","domain":…}`）、`POST /api/probe`（`{"target","control","interval"}`，三项均可省略；出错返回 400 与中英两版 `msg`）。快照中需关注的字段：

- `flow`：`""`（Clash 系，连接级）/ `xray`（出口级）/ `host`（本机模式）
- `path`：`{active, reason, sysproxy}`，`active` 取 `vpn` / `mixed` / `direct` / `down`
- `diag`：`{state, label, why, evidence}`，后三者为 `{zh, en}`
- `split`：`{nic, proxy, direct, client, src}`；`src` 为 `api`（数值来自统计接口）或 `loop`（`client` 为入口字节，此时 `proxy` / `direct` 为 `null`）

其余 `probe` / `tunnel` / `client` / `iface` / `route` / `node` / `egress` / `probes` / `sites` / `extras` / `hist` 按名称读取；`tools/peek.py` 是上述接口的命令行查看器。

## 隐私

仅监听 `127.0.0.1`（局域网内其他主机无法连接）；仅读取本机状态（注册表、进程表、网卡统计、配置，SQLite 以只读方式打开）；对外请求仅有出口 IP 探测与通道探测，不携带身份信息；不写日志、不收集、不上传；面板不引用任何外部资源（无 CDN、字体与统计脚本）。

## 目录结构

```
server.py             采集 + HTTP/SSE（标准库，单文件）
providers.py          客户端发现 / 配置解析 / 订阅感知 / Xray 统计口
hostflow.py           本机模式：GetIfTable2 + GetExtendedTcpTable + GetAdaptersAddresses + 管理员 eStats（纯 ctypes）
diag.py               网关（ICMP）/ DNS 对比 / 按网卡握手 / 错误归类
web/index.html        面板（单文件，内联 CSS/JS，手写 SVG）
start.ps1, start.cmd  启动器 / 双击入口
package.json, bin/flow.js  npm 包装（flow 仅将参数转交 start.ps1）
config.json           配置
docs/                 四张示意图（Clash / v2rayN / 本机 / 本机+管理员）
tools/                peek.py 查看快照 · mock_state.py 生成演示数据 · test_* 自检 · check_js.py JS 语法检查
```

## 常见问题

| 现象或问题 | 原因与处理 |
|---|---|
| 是否必须使用管理员权限 | 否。仅「每进程速率」与「进客户端的字节」需要；进程卡只有连接数、无速率即表示当前为普通权限，执行 `flow stop` → `flow admin` 即可 |
| 为什么「不走代理」是估算值 | 它恒等于网卡总量与经代理之差，含加密与帧开销，略微偏高，不应视为精确的直连流量 |
| 杀毒软件提示或 SmartScreen 拦截 | 未签名的 Python 脚本与 PowerShell 启动器常被拦。可核对源码后本地运行，或提交 issue 附 `flow status` 输出 |
| 面板不刷新或一直显示旧帧 | SSE 被拦截时改用 `http://127.0.0.1:7717/?poll=1`；顶栏显示 `采集器未连接` 则采集器已退出 |
| 提示「本地控制器没有响应」 | 客户端未启动，或未开启 REST API（Clash 系需勾选「外部控制」） |
| 已启用 VPN，面板仍显示「直连」 | 流量未交给客户端：系统代理关闭、TUN 关闭或 `7890` 无连接。请在客户端启用「系统代理」或「TUN」 |
| 未启用 VPN，面板却显示「部分经隧道」 | 先确认顶栏未显示 `采集器未连接`（否则为旧帧）；`flow status` 中 `direct` 表示直连。客户端进程残留时须同时满足「系统代理开启、本地端口在监听、进程存活」三项方判定为在转发 |
| 站点速率持续为 `0 B/s` | 该秒无流量，或该站点走直连（Clash 系不统计直连流量） |
| 中文乱码 / 启动器报语法错误 | `.ps1` 须以带 BOM 的 UTF-8 保存（仓库内文件已含 BOM，编辑后勿丢失） |
| 如何更新与卸载 | 更新：`npm i -g @7icence1z/flow-tracking@latest`；卸载：`npm rm -g @7icence1z/flow-tracking`。git 副本执行 `git pull` |
| 是否支持 macOS / Linux | 否。依赖 Windows 内核网络表（`GetIfTable2` / `GetExtendedTcpTable` / `GetAdaptersAddresses`）与 `netsh` |

## 边界与限制

- **「经代理」仅来源于客户端统计接口**（Clash `/connections`、Xray `/debug/vars`）；**不走代理**恒为网卡总量与经代理之差，属**估算值**（含加密与帧开销，略微偏高）
- **「经本地口」统计入口字节，并非隧道流量**：系统代理模式下应用先连接客户端本地端口，eStats 仅表示进入客户端的流量，客户端可能按规则将部分流量直接转发，故该值仅为上限；且仅覆盖「系统代理 → 本地端口」——TUN 模式无回环代理连接，UDP/QUIC 不经 HTTP 代理端口
- **粒度与精度取决于权限与客户端**：逐进程、逐域名字节需内核 eStats 或 DNS 缓存，二者均需管理员（非管理员 `SetPerTcpConnectionEStats` 返回 5，`ipconfig /displaydns` 需提升权限）；eStats 仅统计 **TCP 净荷**。可见度随客户端而异：Clash 至域名，Xray 至出口，WireGuard 仅有网卡与出口 IP，不以总量分摊到域名后冒充精确值
- **诊断采用排除法，并非抓包**：可区分「链路 / DNS / 隧道 / 目标」四层，无法区分物理链路故障与路由器故障；一轮约 15 秒，证据为快照；公共 DNS 固定为 `223.5.5.5`
- **适配范围与平台**：v2rayN 依据其生成配置的格式适配（以构造样本与假统计接口验证，未覆盖所有版本；`guiNDB.db` 结构变化后仅退回显示地址）；客户端未连接节点时无法区分「未连接」与「已连接但不通」，按最可能的解释以灰色呈现。仅支持 Windows，只读、不修改系统代理与路由，终止采集器不影响任何系统状态

## 许可

以 [MIT](LICENSE) 发布：可自由使用、修改与再分发，须保留版权与许可声明；软件按原样提供，不附带任何担保。本程序不包含第三方代码。
