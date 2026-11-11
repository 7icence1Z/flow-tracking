# FLOW · 流量出口监看

一个只在本机跑的小面板，回答一个问题：**这一刻的流量，是走直连，还是走 VPN？走的哪块网卡、从哪个 IP 出去？**

```
python server.py       →  http://127.0.0.1:7717/
```

打开后是一块深色仪表盘：顶部一句话判定，中间两条并列的"出口路径"，
下面是实时吞吐、通道探测、按域名的流量和网卡明细。

---

## 一、面板在看什么

### 1. 顶部判定（一句话结论）

| 判定 | 含义 |
|---|---|
| **走 VPN** | 系统代理开着且指向 mihomo，代理感知型程序（浏览器等）全部经隧道 |
| **直连** | 系统代理没开，也没有别的分流，流量直接出去 |
| **部分走 VPN** | mihomo 在跑，但系统代理没开 —— 只有显式配了代理的程序走隧道 |
| **隧道异常** | mihomo 进程/控制器/端口没了，或系统代理指向了一个不存在的代理 |

副标题给出关键坐标，比如 `hk-node-07 · 203.0.113.24`（节点 + 隧道出口 IP）。
下面那行灰字是判定依据，例如"系统代理已开启并指向 127.0.0.1:7890（mihomo global 模式）"。

### 2. 出口路径（两条泳道）

```
VPN  代理隧道   本机 ── 网卡 ── 节点 ── 出口        承载 3 条 · 171ms
直连 不经代理   本机 ── 网卡 ── 出口              目标不通 · 对照 58 ms
```

- **VPN 泳道**：本机 IP → 实际承载隧道的网卡（按内核路由判定，不是按名字猜）
  → mihomo 当前在用的节点（名字/端口来自正在生效的 YAML，节点身份来自 `/connections` 的连接链）
  → 隧道出口公网 IP
- **直连泳道**：本机 IP → 直连那条路走的网卡 → 直连出口公网 IP；
  右上角是"这个目标能不能直连 + 延迟"，`目标不通` 说明该站点确实需要代理，
  后面那个"对照"是访问一个国内站点的延迟，用来证明"网不是坏的，只是这个目标不通"

两块网卡不一样的时候（比如有线打隧道、Wi-Fi 走直连），两条泳道会显示不同的网卡名，
页脚也会写 `直连走 WLAN 192.168.1.24` —— 双上行是很容易被忽略的状态。

### 3. 实时吞吐 / 通道探测 / 站点

- **实时吞吐**：mihomo 统计到的全机代理流量，1 秒一次，带 120 秒曲线和本次累计
- **通道探测**：每 10 秒分别从"代理通道"和"直连通道"访问同一个目标，
  给出状态码和耗时；最下面那条刻度是最近 96 次探测的健康记录，红点 = 那次失败
- **站点**：按域名归并的实时速率（↓↑）+ 每个站点的 DNS/IP + 走的是 VPN 还是直连；
  底部一行是其余正在跑流量的域名（TopN），**点一下 ＋ 就把它加到监测列表**

### 4. 自己加要盯的域名

右上角「＋ 域名」→ 输入框里敲 `github.com` 回车就生效（写进 `config.json`，
重启也还在）。随手贴 `https://www.github.com/path` 也行，会自动取成 `github.com`。
鼠标移到某个站点行上，右侧出现 `×`，点掉就不再盯它。
写错了会在底部弹一行提示（比如 `看起来不是个域名`），不会污染配置。

---

## 二、它是怎么判定的（数据来源）

| 事实 | 来源 |
|---|---|
| 系统代理开关/地址 | 注册表 `HKCU\...\Internet Settings` 的 `ProxyEnable` / `ProxyServer` |
| mihomo 在不在、什么模式、TUN 开没开 | `http://127.0.0.1:7892/configs`、`/version` |
| 每条连接走没走代理、走了哪个节点 | `/connections` 的 `chains`（`DIRECT` = 直连） |
| 每个域名的实时速率 | 对 `/connections` 里每条连接的累计字节做 1 Hz 差分，按 `metadata.host` 归并 |
| 隧道出口 IP | 经 7890 访问 `ip-api.com`（120 秒一次） |
| 直连出口 IP | 绕过代理访问 `ip-api.com`（300 秒一次） |
| 走的哪块网卡 | 用 `socket.connect()` 问内核"去这个目的地，源地址选谁"，再反查网卡 —— 比按名字猜可靠 |
| Wi-Fi 细节（SSID/频段/信道/信号/速率） | `netsh wlan show interfaces`（中英文系统都能解析） |
| 网卡地址/网关/接口度量 | `netsh interface ipv4 show addresses` |

---

## 三、跑起来

```powershell
# 双击 start.cmd 也行
powershell -ExecutionPolicy Bypass -File .\start.ps1

# 关掉采集器
powershell -ExecutionPolicy Bypass -File .\start.ps1 -Stop
```

`start.ps1` 会：后台用 `pythonw` 拉起 `server.py`（无控制台窗口）→ 等端口就绪 →
用 Edge 的 `--app=` 应用窗口模式打开面板（独立 profile，不打扰日常浏览器，
窗口 800×630，约为上一版的 2/3 面积）。加 `-DefaultProfile` 就用你日常的浏览器配置。

只依赖 Python 3.10+ 标准库，不需要装任何包。

## 四、配置（`config.json`，改完重启生效）

```json
{
  "port": 7717,
  "controller": "127.0.0.1:7892",
  "mixed_port": "127.0.0.1:7890",
  "sites": ["chatgpt.com", "openai.com"],
  "probe_interval": 10,
  "probe_target": "https://chatgpt.com/",
  "control_target": "https://www.baidu.com/"
}
```

- `sites`：要单独盯着速率的域名（后缀匹配，`chat.openai.com` 会算进 `openai.com`）
- `controller` / `mixed_port`：mihomo 的 external-controller 和混合端口
- `probe_target`：双通道探测打的目标（默认 ChatGPT）
- `control_target`：直连泳道里那个"对照"目标
- 也能用环境变量覆盖：`FLOW_PORT` / `FLOW_CONTROLLER` / `FLOW_MIXED` / `FLOW_SITES`

## 五、接口

| 路径 | 内容 |
|---|---|
| `GET /` | 面板（单文件 HTML，无外链 CDN） |
| `GET /api/state` | 当前快照 JSON |
| `GET /api/stream` | SSE，每秒一帧（面板默认用这个） |
| `GET /?poll=1` | 让页面退化成 1 秒轮询（SSE 被挡时用） |
| `POST /api/sites` | 增删监测域名：`{"action":"add"\|"remove","domain":"github.com"}`，成功 200，域名不合法 400，返回新的列表 |

快照里的 `watched` 就是当前监测列表，`extras` 是其余正在跑流量的域名。

## 六、边界（重要）

1. **只看得见经过 mihomo 的流量。** 系统代理关掉、程序又不认代理时，那部分流量
   在面板里是看不见的 —— 这时判定会显示"部分走 VPN"，而不是假装知道全部。
2. **"站点"是域名维度，不是进程维度。** 同一个域名下多个连接会合并。
3. **直连泳道是"反证"**：它证明了"这个目标不走代理时通不通"，不代表某个具体程序的实际路径。
4. 出口 IP 每 120/300 秒才刷新一次，节点切换后最多滞后这么久。
5. TUN 模式打开时，"网卡"会变成 TUN 虚拟网卡，此时泳道展示的是隧道入口而非物理出口。
6. 采集器只读本机状态，不改任何系统/代理配置。

## 七、目录

```
server.py          采集 + HTTP/SSE 服务（标准库，单文件）
config.json        配置
web/index.html     面板（单文件，内联 CSS/JS，手写 SVG 曲线）
start.ps1/.cmd     启动器（后台起服务 + 应用窗口打开面板）
tools/peek.py      命令行看一眼当前快照（排障用）
tools/shots/       联调时的界面截图
state.json         每个站点的累计流量（自动生成）
```
