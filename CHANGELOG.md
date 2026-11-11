# 变更记录

版本号按语义化来：`主.次.修订`。破坏性改动、新增能力、修复分开写。

## v0.2.0 — 2026-11-11（未发布）

这一版把"只认 mihomo 的小工具"变成了"装谁都能看"的软件。

### 新增

- **客户端自动发现**（`providers.py`，532 行，纯标准库）。发现链：
  `netstat` 端口归属 → WMI 进程表 → 探 `GET /version` 认 Clash 系 API
  → 从内核命令行抠 `-f/-c/--config/-d` 找配置 → 解析 `proxies:` / `outbounds`。
  覆盖 mihomo、Clash Verge、Clash for Windows、Mihomo Party、FlClash、sing-box
  （开了 `clash_api`）、v2rayN / Xray / NekoRay、WireGuard、OpenVPN、深信服、Tailscale，
  以及**认不出来的客户端**（直接拿它自己的 exe 名显示，不写"未知"）。
- **节点名解析**：节点一栏显示软件自己的叫法（`🇯🇵 东京-01`），
  三级回退：控制器 `now`（GLOBAL / 各 Selector 投票）→ 连接链里的配置名 →
  出口 IP 反查配置里的 `server`（域名走 DNS，带缓存）。
- **订阅感知**：Clash 系读 `/providers/proxies`（订阅名 / 更新时间 / 已用流量 / 到期）；
  把订阅拉平成一个 yaml 的客户端则盯配置文件内容指纹，节点表一变立刻刷新。
- **服务端保存 120 帧历史**：面板一打开就有两条分钟的曲线，不用空等。
- 判定新增一档：找到了非 Clash 系客户端时，如实说"它不暴露连接表，只有网卡与出口数据"，
  不再一律报"控制器没有响应"。

### 界面

- 重做配色，改成"语义化三色"：琥珀=走 VPN、青=直连 / 正常、红=不通。
  吞吐曲线、泳道底色、站点小图、标签都跟着**实际生效的路径**变色。
- 去掉渐变光晕、霓虹色、胶囊标签和流动动画，换成平面石墨底 + 发丝线 + 4px 圆角。
- 卡片头显示客户端身份：`Clash Verge · mihomo v1.19.30 · 128 个节点 · 订阅 5 分钟前更新`。
- 站点行曲线按该域名实际走的出口上色（琥珀 / 青）。

### 无障碍

- 补 `color-scheme: dark`，表单控件与滚动条不再刺眼。
- 品牌改 `<h1>`；域名输入框补 `aria-label` / `name` / `inputmode`；
  所有按钮补 `type="button"`；输入框 `outline:none` 换成 `:focus-visible` 焦点环；
  底部提示换成 `role="status" aria-live="polite"`。

### 修复

- 中英文 Windows 上 `netsh` / WMI 输出编码不一致，导致含中文路径的配置读不到（`鹰云` 这类目录）。
- 内核进程名带后缀（`mihomo-windows-amd64`）时认不出是哪个内核，软件名退化成内核名。
- 订阅接口返回空壳 provider 时，把 `0001-01-01` 当成"更新时间"显示。

---

## v0.1.0 — 2026-11-11

首个提交（`d740120`），单客户端版本。

- 判定这一刻的流量走直连还是走 mihomo 隧道，展示两路出口（本机 → 网卡 → 节点 → 出口 IP）。
- 按域名的实时速率（对 `/connections` 的累计字节做 1 Hz 差分，按域名后缀归并）。
- 双通道探测：同一个目标分别从代理通道和直连通道访问，给出状态码和耗时，
  外加一条 96 次探测的健康刻度。
- 网卡判定用内核的源地址选择（`UDP connect` 后读 `getsockname`），不是按网卡名猜。
- 面板内可直接增删要盯的域名（`POST /api/sites`，写回 `config.json`）。
- Windows 启动器：后台 `pythonw` 起服务 + Edge `--app` 应用窗口打开面板。
