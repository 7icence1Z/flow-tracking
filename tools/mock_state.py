"""生成 README 示意图用的演示快照服务（数据全是假的）。

四种模式：
  python tools\\mock_state.py 7799                 结构：Clash 系（按域名归并）
  set MOCK_XRAY=1 && python tools\\mock_state.py 7799   结构：v2rayN（经代理 / 直连两行）
  set MOCK_HOST=1 && python tools\\mock_state.py 7799   结构：没有代理客户端（按进程数连接）
  set MOCK_LOOP=1 && python tools\\mock_state.py 7799   结构：客户端在转发、但没开统计口（经本地口计数）

然后 headless 截图 http://127.0.0.1:7799/?poll=1
"""

import json
import os
import random
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BOOT = time.time() - 3600 * 2 - 733

rnd = random.Random(20261111)
HIST = 120
XRAY = (os.environ.get('MOCK_XRAY') == '1')
LOOP = (os.environ.get('MOCK_LOOP') == '1')
HOST = (os.environ.get('MOCK_HOST') == '1') or LOOP
ELEV = (os.environ.get('MOCK_ELEV') == '1') or LOOP
# 演示"VPN 关掉之后"：第 N 次请求之后转成直连（曲线上的琥珀段应该留在左边、往左滑出去）
OFF_AT = int(os.environ.get('MOCK_OFF_AT', '0') or 0)
# 演示"采集器被 kill"：第 N 次请求之后一句不回就断连接（顶栏该出「采集器未连接」）
DIE_AT = int(os.environ.get('MOCK_DIE_AT', '0') or 0)

# 诊断结论的几种样子，截图时用 MOCK_DIAG 选：ok / target / vpn / link / dns / nopx / loop
DIAG = os.environ.get("MOCK_DIAG", "loop" if LOOP else "nopx" if HOST else "target")
def L(zh, en):
    """和 server.py 一样：面板上的一句话，中英两版"""
    return {"zh": zh, "en": en}


DIAG_CASES = {
    "ok": {"state": "ok",
           "label": L("链路正常", "All paths healthy"),
           "tun": False,
           "why": L("对照、直连、代理三条路径均可达，未发现异常",
                    "Control, direct and proxy paths are all reachable; no anomaly detected"),
           "evidence": ["对照 www.baidu.com 可达 58ms", "直连 chatgpt.com 可达 812ms",
                        "代理通道 可达", "网关 192.168.1.1（以太网）有响应"]},
    "target": {"state": "target",
               "label": L("目标被墙，代理正常", "Target blocked; proxy healthy"),
               "tun": False,
               "why": L("对照片与代理通道均可达，仅直连 chatgpt.com 不可达 —— 属正常现象",
                        "Both the control target and the proxy path are reachable; only direct "
                        "access to chatgpt.com fails — this is expected"),
               "evidence": ["对照 www.baidu.com 可达 58ms", "直连 chatgpt.com 不可达（超时）",
                            "代理通道 可达", "网关 192.168.1.1（以太网）有响应"]},
    "vpn": {"state": "vpn",
            "label": L("VPN 隧道 / 节点异常", "VPN tunnel / node failure"),
            "tun": False,
            "why": L("链路正常、直连对照可达，但经代理访问 chatgpt.com 失败（超时）",
                     "The link is fine and the direct control target is reachable, but "
                     "chatgpt.com fails through the proxy (timed out)"),
            "evidence": ["对照 www.baidu.com 可达 42ms", "直连 chatgpt.com 不可达（超时）",
                         "代理通道 不可达（超时）", "网关 192.168.1.1（以太网）有响应"]},
    "link": {"state": "link",
             "label": L("WLAN 链路不通", "WLAN link down"),
             "tun": False,
             "why": L("连对照目标都不可达，且该网卡的网关 192.168.1.1 无响应 —— "
                      "先检查网线 / Wi-Fi 连接与路由器，与 VPN 无关",
                      "Even the control target is unreachable, and the gateway 192.168.1.1 on "
                      "this interface does not respond — check the cable / Wi-Fi and router "
                      "first; this is not a VPN issue"),
             "evidence": ["对照 www.baidu.com 不可达（超时）", "直连 chatgpt.com 不可达（超时）",
                          "代理通道 可达", "网关 192.168.1.1（WLAN）无响应"]},
    "dns": {"state": "dns",
            "label": L("DNS 解析异常", "DNS resolution failing"),
            "tun": False,
            "why": L("网关有响应，但对照域名无法解析 —— 更换 DNS 或检查 DNS 设置",
                     "The gateway responds, but the control domain does not resolve — change "
                     "DNS or check DNS settings"),
            "evidence": ["对照 www.baidu.com 不可达（DNS 解析失败）", "直连 chatgpt.com 不可达（DNS 解析失败）",
                         "代理通道 可达", "网关 192.168.1.1（以太网）有响应"]},
    "nopx": {"state": "nopx",
             "label": L("没有代理客户端，仅统计本机流量", "No proxy client; local totals only"),
             "tun": False,
             "why": L("面板按网卡统计总流量、按连接数查看连接归属（chatgpt.com 与 www.baidu.com "
                      "的探测照常运行，只是不归因于 VPN）。逐域名的字节数需客户端统计口",
                      "The panel counts interface totals and shows connection ownership "
                      "(chatgpt.com and www.baidu.com are still probed, just not attributed to "
                      "the VPN). Per-domain byte counts need the client's stats API"),
             "evidence": ["对照 www.baidu.com 可达 58ms", "直连 chatgpt.com 不可达（超时）"]},
    "loop": {"state": "nopx",
             "label": L("客户端在转发（经本地口计数）", "Client forwarding (local port)"),
             "tun": False,
             "why": L("系统代理指向 127.0.0.1:10808，v2rayN 确实在转发；其统计口未开启，"
                      "本地代理口上的回环连接可数出「进入客户端」的字节，但那只是入口 —— "
                      "其中多少进入隧道、多少按规则直连发出，无法读取",
                      "System proxy points to 127.0.0.1:10808 and v2rayN is indeed forwarding; "
                      "its stats endpoint is off. Loopback connections on its local proxy port "
                      "give the bytes entering the client, but that is ingress only — how much "
                      "enters the tunnel versus leaves directly by rule cannot be read"),
             "evidence": ["系统代理 127.0.0.1:10808（端口属于 v2rayN 的进程）",
                          "应用→代理口的回环 TCP 连接 6 条（eStats 差分）",
                          "入口字节 ≠ 隧道字节：客户端按规则可能直连放出一部分"]},
}


def wave(n, base, peak_at, width, floor=0.0):
    out = []
    for i in range(n):
        v = floor
        for p in peak_at:
            d = abs(i - p)
            if d < width * 3:
                v += base * pow(0.5, (d / width) ** 1.6)
        out.append(round(v * (0.86 + 0.28 * rnd.random())))
    return out


def rot(arr, i):
    """把窗口转一下，让"最后一帧"就是当前帧 —— 否则页面接上实时帧时曲线会跳一下"""
    return arr[i + 1:] + arr[:i + 1]


SITES = [
    {"key": "chatgpt.com", "label": "chatgpt.com", "watched": True, "via": "vpn", "rate": 1_240_000},
    {"key": "github.com", "label": "github.com", "watched": True, "via": "vpn", "rate": 214_000},
    {"key": "openai.com", "label": "openai.com", "watched": True, "via": "vpn", "rate": 96_000},
    {"key": "bilibili.com", "label": "bilibili.com", "watched": True, "via": "direct", "rate": 61_000},
]
EXTRA = [{"key": "extra:docs.qq.com", "label": "docs.qq.com", "down": 42_000, "up": 8_000,
          "watched": False, "via": "direct"},
         {"key": "extra:github.githubassets.com", "label": "github.githubassets.com",
          "down": 31_000, "up": 2_000, "watched": False, "via": "vpn"}]

TOTAL_H = wave(HIST, 2_600_000, [26, 58, 96], 4.4, 60_000)
SITE_H = {s["label"]: wave(HIST, s["rate"], [26, 58, 96], 3.8, s["rate"] * 0.06) for s in SITES}


def snap(tick, off=False):
    t = time.time()
    i = min(HIST - 1, (tick + HIST) % HIST)
    tot = TOTAL_H[i]
    rows = []
    site_hist = {}
    for k, s in enumerate(SITES):
        at = max(0, i - k * 3)
        v = SITE_H[s["label"]][at]
        rows.append({**s, "down": v, "up": round(v * 0.11)})
        site_hist[s["label"]] = rot(SITE_H[s["label"]], at)
    out = {
        "ok": True,
        "error": "",
        "path": {"active": "vpn",
                 "reason": "系统代理已开启并指向 127.0.0.1:7890（mihomo rule 模式）",
                 "sysproxy": {"enable": 1, "server": "127.0.0.1:7890"}},
        "tunnel": {"up": True, "mode": "rule", "tun": False, "mixed": "127.0.0.1:7890",
                   "controller": "127.0.0.1:9090", "version": "v1.19.30", "conns": 17,
                   "download_total": 1_284_000_000, "upload_total": 96_400_000},
        "client": {"kind": "clash", "name": "Clash Verge", "core": "mihomo", "version": "v1.19.30",
                   "api": "127.0.0.1:9090", "config": "C:\\Users\\me\\clash\\config.yaml",
                   "exe": "C:\\Program Files\\Clash Verge\\verge-mihomo.exe", "pid": 4120,
                   "mode": "rule", "nodes": 128, "updated": t - 300,
                   "sub": {"kind": "provider", "name": "airport", "updated": t - 300,
                           "used": 84_200_000_000, "total": 500_000_000_000, "expire": t + 86400 * 41},
                   "meta": True},
        "iface": {"name": "以太网", "kind": "ethernet", "routed": True, "ssid": "", "ip": "192.168.1.42",
                  "gateway": "192.168.1.1", "metric": "35", "state": "", "band": ""},
        "route": {"vpn": {"name": "以太网", "kind": "ethernet", "ip": "192.168.1.42", "ssid": ""},
                  "direct": {"name": "WLAN", "kind": "wlan", "ip": "192.168.1.88", "ssid": "HomeNet-5G"},
                  "dual": True},
        "node": {"name": "node_42_🇯🇵 东京-01 | IEPL", "server": "jp-node-01.example.net",
                 "port": 443, "type": "VLESS", "pid": 4120,
                 "changed_at": t - 1500, "ip": "203.0.113.24", "rtt": 96},
        "mihomo": {"pid": 4120, "config": "C:\\Users\\me\\clash\\config.yaml", "mode": "rule"},
        "egress": {"vpn_ip": "203.0.113.24", "vpn_geo": "Japan", "vpn_ts": t - 20, "vpn_err": "",
                   "direct_ip": "198.51.100.9", "direct_geo": "China", "direct_ts": t - 90,
                   "direct_err": ""},
        "probe": {"target": "https://chatgpt.com/", "host": "chatgpt.com",
                  "control": "www.baidu.com", "control_url": "https://www.baidu.com/",
                  "interval": 10, "min": 5, "max": 120},
        "probes": {"vpn": {"ok": True, "status": 200, "ms": 812, "ts": t - 4, "err": "", "kind": "", "body": ""},
                   "direct": {"ok": False, "status": 0, "ms": 3005, "ts": t - 4,
                              "err": "URLError", "kind": "timeout", "detail": "TimeoutError: timed out",
                              "body": ""},
                   "control": {"ok": True, "status": 200, "ms": 58, "ts": t - 9, "err": "", "kind": "", "body": ""}},
        "sites": rows,
        "hist": {"total": [[x, round(x * 0.09)] for x in rot(TOTAL_H, i)],
                 "sites": {k: [[v, round(v * 0.11)] for v in vals] for k, vals in site_hist.items()}},
        "watched": [s["label"] for s in SITES],
        "extras": EXTRA,
        "total": {"down": round(tot), "up": round(tot * 0.09)},
        "ts": t, "boot": BOOT,
    }
    if XRAY:
        ph = wave(HIST, 2_150_000, [26, 58, 96], 4.0, 40_000)
        dh = wave(HIST, 310_000, [40, 80], 3.0, 6_000)
        pv, dv = ph[i], dh[i]
        out["flow"] = "xray"
        out["tunnel"] = {"up": True, "mode": "", "tun": False, "mixed": "127.0.0.1:10808",
                         "controller": "127.0.0.1:10085", "version": "", "conns": 0,
                         "download_total": 0, "upload_total": 0}
        out["client"] = {"kind": "xray", "name": "v2rayN", "core": "xray", "version": "25.10.1",
                         "api": "", "config": "C:\\Users\\me\\v2rayN\\guiConfigs\\config.json",
                         "exe": "C:\\Users\\me\\v2rayN\\bin\\xray\\xray.exe", "pid": 8840,
                         "mode": "", "nodes": 214, "updated": t - 240,
                         "sub": {"kind": "file", "name": "config.json", "updated": t - 240,
                                 "used": 0, "total": 0, "expire": 0},
                         "meta": False, "flow": "xray", "metrics": "127.0.0.1:10085",
                         "local": "127.0.0.1:10808"}
        out["node"] = {"name": "🇸🇬 新加坡-02 | IEPL", "server": "sg2.example.net",
                       "port": 443, "type": "VMESS", "pid": 8840,
                       "changed_at": t - 240, "ip": "203.0.113.57", "rtt": 0}
        out["path"] = {"active": "vpn",
                       "reason": "系统代理已开启并指向 127.0.0.1:10808（v2rayN），代理感知型应用全部经隧道转发",
                       "sysproxy": {"enable": 1, "server": "127.0.0.1:10808"}}
        out["egress"]["vpn_ip"] = "203.0.113.57"
        out["sites"] = [
            {"key": "proxy", "label": "经代理", "watched": True, "fixed": True,
             "down": pv, "up": round(pv * 0.1), "conns": 0, "ip": "",
             "chain": "v2rayN", "rule": "", "via": "vpn",
             "total_down": 84_000_000_000, "total_up": 6_200_000_000},
            {"key": "direct", "label": "直连", "watched": True, "fixed": True,
             "down": dv, "up": round(dv * 0.12), "conns": 0, "ip": "",
             "chain": "", "rule": "", "via": "direct",
             "total_down": 5_400_000_000, "total_up": 700_000_000},
        ]
        out["hist"] = {"total": [[x, round(x * 0.1)] for x in
                                 [a + b for a, b in zip(rot(ph, i), rot(dh, i))]],
                       "sites": {"proxy": [[v, round(v * 0.1)] for v in rot(ph, i)],
                                 "direct": [[v, round(v * 0.12)] for v in rot(dh, i)]}}
        out["watched"] = []
        out["extras"] = []
        out["total"] = {"down": pv + dv, "up": round((pv + dv) * 0.1)}
    if HOST:
        # 没有代理客户端：网卡总量 + 谁在连谁。行里没有字节数，只有连接数
        th = wave(HIST, 3_400_000, [26, 58, 96], 4.2, 40_000)
        tv = th[i]
        out["flow"] = "host"
        out["client"] = {"kind": "none", "name": "", "core": "", "version": "", "api": "",
                         "config": "", "exe": "", "pid": 0, "mode": "", "nodes": 0,
                         "meta": False, "sub": {}}
        out["path"] = {"active": "direct", "brief": L("读不到它的流量 · 按网卡统计", "traffic unreadable · interface totals only"),
                       "reason": "没检测到代理客户端：按网卡「以太网」统计本机流量，"
                                 "逐域名/逐进程的字节数要客户端统计口或管理员权限才看得到",
                       "sysproxy": {"enable": 0, "server": ""}}
        out["tunnel"] = {"up": False, "mode": "", "tun": False, "mixed": "", "controller": "",
                         "version": "", "conns": 118, "download_total": 0, "upload_total": 0}
        out["node"] = {"rtt": None}
        out["route"] = {"vpn": {},
                        "direct": {"name": "以太网", "kind": "ethernet", "ip": "192.168.1.42", "ssid": ""},
                        "dual": False}
        out["iface"] = {"name": "以太网", "kind": "ethernet", "routed": True, "ssid": "",
                        "ip": "192.168.1.42", "gateway": "192.168.1.1", "metric": "25",
                        "state": "", "band": ""}
        out["mihomo"] = {"pid": 0, "config": "", "mode": ""}
        out["egress"] = {"vpn_ip": "", "vpn_geo": "", "vpn_ts": 0, "vpn_err": "",
                         "direct_ip": "198.51.100.9", "direct_geo": "China",
                         "direct_ts": t - 60, "direct_err": ""}
        out["probes"]["vpn"] = {"ok": False, "status": 0, "ms": 0, "ts": t - 4,
                                "err": "ConnectionRefusedError", "kind": "refused",
                                "detail": "ConnectionRefusedError: [WinError 10061]", "body": ""}
        out["host"] = {"nic": "以太网", "conns": 118,
                       "cum": {"down": 3_902_000_000, "up": 214_000_000},
                       "procs": [
                           {"name": "chrome.exe", "pid": 20208, "conns": 14, "remotes": 9,
                            "sample": "101.91.136.148"},
                           {"name": "Code.exe", "pid": 17120, "conns": 6, "remotes": 4,
                            "sample": "140.82.113.4"},
                           {"name": "svchost.exe", "pid": 14852, "conns": 5, "remotes": 3,
                            "sample": "4.145.79.81"},
                           {"name": "WeChat.exe", "pid": 3304, "conns": 3, "remotes": 2,
                            "sample": "103.7.7.30"},
                           {"name": "explorer.exe", "pid": 5180, "conns": 2, "remotes": 2,
                            "sample": "52.110.20.130"},
                           {"name": "OneDrive.exe", "pid": 6188, "conns": 2, "remotes": 1,
                            "sample": "13.107.42.12"},
                       ]}
        out["sites"] = []
        out["extras"] = []
        out["watched"] = []
        out["host"]["estats"] = False
        out["host"]["elevated"] = False
        if ELEV:
            # 管理员权限：每进程都有 eStats 差分出来的真字节数，站点表直接复用
            rates = [265_000, 88_000, 41_000, 12_400, 5_200, 1_100]
            for k, p in enumerate(out["host"]["procs"]):
                p["down"] = rates[k]
                p["up"] = round(rates[k] * 0.13)
                p["cum_down"] = 40_000_000 + k * 3_100_000
                p["cum_up"] = 2_400_000 + k * 180_000
            out["host"]["estats"] = True
            out["host"]["elevated"] = True
            out["path"]["reason"] = ("没检测到代理客户端：按网卡「以太网」统计本机流量，"
                                     "管理员权限：每行的 ↓↑ 用内核 eStats 差分出来的"
                                     "（含 TCP 净荷，不含 UDP）")
            out["sites"] = [{"key": p["name"], "label": p["name"], "watched": True, "fixed": True,
                             "down": p["down"], "up": p["up"], "conns": p["conns"],
                             "ip": p["sample"], "chain": "", "rule": "", "via": "direct",
                             "remotes": p["remotes"], "total_down": p["cum_down"],
                             "total_up": p["cum_up"]} for p in out["host"]["procs"]]
            out["watched"] = [p["name"] for p in out["host"]["procs"]]
            for k, p in enumerate(out["host"]["procs"]):
                out.setdefault("_elev_hist", {})[p["name"]] = [
                    [v, round(v * 0.12)] for v in
                    wave(HIST, p["down"], [30, 62, 92], 4.0 + k * 0.35, p["down"] * 0.08)]
        if LOOP:
            # 客户端在转发、但没开统计口：经代理从"应用→本地代理口"的回环连接上数出来。
            # 数字按网卡峰值摆，免得大盘比某一行还小（示意数据只求自洽）
            peak = max(TOTAL_H)
            px_d, px_u = round(peak * 0.70), round(peak * 0.09 * 0.62)
            out["client"] = {"kind": "xray", "name": "v2rayN", "core": "xray", "version": "25.10.1",
                             "api": "", "config": "C:\\Users\\me\\v2rayN\\guiConfigs\\config.json",
                             "exe": "C:\\Users\\me\\v2rayN\\bin\\xray\\xray.exe", "pid": 8840,
                             "mode": "", "nodes": 214, "updated": t - 240,
                             "sub": {"kind": "file", "name": "config.json", "updated": t - 240,
                                     "used": 0, "total": 0, "expire": 0},
                             "meta": False, "flow": "xray", "metrics": "",
                             "local": "127.0.0.1:10808"}
            out["path"] = {
                "active": "mixed",
                "brief": L("在转发 · 经其本地端口计数，隧道份额未知",
                           "forwarding · counted at its local port, tunnel share unknown"),
                "reason": ("系统代理已开启并指向 127.0.0.1:10808（v2rayN）：它确实在转发，"
                           "但没给字节统计（统计口没开），只能数「应用 → 它的本地口」"
                           "那条回环连接 —— 那是入口字节，其中多少进了隧道、多少被规则"
                           "按直连放出去，读不到"),
                "sysproxy": {"enable": 1, "server": "127.0.0.1:10808"}}
            out["tunnel"] = {"up": True, "mode": "", "tun": False, "mixed": "127.0.0.1:10808",
                             "controller": "", "version": "", "conns": 0,
                             "download_total": 0, "upload_total": 0}
            out["node"] = {"name": "🇸🇬 新加坡-02 | IEPL", "server": "sg2.example.net",
                           "port": 443, "type": "VMESS", "pid": 8840, "changed_at": t - 240,
                           "ip": "203.0.113.57", "rtt": 210}
            out["egress"]["vpn_ip"] = "203.0.113.57"
            out["egress"]["vpn_geo"] = "Singapore"
            # 本机模式发布的 host 里没有明细字段：入口字节只走 split.client
            out["split"] = {"nic": {"down": max(TOTAL_H), "up": round(max(TOTAL_H) * 0.09)},
                            "proxy": None, "direct": None,
                            "client": {"down": px_d, "up": px_u}, "src": "loop"}
            # 本地口在听、通道也通：这一路现在是"真的在用"，不是未启用
            out["probes"]["vpn"] = {"ok": True, "status": 200, "ms": 210, "ts": t - 4,
                                    "err": "", "kind": "", "body": ""}
            # 浏览器流量主要进客户端 → 行标"经客户端"（中性色），不冒充琥珀色的"走 VPN"
            ch = out["host"]["procs"][0]
            ch["px_down"], ch["px_up"] = px_d, px_u
            ch["down"], ch["up"] = px_d + 80_000, px_u + 8_000
            out["sites"][0].update({"down": ch["down"], "up": ch["up"],
                                    "px": px_d + px_u, "via": "proxy"})
            out["_elev_hist"][ch["name"]] = [
                [v, round(v * 0.11)] for v in
                wave(HIST, ch["down"], [30, 62, 92], 4.0, ch["down"] * 0.08)]
        out["hist"] = {"total": [[x, round(x * 0.09)] for x in rot(th, i)], "sites": {}}
        out["total"] = {"down": round(tv), "up": round(tv * 0.09)}
        if LOOP:
            out["total"] = {"down": max(TOTAL_H), "up": round(max(TOTAL_H) * 0.09)}
    # 分账：网卡总量 = 经代理 + 不走代理（演示数据；真机上后者是两块计数相减）
    td, tu = out["total"]["down"], out["total"]["up"]
    if HOST:
        if LOOP:
            pass                      # LOOP 已在上面摆好（入口字节走 split.client）
        else:
            out["split"] = {"nic": {"down": td, "up": tu}, "proxy": None, "direct": None,
                            "client": None, "src": ""}
    else:
        nic_d, nic_u = round(td * 1.07), round(tu * 1.25)
        out["split"] = {"nic": {"down": nic_d, "up": nic_u},
                        "proxy": {"down": td, "up": tu},
                        "direct": {"down": nic_d - td, "up": nic_u - tu}}
        out["host"] = {"nic": "以太网", "conns": 132 if XRAY else 118,
                       "cum": {"down": 3_902_000_000, "up": 214_000_000}, "procs": []}
    out["diag"] = DIAG_CASES.get(DIAG, DIAG_CASES["target"])
    out["diag"] = {**out["diag"], "ts": t - 6}
    if "_elev_hist" in out:
        out["hist"]["sites"] = out.pop("_elev_hist")
    if off:
        # 演示"隧道切断了"：判定、探测、分账一起变，曲线上的琥珀段只能靠自己留住
        out["path"] = {"active": "direct",
                       "reason": "系统代理已关闭，也没有端口在监听：此刻没有转发证据",
                       "sysproxy": {"enable": 0, "server": ""}}
        out["tunnel"]["up"] = False
        out["probes"]["vpn"] = {"ok": False, "status": 0, "ms": 1200, "ts": t - 4,
                                "err": "URLError", "kind": "refused", "detail": "", "body": ""}
        out["diag"] = {**DIAG_CASES["nopx"], "ts": t - 6}
        out["node"] = {}
        out["egress"]["vpn_ip"] = ""
        out["egress"]["vpn_geo"] = ""
        out["split"] = {"nic": {"down": td, "up": tu}, "proxy": None, "direct": None,
                        "client": None, "src": ""}
    return out


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/api/state"):
            H.hits = getattr(H, "hits", 0) + 1
            if DIE_AT and H.hits > DIE_AT:
                self.close_connection = True    # 一句不回就断：等同采集器被 kill
                return
            off = bool(OFF_AT and H.hits > OFF_AT)
            body = json.dumps(snap(int(time.time() * 2), off), ensure_ascii=False).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
        else:
            with open(os.path.join(ROOT, "web", "index.html"), "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        """演示用：面板上的 ✎ 改探测设置时别 404 —— 照单全收，回一句"已更新" """
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        if self.path.startswith("/api/probe"):
            cur = {"target": body.get("target") or "https://chatgpt.com/",
                   "host": "chatgpt.com", "control": "www.baidu.com",
                   "control_url": "https://www.baidu.com/",
                   "interval": int(body.get("interval") or 10), "min": 5, "max": 120}
            out = {"ok": True,
                   "msg": {"zh": "探测设置已更新（演示数据，不会落盘）",
                           "en": "Probe settings updated (demo only, not saved)"},
                   "probe": cur}
        elif self.path.startswith("/api/sites"):
            out = {"ok": True, "msg": {"zh": "已更新（演示）", "en": "Updated (demo)"},
                   "sites": body.get("domain") and [body["domain"]] or []}
        else:
            out = {"ok": False, "msg": {"zh": "演示服务只接口 /api/probe 与 /api/sites",
                                        "en": "the demo server only handles /api/probe and /api/sites"}}
        data = json.dumps(out, ensure_ascii=False).encode()
        self.send_response(200 if out["ok"] else 404)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 7799
    print(f"mock on http://127.0.0.1:{port}/")
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
