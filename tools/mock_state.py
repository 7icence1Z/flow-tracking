"""生成 README 示意图用的演示快照服务（数据全是假的）。

两种模式：
  python tools\\mock_state.py 7799                 结构：Clash 系（按域名归并）
  set MOCK_XRAY=1 && python tools\\mock_state.py 7799   结构：v2rayN（经代理 / 直连两行）

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


def snap(tick):
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
        "probes": {"vpn": {"ok": True, "status": 200, "ms": 812, "ts": t - 4, "err": "", "body": ""},
                   "direct": {"ok": False, "status": 0, "ms": 3005, "ts": t - 4,
                              "err": "URLError", "body": ""},
                   "control": {"ok": True, "status": 200, "ms": 58, "ts": t - 9, "err": "", "body": ""}},
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
    return out


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/api/state"):
            body = json.dumps(snap(int(time.time() * 2)), ensure_ascii=False).encode()
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


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 7799
    print(f"mock on http://127.0.0.1:{port}/")
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
