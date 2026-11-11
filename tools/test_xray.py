"""v2rayN / Xray 适配的自检（不依赖本机装没装 v2rayN）

三件事各验一遍：
  ① 按 v2rayN 的生成规则手写一份 config.json，看能不能认出统计口 / 本地代理口 / 当前节点
  ② 起一个假的 Xray 统计口，喂一份 /debug/vars 的真实结构，看解析对不对
  ③ 连着采两帧，看速率、归属、"总量 = 两行之和"

run:  python tools/test_xray.py
"""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding="utf-8")

import providers  # noqa: E402

# v2rayN 生成的客户端配置（按 CoreConfigV2rayService + V2rayStatisticService 的形状）
CFG = {
    "log": {"loglevel": "warning"},
    "stats": {},
    "metrics": {"listen": "127.0.0.1:10085"},
    "policy": {"system": {"statsOutboundDownlink": True, "statsOutboundUplink": True}},
    "inbounds": [
        {"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
         "settings": {"udp": True, "auth": "noauth"}},
        {"tag": "http", "listen": "127.0.0.1", "port": 10809, "protocol": "http", "settings": {}},
    ],
    "outbounds": [
        {"tag": "proxy", "protocol": "vmess",
         "settings": {"vnext": [{"address": "sg1.example.net", "port": 443,
                                 "users": [{"id": "00000000-0000-0000-0000-000000000000",
                                            "security": "auto"}]}]},
         "streamSettings": {"network": "tcp", "security": "tls"}},
        {"tag": "direct", "protocol": "freedom", "settings": {}},
        {"tag": "block", "protocol": "blackhole", "settings": {}},
    ],
    "routing": {"domainStrategy": "AsIs",
                "rules": [{"type": "field", "outboundTag": "direct", "domain": ["geosite:cn"]}]},
}

VARS = {
    "stats": {
        "inbound": {"socks": {"uplink": 900, "downlink": 1200}},
        "outbound": {"proxy": {"uplink": 7_000_000, "downlink": 88_000_000},
                     "direct": {"uplink": 300_000, "downlink": 2_100_000}},
        "user": {},
    },
    "observatory": {},
}

fail = 0


def check(name, got, want):
    global fail
    ok = got == want
    print(("  ok  " if ok else " FAIL ") + name + f": {got!r}" + ("" if ok else f"  ≠ {want!r}"))
    if not ok:
        fail += 1


print("① 配置解析")
info = providers.parse_xray_config(json.dumps(CFG))
check("统计口", info["metrics"], "127.0.0.1:10085")
check("本地代理口", info["local"], "127.0.0.1:10808")
check("当前节点 tag", info["proxy_tag"], "proxy")
check("节点地址", info["server"], "sg1.example.net")
check("节点端口", info["port"], 443)
check("协议", info["type"], "VMESS")
check("不是 Xray 配置时返回空", providers.parse_xray_config('{"a":1}'), {})


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(VARS).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


srv = HTTPServer(("127.0.0.1", 0), H)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

print("② 统计口 /debug/vars")
reg = providers.Registry()
reg.client.metrics = f"127.0.0.1:{port}"
st = reg.xray_stats()
check("proxy 上行", st.get("proxy", (0, 0))[0], 7_000_000)
check("proxy 下行", st.get("proxy", (0, 0))[1], 88_000_000)
check("direct 下行", st.get("direct", (0, 0))[1], 2_100_000)
reg.client.metrics = ""
check("没有统计口时返回空", reg.xray_stats(), {})

print("③ 采样：第一帧建基线，第二帧出速率")
import server as sv  # noqa: E402


class FakeDISCO:
    """替掉真实的客户端发现，其余逻辑走 server.py 自己的代码"""

    def __init__(self, port):
        self.client = providers.Client()
        self.client.flow = "xray"
        self.client.kind = "v2ray"
        self.client.name = "v2rayN"
        self.client.core = "xray"
        self.client.metrics = f"127.0.0.1:{port}"
        self.client.local_proxy = f"127.0.0.1:{port}"
        self.client.proxies = {"proxy": {"name": "SG-02", "server": "sg1.example.net", "port": 443}}
        self.step = 0

    def xray_stats(self):
        self.step += 1
        k = self.step
        return {"proxy": (1000 * k, 100_000 * k), "direct": (100 * k, 5_000 * k)}


sv.DISCO = FakeDISCO(port)
col = sv.Collector(sv.NetInfo())
col.sample_xray()
col.sample_xray()
snap, _ = sv.ST.read()
rows = {r["key"]: r for r in snap["sites"]}
print("    flow =", snap["flow"])
print("    经代理 ↓", rows["proxy"]["down"], "B/s   ↑", rows["proxy"]["up"], "B/s")
print("    直连   ↓", rows["direct"]["down"], "B/s   ↑", rows["direct"]["up"], "B/s")
check("两行都在", sorted(rows), ["direct", "proxy"])
check("两行都是固定行（不能删）", (rows["proxy"].get("fixed"), rows["direct"].get("fixed")), (True, True))
check("流量归属正确", (rows["proxy"]["via"], rows["direct"]["via"]), ("vpn", "direct"))
check("总速率 = 两行之和", snap["total"]["down"], rows["proxy"]["down"] + rows["direct"]["down"])

srv.shutdown()
print()
print("结论：" + ("全部通过" if not fail else f"{fail} 项不通过"))
sys.exit(1 if fail else 0)
