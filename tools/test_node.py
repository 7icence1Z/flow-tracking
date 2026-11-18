"""节点名与"当前在用哪个节点"的自检（不需要装任何客户端）

四件事各验一遍：
  ① 占位名判定：proxy / 自动选择 / 只有 emoji 的节点名，不会被当成真名字显示
  ② 地域识别：🇯🇵 / 东京 / Tokyo / JP-01 / jp-xxx-aa-10077... 这类都要认得出
  ③ 各家的配置解析：Clash YAML（含 proxy-groups）、sing-box JSON（含 selector）、v2rayN
  ④ 判定顺序：连接表 > 出口 IP > 默认分组 > 全局模式 > 分组投票 > 唯一节点 > 不知道

run:  python tools/test_node.py
"""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.stdout.reconfigure(encoding="utf-8")

import providers  # noqa: E402
import server  # noqa: E402

OK = 0


def check(name, got, want):
    global OK
    good = got == want
    OK += good
    print(("  ok   " if good else "  FAIL ") + name)
    if not good:
        print(f"         得到 {got!r}，期望 {want!r}")


# ── ① 占位名 ────────────────────────────────────────────────────────────
print("① 占位名判定")
for name in ("proxy", "PROXY", "proxy-node", "自动选择", "节点", "代理节点", "01", "🇯🇵", ""):
    check(f"{name!r} 是占位名", providers.is_placeholder(name, ["PROXY", "GLOBAL"]), True)
for name in ("🇯🇵 东京-01", "🇸🇬 新加坡-02 | IEPL", "node_42_🇯🇵 东京-01 | IEPL",
             "US-LA-01", "香港 01 号"):
    check(f"{name!r} 不是占位名", providers.is_placeholder(name, ["PROXY"]), False)
check("只剩国旗的名字按占位处理（但它仍能指出地域）",
      providers.is_placeholder("🇯🇵", ["PROXY"]), True)
check("等于分组名时按占位处理", providers.is_placeholder("PROXY", ["PROXY"]), True)

# ── ② 地域 ──────────────────────────────────────────────────────────────
print("② 地域识别")
cases = [
    ("🇯🇵 东京-01", "JP"), ("JP-01", "JP"), ("jp01", "JP"), ("us1", "US"),
    ("🇸🇬 新加坡-02 | IEPL", "SG"), ("香港 HK-01", "HK"), ("美国 洛杉矶", "US"),
    ("node_42_🇩🇪 法兰克福", "DE"), ("节点1", ""), ("proxy", ""),
]
for name, want in cases:
    check(f"名字 {name!r} → {want or '认不出'}", providers.region_from_name(name), want)
hosts = [
    ("jp-xxx-aa-10077.node-yingyun.site", "JP"), ("us1.example.net", "US"),
    ("hk.example.net", "HK"), ("nrt-01.example.net", "JP"),
    ("node.example.com", ""), ("australia-1.example.com", "AU"),
    ("v2ray-ss-01.example.net", ""),
]
for host, want in hosts:
    check(f"地址 {host} → {want or '认不出'}", providers.region_from_host(host), want)

# ── ③ 各家的配置解析 ────────────────────────────────────────────────────
print("③ 配置解析")
CLASH = '''mixed-port: 7890
external-controller: 127.0.0.1:9090
proxies:
  - name: "🇸🇬 新加坡-02"
    type: vless
    server: sg2.example.net
    port: 443
    reality-opts:
      server-name: www.example.com
  - name: "🇺🇸 美国-01"
    type: vless
    server: us1.example.net
    port: 443
proxy-groups:
  - name: PROXY
    type: select
    proxies: ["🇸🇬 新加坡-02", "🇺🇸 美国-01"]
  - name: GLOBAL
    type: select
    proxies: ["PROXY", "🇸🇬 新加坡-02"]
rules:
  - DOMAIN-SUFFIX,cn,DIRECT
  - MATCH,PROXY
'''
px = providers.parse_clash_proxies(CLASH)
check("Clash：只解析出真节点", set(px), {"🇺🇸 美国-01", "🇸🇬 新加坡-02"})
check("Clash：策略组没混进节点表", "PROXY" in px, False)
check("Clash：节点地址没被 reality-opts 串掉", px["🇺🇸 美国-01"]["server"], "us1.example.net")
check("Clash：默认分组 = MATCH 指向的组", providers.parse_clash_default_group(CLASH), "PROXY")

CLASH_SINGLE = '''proxies:
  - name: proxy
    type: vless
    server: jp-xxx-aa-10077.node-yingyun.site
    port: 6006
proxy-groups:
  - name: GLOBAL
    type: select
    proxies: [proxy]
  - name: PROXY
    type: select
    proxies: [proxy]
rules:
  - MATCH,PROXY
'''
single = providers.parse_clash_proxies(CLASH_SINGLE)
check("单节点配置：只有一个节点", list(single), ["proxy"])
check("单节点配置：默认分组", providers.parse_clash_default_group(CLASH_SINGLE), "PROXY")

SINGBOX = json.dumps({
    "outbounds": [
        {"type": "selector", "tag": "proxy", "outbounds": ["s1", "s2"], "default": "s2"},
        {"type": "urltest", "tag": "auto", "outbounds": ["s1", "s2"]},
        {"type": "vless", "tag": "s1", "server": "jp1.example.net", "server_port": 443},
        {"type": "trojan", "tag": "s2", "server": "us1.example.net", "server_port": 443},
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
    ],
    "route": {"final": "proxy"},
})
sb = providers.parse_json_outbounds(SINGBOX)
check("sing-box：只留真节点", sorted(sb), ["s1", "s2"])
check("sing-box：默认出口顺着 selector 走到节点",
      providers.parse_json_default_outbound(SINGBOX), "s2")
check("sing-box：节点数", providers.count_nodes(sb), 2)

XRAY = {
    "inbounds": [{"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks"}],
    "outbounds": [
        {"tag": "proxy", "protocol": "vmess",
         "settings": {"vnext": [{"address": "sg1.example.net", "port": 443, "users": [{}]}]}},
        {"tag": "direct", "protocol": "freedom", "settings": {}},
        {"tag": "block", "protocol": "blackhole", "settings": {}},
    ],
}
xr = providers.parse_xray_config(json.dumps(XRAY))
check("v2rayN：认出在用的 outbound", (xr["proxy_tag"], xr["server"], xr["port"]),
      ("proxy", "sg1.example.net", 443))
check("v2rayN：认出本地代理口", xr["local"], "127.0.0.1:10808")

MIHOMO_API = {
    "PROXY": {"type": "Selector", "now": "🇺🇸 美国-01"},
    "GLOBAL": {"type": "Selector", "now": "🇸🇬 新加坡-02"},
    "AUTO": {"type": "URLTest", "now": "🇸🇬 新加坡-02"},
    "DIRECT": {"type": "Direct"},
    "REJECT": {"type": "Reject"},
    "REJECT-DROP": {"type": "RejectDrop"},
    "PASS-RULE": {"type": "PassRule"},
    "🇺🇸 美国-01": {"type": "VLESS"},
    "🇸🇬 新加坡-02": {"type": "VLESS"},
}
check("控制器 /proxies：节点数不含组/直连/拒绝/内置规则项",
      providers.count_nodes(MIHOMO_API), 2)

# ── ④ 判定顺序 ──────────────────────────────────────────────────────────
print("④ 判定顺序")


def tmp(text, suffix=".yaml"):
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.write(fd, text.encode("utf-8"))
    os.close(fd)
    return path


def resolve(proxies, groups=None, conns=None, mode="rule", exit_ip="", prev=None, config=None):
    n = server.NetInfo()
    c = providers.Client()
    c.api, c.proxies = "127.0.0.1:9090", dict(proxies)
    c.nodes = len(proxies)
    if config is not None:
        c.config = tmp(config, ".json" if config.lstrip().startswith("{") else ".yaml")
    n.client, n.mihomo = c, {"pid": 7, "config": c.config, "mode": mode}
    n.vpn_exit_ip, n.node = exit_ip, dict(prev or {})
    table = {"/proxies": {"proxies": groups if groups is not None else dict(proxies)}}
    if conns is not None:
        table["/connections"] = {"connections": [{"chains": ch} for ch in conns]}
    server.api = lambda path: table.get(path) or {}
    server.DISCO.match_exit = lambda ip: next(
        (p for p in proxies.values() if p.get("server") == ip), {})
    n._node()
    return n, c


three = {
    "🇸🇬 新加坡-02": {"name": "🇸🇬 新加坡-02", "type": "VLESS", "server": "sg2.example.net", "port": 443},
    "🇺🇸 美国-01": {"name": "🇺🇸 美国-01", "type": "VLESS", "server": "us1.example.net", "port": 443},
    "🇯🇵 东京-01": {"name": "🇯🇵 东京-01", "type": "VLESS", "server": "jp1.example.net", "port": 443},
}
groups_mixed = {
    "PROXY": {"type": "Selector", "now": "🇺🇸 美国-01"},
    "GLOBAL": {"type": "Selector", "now": "🇸🇬 新加坡-02"},
    "AUTO": {"type": "URLTest", "now": "🇸🇬 新加坡-02"},
    **three,
}

n, _ = resolve(three, groups_mixed, conns=[["🇺🇸 美国-01", "PROXY"]])
check("连接表说美国时就是美国（组投票说有 2 票新加坡也不听）",
      (n.node["name"], n.node["source"]), ("🇺🇸 美国-01", "conn"))

n, _ = resolve(three, groups_mixed, conns=[], config=CLASH)
check("没有流量时按配置里 MATCH 的组（PROXY→美国）",
      (n.node["name"], n.node["source"]), ("🇺🇸 美国-01", "default"))

n, _ = resolve(three, groups_mixed, conns=[])
check("连 MATCH 都读不到才退回组投票，并标出'多组不一致'",
      (n.node["name"], n.node["source"], n.node["multi"]), ("🇸🇬 新加坡-02", "group", True))

n, _ = resolve({"us1.example.net 直连": {"name": "us1.example.net 直连", "type": "VLESS",
                                         "server": "9.9.9.9", "port": 443}},
               groups={}, conns=[], exit_ip="9.9.9.9")
check("出口 IP 就是节点地址时按地址认", (n.node["name"], n.node["source"]),
      ("us1.example.net 直连", "exit"))

n, _ = resolve(three, mode="global",
               groups={**three, "GLOBAL": {"type": "Selector", "now": "🇯🇵 东京-01"}},
               conns=[])
check("global 模式按 GLOBAL.now", (n.node["name"], n.node["source"]),
      ("🇯🇵 东京-01", "global"))

n, _ = resolve(single, groups={"PROXY": {"type": "Selector", "now": "proxy"},
                               "GLOBAL": {"type": "Selector", "now": "proxy"},
                               "proxy": {"type": "VLESS"}}, conns=[])
check("鹰云那种单节点：名字照留，但标成占位名",
      (n.node["name"], n.node["generic"]), ("proxy", True))

n, _ = resolve(three, groups={}, conns=[], exit_ip="9.9.9.9",
               prev={"name": "🇸🇬 新加坡-02", "server": "sg2.example.net",
                     "port": 443, "type": "VLESS", "exit": "1.1.1.1"})
check("出口换了又判不出是谁：宁可空着也不顶着旧节点", n.node, {})

n, _ = resolve(three, groups={}, conns=[], exit_ip="1.1.1.1",
               prev={"name": "🇸🇬 新加坡-02", "server": "sg2.example.net",
                     "port": 443, "type": "VLESS", "exit": "1.1.1.1"})
check("出口没变：沿用上次认出的节点", n.node["name"], "🇸🇬 新加坡-02")

n, _ = resolve(three, groups={}, conns=[], exit_ip="1.1.1.1",
               prev={"name": "🇸🇬 新加坡-02", "server": "sg2.example.net", "pid": 7,
                     "port": 443, "type": "VLESS", "exit": "1.1.1.1"})
check("同一个客户端、出口没变：沿用上次的节点", n.node["name"], "🇸🇬 新加坡-02")

n, _ = resolve(three, groups={}, conns=[], exit_ip="1.1.1.1",
               prev={"name": "🇸🇬 新加坡-02", "server": "sg2.example.net", "pid": 999,
                     "port": 443, "type": "VLESS", "exit": "1.1.1.1"})
check("换了客户端进程：不沿用旧节点", n.node, {})

# proxy-providers 订阅：配置里没有 proxies 段，节点表只在控制器里
n, c = resolve({}, groups={**three, "PROXY": {"type": "Selector", "now": "🇺🇸 美国-01"}},
               conns=[], config=CLASH)
check("provider 订阅：用控制器里的节点名兜底", (n.node["name"], n.node["source"]),
      ("🇺🇸 美国-01", "default"))
check("provider 订阅：节点数按控制器算", c.nodes, 3)

# ── ⑤ 发给面板的节点视图 ────────────────────────────────────────────────
print("⑤ 节点视图")


def view(node, egress):
    col = object.__new__(server.Collector)
    col.net, col.egress = type("N", (), {"node": node})(), dict(egress)
    return col._node_view()


EG = {"vpn_ip": "203.0.113.24", "vpn_geo": "Japan", "vpn_cc": "JP", "direct_ip": ""}
v = view({"name": "proxy", "server": "jp-xxx-aa-10077.node-yingyun.site", "port": 6006,
          "type": "VLESS", "generic": True, "source": "only"}, EG)
check("占位节点：带上国家码/地域提示", (v["cc"], v["hint"], v["generic"]), ("JP", "JP", True))

v = view({"name": "🇺🇸 美国-01", "server": "us1.example.net", "port": 443,
          "type": "VLESS", "source": "conn"}, EG)
check("正常节点：名字不动，只补地域字段", (v["name"], v["generic"], v["hint"]),
      ("🇺🇸 美国-01", False, "US"))

v = view({}, EG)
check("认不出节点但知道出口：只报地域", (v.get("generic"), v["cc"]), (True, "JP"))

v = view({}, {"vpn_ip": "", "vpn_geo": "", "vpn_cc": ""})
check("什么都没有：空视图", v, {})

# ── ⑥ 配置边界 ────────────────────────────────────────────────────────────
print("⑥ 配置边界")

FLOW = """proxies:
  - {name: "JP-01", server: jp1.example.net, port: 443, type: vless}
  -  name: "US-02"
     server: us2.example.net
     port: 8443
     type: vmess
  - name: "HK-03"
    server: hk3.example.net
    port: 443
    type: trojan
rules:
  - MATCH,PROXY
"""
px = providers.parse_clash_proxies(FLOW)
check("Clash：行内 {…} 写法也认", px.get("JP-01", {}).get("server"), "jp1.example.net")
check("Clash：`-  name:` 多空格时缩进仍对得上", px.get("US-02", {}).get("port"), 8443)
check("Clash：行内 + 块状混写，节点一个不少", len(px), 3)

XRAY_MULTI = {
    "outbounds": [
        {"tag": "美国-01", "protocol": "vmess",
         "settings": {"vnext": [{"address": "us1.example.net", "port": 443}]}},
        {"tag": "proxy", "protocol": "vless",
         "settings": {"vnext": [{"address": "jp9.example.net", "port": 6006}]}},
        {"tag": "direct", "protocol": "freedom", "settings": {}},
    ],
    "routing": {"rules": [{"type": "field", "outboundTag": "proxy"}]},
}
info = providers.parse_xray_config(json.dumps(XRAY_MULTI))
check("xray：按路由末条认当前 outbound，不按列表顺序",
      (info["proxy_tag"], info["server"]), ("proxy", "jp9.example.net"))
XRAY_D = dict(XRAY_MULTI)
XRAY_D["routing"] = {"rules": [{"type": "field", "outboundTag": "direct"}]}
info = providers.parse_xray_config(json.dumps(XRAY_D))
check("xray：路由指向直连时，退回第一个带地址的节点", info["server"], "us1.example.net")

cfg = tmp(json.dumps(XRAY_MULTI), ".json")
reg = providers.Registry()
reg.client.config = cfg
reg._db_at = __import__("time").time()
reg._db_rows = [(f"节点{i}", f"srv{i}.example.net", 443) for i in range(57)]
reg._xray(reg.client, {})
check("v2rayN：节点总数取自 guiNDB，不被盖成 1", reg.client.nodes, 57)
check("v2rayN：备注查得到时用备注当节点名", reg.client.proxies["proxy"]["name"], "proxy")

# match_exit：一轮最多解析 16 个域名、成功/失败各有 TTL
import socket as _sock
_orig = _sock.getaddrinfo
seen = []
def _fake(host, port, *a, **k):
    seen.append(host)
    if host.startswith("ok"):
        return [(_sock.AF_INET, _sock.SOCK_STREAM, 6, "", ("203.0.113.9", port))]
    raise _sock.gaierror("no")
providers.socket.getaddrinfo = _fake
try:
    r2 = providers.Registry()
    r2.client.proxies = {f"n{i}": {"name": f"n{i}", "server": f"bad{i}.example.net", "port": 443}
                         for i in range(40)}
    r2.match_exit("198.51.100.1")
    check("出口反查：一轮最多解析 16 个域名", len(seen), 16)
    seen.clear()
    r2.match_exit("198.51.100.1")
    check("出口反查：下一轮接着解析下一批（不会只盯前 16 个）", len(seen), 16)
    r3 = providers.Registry()
    r3.client.proxies = {f"n{i}": {"name": f"n{i}", "server": f"ok{i}.example.net", "port": 443}
                         for i in range(10)}
    seen.clear()
    hit = r3.match_exit("203.0.113.9")
    check("出口反查：域名 server 解析后能认出来", hit.get("name"), "n0")
    r4 = providers.Registry()
    r4.client.proxies = dict(r3.client.proxies)
    seen.clear()
    r4.match_exit("198.51.100.1")          # 第一遍：这一轮的 10 个域名全部解析
    check("出口反查：第一遍把能解析的都解析掉", len(seen), 10)
    seen.clear()
    r4.match_exit("198.51.100.1")          # 第二遍：都在缓存里
    check("出口反查：命中过的域名走缓存，不再重复解析", len(seen), 0)
    for k, (ip, _at) in list(r4._dns.items()):
        r4._dns[k] = (ip, 0.0)
    seen.clear()
    r4.match_exit("198.51.100.1")
    check("出口反查：缓存过期后会重新解析", len(seen) > 0, True)
finally:
    providers.socket.getaddrinfo = _orig

check("内置规则项不算节点", (providers.is_pseudo_type("RejectDrop"),
                             providers.is_pseudo_type("PassRule"),
                             providers.is_pseudo_type("VLESS")), (True, True, False))

print(f"\n{OK} 项通过" + ("" if OK else " —— 全挂，检查上面的 FAIL"))
