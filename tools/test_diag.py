"""诊断逻辑自检：喂进构造好的证据，看它把锅甩给谁

只测归因判定（_diagnose），不碰真实网络 —— 所以离线、可重复、秒级。
运行：python -X utf8 tools\\test_diag.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding="utf-8")

import diag  # noqa: E402
import server  # noqa: E402


class Fake(server.Collector):
    """不跑线程、不发包，只提供 _diagnose 需要的那几个字段"""

    def __init__(self):
        self.net = server.NetInfo()
        self.probes = {}
        self.link = {}
        self.cfg = {}
        self.sysproxy = {"enable": 1, "server": "127.0.0.1:7890"}
        self._proxy = "127.0.0.1:7890"
        self.egress = {}
        self.diag = {}

    @property
    def proxy(self):
        return self._proxy


def ok(ms=40):
    return {"ok": True, "status": 200, "ms": ms, "err": "", "kind": ""}


def bad(kind, ms=2000):
    return {"ok": False, "status": 0, "ms": ms, "err": "URLError", "kind": kind}


GW_UP = {"ok": True, "ms": 3, "kind": "", "ip": "192.0.2.1", "name": "以太网"}
GW_DOWN = {"ok": False, "ms": 900, "kind": "unreach", "ip": "192.0.2.1", "name": "WLAN"}
DNS_OK = {"system": {"ok": True, "ms": 12, "ips": ["203.0.113.9"]},
          "public": {"ok": True, "ms": 9, "ips": ["203.0.113.9"]}, "mismatch": False}
DNS_FAIL = {"system": {"ok": False, "ms": 90, "ips": [], "kind": "dns"},
            "public": {"ok": True, "ms": 8, "ips": ["203.0.113.9"]}, "mismatch": False}


def mk(probes, link=None, tun=False, route=None, proxy_port=None, conns=0, flow="", client=None):
    c = Fake()
    c.probes = probes
    c._test_conns, c._test_flow, c._test_client = conns, flow, client
    c.cfg = {"tun": {"enable": tun}, "mode": "rule"}
    c.net.route = route or {
        "vpn": {"name": "以太网 2", "kind": "ethernet", "ip": "192.0.2.10", "gateway": "192.0.2.1"},
        "direct": {"name": "WLAN", "kind": "wlan", "ip": "192.0.2.20", "ssid": "Demo", "gateway": "192.0.2.1"},
        "dual": True,
    }
    c.link = {
        "ts": 0, "dst": "203.0.113.9",
        "gw": {"vpn": GW_UP, "direct": GW_UP},
        "dns": {"target": DNS_OK, "control": {"system": {"ok": True, "ips": ["1.1.1.1"]}}},
        "by_nic": {"vpn": {"ok": True}, "direct": {"ok": False, "kind": "timeout"}},
        "proxy_port": proxy_port or {"ok": True, "ms": 1},
    }
    if link:
        c.link.update(link)
    return c


CASES = [
    ("对照片不通 + 网关无响应 → 甩给链路", dict(
        probes={"control": bad("timeout"), "direct": bad("timeout"), "vpn": ok()},
        link={"gw": {"vpn": GW_UP, "direct": GW_DOWN}}),
     "link"),

    ("对照片不通 + 网关正常 + DNS 坏 → 甩给 DNS", dict(
        probes={"control": bad("dns"), "direct": bad("timeout"), "vpn": ok()},
        link={"dns": {"target": DNS_OK, "control": {"system": {"ok": False, "kind": "dns"}}}}),
     "dns"),

    ("对照片不通 + 网关正常 + DNS 正常 → 甩给上游", dict(
        probes={"control": bad("timeout"), "direct": bad("timeout"), "vpn": ok()}),
     "upstream"),

    ("链路通 + 代理口连不上 → VPN 没开", dict(
        probes={"control": ok(), "direct": bad("timeout"), "vpn": bad("refused")},
        proxy_port={"ok": False, "ms": 1500, "kind": "refused"}),
     "vpn"),

    ("链路通 + 代理口有东西但不转发、又没客户端 → 端口被占", dict(
        probes={"control": ok(), "direct": bad("timeout"), "vpn": bad("refused")}),
     "vpn"),

    ("链路通 + 代理超时 → 隧道/节点", dict(
        probes={"control": ok(), "direct": bad("timeout"), "vpn": bad("timeout")}),
     "vpn"),

    ("链路通 + 隧道那块网卡网关挂了 → 甩给链路", dict(
        probes={"control": ok(), "direct": bad("timeout"), "vpn": bad("timeout")},
        link={"gw": {"vpn": GW_DOWN, "direct": GW_UP}},
        route={"vpn": {"name": "WLAN", "kind": "wlan", "ip": "192.0.2.20", "ssid": "Demo", "gateway": "192.0.2.1"},
               "direct": {"name": "以太网", "kind": "ethernet", "ip": "192.0.2.10", "gateway": "192.0.2.1"}}),
     "link"),

    ("代理通、直连目标不通 → 目标被墙（正常）", dict(
        probes={"control": ok(), "direct": bad("timeout"), "vpn": ok(900)}),
     "target"),

    ("TUN 开着时直连不通 → 不算链路坏", dict(
        probes={"control": ok(), "direct": bad("timeout"), "vpn": ok(900)}, tun=True),
     "target"),

    ("三条全通 → 正常", dict(
        probes={"control": ok(), "direct": ok(300), "vpn": ok(600)}),
     "ok"),

    ("还没探测过 → 不装懂", dict(probes={}, link={}),
     "unknown"),

    # 客户端关掉节点之后最容易误报的两条：不该红
    ("客户端壳还在、控制器读不到（已退回网卡）→ 中性，不报红", dict(
        probes={"control": ok(), "direct": bad("timeout"), "vpn": bad("refused")},
        proxy_port={"ok": False, "ms": 1500, "kind": "refused"},
        flow="host", client=("演示客户端", "clash")),
     "nopx"),

    ("代理口通、但隧道里 0 条连接 → 没连上节点（中性）", dict(
        probes={"control": ok(), "direct": bad("timeout"), "vpn": bad("timeout")},
        conns=0, flow="clash"),
     "off"),

    ("隧道里明明有连接却打不通 → 仍是隧道异常（红）", dict(
        probes={"control": ok(), "direct": bad("timeout"), "vpn": bad("timeout")},
        conns=7, flow="clash"),
     "vpn"),
]


def main() -> int:
    bad_n = 0
    print("=== 归因判定 ===")
    for i, (name, kw, want) in enumerate(CASES, 1):
        c = mk(**kw)
        # 客户端身份由用例显式给定，别让这台机器上真在跑的客户端影响结论
        saved = (server.DISCO.client.name, server.DISCO.client.kind)
        cn = c._test_client
        server.DISCO.client.name, server.DISCO.client.kind = cn if cn else ("", "none")
        try:
            got = c._diagnose(conns=c._test_conns, flow=c._test_flow)
        finally:
            server.DISCO.client.name, server.DISCO.client.kind = saved
        flag = "ok " if got["state"] == want else "FAIL"
        if got["state"] != want:
            bad_n += 1
        print(f"[{flag}] {i}. {name}")
        print(f"        → {got['state']}  「{got['label']}」 {got['why']}")
        if got["evidence"]:
            print(f"        证据: {' | '.join(got['evidence'][:3])}")
        if got["state"] != want:
            print(f"        期望 {want}，实际 {got['state']}")

    print("\n=== 错误分类 ===")
    import socket
    import ssl
    import urllib.error
    import urllib.request
    pairs = [
        (socket.gaierror(11001, "x"), "dns"),
        (ConnectionRefusedError(10061, "x"), "refused"),
        (ConnectionResetError(10054, "x"), "reset"),
        (TimeoutError("timed out"), "timeout"),
        (OSError(10051, "x"), "unreach"),
        (ssl.SSLCertVerificationError(1, "x"), "tls"),
        (urllib.error.URLError(socket.gaierror(11001, "x")), "dns"),
        (urllib.error.URLError(ConnectionRefusedError(10061, "x")), "refused"),
        (urllib.request.HTTPError("u", 404, "nf", {}, None), "http"),
    ]
    for exc, want in pairs:
        got = diag.classify(exc)
        flag = "ok " if got == want else "FAIL"
        if got != want:
            bad_n += 1
        print(f"[{flag}] {type(exc).__name__:22} → {got:8} {diag.label(got)}")

    print("\n=== 没有代理客户端（本机模式） ===")
    import types
    orig = server.DISCO.client
    try:
        nocli = types.SimpleNamespace(name="", kind="none", metrics="", api="", flow="")
        server.DISCO.client = nocli
        c = mk({"control": ok(), "direct": bad("timeout"), "vpn": bad("refused")})
        c.sysproxy = {"enable": 0, "server": ""}
        got = c._diagnose()
        flag = "ok " if got["state"] == "nopx" else "FAIL"
        bad_n += got["state"] != "nopx"
        print(f"[{flag}] 1. 没客户端 + 没系统代理 → 不判故障")
        print(f"        → {got['state']}  「{got['label']}」")
        if got["evidence"]:
            print(f"        证据: {' | '.join(got['evidence'][:3])}")

        # 有系统代理还指着 7890 却说"没客户端"才是真异常，不能被 nopx 吞掉
        c.sysproxy = {"enable": 1, "server": "127.0.0.1:7890"}
        got = c._diagnose()
        flag = "ok " if got["state"] != "nopx" else "FAIL"
        bad_n += got["state"] == "nopx"
        print(f"[{flag}] 2. 系统代理开着但没客户端 → 照旧报 VPN 问题")
        print(f"        → {got['state']}  「{got['label']}」")
    finally:
        server.DISCO.client = orig

    print("\n结论：" + ("全部通过" if not bad_n else f"{bad_n} 项不通过"))
    return 0 if not bad_n else 1


if __name__ == "__main__":
    raise SystemExit(main())
