"""诊断逻辑自检：喂进构造好的证据，看它把锅甩给谁

只测归因判定（_diagnose）、"客户端在不在转发"的判据（_forwarding_proxy）、
以及"进客户端"入口字节的端口集合与累计（proxy_ports / hostflow.sample），
不碰真实网络 —— 所以离线、可重复、秒级。用到的只有本机 netstat / WMI。
运行：python -X utf8 tools\\test_diag.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding="utf-8")

import diag  # noqa: E402
import providers  # noqa: E402
import server  # noqa: E402


def zh(v):
    """"后端发的是 L() 双语对象；自检只看中文那版"（顺带挡住"字段类型变了"这种退化）"""
    return v["zh"] if isinstance(v, dict) else v


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


def mk(probes, link=None, tun=False, route=None, proxy_port=None, conns=0, flow="", client=None,
       fwd=None, px=False):
    c = Fake()
    c.probes = probes
    c._test_conns, c._test_flow, c._test_client = conns, flow, client
    c._test_fwd, c._test_px = fwd, px
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

    # issue #1：有证据表明客户端在转发（系统代理指着它自己开的本地口），
    # 只是它没给字节数 —— 这时说"没在转发"就是假话
    ("能证明它在转发，只是读不到字节数 → 中性且不说「没在转发」", dict(
        probes={"control": ok(), "direct": bad("timeout"), "vpn": bad("refused")},
        proxy_port={"ok": False, "ms": 1500, "kind": "refused"},
        flow="host", client=("演示客户端", "v2ray"), fwd="127.0.0.1:10809"),
     "nopx"),

    # 管理员下从回环口数到了"进客户端"的字节：再说"读不到字节数"也错，
    # 但措辞只能是"经本地口计数"——入口字节不等于隧道流量
    ("能转发 + 也从环回口数到了字节 → 中性，且只声称入口字节", dict(
        probes={"control": ok(), "direct": bad("timeout"), "vpn": bad("refused")},
        proxy_port={"ok": False, "ms": 1500, "kind": "refused"},
        flow="host", client=("演示客户端", "v2ray"), fwd="127.0.0.1:10809", px=True),
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
            got = c._diagnose(conns=c._test_conns, flow=c._test_flow,
                              fwd=c._test_fwd, px=c._test_px)
        finally:
            server.DISCO.client.name, server.DISCO.client.kind = saved
        flag = "ok " if got["state"] == want else "FAIL"
        if got["state"] != want:
            bad_n += 1
        print(f"[{flag}] {i}. {name}")
        print(f"        → {got['state']}  「{zh(got['label'])}」 {zh(got['why'])}")
        if got["evidence"]:
            print(f"        证据: {' | '.join(zh(x) for x in got['evidence'][:3])}")
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
        print(f"        → {got['state']}  「{zh(got['label'])}」")
        if got["evidence"]:
            print(f"        证据: {' | '.join(zh(x) for x in got['evidence'][:3])}")

        # 有系统代理还指着 7890 却说"没客户端"才是真异常，不能被 nopx 吞掉
        c.sysproxy = {"enable": 1, "server": "127.0.0.1:7890"}
        got = c._diagnose()
        flag = "ok " if got["state"] != "nopx" else "FAIL"
        bad_n += got["state"] == "nopx"
        print(f"[{flag}] 2. 系统代理开着但没客户端 → 照旧报 VPN 问题")
        print(f"        → {got['state']}  「{zh(got['label'])}」")
    finally:
        server.DISCO.client = orig

    print("\n=== 「在转发」还是「没在转发」（issue #1）===")
    orig = server.DISCO.client
    try:
        server.DISCO.client = types.SimpleNamespace(
            name="演示客户端", kind="v2ray", core="v2ray", metrics="", api="", flow="", pid=0)
        c = mk({"control": ok(), "direct": bad("timeout"), "vpn": bad("refused")},
               proxy_port={"ok": False, "ms": 1500, "kind": "refused"},
               flow="host", client=("演示客户端", "v2ray"))
        got = c._diagnose(conns=0, flow="host", fwd="127.0.0.1:10809")
        good = "在转发" in zh(got["label"]) and "没在转发" not in zh(got["why"])
        bad_n += not good
        print(f"[{'ok ' if good else 'FAIL'}] 1. 有转发证据 → 「{zh(got['label'])}」，不说「没在转发」")
        print(f"        {zh(got['why'])}")

        got = c._diagnose(conns=0, flow="host", fwd="")
        good = "在转发" not in zh(got["label"]) and "连不上" not in zh(got["why"])
        bad_n += not good
        print(f"[{'ok ' if good else 'FAIL'}] 2. 没证据 → 「{zh(got['label'])}」，也不顺口断言「代理口都连不上」")
        print(f"        {zh(got['why'])}")

        # 真开一个监听口，验证判据本身（只用本机 netstat / WMI，不联网）
        import os as _os
        import socket as _sk
        lsn = _sk.socket()
        lsn.bind(("127.0.0.1", 0))
        lsn.listen(8)
        port = lsn.getsockname()[1]

        server.DISCO.client = types.SimpleNamespace(
            name="演示客户端", kind="v2ray", core="v2ray", metrics="", api="", flow="",
            pid=_os.getpid(), local_proxy=f"127.0.0.1:{port}")
        c.sysproxy = {"enable": 1, "server": f"http=127.0.0.1:{port};https=127.0.0.1:{port}"}
        addr, why = c._forwarding_proxy()
        good = addr.endswith(f":{port}") and bool(why)
        bad_n += not good
        print(f"[{'ok ' if good else 'FAIL'}] 3. 本机口在听 + 进程对得上 → ({addr!r}, {why!r})")

        c.sysproxy = {"enable": 0, "server": f"127.0.0.1:{port}"}
        addr, why = c._forwarding_proxy()
        good = (addr, why) == ("", "")
        bad_n += not good
        print(f"[{'ok ' if good else 'FAIL'}] 4. 系统代理关掉 → 不算在转发 ({addr!r})")

        server.DISCO.client = types.SimpleNamespace(
            name="演示客户端", kind="v2ray", core="v2ray", metrics="", api="", flow="",
            pid=999999, local_proxy="")
        c.sysproxy = {"enable": 1, "server": f"127.0.0.1:{port}"}
        addr, why = c._forwarding_proxy()
        good = addr == ""
        bad_n += not good
        print(f"[{'ok ' if good else 'FAIL'}] 5. 口不是它开的（别的程序占着）→ 不当证据 ({addr!r})")

        # 缓存里名字对得上、但那个 PID 已经不在了：缓存不能当"它此刻在转发"
        o_ports, o_table, o_alive = server.DISCO._ports, server.DISCO._table, providers._alive
        try:
            server.DISCO.client = types.SimpleNamespace(
                name="演示客户端", kind="v2ray", core="v2ray", metrics="", api="", flow="",
                pid=0, local_proxy="")
            server.DISCO._ports = lambda force=False: {port: 999999}
            server.DISCO._table = lambda force=False: {999999: {"name": "v2ray.exe", "ppid": 0}}
            providers._alive = lambda pid: False
            addr, why = c._forwarding_proxy()
            good = (addr, why) == ("", "")
            bad_n += not good
            print(f"[{'ok ' if good else 'FAIL'}] 6. 缓存里名字对得上、但进程已死 → 不算在转发 ({addr!r})")

            providers._alive = lambda pid: True
            addr, why = c._forwarding_proxy()
            good = addr.endswith(f":{port}") and bool(why)
            bad_n += not good
            print(f"[{'ok ' if good else 'FAIL'}] 7. 进程还活着 → 才算它内核在转发 ({addr!r}, {why!r})")
        finally:
            server.DISCO._ports, server.DISCO._table, providers._alive = o_ports, o_table, o_alive
        lsn.close()
    finally:
        server.DISCO.client = orig

    print("\n=== 客户端入口字节（经本地代理口，不看客户端的统计口）===")
    import socket as _sk
    import time as _time

    import hostflow as _hf
    orig = server.DISCO.client
    try:
        server.DISCO.client = types.SimpleNamespace(
            name="演示客户端", kind="v2ray", core="v2ray", metrics="", api="", flow="",
            pid=0, local_proxy="")
        c = mk({"control": ok(), "direct": ok(), "vpn": ok()}, flow="host")

        c.sysproxy = {"enable": 1, "server": "http=127.0.0.1:10909;https=127.0.0.1:10909"}
        ports = c._proxy_ports()
        good = 10909 in ports
        bad_n += not good
        print(f"[{'ok ' if good else 'FAIL'}] 1. 系统代理开着 → 回环代理口进集合 {sorted(ports)}")

        c.sysproxy = {"enable": 0, "server": ""}
        ports = c._proxy_ports()
        good = not ports
        bad_n += not good
        print(f"[{'ok ' if good else 'FAIL'}] 2. 没客户端也没系统代理 → 空集合，不去数 7890 {sorted(ports)}")

        # 关掉系统代理后注册表里留着旧地址：那端口可能正被别的程序用着，不能算
        c.sysproxy = {"enable": 0, "server": "http=127.0.0.1:8080"}
        ports = c._proxy_ports()
        good = not ports
        bad_n += not good
        print(f"[{'ok ' if good else 'FAIL'}] 3. 系统代理关着、只剩注册表残留 → 不算 {sorted(ports)}")

        # 远端代理（http=10.x.x.x:3128）：它占的不是本机端口，不能拿去配本机回环连接
        c.sysproxy = {"enable": 1, "server": "http=10.1.2.3:3128"}
        ports = c._proxy_ports()
        good = 3128 not in ports
        bad_n += not good
        print(f"[{'ok ' if good else 'FAIL'}] 4. 代理地址不是回环 → 端口不进集合 {sorted(ports)}")

        # 真开一个监听口 + 一条连接，eStats 换成假计数（所以不需要管理员）
        lsn = _sk.socket()
        lsn.bind(("127.0.0.1", 0))
        lsn.listen(4)
        port = lsn.getsockname()[1]
        cli = _sk.create_connection(("127.0.0.1", port), timeout=2)
        srv, _ = lsn.accept()
        cnt = {}
        o_on, o_bytes = _hf.estats_on, _hf.estats_bytes

        def fake_bytes(conn):
            k = (conn["laddr"], conn["lportn"], conn["raddr"], conn["rportn"])
            n = cnt.get(k, 0)
            cnt[k] = n + 1
            return (n * 100_000, n * 50_000)

        _hf.estats_on = lambda conn: 0
        _hf.estats_bytes = fake_bytes
        try:
            h = _hf.HostFlow(nic_name="")
            h.estats = True
            h.MAX_ROWS = 99
            for _ in range(3):
                s = h.sample(want_procs=True, proxy_ports={port})
                _time.sleep(0.2)
            px = s.get("proxy") or {}
            good = px.get("down", 0) > 0 and px.get("up", 0) > 0
            bad_n += not good
            print(f"[{'ok ' if good else 'FAIL'}] 5. 应用→本地口的回环连接数出入口字节 "
                  f"↓{px.get('down', 0):.0f} ↑{px.get('up', 0):.0f} B/s")

            row = [p for p in (s.get("procs") or []) if p.get("px_down") or p.get("px_up")]
            good = bool(row)
            bad_n += not good
            print(f"[{'ok ' if good else 'FAIL'}] 6. 这份字节也记到了进程头上"
                  f"{'：' + row[0]['name'] if row else ''}")

            h._pxema = [0.0, 0.0]      # 把平滑值清零，只这一帧看增量
            s2 = h.sample(want_procs=True, proxy_ports={1})
            px2 = s2.get("proxy") or {}
            good = (s2.get("proxy_conns") == 0 and not px2.get("down") and not px2.get("up"))
            bad_n += not good
            print(f"[{'ok ' if good else 'FAIL'}] 7. 端口不在集合里 → 不算入口字节（0 字节）")
        finally:
            _hf.estats_on, _hf.estats_bytes = o_on, o_bytes
            cli.close()
            srv.close()
            lsn.close()
    finally:
        server.DISCO.client = orig

    print("\n结论：" + ("全部通过" if not bad_n else f"{bad_n} 项不通过"))
    return 0 if not bad_n else 1


if __name__ == "__main__":
    raise SystemExit(main())
