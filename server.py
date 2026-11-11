#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FLOW — 本机流量出口监视器（只读）

数据全部来自本机已有组件，不抓包、不要管理员权限：
  · mihomo external-controller 的 /connections /configs /version
    → 每条连接的真实域名、上下行字节、所属节点链（判断"走没走 VPN"的依据）
  · netsh wlan / netsh interface ipv4
    → 走哪个 Wi-Fi（SSID/频段/信道/信号/协商速率）、本机 IP、网关
  · 代理通道 / 直连通道 双路探测
    → 该站点此刻是否可直连、延迟多少、出口 IP 是谁

接口：GET /  ·  GET /api/state  ·  GET /api/stream (SSE, 每秒推送)
"""
from __future__ import annotations

import ctypes

import providers
import json
import os
import re
import socket
import subprocess
import threading
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import ProxyHandler, Request, build_opener

BASE = os.path.dirname(os.path.abspath(__file__))


def _load_config() -> dict:
    cfg = {
        "port": 7717,
        "controller": "127.0.0.1:7892",
        "mixed_port": "127.0.0.1:7890",
        "sites": ["chatgpt.com", "openai.com"],
        "probe_interval": 10,
        "probe_target": "https://chatgpt.com/",
    }
    path = os.path.join(BASE, "config.json")
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                cfg.update(json.load(f))
        except Exception:
            pass
    if os.environ.get("FLOW_PORT"):
        cfg["port"] = int(os.environ["FLOW_PORT"])
    if os.environ.get("FLOW_CONTROLLER"):
        cfg["controller"] = os.environ["FLOW_CONTROLLER"]
    return cfg


CFG = _load_config()
PORT = int(CFG["port"])
CTRL = str(CFG.get("controller", ""))
DISCO = providers.Registry(CTRL)          # 自动发现：不绑死某一家客户端
MIXED = str(CFG["mixed_port"])
SITES = [s.strip().lower() for s in CFG["sites"] if s.strip()]
PROBE_EVERY = max(5, int(CFG.get("probe_interval", 10)))
PROBE_TARGET = str(CFG.get("probe_target", "https://chatgpt.com/"))
CONTROL_URL = str(CFG.get("control_target", "https://www.baidu.com/"))
CONTROL_HOST = CONTROL_URL.split("//", 1)[-1].split("/", 1)[0]
STATE_FILE = os.path.join(BASE, "state.json")
CFG_PATH = os.path.join(BASE, "config.json")
MAX_EXTRA_ROWS = 4
HIST_MAX = 120
DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62})(\.[a-z0-9]([a-z0-9-]{0,62}))+$")


def norm_domain(raw: str) -> str:
    """吃用户随手贴的东西：带 https://、带路径、带 www.、大写、空格"""
    s = (raw or "").strip().lower()
    s = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", s)
    s = s.split("/")[0].split("?")[0].split("#")[0].strip()
    s = s.split(":")[0].strip(".")
    if s.startswith("www."):
        s = s[4:]
    if not s or len(s) > 253 or ".." in s or not DOMAIN_RE.match(s):
        return ""
    return s


def set_site(action: str, raw: str):
    """增删监测域名，立刻落盘到 config.json"""
    d = norm_domain(raw)
    if not d:
        return False, "看起来不是个域名", list(SITES)
    if action == "add":
        if d in SITES:
            return True, f"{d} 已经在列表里", list(SITES)
        SITES.append(d)
        msg = f"已添加 {d}"
    elif action == "remove":
        if d not in SITES:
            return True, f"{d} 不在列表里", list(SITES)
        SITES.remove(d)
        msg = f"已移除 {d}"
    else:
        return False, "未知操作", list(SITES)
    CFG["sites"] = list(SITES)
    try:
        with open(CFG_PATH, "w", encoding="utf-8") as f:
            json.dump(CFG, f, ensure_ascii=False, indent=2)
    except Exception as e:
        log("写 config.json 失败:", e)
        return False, "已生效，但写配置文件失败", list(SITES)
    log("监测列表 →", ", ".join(SITES) or "(空)")
    return True, msg, list(SITES)

DIRECT = build_opener(ProxyHandler({}))   # 真·直连：urllib 默认不读 Windows 注册表代理


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


# ---------------------------------------------------------------- 基础
def api(path: str, timeout: float = 2.5):
    c = DISCO.client
    host = (c.api if c else "") or CTRL
    if not host:
        raise RuntimeError("未发现代理控制器")
    req = Request(f"http://{host}{path}", headers={"Accept": "application/json"})
    if c and c.secret:
        req.add_header("Authorization", f"Bearer {c.secret}")
    with DIRECT.open(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def run(cmd, timeout: float = 6.0) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        raw = p.stdout or b""
        for enc in ("utf-8", "gbk"):
            try:
                return raw.decode(enc)
            except UnicodeDecodeError:
                continue
        return raw.decode("utf-8", "replace")
    except Exception:
        return ""


def pid_alive(pid: int) -> bool:
    """不加信号地探活；os.kill(pid, 0) 在 Windows 上会直接杀进程，绝不能用"""
    if not pid:
        return False
    try:
        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(0x1000, False, int(pid))   # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return False
        code = ctypes.c_ulong()
        ok = k32.GetExitCodeProcess(h, ctypes.byref(code))
        k32.CloseHandle(h)
        return bool(ok) and code.value == 259          # STILL_ACTIVE
    except Exception:
        return False


def http_get(url: str, proxy: str | None, timeout: float = 6.0, read: int = 4096) -> dict:
    if proxy:
        opener = build_opener(ProxyHandler({"http": f"http://{proxy}", "https": f"http://{proxy}"}))
    else:
        opener = DIRECT
    t0 = time.monotonic()
    try:
        req = Request(url, headers={"User-Agent": "flow/1.0", "Accept": "*/*"})
        with opener.open(req, timeout=timeout) as r:
            body = r.read(read).decode("utf-8", "replace")
            return {"ok": True, "status": getattr(r, "status", 200),
                    "ms": round((time.monotonic() - t0) * 1000), "err": "", "body": body}
    except Exception as e:
        code = getattr(e, "code", 0) or 0
        return {"ok": bool(code), "status": code,
                "ms": round((time.monotonic() - t0) * 1000),
                "err": "" if code else type(e).__name__, "body": ""}


# ---------------------------------------------------------------- 状态发布
class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.boot = time.time()
        self.snap: dict = {}
        self.version = 0

    def publish(self, snap: dict):
        snap["ts"] = time.time()
        snap["boot"] = self.boot
        with self.lock:
            self.snap = snap
            self.version += 1

    def read(self):
        with self.lock:
            return self.snap, self.version


ST = State()


# ---------------------------------------------------------------- 网卡 / 节点
class NetInfo:
    # 键一律去掉空白后再比对，这样中英文本地化都能命中
    WLAN_KEYS = {
        "name": "name", "名称": "name",
        "state": "state", "状态": "state",
        "ssid": "ssid",
        "apbssid": "bssid", "bssid": "bssid",
        "band": "band", "频带": "band", "波段": "band",
        "channel": "channel", "信道": "channel", "通道": "channel",
        "radiotype": "radio", "无线电类型": "radio",
        "signal": "signal", "信号": "signal",
        "rssi": "rssi",
        "receiverate(mbps)": "rx", "接收速率(mbps)": "rx",
        "transmitrate(mbps)": "tx", "传输速率(mbps)": "tx",
        "authentication": "auth", "身份验证": "auth",
        "profile": "profile", "配置文件": "profile",
    }
    ADDR_KEYS = {
        "ipaddress": "ip", "ip地址": "ip",
        "defaultgateway": "gateway", "默认网关": "gateway",
        "interfacemetric": "metric", "接口跃点数": "metric",
    }

    @staticmethod
    def _norm(s: str) -> str:
        return re.sub(r"\s+", "", s).lower()

    def __init__(self):
        self.iface: dict = {"kind": "unknown"}
        self.node: dict = {}
        self.mihomo: dict = {"pid": 0, "config": ""}
        self.client = None
        self.vpn_exit_ip = ""
        self._last_proc = 0.0
        self.route: dict = {}
        self.direct_dst_ip = ""
        self.direct_src_ip = ""
        self._last_dst = 0.0

    def _wlan(self) -> dict:
        info: dict = {}
        for line in run(["netsh", "wlan", "show", "interfaces"]).splitlines():
            if ":" not in line:
                continue
            k, _, v = line.partition(":")
            key = self.WLAN_KEYS.get(self._norm(k))
            if key and v.strip() and key not in info:
                info[key] = v.strip()
        if info.get("signal", "").endswith("%"):
            info["signal"] = info["signal"].rstrip("% ").strip()
        return info

    def _addrs(self) -> dict:
        blocks: dict = {}
        cur = None
        for line in run(["netsh", "interface", "ipv4", "show", "addresses"]).splitlines():
            m = re.search(r'"([^"]+)"', line)
            if m and ("Configuration" in line or "配置" in line):
                cur = m.group(1)
                blocks[cur] = {}
                continue
            if cur and ":" in line:
                k, _, v = line.partition(":")
                key = self.ADDR_KEYS.get(self._norm(k))
                if key and v.strip() and key not in blocks[cur]:
                    blocks[cur][key] = v.strip()
        return blocks

    @staticmethod
    def _local_ip_to(dst: str, port: int = 443) -> str:
        """内核实际选中的源地址 —— 用它来判定"走的是哪块网卡"，比按名字猜可靠"""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((dst, port))
            return s.getsockname()[0]
        except Exception:
            return ""
        finally:
            s.close()

    def _proc(self):
        """客户端识别全部交给 providers：换软件、换端口、重启订阅都能自己跟上"""
        self.client = DISCO.tick()
        c = self.client
        self.mihomo = {"pid": c.pid, "config": c.config, "mode": c.mode}

    @staticmethod
    def _parse_proxies(text: str) -> dict:
        """把配置里的 proxies 段解析成 name → {type, server, port}。
        只认与 name 同级的键，ws-opts / reality-opts 里的同名键不会串进来。"""
        out: dict = {}
        if "proxies:" not in text:
            return out
        seg = text.split("proxies:", 1)[1]
        cur = None
        base = -1
        for raw in seg.splitlines():
            line = raw.rstrip()
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            indent = len(line) - len(line.lstrip())
            if s.startswith("- "):
                cur = None
                body = s[2:]
                if not body.startswith("name:"):
                    continue
                base = indent + 2
                cur = {"name": body.split("name:", 1)[1].strip().strip("\"'"),
                       "server": "", "port": 0, "type": ""}
                out[cur["name"]] = cur
                continue
            if cur is None or indent != base:
                continue
            k, sep, v = s.partition(":")
            if not sep or k.strip() not in ("name", "type", "server", "port"):
                continue
            v = v.strip().strip("\"'")
            k = k.strip()
            if k == "port":
                cur["port"] = int(re.sub(r"\D", "", v) or 0)
            elif k == "type":
                cur["type"] = v.upper()
            else:
                cur[k] = v
        return out

    def _node(self):
        c = self.client
        proxies = dict(c.proxies) if (c and c.proxies) else {}
        if not proxies:
            conf = self.mihomo.get("config") or ""
            if conf and os.path.exists(conf):
                proxies = self._parse_proxies(providers._read(conf))
        if not proxies:
            if c and not c.api:
                self.node = {}          # 既没有控制器也没有配置：宁可空着也不猜
            return
        self.proxies = proxies
        # 真正在用的节点：先问控制器选中的是谁（global 模式下 GLOBAL 组的 now 就是它），
        # 再退到连接链里出现次数最多的那个配置名
        want, counts = "", {}
        try:
            groups = (api("/proxies") or {}).get("proxies") or {}
            g = groups.get("GLOBAL") or {}
            if (self.mihomo.get("mode") or "").lower() == "global" and g.get("now") in proxies:
                want = g["now"]
            else:
                for gg in groups.values():
                    if gg.get("type") in ("Selector", "URLTest", "Fallback") and gg.get("now") in proxies:
                        counts[gg["now"]] = counts.get(gg["now"], 0) + 1
        except Exception:
            pass
        if not want and getattr(self, "vpn_exit_ip", ""):
            hit = DISCO.match_exit(self.vpn_exit_ip)
            if hit:
                want = hit["name"]
        if not want:
            try:
                for c in api("/connections").get("connections") or []:
                    for x in c.get("chains") or []:
                        if x in proxies:
                            counts[x] = counts.get(x, 0) + 1
                if counts:
                    want = max(counts, key=counts.get)
            except Exception:
                pass
        prev = dict(self.node)
        p = proxies.get(want) or {}
        if not p:
            if prev.get("server"):
                # 没有依据时沿用上次认出的节点，别随手抓配置里的第一条（可能是占位项）
                self.node = {**prev, "pid": self.mihomo.get("pid", 0)}
                return
            for v in proxies.values():
                srv = v.get("server") or ""
                if srv and not re.fullmatch(r"\d+", srv) and "." in srv:
                    p, want = v, v["name"]
                    break
        self.node = {
            "name": want or p.get("name", ""),
            "server": p.get("server", ""),
            "port": p.get("port", 0),
            "type": p.get("type", ""),
            "pid": self.mihomo.get("pid", 0),
        }
        if self.node.get("server") != prev.get("server"):
            self.node["changed_at"] = time.time()
        else:
            self.node["changed_at"] = prev.get("changed_at", 0)

    def _pack_nic(self, addrs, wlan, ip: str) -> dict:
        name, a = "", {}
        if ip:
            for k, v in addrs.items():
                if v.get("ip") == ip:
                    name, a = k, v
                    break
        if not a and wlan.get("name") and addrs.get(wlan["name"], {}).get("ip"):
            name = wlan["name"]
            a = addrs[name]
        if not a:
            for k, v in addrs.items():
                if v.get("ip", "").startswith(("10.", "192.168.", "172.")):
                    name, a = k, v
                    break
        is_wlan = bool(wlan.get("ssid")) and name == wlan.get("name")
        return {
            "name": name,
            "kind": "wlan" if is_wlan else ("ethernet" if a.get("ip") else "unknown"),
            "routed": bool(ip) and a.get("ip") == ip,
            "ssid": wlan.get("ssid", "") if is_wlan else "",
            "state": wlan.get("state", "") if is_wlan else "",
            "band": wlan.get("band", "") if is_wlan else "",
            "channel": wlan.get("channel", "") if is_wlan else "",
            "radio": wlan.get("radio", "") if is_wlan else "",
            "signal": wlan.get("signal", "") if is_wlan else "",
            "rssi": wlan.get("rssi", "") if is_wlan else "",
            "rx": wlan.get("rx", "") if is_wlan else "",
            "tx": wlan.get("tx", "") if is_wlan else "",
            "bssid": wlan.get("bssid", "") if is_wlan else "",
            "ip": a.get("ip", ""),
            "gateway": a.get("gateway", ""),
            "metric": a.get("metric", ""),
        }

    def tick_iface(self):
        wlan = self._wlan()
        addrs = self._addrs()
        vpn_nic = self._pack_nic(addrs, wlan, getattr(self, "upstream_ip", ""))
        dir_nic = self._pack_nic(addrs, wlan, getattr(self, "direct_src_ip", ""))
        self.iface = vpn_nic
        self.route = {
            "vpn": {k: vpn_nic[k] for k in ("name", "kind", "ip", "ssid")},
            "direct": {k: dir_nic[k] for k in ("name", "kind", "ip", "ssid")},
            "dual": bool(vpn_nic["name"]) and bool(dir_nic["name"]) and vpn_nic["name"] != dir_nic["name"],
        }

    def tick_node(self):
        self._proc()
        self._node()
        host, port = self.node.get("server"), self.node.get("port")
        rtt = None
        if host and port:
            try:
                addr = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
                self.node["ip"] = addr
                self.upstream_ip = self._local_ip_to(addr, port)
                t0 = time.monotonic()
                with socket.create_connection((addr, port), timeout=3):
                    rtt = round((time.monotonic() - t0) * 1000)
            except Exception:
                rtt = -1
        self.node["rtt"] = rtt
        # 直连那条路走哪块网卡：用对照站点的地址去问一次内核
        if time.time() - self._last_dst > 300:
            ip = ""
            try:
                ip = socket.getaddrinfo(CONTROL_HOST, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
            except Exception:
                pass
            if ip:
                self.direct_dst_ip = ip
                self._last_dst = time.time()
        if self.direct_dst_ip:
            self.direct_src_ip = self._local_ip_to(self.direct_dst_ip)

    def loop(self, stop: threading.Event):
        n = 0
        while not stop.is_set():
            try:
                if n % 3 == 0:
                    self.tick_node()
                self.tick_iface()
            except Exception as e:
                log("netinfo:", e)
            n += 1
            stop.wait(20)


# ---------------------------------------------------------------- 采集器
class Collector:
    def __init__(self, net: NetInfo):
        self.net = net
        self.prev: dict[str, tuple[int, int]] = {}
        self.last_ts = 0.0
        self.ema: dict[str, list[float]] = defaultdict(lambda: [0.0, 0.0])
        self.ex_ema: dict[str, list[float]] = defaultdict(lambda: [0.0, 0.0])
        self.ex_meta: dict[str, dict] = {}
        self.last_via: dict[str, str] = {}
        self.tot = [0.0, 0.0]
        self.hist_total: list[list[int]] = []
        self.hist_sites: dict[str, list[list[int]]] = {}
        self.cum: dict[str, list[float]] = defaultdict(lambda: [0.0, 0.0])
        self.egress = {"vpn_ip": "", "vpn_geo": "", "vpn_ts": 0, "vpn_err": "",
                       "direct_ip": "", "direct_geo": "", "direct_ts": 0, "direct_err": ""}
        self.probes: dict[str, dict] = {}
        self.cfg: dict = {}
        self.cfg_ts = 0.0
        self.ver = ""
        self.sysproxy = {"enable": 0, "server": ""}
        self.error = ""
        self._load_state()

    def _load_state(self):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                for k, v in json.load(f).items():
                    if isinstance(v, list) and len(v) == 2:
                        self.cum[k] = [float(v[0]), float(v[1])]
        except Exception:
            pass

    def _save_state(self):
        try:
            tmp = STATE_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(dict(self.cum), f)
            os.replace(tmp, STATE_FILE)
        except Exception:
            pass

    def read_sysproxy(self):
        key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        out = run(["reg", "query", key, "/v", "ProxyEnable"])
        m = re.search(r"ProxyEnable\s+REG_DWORD\s+0x([0-9a-fA-F]+)", out)
        enable = int(m.group(1), 16) if m else 0
        out2 = run(["reg", "query", key, "/v", "ProxyServer"])
        m2 = re.search(r"ProxyServer\s+REG_SZ\s+(\S+)", out2)
        self.sysproxy = {"enable": enable, "server": m2.group(1) if m2 else ""}

    def tick_cfg(self):
        if time.time() - self.cfg_ts < 15:
            return
        self.cfg_ts = time.time()
        try:
            self.cfg = api("/configs", timeout=2)
        except Exception:
            self.cfg = {}
        if not self.ver:
            try:
                self.ver = api("/version", timeout=2).get("version", "")
            except Exception:
                pass

    # -- 1 秒采样
    def sample(self):
        now = time.time()
        try:
            data = api("/connections", timeout=2)
        except Exception as e:
            self.error = f"mihomo 接口不可达：{type(e).__name__}"
            self._publish(ok=False)
            return
        self.error = ""
        conns = data.get("connections") or []
        dt = max(0.25, now - self.last_ts) if self.last_ts else 1.0
        self.last_ts = now

        per_host: dict[str, list[float]] = defaultdict(lambda: [0.0, 0.0])
        per_n: dict[str, int] = defaultdict(int)
        per_ip: dict[str, str] = {}
        per_chain: dict[str, str] = {}
        per_rule: dict[str, str] = {}
        seen = set()

        for c in conns:
            cid = c.get("id") or ""
            seen.add(cid)
            up = int(c.get("upload", 0))
            dn = int(c.get("download", 0))
            pu, pd = self.prev.get(cid, (None, None))
            dup = 0 if pu is None else max(0, up - pu)
            ddn = 0 if pd is None else max(0, dn - pd)
            self.prev[cid] = (up, dn)

            md = c.get("metadata") or {}
            host = (md.get("host") or md.get("sniffHost") or
                    md.get("remoteDestination") or md.get("destinationIP") or "").lower()
            key = "other"
            for w in SITES:
                if host and (host == w or host.endswith("." + w)):
                    key = w
                    break
            else:
                if host:
                    key = "extra:" + host

            per_host[key][0] += ddn
            per_host[key][1] += dup
            per_n[key] += 1
            if key not in per_ip:
                per_ip[key] = md.get("remoteDestination") or md.get("destinationIP") or ""
            if key not in per_chain:
                ch = c.get("chains") or []
                per_chain[key] = " > ".join(ch) if ch else "DIRECT"
            if key not in per_rule:
                per_rule[key] = c.get("rule") or ""

        for cid in [k for k in self.prev if k not in seen]:
            del self.prev[cid]

        rows = []
        total_down = total_up = 0.0
        now = time.time()
        for key in list(SITES) + [k for k in per_host if k.startswith("extra:")]:
            dv, uv = per_host.get(key, [0.0, 0.0])
            total_down += dv
            total_up += uv
            n = per_n.get(key, 0)
            chain = per_chain.get(key, "")
            via = "vpn" if chain and chain != "DIRECT" else ("direct" if chain else "")
            if n and via:
                self.last_via[key] = via
            if key in SITES:
                e = self.ema[key]
                e[0] = e[0] * 0.45 + (dv / dt) * 0.55
                e[1] = e[1] * 0.45 + (uv / dt) * 0.55
                self.cum[key][0] += dv
                self.cum[key][1] += uv
                cur = e
                cum = self.cum[key]
            else:
                # 连接关掉后行会瞬间消失、下一帧又冒出来 —— 用同一个 EMA 衰减，行才不闪
                e = self.ex_ema[key]
                e[0] = e[0] * 0.45 + (dv / dt) * 0.55
                e[1] = e[1] * 0.45 + (uv / dt) * 0.55
                self.ex_meta[key] = {"ip": per_ip.get(key, ""), "chain": chain, "ts": now}
                cur, cum = e, [0.0, 0.0]
            rows.append({
                "key": key,
                "label": key[6:] if key.startswith("extra:") else key,
                "watched": key in SITES,
                "down": round(cur[0]),
                "up": round(cur[1]),
                "conns": n,
                "ip": per_ip.get(key, ""),
                "chain": chain,
                "rule": per_rule.get(key, ""),
                "via": "idle" if cur[0] + cur[1] < 1 else (via or self.last_via.get(key, "direct")),
                "total_down": round(cum[0]),
                "total_up": round(cum[1]),
            })

        # 本帧没出现的 extra：继续衰减，衰减完了或 20 秒没动静就把行撤掉
        for key in list(self.ex_ema):
            if key in per_host:
                continue
            e = self.ex_ema[key]
            meta = self.ex_meta.get(key, {})
            e[0] *= 0.45
            e[1] *= 0.45
            if e[0] + e[1] < 1 or now - meta.get("ts", 0) > 20:
                del self.ex_ema[key]
                self.ex_meta.pop(key, None)
                self.last_via.pop(key, None)
                continue
            rows.append({
                "key": key, "label": key[6:], "watched": False,
                "down": round(e[0]), "up": round(e[1]), "conns": 0,
                "ip": meta.get("ip", ""), "chain": meta.get("chain", ""), "rule": "",
                "via": self.last_via.get(key, "direct"),
                "total_down": 0, "total_up": 0,
            })

        order = {k: i for i, k in enumerate(SITES)}
        rows.sort(key=lambda r: (0 if r["watched"] else 1, order.get(r["key"], 0), -r["down"]))
        # 总和与站点行用同一个平滑系数，否则会出现"总量 0、某站点 121"的错觉
        raw_d, raw_u = total_down / dt, total_up / dt
        self.tot[0] = self.tot[0] * 0.45 + raw_d * 0.55
        self.tot[1] = self.tot[1] * 0.45 + raw_u * 0.55
        self.hist_total.append([round(self.tot[0]), round(self.tot[1])])
        if len(self.hist_total) > HIST_MAX:
            del self.hist_total[:-HIST_MAX]
        for r in rows:
            if not r["watched"]:
                continue
            q = self.hist_sites.setdefault(r["key"], [])
            q.append([r["down"], r["up"]])
            if len(q) > HIST_MAX:
                del q[:-HIST_MAX]
        self._publish(ok=True, conns=len(conns), total=(self.tot[0], self.tot[1]),
                      rows=rows, raw=data)

    def _publish(self, ok, conns=0, total=(0.0, 0.0), rows=None, raw=None):
        cfg = self.cfg or {}
        tun = bool((cfg.get("tun") or {}).get("enable"))
        mode = cfg.get("mode", "")
        mixed_no = MIXED.split(":")[-1]
        sp_on = self.sysproxy.get("enable") == 1

        cli = DISCO.client
        if not ok:
            # 没有 Clash 系控制器：别的客户端（v2rayN / WireGuard / 深信服…）不暴露连接表，
            # 这时只能说清楚"能看见什么"，不能假装知道逐条流量
            if sp_on:
                active = "vpn"
                reason = (f"系统代理已开启并指向 {self.sysproxy.get('server') or MIXED}，"
                          f"但没找到可读的连接控制器，逐条明细不可见")
            elif cli.name and cli.kind not in ("clash", "singbox", "none"):
                active = "mixed"
                reason = f"检测到 {cli.name}，它不暴露连接表；下面只有网卡与出口层面的数据"
            else:
                active, reason = "down", "本地控制器没有响应，无法读取连接表"
        elif sp_on:
            active = "vpn"
            reason = (f"系统代理已开启并指向 {self.sysproxy.get('server') or MIXED}"
                      f"（{cli.core or '内核'} {mode or '?'} 模式），代理感知型应用全部经隧道转发")
        elif tun:
            active, reason = "vpn", "系统代理未开，但 TUN 已接管全部流量"
        elif mode == "global":
            active, reason = "mixed", "mihomo 为 global 模式但系统代理未开：只有显式配代理的程序走 VPN"
        else:
            active, reason = "direct", "系统代理未开启，流量直连"

        sites = [r for r in (rows or []) if r["watched"]]
        extras = sorted([r for r in (rows or []) if r["key"].startswith("extra:") and (r["down"] + r["up"]) > 0],
                        key=lambda r: -(r["down"] + r["up"]))[:MAX_EXTRA_ROWS]

        ST.publish({
            "ok": ok,
            "error": self.error,
            "path": {"active": active, "reason": reason, "sysproxy": self.sysproxy},
            "tunnel": {"up": ok, "mode": mode, "tun": tun, "mixed": MIXED,
                       "controller": DISCO.client.api or CTRL, "version": self.ver, "conns": conns,
                       "download_total": (raw or {}).get("downloadTotal", 0),
                       "upload_total": (raw or {}).get("uploadTotal", 0)},
            "client": DISCO.client.pack(),
            "iface": self.net.iface,
            "route": self.net.route,
            "node": self.net.node,
            "mihomo": self.net.mihomo,
            "egress": self.egress,
            "probes": self.probes,
            "sites": sites,
            "hist": {"total": list(self.hist_total),
                     "sites": {k: list(v) for k, v in self.hist_sites.items()}},
            "watched": list(SITES),
            "extras": extras,
            "total": {"down": round(total[0]), "up": round(total[1])},
        })

    # -- 探测
    @staticmethod
    def _parse_ipapi(body: str):
        """ip-api 的 line 格式，行的顺序不保证，按内容判定哪个是 IP"""
        ip = geo = ""
        for raw in body.splitlines():
            t = raw.strip()
            if not t:
                continue
            if re.fullmatch(r"[0-9a-fA-F:.]+", t) and ("." in t or ":" in t):
                ip = ip or t
            elif not geo:
                geo = t
        return ip, geo

    def probe_egress(self):
        now = time.time()
        if now - self.egress["vpn_ts"] > 120:
            r = http_get("http://ip-api.com/line/?fields=query,country", MIXED, timeout=8, read=256)
            ip, geo = self._parse_ipapi(r.get("body", "")) if r["ok"] else ("", "")
            if not ip:
                r2 = http_get("https://api.ipify.org", MIXED, timeout=8, read=64)
                if r2["ok"]:
                    ip = r2["body"].strip()
            self.egress["vpn_ip"] = ip
            self.net.vpn_exit_ip = ip
            self.egress["vpn_geo"] = geo
            self.egress["vpn_err"] = "" if ip else (r.get("err") or "失败")
            self.egress["vpn_ts"] = now
        if now - self.egress["direct_ts"] > 300:
            r = http_get("http://ip-api.com/line/?fields=query,country", None, timeout=6, read=256)
            ip, geo = self._parse_ipapi(r.get("body", "")) if r["ok"] else ("", "")
            self.egress["direct_ip"] = ip
            self.egress["direct_geo"] = geo
            self.egress["direct_err"] = "" if ip else (r.get("err") or "失败")
            self.egress["direct_ts"] = now

    def probe_loop(self, stop: threading.Event):
        """代理通道：快，驱动探测条与出口 IP"""
        n = 0
        self.read_sysproxy()
        while not stop.is_set():
            try:
                self.read_sysproxy()
                if n % 3 == 0:
                    self.tick_cfg()
                self.probes["vpn"] = {**http_get(PROBE_TARGET, MIXED, timeout=8),
                                      "ts": time.time(), "target": PROBE_TARGET}
                self.probe_egress()
            except Exception as e:
                log("probe:", e)
            n += 1
            stop.wait(PROBE_EVERY)

    def direct_loop(self, stop: threading.Event):
        """直连通道：目标常年被墙，单独线程慢跑，不拖累代理通道的节奏"""
        while not stop.is_set():
            try:
                self.probes["direct"] = {**http_get(PROBE_TARGET, None, timeout=3),
                                         "ts": time.time(), "target": PROBE_TARGET}
                self.probes["control"] = {**http_get(CONTROL_URL, None, timeout=4),
                                          "ts": time.time(), "target": "baidu.com"}
            except Exception as e:
                log("direct:", e)
            stop.wait(15)

    def loop(self, stop: threading.Event):
        while not stop.is_set():
            t0 = time.time()
            try:
                self.sample()
            except Exception as e:
                log("sample:", e)
            stop.wait(max(0.05, 1.0 - (time.time() - t0)))


# ---------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "flow/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def do_GET(self):
        p = self.path.split("?")[0]
        if p in ("/", "/index.html"):
            try:
                with open(os.path.join(BASE, "web", "index.html"), "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            except Exception:
                self._send(500, "缺少 web/index.html", "text/plain; charset=utf-8")
            return
        if p == "/api/state":
            snap, _ = ST.read()
            self._send(200, json.dumps(snap, ensure_ascii=False))
            return
        if p == "/api/stream":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            last = -1
            try:
                while True:
                    snap, ver = ST.read()
                    if ver != last and snap:
                        last = ver
                        self.wfile.write(f"data: {json.dumps(snap, ensure_ascii=False)}\n\n".encode())
                        self.wfile.flush()
                    else:
                        time.sleep(0.2)
                        continue
                    time.sleep(0.15)
            except Exception:
                pass
            return
        self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        p = self.path.split("?")[0]
        if p != "/api/sites":
            self._send(404, json.dumps({"error": "not found"}))
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads((self.rfile.read(n) or b"{}").decode("utf-8", "replace"))
        except Exception:
            body = {}
        ok, msg, cur = set_site(str(body.get("action", "")), str(body.get("domain", "")))
        self._send(200 if ok else 400,
                   json.dumps({"ok": ok, "msg": msg, "sites": cur}, ensure_ascii=False))


def main():
    net = NetInfo()
    col = Collector(net)
    stop = threading.Event()
    threading.Thread(target=net.loop, args=(stop,), daemon=True).start()
    threading.Thread(target=col.loop, args=(stop,), daemon=True).start()
    threading.Thread(target=col.probe_loop, args=(stop,), daemon=True).start()
    threading.Thread(target=col.direct_loop, args=(stop,), daemon=True).start()

    def saver():
        while not stop.is_set():
            col._save_state()
            stop.wait(30)
    threading.Thread(target=saver, daemon=True).start()

    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    srv.daemon_threads = True
    log(f"FLOW ▶ http://127.0.0.1:{PORT}/   站点 {', '.join(SITES)}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        stop.set()


if __name__ == "__main__":
    main()
