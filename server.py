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

import diag
import hostflow
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
from urllib.parse import urlsplit

BASE = os.path.dirname(os.path.abspath(__file__))


def _load_config() -> dict:
    cfg = {
        "port": 7717,
        "controller": "127.0.0.1:7892",
        "mixed_port": "127.0.0.1:7890",
        "sites": ["chatgpt.com", "openai.com"],
        "probe_interval": 10,
        "probe_target": "https://chatgpt.com/",
        "control_target": "https://www.baidu.com/",
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
PROBE_MIN, PROBE_MAX = 5, 120      # 面板上能改的探测间隔范围（秒）
PROBE_TARGET = str(CFG.get("probe_target", "https://chatgpt.com/"))
PROBE_HOST = PROBE_TARGET.split("//", 1)[-1].split("/", 1)[0]
CONTROL_URL = str(CFG.get("control_target", "https://www.baidu.com/"))
CONTROL_HOST = CONTROL_URL.split("//", 1)[-1].split("/", 1)[0]
STATE_FILE = os.path.join(BASE, "state.json")
CFG_PATH = os.path.join(BASE, "config.json")


def L(zh: str, en: str) -> dict:
    """面向面板的一句话，中英两版一起发：面板按自己的界面语言取，缺英文就退回中文"""
    return {"zh": zh, "en": en}


def _probe_url_err(u: str) -> dict:
    """探测地址的准入：只要是 http(s) + 有主机名，且别指向本机

    指向 127.0.0.1 / localhost 的"目标"证明不了隧道（那条路根本不出去），
    所以直接拒绝，别让它一直"不通"却看不出原因。
    返回空 dict 表示没问题，否则返回 L(zh, en) 的原因。
    """
    try:
        p = urlsplit(u)
    except Exception:
        return L("地址不合法", "invalid URL")
    if p.scheme not in ("http", "https"):
        return L("只支持 http / https", "only http and https are supported")
    if not p.hostname:
        return L("缺少主机名", "no host name")
    if p.hostname.lower() in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return L("不能指向本机（探本机证明不了隧道）",
                 "must not point at this machine (that proves nothing about the tunnel)")
    return {}


def set_probe(target=None, control=None, interval=None):
    """改探测目标 / 对照目标 / 间隔：立刻生效（探测线程每轮都读这几个全局量）并落盘

    以前这三个只能手改 config.json 再重启，而且 control_target 连默认文件里都没有；
    面板上的 ✎ 就是走这里。
    """
    global PROBE_TARGET, PROBE_HOST, CONTROL_URL, CONTROL_HOST, PROBE_EVERY
    changes: dict = {}
    if target is not None:
        t = str(target).strip()
        err = _probe_url_err(t)
        if err:
            return False, L(f"探测目标不可用：{err['zh']}", f"Unusable probe target: {err['en']}")
        changes["probe_target"] = t
    if control is not None:
        c = str(control).strip()
        err = _probe_url_err(c)
        if err:
            return False, L(f"对照目标不可用：{err['zh']}", f"Unusable control target: {err['en']}")
        changes["control_target"] = c
    if interval is not None:
        try:
            iv = int(interval)
        except Exception:
            iv = 0
        if not (PROBE_MIN <= iv <= PROBE_MAX):
            return False, L(f"探测间隔需在 {PROBE_MIN}～{PROBE_MAX} 秒之间",
                           f"Probe interval must be between {PROBE_MIN} and {PROBE_MAX} s")
        changes["probe_interval"] = iv
    if not changes:
        return False, L("没有需要修改的内容", "Nothing to change")
    if "probe_target" in changes:
        PROBE_TARGET = changes["probe_target"]
        PROBE_HOST = PROBE_TARGET.split("//", 1)[-1].split("/", 1)[0]
    if "control_target" in changes:
        CONTROL_URL = changes["control_target"]
        CONTROL_HOST = CONTROL_URL.split("//", 1)[-1].split("/", 1)[0]
    if "probe_interval" in changes:
        PROBE_EVERY = changes["probe_interval"]
    CFG.update(changes)
    try:
        with open(CFG_PATH, "w", encoding="utf-8") as f:
            json.dump(CFG, f, ensure_ascii=False, indent=2)
    except Exception as e:
        log("写 config.json 失败:", e)
        return True, L("已生效，但写配置文件失败", "Applied, but writing config.json failed")
    log("探测设置 →", f"{PROBE_TARGET} | {CONTROL_URL} | {PROBE_EVERY}s")
    return True, L("探测设置已更新", "Probe settings updated")


MAX_EXTRA_ROWS = 4
HIST_MAX = 240            # 曲线留 240 帧：代理模式 0.5 秒一帧 = 2 分钟
SAMPLE_EVERY = 0.5        # 有客户端时快采，曲线看起来才跟手（本机模式自己会退到 1 秒）
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
    return providers._http_json(host, path, (c.secret if c else ""), timeout)


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
        kind = "http" if code else diag.classify(e)
        return {"ok": bool(code), "status": code,
                "ms": round((time.monotonic() - t0) * 1000),
                "err": "" if code else type(e).__name__,
                "kind": kind if not code else "",
                "detail": "" if code else diag.detail(e), "body": ""}


# ---------------------------------------------------------------- 状态发布
class State:
    """一份快照，多个读者。

    面板（SSE）、轮询、`flow peek` 拿的都是同一帧；以前每个读者各自 `json.dumps` 一遍，
    240 点的历史曲线乘上站点数，一帧几十 KB、每个读者每次都要重新编码一次。
    现在发布时编码一次，读者直接拿字节 —— 编码开销只跟"帧"有关，不跟"几个面板"有关。
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.boot = time.time()
        self.snap: dict = {}
        self.blob = b"{}"
        self.version = 0

    def publish(self, snap: dict):
        snap["ts"] = time.time()
        snap["boot"] = self.boot
        # 编码一次、留字节：SSE 直接拼 b"data: …"，轮询原样写回，两边都不再各自编码
        blob = json.dumps(snap, ensure_ascii=False).encode("utf-8")
        with self.lock:
            self.snap = snap
            self.blob = blob
            self.version += 1

    def read(self):
        with self.lock:
            return self.snap, self.version

    def read_blob(self):
        with self.lock:
            return self.blob, self.version


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
        if not self._wlan_up():
            return {}
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

    @staticmethod
    def _wlan_up() -> bool:
        """有没有"真连着"的无线网卡。没有就别起 netsh（它一次 240 ms，有线机器上纯浪费）

        拿不准（内核表读不到）时返回 True：宁可多花一次调用，也不让 Wi-Fi 信息消失。
        """
        try:
            return any(n["type"] == 71 and n["media"] == 1 for n in hostflow.if_table())
        except Exception:
            return True

    def _addrs(self) -> dict:
        """网卡名 → {ip, gateway, metric}。先问内核，拿不到再退回 netsh"""
        try:
            got = hostflow.adapters()
        except Exception as e:
            log("addrs:", e)
            got = {}
        return got or self._addrs_netsh()

    def _addrs_netsh(self) -> dict:
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
        # 诊断要用：每条路各自那块网卡的网关，用来分开"链路断了"和"上游断了"
        self.route["vpn"]["gateway"] = vpn_nic.get("gateway", "")
        self.route["direct"]["gateway"] = dir_nic.get("gateway", "")

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
        self.xprev: dict[str, tuple[int, int]] = {}     # Xray 统计口的上一帧累计值
        self.last_ts = 0.0
        self.dt = 1.0          # 上一帧到这一帧的实测间隔（秒），面板据此显示采样节奏
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
        self.link: dict = {}          # 诊断用的原始证据：网关、DNS、各网卡到目标的握手
        self.diag: dict = {}          # 由证据算出来的结论：怀疑谁
        self.cfg: dict = {}
        self.cfg_ts = 0.0
        self.ver = ""
        self.sysproxy = {"enable": 0, "server": ""}
        self.error = ""
        self.host = None              # 没有代理客户端时的数据源（网卡 + 连接表）
        self.host_data: dict = {}
        self.nic_data: dict = {}      # 每帧都采的网卡速率：有客户端时用来"分账"
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

    # -- 客户端到底在不在转发（而不是"读不到"被我当成"没在转发"）
    @staticmethod
    def _sysproxy_addrs(server: str) -> list:
        """系统代理设置里出现的本机回环口

        ProxyServer 可能是 "127.0.0.1:7890"，也可能是按协议分行写的
        "http=127.0.0.1:10809;https=127.0.0.1:10809"。非本机地址一律忽略：
        指向远端的那种，本机根本看不到是哪个进程在转发。
        """
        out = []
        for m in re.finditer(r"(127\.0\.0\.1|localhost|\[::1\]):(\d{1,5})", server or ""):
            port = int(m.group(2))
            if 0 < port < 65536:
                host = "127.0.0.1" if m.group(1).startswith(("localhost", "[::1]")) else m.group(1)
                out.append((host, port))
        return out

    @staticmethod
    def _why_unreadable(cli, lang: str = "zh") -> str:
        """为什么读不到这个客户端的字节数 —— 每种客户端的原因不一样，别混成一句"""
        en = lang == "en"
        if cli.metrics:
            return (f"its stats endpoint {cli.metrics} is not responding" if en
                    else f"统计口 {cli.metrics} 没响应")
        if cli.api:
            return (f"its controller {cli.api} is not responding" if en
                    else f"控制器 {cli.api} 没响应")
        if cli.kind in ("v2ray", "xray"):
            return ("statistics are off: v2rayN guiItem.enableStatistics = false" if en
                    else "统计口未开启，v2rayN 的 guiItem.enableStatistics 是关的")
        return ("it exposes no byte counters" if en else "它不提供字节统计")

    def _forwarding_proxy(self):
        """客户端此刻是否真的在转发：能证明就返回 (本地代理口, 证据)，证不了返回 ("", "")

        判据缺一不可：系统代理开着 → 地址是本机回环口 → 那个口正在监听 →
        监听它的进程就是这个客户端（它自己，或它的内核子进程，往上找两层）。

        为什么非要多这一步：v2rayN 关掉统计口时，面板只拿得到网卡总量，
        于是既证明不了"在转发"，也证明不了"没在转发"。少了这条判据，它就
        会把"读不到字节数"说成"没在转发"，而这句断言是错的（issue #1）。
        """
        cli = DISCO.client
        if self.sysproxy.get("enable") != 1:
            return "", ""
        if not (cli.name and cli.kind != "none"):
            return "", ""
        ports = DISCO._ports()          # 端口 → PID，15 秒缓存
        table = DISCO._table()          # PID → {name, ppid, ...}，30 秒缓存
        stems = {providers._stem(cli.name), providers._stem(cli.core)} - {""}
        for host, port in self._sysproxy_addrs(self.sysproxy.get("server") or ""):
            try:
                with socket.create_connection((host, port), timeout=0.25):
                    pass
            except OSError:
                continue                # 没在监听：这一口不是转发口
            pid = ports.get(port, 0)
            owner = table.get(pid) or {}
            ppid = owner.get("ppid", 0)
            gppid = (table.get(ppid) or {}).get("ppid", 0)
            # 缓存里名字/端口归属对得上还不够：PID 得活着（客户端被 kill 之后缓存还在）
            if cli.pid and cli.pid in (pid, ppid, gppid) and providers._alive(cli.pid):
                return f"{host}:{port}", f"{cli.name} 的进程在监听它"
            if providers._stem(owner.get("name", "")) in stems and providers._alive(pid):
                return f"{host}:{port}", f"{cli.core or cli.name} 内核在监听它"
            # 口在监听，但不是它开的（是别的程序，或端口归属查不到）→ 不当证据
            continue
        return "", ""

    @staticmethod
    def _port_of(addr) -> int:
        """"127.0.0.1:7890" / "http=127.0.0.1:10809" 都取末尾端口，取不到给 0"""
        m = re.search(r":(\d{1,5})\s*$", str(addr or "").strip())
        return int(m.group(1)) if m else 0

    def _proxy_ports(self) -> set:
        """可能承载"客户端入口"字节的本地端口：只认现在真在用的回环口

        给 hostflow 用：应用 → 这些端口（回环）的连接上跑的是"进客户端"的字节。
        - 系统代理：只认 ProxyEnable=1 且地址是回环的。关掉之后注册表里残留的地址
          不算 —— 那个端口可能正被别的程序用着，算进来就把别人的流量记到客户端头上。
        - 客户端自己的本地口（local_proxy）：有客户端才算；控制器猜的混合口同理。
        端口猜错不要紧 —— 少算只会让"经客户端"偏小，不会把直连算成走了它。
        """
        cli = DISCO.client
        out = set()
        if self.sysproxy.get("enable") == 1:
            for part in re.split(r"[;,]", str(self.sysproxy.get("server") or "")):
                addr = part.split("=")[-1].strip()
                port = self._port_of(addr)
                if (0 < port < 65536
                        and addr.startswith(("127.0.0.1:", "localhost:", "[::1]:", "::1:"))):
                    out.add(port)
        if cli.local_proxy:
            for addr in (cli.local_proxy, self.proxy):
                port = self._port_of(addr)
                if 0 < port < 65536:
                    out.add(port)
        return out

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
    def _nic_tick(self, want_procs=False) -> dict:
        """每帧都采一次网卡：不管有没有客户端、走不走隧道，它都是真的

        有客户端时用它和"经代理字节"做差，分账出"这秒有多少没走代理"；
        没有客户端时它就是全部数据来源。
        """
        if self.host is None:
            lane = (self.net.route.get("direct") or {})
            self.host = hostflow.HostFlow(nic_name=lane.get("name") or "",
                                          proc_fn=providers._name_table)
        else:
            nic = (self.net.route.get("direct") or {}).get("name") or ""
            if nic and self.host.nic_name != nic:
                self.host.nic_name = nic
        try:
            s = self.host.sample(want_procs=want_procs, proxy_ports=self._proxy_ports())
        except Exception as e:                  # noqa: BLE001
            log("hostflow:", e)
            return {}
        self.nic_data = s
        return s

    def sample_host(self, hint=""):
        """没有代理客户端时（没开 VPN）照样能看流量：网卡总量 + 谁在连谁

        粒度掉到"整块网卡 + 进程连接数"是权限决定的，不是偷懒：
        逐进程/逐域名的字节数要靠内核 eStats 或 DNS 缓存，两者在普通权限下
        都是 ACCESS_DENIED。这里给的是真数字，只是粗。
        管理员启动时 hostflow 会把 eStats 打开，于是每进程的 ↓↑ 也是真数字，
        本方法再把它们发成"站点行"，让面板用同一套曲线画出来。

        hint：客户端在跑但读不到它的数（没连节点、控制器没开）时的说明，
        会写进"出口路径"那句 reason，免得面板说"没检测到客户端"却在别处
        显示着客户端名字。
        """
        s = self._nic_tick(want_procs=True)
        if not s:
            self._publish(ok=False, flow="host", hint=hint)
            return False
        # 本机模式没有"每秒速率"这回事（eStats 本身就是按秒给的），但节奏要报给面板
        now = time.time()
        self.dt = max(0.25, now - self.last_ts) if self.last_ts else 1.0
        self.last_ts = now
        self.host_data = s
        self.error = ""
        self.tot[0], self.tot[1] = s["total"]
        self.hist_total.append([round(self.tot[0]), round(self.tot[1])])
        if len(self.hist_total) > HIST_MAX:
            del self.hist_total[:-HIST_MAX]
        rows = []
        if s.get("estats"):
            # 管理员权限下 eStats 可用：每进程的 ↓↑ 速率就是真数字，
            # 直接发成"站点行"，UI 用同一套曲线画出来 —— 和 VPN 那边长得一样
            for p in s.get("procs") or []:
                # 这行的字节是"直连 + 经客户端"的合计。px 只是"进了客户端本地口"的
                # 那一份（可能被规则直连放出去），所以染成中性色，不冒充"走 VPN"的琥珀
                pxt = (p.get("px_down") or 0.0) + (p.get("px_up") or 0.0)
                tot = (p.get("down") or 0.0) + (p.get("up") or 0.0)
                r = {"key": p["name"], "label": p["name"], "watched": True, "fixed": True,
                     "down": round(p.get("down") or 0), "up": round(p.get("up") or 0),
                     "conns": p.get("conns", 0), "ip": p.get("sample", ""),
                     "chain": "", "rule": "",
                     "via": "proxy" if (tot > 0 and pxt >= tot * 0.6) else "direct",
                     "px": round(pxt),
                     "remotes": p.get("remotes", 0),
                     "total_down": round(p.get("cum_down") or 0),
                     "total_up": round(p.get("cum_up") or 0)}
                rows.append(r)
                q = self.hist_sites.setdefault(r["key"], [])
                q.append([r["down"], r["up"]])
                if len(q) > HIST_MAX:
                    del q[:-HIST_MAX]
        self._publish(ok=True, conns=s["conns"], total=s["total"], rows=rows, flow="host", hint=hint)
        return True

    def sample(self):
        now = time.time()
        try:
            data = api("/connections", timeout=2)
        except Exception as e:
            # 不在这里 publish：调用方会退回网卡统计，一帧只该有一次快照
            self.error = f"mihomo 接口不可达：{type(e).__name__}"
            return False
        self.error = ""
        conns = data.get("connections") or []
        dt = max(0.25, now - self.last_ts) if self.last_ts else 1.0
        self.last_ts = now
        self.dt = dt

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
        self._nic_tick()                        # 网卡总量：和"经代理"做差就是没走代理的部分
        self._publish(ok=True, conns=len(conns), total=(self.tot[0], self.tot[1]),
                      rows=rows, raw=data)
        return True

    @property
    def proxy(self) -> str:
        """当前真正在用的本地代理口：Clash 系看配置，Xray 系看它生成的 config.json"""
        return DISCO.client.local_proxy or MIXED

    def sample_xray(self):
        """非 Clash 系：用 Xray 的统计口按"经代理 / 直连"两个出口归并

        v2rayN 为了画实时速率曲线，自己在生成的配置里开了 stats + metrics，
        GET /debug/vars 回来的就是每个 outbound 的累计字节。拆不到域名，
        但"哪些字节走了隧道"是精确的，不是估的。
        """
        now = time.time()
        stats = DISCO.xray_stats()
        if not stats:
            self.error = "Xray 统计口不可达"
            return False
        self.error = ""
        dt = max(0.25, now - self.last_ts) if self.last_ts else 1.0
        self.last_ts = now
        self.dt = dt

        cli = DISCO.client
        ptag = next(iter(cli.proxies), "proxy")
        proxy = stats.get(ptag) or stats.get("proxy") or (0, 0)
        direct = (0, 0)
        for tag, v in stats.items():
            if tag in (ptag, "proxy"):
                continue
            direct = (direct[0] + v[0], direct[1] + v[1])

        rows = []
        for key, label, via, cur in (("proxy", "经代理", "vpn", proxy),
                                     ("direct", "直连", "direct", direct)):
            pu, pd = self.xprev.get(key, (-1, -1))
            du = 0 if pu < 0 else max(0, cur[0] - pu)
            dd = 0 if pd < 0 else max(0, cur[1] - pd)
            self.xprev[key] = cur
            e = self.ema[key]
            e[0] = e[0] * 0.45 + (dd / dt) * 0.55
            e[1] = e[1] * 0.45 + (du / dt) * 0.55
            rows.append({
                "key": key, "label": label, "watched": True, "fixed": True,
                "down": round(e[0]), "up": round(e[1]), "conns": 0, "ip": "",
                "chain": (cli.name or cli.core) if key == "proxy" else "",
                "rule": "", "via": "idle" if e[0] + e[1] < 1 else via,
                "total_down": round(cur[1]), "total_up": round(cur[0]),
            })

        self.tot[0] = rows[0]["down"] + rows[1]["down"]
        self.tot[1] = rows[0]["up"] + rows[1]["up"]
        self.hist_total.append([round(self.tot[0]), round(self.tot[1])])
        if len(self.hist_total) > HIST_MAX:
            del self.hist_total[:-HIST_MAX]
        for r in rows:
            q = self.hist_sites.setdefault(r["key"], [])
            q.append([r["down"], r["up"]])
            if len(q) > HIST_MAX:
                del q[:-HIST_MAX]
        self._nic_tick()
        self._publish(ok=True, conns=0, total=(self.tot[0], self.tot[1]),
                      rows=rows, flow="xray")
        return True

    def _publish(self, ok, conns=0, total=(0.0, 0.0), rows=None, raw=None, flow="", hint=""):
        cfg = self.cfg or {}
        tun = bool((cfg.get("tun") or {}).get("enable"))
        mode = cfg.get("mode", "")
        sp_on = self.sysproxy.get("enable") == 1
        # 同一个快照里必须是同一批证据：先钉住引用，再拿它算判定、也拿它当输出
        probes = self.probes
        link = self.link
        # 本机模式下先捞"客户端是否真在转发"这条证据：判定和出口路径共用一份，
        # 免得上面说"没在转发"、下面又显示着它的名字
        fwd, fwd_why = self._forwarding_proxy() if flow == "host" else ("", "")
        host = self.host_data if flow == "host" else {}
        cli = DISCO.client
        # 客户端入口字节：管理员下 hostflow 从"应用→客户端本地口"的回环连接里数出来的。
        # 它是"进了客户端"的字节，不是"进了隧道"的字节 —— 客户端的规则可能把一部分
        # 按直连放出去，所以只发 split.client，不拿它冒充经代理/直连（review #1）。
        # 没有"它确实在转发"或"它自己有本地口"的证据时，这堆字节不归它（review #2）。
        hx = (host.get("proxy") or None) if flow == "host" else None
        if hx and not (fwd or cli.local_proxy):
            hx = None
        if hx and not ((hx.get("down") or 0) + (hx.get("up") or 0)):
            hx = None
        self.diag = self._diagnose(probes, link, conns, flow, fwd=fwd, px=bool(hx))

        ns = self.nic_data or {}
        brief = ""
        if flow == "host":
            nic = ns.get("nic") or "未知"
            if host.get("estats"):
                tz = "管理员权限：每行的 ↓↑ 由内核 eStats 差分得出（含 TCP 净荷，不含 UDP）"
                te = "Administrator: per-row ↓↑ from kernel eStats deltas (TCP payload only, UDP excluded)"
            else:
                tz = "逐域名 / 逐进程的字节数需客户端统计口或管理员权限"
                te = "Per-domain / per-process byte counts require the client's stats API or admin rights"
            nz = cli.name or "客户端"
            ne = cli.name or "client"
            if fwd:
                # 系统代理指着它的本地口、且能证明那个口是它开的 → 它在转发，只是没给字节数。
                # 这时"未在转发"是假话，"全部直连"也不成立：使用系统代理的程序都在隧道里。
                active = "mixed"
                if hx:
                    # 管理员下能数到"进客户端"的字节，但入口不等于隧道（review #1）
                    reason = L(
                        f"{nz} 正在转发（系统代理 → {fwd}，{fwd_why}）—— 它未提供字节统计"
                        f"（{self._why_unreadable(cli)}），只能统计「应用 → 其本地端口」这条"
                        f"回环连接：那是入口字节，其中多少进入隧道、多少按规则直连发出，无法读取",
                        f"{ne} is forwarding (system proxy → {fwd}, {fwd_why}) but provides no "
                        f"byte counters ({self._why_unreadable(cli, 'en')}); only the loopback "
                        f"connection from applications to its local port can be counted — that "
                        f"is ingress, and how much enters the tunnel versus leaves directly by "
                        f"rule cannot be read")
                    brief = L(f"{nz} 在转发 · 经其本地端口计数，隧道份额未知",
                              f"{ne} is forwarding · counted at its local port, tunnel share unknown")
                else:
                    reason = L(
                        f"{nz} 正在转发（系统代理 → {fwd}，{fwd_why}），但字节数不可读"
                        f"（{self._why_unreadable(cli)}）—— 只能按网卡「{nic}」统计总量，"
                        f"无法区分其中多少进入隧道",
                        f"{ne} is forwarding (system proxy → {fwd}, {fwd_why}) but its byte "
                        f"counters are unreadable ({self._why_unreadable(cli, 'en')}); totals can "
                        f"only come from interface '{nic}', so the tunnel share cannot be separated")
                    brief = L(f"{nz} 在转发，但字节数不可读 · 仅按网卡「{nic}」统计",
                              f"{ne} is forwarding but byte counters are unreadable · "
                              f"interface '{nic}' only")
            elif hint:
                # 客户端进程还在，但读不到它的数（未连节点 / 统计口未开 / 控制器未开）：
                # 不要说成"未检测到客户端"，也不要停摆，按网卡继续统计
                active = "direct"
                reason = L(f"{hint['zh']}：按网卡「{nic}」统计本机流量，{tz}",
                           f"{hint['en']}: totals come from interface '{nic}'; {te}")
                brief = L(f"读不到 {nz} 的流量 · 按网卡「{nic}」统计",
                          f"{ne} bytes unreadable · interface '{nic}' only")
            else:
                active = "direct"
                reason = L(f"未检测到代理客户端：按网卡「{nic}」统计本机流量，{tz}",
                           f"No proxy client detected: totals come from interface '{nic}'; {te}")
                brief = L(f"未检测到代理客户端 · 按网卡「{nic}」统计",
                          f"No proxy client · interface '{nic}' only")

        elif not ok and flow == "xray":
            active = "vpn" if sp_on else ("mixed" if cli.name else "down")
            nz = cli.name or "客户端"
            ne = cli.name or "client"
            reason = L(f"{nz} 在运行，但统计口 {cli.metrics or '?'} 本帧无响应，字节数暂不可读",
                       f"{ne} is running, but its stats endpoint {cli.metrics or '?'} did not "
                       f"answer this frame; byte counts are temporarily unavailable")
        elif not ok:
            # 没有 Clash 系控制器：别的客户端（v2rayN / WireGuard / 深信服…）不暴露连接表，
            # 这时只能说清"能看见什么"，不能假装知道逐条流量
            srv = self.sysproxy.get("server") or self.proxy
            if sp_on:
                active = "vpn"
                reason = L(f"系统代理已开启并指向 {srv}，但未找到可读取的连接控制器，逐条明细不可见",
                           f"System proxy is on and points to {srv}, but no readable connection "
                           f"controller was found; per-connection detail is unavailable")
            elif cli.name and cli.kind not in ("clash", "singbox", "none"):
                active = "mixed"
                reason = L(f"检测到 {cli.name}，它不暴露连接表；面板只有网卡与出口层面的数据",
                           f"Detected {cli.name}, which exposes no connection table; only "
                           f"interface and egress data is available")
            else:
                active = "down"
                reason = L("本地控制器无响应，无法读取连接表",
                           "The local controller is not responding, so the connection table "
                           "cannot be read")
        elif sp_on:
            active = "vpn"
            srv = self.sysproxy.get("server") or self.proxy
            if mode:
                mtz, mte = f"{cli.core} {mode} 模式", f"{cli.core} {mode} mode"
            else:
                mtz, mte = (cli.name or cli.core or "客户端"), (cli.name or cli.core or "client")
            reason = L(f"系统代理已开启并指向 {srv}（{mtz}），使用系统代理的应用全部经隧道转发",
                       f"System proxy is on and points to {srv} ({mte}); applications using it "
                       f"are tunnelled")
        elif tun:
            active = "vpn"
            reason = L("系统代理未开启，但 TUN 已接管全部流量",
                       "System proxy is off, but TUN captures all traffic")
        elif mode == "global":
            active = "mixed"
            reason = L("mihomo 处于 global 模式但系统代理未开启：仅显式配置代理的程序经隧道",
                       "mihomo is in global mode with the system proxy off: only programs "
                       "configured to use the proxy are tunnelled")
        else:
            active = "direct"
            reason = L("系统代理未开启，流量直连", "System proxy is off; traffic goes direct")

        sites = [r for r in (rows or []) if r["watched"]]
        extras = sorted([r for r in (rows or []) if r["key"].startswith("extra:") and (r["down"] + r["up"]) > 0],
                        key=lambda r: -(r["down"] + r["up"]))[:MAX_EXTRA_ROWS]

        # 分账：网卡总数是真的；"经代理"优先用客户端自己报的统计口。
        # 本机模式下没有统计口时，hostflow 从"应用 → 客户端本地口"的回环连接里
        # 数出来的是**入口字节**（split.client），不等于走了隧道 —— 客户端的规则
        # 可能把一部分按直连放出去，所以既不当"经代理"、也不拿它做差算"直连"。
        ntot = ns.get("total") or (0.0, 0.0)
        prox = tuple(total) if (ok and flow != "host") else None
        split = {"nic": {"down": round(ntot[0]), "up": round(ntot[1])},
                 "proxy": {"down": round(prox[0]), "up": round(prox[1])} if prox else None,
                 "direct": ({"down": max(0, round(ntot[0] - prox[0])),
                             "up": max(0, round(ntot[1] - prox[1]))} if prox else None),
                 "client": None,
                 "src": "api" if prox else ""}
        if ok and flow == "host" and hx:
            split["client"] = {"down": round(hx.get("down") or 0.0),
                              "up": round(hx.get("up") or 0.0)}
            split["src"] = "loop"

        ST.publish({
            "ok": ok,
            "error": self.error,
            "dt": round(self.dt, 2),
            "path": {"active": active, "reason": reason, "brief": brief, "sysproxy": self.sysproxy},
            "tunnel": {"up": ok and flow != "host", "mode": mode, "tun": tun, "mixed": self.proxy,
                       "controller": cli.metrics or cli.api or CTRL, "version": self.ver,
                       "conns": 0 if flow == "host" else conns,
                       "download_total": (raw or {}).get("downloadTotal", 0),
                       "upload_total": (raw or {}).get("uploadTotal", 0)},
            "host": {"nic": ns.get("nic") or host.get("nic", ""),
                     "conns": ns.get("conns", 0),
                     "cum": ns.get("cum") or {"down": 0, "up": 0},
                     "estats": bool(host.get("estats")),
                     "elevated": hostflow.elevated(),
                     "procs": host.get("procs") or []},
            "split": split,
            "flow": flow or ("clash" if ok else ""),
            "client": DISCO.client.pack(),
            "iface": self.net.iface,
            "route": self.net.route,
            "node": self.net.node,
            "mihomo": self.net.mihomo,
            "egress": self.egress,
            "probes": probes,
            "probe": {"target": PROBE_TARGET, "host": PROBE_HOST,
                      "control": CONTROL_HOST, "control_url": CONTROL_URL,
                      "interval": PROBE_EVERY,
                      "min": PROBE_MIN, "max": PROBE_MAX},
            "diag": self.diag,
            "link": {"ts": (link or {}).get("ts", 0),
                     "gw": (link or {}).get("gw") or {},
                     "dns": (link or {}).get("dns") or {},
                     "by_nic": (link or {}).get("by_nic") or {},
                     "proxy_port": (link or {}).get("proxy_port") or {},
                     "dst": (link or {}).get("dst", "")},
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
            r = http_get("http://ip-api.com/line/?fields=query,country", self.proxy, timeout=8, read=256)
            ip, geo = self._parse_ipapi(r.get("body", "")) if r["ok"] else ("", "")
            if not ip:
                r2 = http_get("https://api.ipify.org", self.proxy, timeout=8, read=64)
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

    # -- 诊断：把"连不上"拆到具体的那一跳
    def _lane_gateway(self, lane: str) -> dict:
        """每条路各自那块网卡的网关通不通 —— 这是"Wi-Fi 断了"和"上游断了"的分界"""
        r = (self.net.route or {}).get(lane) or {}
        gw = r.get("gateway") or ""
        res = diag.gateway(gw) if gw else {"ok": False, "ms": 0, "kind": "unknown", "detail": "没有网关"}
        return {**res, "ip": gw, "name": r.get("name", ""), "kind_nic": r.get("kind", "")}

    def _link_probe(self):
        """采证据：网关、DNS（系统 vs 公共）、按网卡分别握手。
        只读探测，不改系统状态；一整套下来通常 < 3 秒。"""
        rv = (self.net.route or {}).get("vpn") or {}
        rd = (self.net.route or {}).get("direct") or {}
        link: dict = {"ts": time.time()}

        # 1) 两块网卡的网关
        link["gw"] = {"vpn": self._lane_gateway("vpn"), "direct": self._lane_gateway("direct")}

        # 2) 名字：系统解析器 vs 直接问公共 DNS，两者不一致就说明本地解析被动了手脚
        tgt_sys = diag.resolve(PROBE_HOST)
        tgt_pub = diag.udp_dns(PROBE_HOST)
        ctl_sys = diag.resolve(CONTROL_HOST)
        link["dns"] = {"target": {"system": tgt_sys, "public": tgt_pub},
                       "control": {"system": ctl_sys},
                       "mismatch": bool(tgt_sys["ok"] and tgt_pub["ok"]
                                        and not (set(tgt_sys["ips"]) & set(tgt_pub["ips"])))}

        # 3) 每块网卡到目标的 TCP 握手：绑定源地址，Wi-Fi 和有线各自独立成组
        dst = (tgt_sys["ips"] or tgt_pub["ips"] or [""])[0]
        by_nic = {}
        for lane, nic in (("vpn", rv), ("direct", rd)):
            ip = nic.get("ip") or ""
            if not ip or not dst:
                by_nic[lane] = {"ok": False, "ms": 0, "kind": "unknown",
                                "detail": "没有源地址或没解析到目标", "src": ip}
                continue
            by_nic[lane] = {**diag.tcp_from(ip, dst, 443, timeout=2.5), "src": ip}
        link["by_nic"] = by_nic
        link["dst"] = dst

        # 4) 本地代理口还活着吗（VPN 探针 rejected 时这个能立刻指出是口子没了还是节点没了）
        port = (self.proxy or "").rsplit(":", 1)[-1]
        if port.isdigit():
            t0 = time.monotonic()
            try:
                with socket.create_connection(("127.0.0.1", int(port)), timeout=1.5):
                    link["proxy_port"] = {"ok": True, "ms": round((time.monotonic() - t0) * 1000)}
            except Exception as e:                                # noqa: BLE001
                link["proxy_port"] = {"ok": False, "ms": round((time.monotonic() - t0) * 1000),
                                      "kind": diag.classify(e)}
        else:
            link["proxy_port"] = {"ok": False, "ms": 0, "kind": "unknown", "detail": "没有代理口"}
        self.link = link

    def _diagnose(self, probes=None, link=None, conns=0, flow="", fwd=None, px=False) -> dict:
        """把证据拼成一句话：这次连不上，最该怀疑谁

        顺序即优先级：链路 → 名字 → 隧道 → 目标本身。越底层的问题越先报，
        因为上层现象都是被它带出来的。

        fwd：本机模式下"客户端确实在转发"的本地代理口（空 = 没证明到），
        由 _forwarding_proxy() 算好传进来 —— 这里不自己探测，免得一帧里两套证据。
        px：有没有从环回代理连接里数出字节（管理员）；有就别再嘴硬说"读不到字节数"。

        label / why / evidence 一律是 L() 双语对象：面板按界面语言取，缺英文退回中文。
        """
        # 调用方把这一帧的证据传进来，避免"判定用的探测"和"显示出来的探测"是两批数据
        p = probes if probes is not None else (self.probes or {})
        lk = link if link is not None else (self.link or {})
        pv, pd, pc = p.get("vpn") or {}, p.get("direct") or {}, p.get("control") or {}
        gw = lk.get("gw") or {}
        gv, gd = gw.get("vpn") or {}, gw.get("direct") or {}
        rd = (self.net.route or {}).get("direct") or {}
        rv = (self.net.route or {}).get("vpn") or {}
        dns = lk.get("dns") or {}
        by_nic = lk.get("by_nic") or {}
        pp = lk.get("proxy_port") or {}
        tun = bool((self.cfg or {}).get("tun", {}).get("enable"))
        ctl_ok = bool(pc.get("ok"))
        cli = DISCO.client

        def lane(nic, lang):
            if lang == "en":
                return nic.get("ssid") or nic.get("name") or "network interface"
            return nic.get("ssid") or nic.get("name") or "网卡"

        # 一条证据 = 判别码 + 两种语言；判别码只用于过滤（如"代理通道没启用就别列它"）
        ev: list = []

        def add(code, zh, en):
            ev.append({"code": code, "zh": zh, "en": en})

        if pc:
            add("control",
                f"对照 {CONTROL_HOST} " + ("可达" if ctl_ok else f"不可达（{diag.label(pc.get('kind') or 'unknown')}）")
                + f" {pc.get('ms', 0)}ms",
                f"control {CONTROL_HOST} " + ("reachable" if ctl_ok else f"unreachable ({diag.label(pc.get('kind') or 'unknown', 'en')})")
                + f" {pc.get('ms', 0)}ms")
        if pd:
            add("direct",
                f"直连 {PROBE_HOST} " + ("可达" if pd.get("ok") else f"不可达（{diag.label(pd.get('kind') or 'unknown')}）"),
                f"direct {PROBE_HOST} " + ("reachable" if pd.get("ok") else f"unreachable ({diag.label(pd.get('kind') or 'unknown', 'en')})"))
        if pv:
            add("proxy",
                "代理通道 " + ("可达" if pv.get("ok") else f"不可达（{diag.label(pv.get('kind') or 'unknown')}）"),
                "proxy path " + ("reachable" if pv.get("ok") else f"unreachable ({diag.label(pv.get('kind') or 'unknown', 'en')})"))
        if gd.get("ip"):
            add("gw_direct",
                f"网关 {gd['ip']}（{lane(rd, 'zh')}）" + ("有响应" if gd.get("ok") else "无响应"),
                f"gateway {gd['ip']} ({lane(rd, 'en')}) " + ("responding" if gd.get("ok") else "not responding"))
        if gv.get("ip") and gv.get("ip") != gd.get("ip"):
            add("gw_vpn",
                f"网关 {gv['ip']}（{lane(rv, 'zh')}）" + ("有响应" if gv.get("ok") else "无响应"),
                f"gateway {gv['ip']} ({lane(rv, 'en')}) " + ("responding" if gv.get("ok") else "not responding"))
        if dns.get("mismatch"):
            add("dns", "系统解析与公共 DNS 给出的地址不一致（疑似污染）",
                "system resolution differs from public DNS (possible poisoning)")
        elif (dns.get("target") or {}).get("system", {}).get("ok") is False:
            add("dns", f"{PROBE_HOST} 解析不出地址", f"{PROBE_HOST} does not resolve")

        def out(state, label, why, evs=None):
            src = ev if evs is None else evs
            return {"state": state, "label": label, "why": why,
                    "evidence": [{"zh": x["zh"], "en": x["en"]} for x in src][:5],
                    "tun": tun, "ts": lk.get("ts", 0)}

        def only(*codes):
            return [x for x in ev if x["code"] in codes]

        def skip(*codes):
            return [x for x in ev if x["code"] not in codes]

        # 有结论才谈得上归因；一个探针都还没跑过就老实说不知道
        if not (pv or pd or pc):
            return out("unknown", L("等待首轮探测", "Waiting for the first probe"),
                       L("刚启动，尚未取得证据", "Just started; no evidence yet"))

        # ⓪ 压根没有代理客户端（也没开系统代理/TUN）—— 这不叫故障，是本机模式
        #    再往下判会得出"VPN 本地代理口没开"这种红字，可用户根本没装/没打算开
        sp_on = self.sysproxy.get("enable") == 1
        client_on = bool(DISCO.client.name and DISCO.client.kind != "none")
        if flow == "host" and client_on:
            # 客户端的壳还在跑，但转发那一层的数读不到：这是"当前未使用隧道"，
            # 不是"隧道故障"，所以给中性灰，不给红。
            # 但要分清两种"读不到"：一种能证明它在转发（系统代理指着它自己开的
            # 本地口），那种只能叫"读不到字节数"，绝不能替它说"未在转发"（issue #1）。
            name = cli.name
            en_name = cli.name
            if fwd:
                if px:
                    return out("nopx", L("客户端在转发（经本地口计数）", "Client is forwarding (counted at local port)"),
                               L(f"系统代理指向 {fwd}，{name} 确实在转发；其统计口未开"
                                 f"（{self._why_unreadable(cli)}），本地代理口上的回环连接可数出"
                                 f"「进入客户端」的字节，但那只是入口 —— 其中多少进入隧道、"
                                 f"多少按规则直连发出，无法读取",
                                 f"System proxy points to {fwd} and {en_name} is indeed forwarding; "
                                 f"its stats endpoint is off ({self._why_unreadable(cli, 'en')}). "
                                 f"Loopback connections on its local proxy port give the bytes "
                                 f"entering the client, but that is ingress only — how much enters "
                                 f"the tunnel versus leaves directly by rule cannot be read"),
                               skip("proxy"))
                return out("nopx", L("客户端在转发，但字节数不可读", "Client is forwarding; byte counts unreadable"),
                           L(f"系统代理指向 {fwd}，{name} 确实在转发；但它未提供字节统计"
                             f"（{self._why_unreadable(cli)}）—— 这里只能统计网卡总量，"
                             f"无法区分其中多少进入隧道",
                             f"System proxy points to {fwd} and {en_name} is indeed forwarding, "
                             f"but it provides no byte counters "
                             f"({self._why_unreadable(cli, 'en')}) — only interface totals are "
                             f"available, so the tunnel share cannot be separated"),
                           skip("proxy"))
            return out("nopx", L("未在走隧道，仅统计本机流量", "Not tunnelled; local totals only"),
                       L(f"{name} 的进程仍在，但读不到它的流量统计 —— 可能未连接节点，"
                         f"或其统计来源未开启；网卡总流量与连接数照常统计，"
                         f"逐域名明细需其提供字节数",
                         f"{en_name} is still running but its traffic statistics cannot be read — "
                         f"it may not be connected to a node, or its stats source is off; interface "
                         f"totals and connection counts still work, per-domain detail needs byte counters"),
                       skip("proxy"))
        if not client_on and not sp_on and not tun:
            return out("nopx", L("没有代理客户端，仅统计本机流量", "No proxy client; local totals only"),
                       L(f"面板按网卡统计总流量、按连接数查看连接归属（{PROBE_HOST} 与 {CONTROL_HOST} "
                         f"的探测照常运行，只是不归因于 VPN）。逐域名字节数需客户端统计口",
                         f"The panel counts interface totals and shows connection ownership "
                         f"({PROBE_HOST} and {CONTROL_HOST} are still probed, just not attributed "
                         f"to the VPN). Per-domain byte counts need the client's stats API"),
                       skip("proxy", "gw_direct", "gw_vpn"))

        # ① 对照都不可达 → 问题在本机链路或 DNS，不在 VPN
        if pc and not ctl_ok:
            if gd.get("ip") and not gd.get("ok"):
                return out("link", L(f"{lane(rd, 'zh')} 链路不通", f"{lane(rd, 'en')} link down"),
                           L(f"连对照目标都不可达，且该网卡的网关 {gd['ip']} 无响应 —— "
                             f"先检查网线 / Wi-Fi 与路由器，与 VPN 无关",
                             f"Even the control target is unreachable, and the gateway {gd['ip']} "
                             f"on this interface does not respond — check the cable / Wi-Fi and "
                             f"router first; this is not a VPN issue"))
            if (dns.get("control") or {}).get("system", {}).get("ok") is False:
                return out("dns", L("DNS 解析异常", "DNS resolution failing"),
                           L("网关有响应，但对照域名无法解析 —— 更换 DNS 或检查 DNS 设置",
                             "The gateway responds, but the control domain does not resolve — "
                             "change DNS or check DNS settings"))
            return out("upstream", L("链路正常，外部不可达", "Link up, upstream down"),
                       L("网关响应正常、域名也可解析，但对照仍不可达 —— 问题在运营商或站点侧",
                         "Gateway responds and DNS resolves, but the control target is still "
                         "unreachable — the problem is upstream (ISP or site)"))

        # ② 链路正常，代理通道不可达 → 隧道/节点
        if pv and not pv.get("ok"):
            kind = pv.get("kind") or "unknown"
            ppk = pp.get("kind") or ""
            if not pp.get("ok") and ppk in ("refused", "timeout"):
                if "refused" in (ppk, kind):
                    return out("vpn", L("VPN 本地代理口未开", "VPN local proxy port closed"),
                               L(f"{self.proxy} 拒绝连接 —— 客户端未启动，或该端口被其他程序占用",
                                 f"{self.proxy} refused the connection — the client is not running, "
                                 f"or another program holds the port"))
                return out("vpn", L("VPN 本地代理口未开", "VPN local proxy port closed"),
                           L(f"{self.proxy} 无法连接（超时）—— 客户端可能未启动，或系统代理未开启",
                             f"Cannot connect to {self.proxy} (timeout) — the client may not be "
                             f"running, or the system proxy is off"))
            if kind == "refused":
                if not (cli.name and cli.kind != "none"):
                    return out("vpn", L("代理口被占用，非客户端", "Proxy port held by another program"),
                               L(f"{self.proxy} 可连接但拒绝转发，且未找到代理客户端 —— "
                                 f"多半是其他程序占用了该端口",
                                 f"{self.proxy} accepts connections but refuses to forward, and no "
                                 f"proxy client was found — most likely another program holds it"))
            # 代理口通、客户端在跑，但隧道里一条连接都没有 —— 这不是"节点故障"，是"尚未连接"
            # （断开节点连接之后最常见：以前这里会一直红着喊"隧道异常"）
            if conns == 0 and flow not in ("", "host"):
                return out("off", L("VPN 未连接节点", "VPN not connected to a node"),
                           L(f"{self.proxy} 可连接、客户端也在运行，但隧道内没有任何连接 —— "
                             f"多半未选择节点，或已断开；连接节点后此格会自动恢复正常",
                             f"{self.proxy} is reachable and the client is running, but there are "
                             f"no connections in the tunnel — probably no node selected, or it was "
                             f"disconnected; this clears once a node connects"))
            if kind == "refused":
                return out("vpn", L("VPN 拒绝连接", "VPN refused the connection"),
                           L(f"本地代理口 {self.proxy} 拒绝了请求（{diag.label(kind)}）—— "
                             f"客户端在运行但未就绪，或端口已变更",
                             f"The local proxy port {self.proxy} refused the request "
                             f"({diag.label(kind, 'en')}) — the client runs but is not ready, "
                             f"or the port changed"))
            if gv.get("ip") and not gv.get("ok"):
                return out("link", L(f"{lane(rv, 'zh')} 链路不通", f"{lane(rv, 'en')} link down"),
                           L(f"隧道所在网卡的网关 {gv['ip']} 无响应 —— 先修复链路，VPN 只是症状",
                             f"The gateway {gv['ip']} on the tunnelled interface does not respond — "
                             f"fix the link first; the VPN is only a symptom"))
            if kind == "dns":
                return out("dns", L("代理侧 DNS 失败", "DNS failure through the tunnel"),
                           L("请求已到达隧道，但域名在隧道内无法解析 —— 多半是节点 DNS 配置",
                             "The request reaches the tunnel, but the domain does not resolve "
                             "inside it — most likely the node's DNS configuration"))
            return out("vpn", L("VPN 隧道 / 节点异常", "VPN tunnel / node failure"),
                       L(f"链路正常、直连对照可达，但经代理访问 {PROBE_HOST} 失败"
                         f"（{diag.label(kind)}）",
                         f"The link is fine and the direct control target is reachable, but "
                         f"{PROBE_HOST} fails through the proxy ({diag.label(kind, 'en')})"))

        # ③ 代理通、直连目标不可达 → 这就是设计意图，不是故障
        if pd and not pd.get("ok"):
            if tun:
                return out("target", L("目标需经隧道访问", "Target requires the tunnel"),
                           L("TUN 已接管全部流量，直连探测实际也经过隧道；此处不可达不代表链路故障",
                             "TUN captures all traffic, so the direct probe also went through the "
                             "tunnel; unreachable here does not mean a broken link"))
            bn = by_nic.get("direct") or {}
            extra = ""
            extra_en = ""
            if bn and not bn.get("ok"):
                extra = (f"；绑定 {lane(rd, 'zh')} 直接握手也不通（{diag.label(bn.get('kind') or 'unknown')}）")
                extra_en = (f"; a handshake bound to {lane(rd, 'en')} also fails "
                            f"({diag.label(bn.get('kind') or 'unknown', 'en')})")
            return out("target", L("目标被墙，代理正常", "Target blocked; proxy healthy"),
                       L(f"对照与代理通道均可达，仅直连 {PROBE_HOST} 不可达 —— 属正常现象{extra}",
                         f"Both the control target and the proxy path are reachable; only direct "
                         f"access to {PROBE_HOST} fails — this is expected{extra_en}"))

        return out("ok", L("链路正常", "All paths healthy"),
                   L("对照、直连、代理三条路径均可达，未发现异常",
                     "Control, direct and proxy paths are all reachable; no anomaly detected"))

    def probe_loop(self, stop: threading.Event):
        """代理通道：快，驱动探测条与出口 IP"""
        n = 0
        self.read_sysproxy()
        while not stop.is_set():
            try:
                self.read_sysproxy()
                if n % 3 == 0:
                    self.tick_cfg()
                self.probes["vpn"] = {**http_get(PROBE_TARGET, self.proxy, timeout=8),
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
                                          "ts": time.time(), "target": CONTROL_HOST}
                self._link_probe()
            except Exception as e:
                log("direct:", e)
            stop.wait(15)

    def loop(self, stop: threading.Event):
        while not stop.is_set():
            t0 = time.time()
            try:
                cli = DISCO.client
                hint = ""
                if cli.flow == "xray" and cli.metrics:
                    ok = self.sample_xray()
                    hint = L(f"{cli.name or '客户端'} 的统计口 {cli.metrics} 无响应",
                             f"the stats endpoint {cli.metrics} of {cli.name or 'the client'} "
                             f"did not respond")
                elif not cli.name or cli.kind == "none":
                    # 没有任何代理客户端在跑 —— 不是"没数据"，是换一种数法
                    ok = self.sample_host() or True
                else:
                    ok = self.sample()
                    # 说清是"哪一环读不到"：v2rayN 关掉统计口时，控制器和代理口其实都好好的，
                    # 再写"控制器未开"就是在冤枉它（issue #1）
                    if cli.metrics:
                        where = L(f"统计口 {cli.metrics} 无响应",
                                  f"the stats endpoint {cli.metrics} did not respond")
                    elif cli.api:
                        where = L(f"控制器 {cli.api} 无响应",
                                  f"the controller {cli.api} did not respond")
                    elif cli.kind in ("v2ray", "xray"):
                        where = L("其统计来源未开启", "its statistics source is off")
                    else:
                        where = L("它不提供字节统计", "it provides no byte counters")
                    hint = L(f"{cli.name} 在运行，但读不到它的流量（{where['zh']}）",
                             f"{cli.name} is running, but its traffic cannot be read ({where['en']})")
                if not ok:
                    # 客户端在、数读不到：退回网卡统计，别让面板停在错误上不动
                    self.sample_host(hint=hint)
            except Exception as e:
                log("sample:", e)
            d = time.time() - t0
            # 采一帧就花了 0.35 秒以上（本机模式要枚举连接/进程）就别催它：
            # 跑不赢的节奏会把 CPU 占满，退回 1 秒
            stop.wait(max(0.05, (1.0 if d > 0.35 else SAMPLE_EVERY) - d))


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
            blob, _ = ST.read_blob()
            self._send(200, blob)
            return
        if p == "/api/stream":
            # SSE 是每秒一小段，别让 Nagle 攒包：攒一下面板就晚几百毫秒，连着攒就像"卡住"
            try:
                self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            last = -1
            try:
                while True:
                    blob, ver = ST.read_blob()
                    if ver != last and ver:      # 一帧都还没采到就别发空的 {} 给面板
                        last = ver
                        self.wfile.write(b"data: " + blob + b"\n\n")
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
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads((self.rfile.read(n) or b"{}").decode("utf-8", "replace"))
        except Exception:
            body = {}
        if p == "/api/probe":
            ok, msg = set_probe(target=body.get("target"), control=body.get("control"),
                                interval=body.get("interval"))
            self._send(200 if ok else 400,
                       json.dumps({"ok": ok, "msg": msg,
                                   "probe": {"target": PROBE_TARGET, "host": PROBE_HOST,
                                             "control": CONTROL_HOST,
                                             "control_url": CONTROL_URL,
                                             "interval": PROBE_EVERY,
                                             "min": PROBE_MIN, "max": PROBE_MAX}},
                                  ensure_ascii=False))
            return
        if p != "/api/sites":
            self._send(404, json.dumps({"error": "not found"}))
            return
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
