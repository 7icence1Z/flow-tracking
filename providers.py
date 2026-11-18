"""VPN 客户端自动发现 / 识别 / 配置解析。

只依赖标准库。思路是"先找控制器，再找它属于谁"：

1. 谁在本地监听（netstat -ano）→ 端口归属 PID
2. 一次 WMI 拿全进程表：名字、路径、命令行、父进程
3. 对可疑端口探 `GET /version`，能回 `{"version": …}` 的就是 Clash 系 REST API
   （mihomo / Clash Verge / ClashX Meta / sing-box 的 clash_api 都长这样）
4. 从内核进程的命令行里抠 `-f/-c/--config/-d` → 配置文件路径
5. 读配置里的 proxies（YAML）或 outbounds（JSON）→ 节点名 ↔ 服务器映射

非 Clash 系（v2rayN / WireGuard / OpenVPN / 深信服…）没有统一 API，
只做"进程 + 网卡 + 系统代理"级别的识别，节点名给不出来就如实留空。
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import hashlib
import http.client
import json
import os
import re
import socket
import subprocess
import threading
import time
from urllib.request import Request, build_opener, ProxyHandler

DIRECT = build_opener(ProxyHandler({}))

# 常见外部控制端口（Clash 系默认 9090，mihomo 分支常用 7892/9097）
API_PORTS = (9090, 9091, 9092, 9097, 7892, 7893, 6170, 2019, 33333)

# 这些进程名之下，端口才值得去探
CORE_HINT = re.compile(r"mihomo|clash|sing-box|v2ray|xray|nekoray|nekobox|hiddify|singbox", re.I)

# 进程名 → 展示名。核心进程和外壳进程分开认：外壳（鹰云/Verge）才是用户嘴里的"软件"。
DISPLAY = {
    "mihomo": "mihomo",
    "verge-mihomo": "Clash Verge",
    "clash-verge": "Clash Verge",
    "clash": "Clash",
    "clash-win64": "Clash for Windows",
    "clash-meta": "Clash Meta",
    "clash-nyanpasu": "Clash Nyanpasu",
    "sing-box": "sing-box",
    "v2ray": "v2ray",
    "xray": "Xray",
    "v2rayn": "v2rayN",
    "nekoray": "NekoRay",
    "nekobox": "NekoBox",
    "hiddify": "Hiddify",
    "hiddify-core": "Hiddify",
    "shadowsocks": "Shadowsocks",
    "shadowsocksr": "ShadowsocksR",
    "myvpn": "鹰云 MyVPN",
    "flclash": "FlClash",
    "clashparty": "Mihomo Party",
    "mihomo-party": "Mihomo Party",
    "wireguard": "WireGuard",
    "openvpn": "OpenVPN",
    "openvpn-gui": "OpenVPN",
    "tailscale": "Tailscale",
    "zerotier-one": "ZeroTier",
    "sangfor": "深信服 EasyConnect",
    "easyconnect": "深信服 EasyConnect",
    "svpncli": "深信服 EasyConnect",
}

KIND = {
    "mihomo": "clash", "verge-mihomo": "clash", "clash": "clash", "clash-win64": "clash",
    "clash-meta": "clash", "clash-verge": "clash", "clash-nyanpasu": "clash",
    "myvpn": "clash", "flclash": "clash", "clashparty": "clash", "mihomo-party": "clash",
    "sing-box": "singbox", "hiddify-core": "singbox",
    "v2ray": "v2ray", "xray": "v2ray", "v2rayn": "v2ray", "nekoray": "v2ray", "nekobox": "v2ray",
    "wireguard": "wireguard", "openvpn": "openvpn", "openvpn-gui": "openvpn",
    "tailscale": "mesh", "zerotier-one": "mesh", "sangfor": "ssl", "easyconnect": "ssl",
}

# 客户端没开控制器时，靠网卡描述兜底
NIC_HINT = re.compile(r"wintun|wireguard|openvpn|tap-|tap adapter|sing-box|clash|mihomo|"
                      r"sangfor|easyconnect|tailscale|zerotier|vpn", re.I)


# ---------------------------------------------------------------- 基础工具
_K32 = ctypes.WinDLL("kernel32", use_last_error=True)
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_TH32CS_SNAPPROCESS = 0x00000002
_INVALID_HANDLE = ctypes.c_void_p(-1).value


class _FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", ctypes.wintypes.DWORD),
                ("dwHighDateTime", ctypes.wintypes.DWORD)]


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", ctypes.wintypes.DWORD), ("cntUsage", ctypes.wintypes.DWORD),
                ("th32ProcessID", ctypes.wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", ctypes.wintypes.DWORD),
                ("cntThreads", ctypes.wintypes.DWORD),
                ("th32ParentProcessID", ctypes.wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long), ("dwFlags", ctypes.wintypes.DWORD),
                ("szExeFile", ctypes.wintypes.WCHAR * 260)]


_K32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p


def _toolhelp() -> list[tuple[int, int, str]]:
    """(pid, 父 pid, 映像名)。内核里现成的进程清单，1～3 ms，不需要权限"""
    snap = _K32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if not snap or snap == _INVALID_HANDLE:
        return []
    try:
        pe = _PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(pe)
        out: list[tuple[int, int, str]] = []
        if not _K32.Process32FirstW(snap, ctypes.byref(pe)):
            return []
        while True:
            out.append((pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile or ""))
            if not _K32.Process32NextW(snap, ctypes.byref(pe)):
                break
        return out
    finally:
        _K32.CloseHandle(snap)


def _name_table() -> dict[int, dict]:
    """pid → {name, ppid}。只回答"谁是谁"的时候用这个（本机模式的进程名就靠它）"""
    return {pid: {"name": name, "ppid": ppid} for pid, ppid, name in _toolhelp()}


def _proc_info(pid: int) -> tuple[str, float]:
    """一次 OpenProcess 拿 路径 + 创建时间。系统进程、权限不够就留空，不猜"""
    h = _K32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return "", 0.0
    try:
        buf = ctypes.create_unicode_buffer(1024)
        n = ctypes.wintypes.DWORD(1024)
        path = buf.value if _K32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)) else ""
        c, e, k, u = _FILETIME(), _FILETIME(), _FILETIME(), _FILETIME()
        created = 0.0
        if _K32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e),
                                ctypes.byref(k), ctypes.byref(u)):
            created = float(c.dwLowDateTime | (c.dwHighDateTime << 32))
        return path, created
    finally:
        _K32.CloseHandle(h)


# 命令行只有"像代理软件的那几个进程"用得上（抠 -f/--config 定位配置文件），
# 所以只给候选进程补，并按 (pid, 创建时间) 缓存 —— 客户端不重启就不再起 powershell。
_CMD_WHY = re.compile(r"proxy|vpn|tunnel", re.I)
_CMD: dict[int, tuple[float, float, str]] = {}
_CMD_TTL = 300.0


def _ps_cmd(pids: list[int]) -> dict[int, str]:
    """只问这几个 pid 的命令行。一次 powershell 约 1 秒，所以调用方必须先把范围收窄"""
    if not pids:
        return {}
    cond = " or ".join(f"ProcessId={p}" for p in pids)
    ps = ("[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); "
          f"Get-CimInstance Win32_Process -Filter \"{cond}\" | ForEach-Object {{ "
          "\"$($_.ProcessId)|$($_.CommandLine)\" }")
    try:
        p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                           capture_output=True, timeout=20,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:
        return {}
    out = (p.stdout or b"").decode("utf-8", "replace")
    if "\ufffd" in out:
        out = (p.stdout or b"").decode("gbk", "replace")
    got: dict[int, str] = {}
    for line in out.splitlines():
        head, _, cmd = line.partition("|")
        if head.strip().isdigit():
            got[int(head)] = cmd.strip()
    return got


def _fill_cmd(table: dict[int, dict]) -> None:
    want: list[int] = []
    now = time.time()
    for pid, info in table.items():
        st = _stem(info.get("name", ""))
        if not st:
            continue
        if not (st in DISPLAY or CORE_HINT.search(st) or _CMD_WHY.search(st)):
            continue
        hit = _CMD.get(pid)
        created = info.get("_created", 0.0)
        if hit and hit[0] == created and now - hit[1] < _CMD_TTL:
            info["cmd"] = hit[2]
        else:
            want.append(pid)
    if not want:
        return
    got = _ps_cmd(want[:24])
    for pid in want:
        info = table.get(pid) or {}
        cmd = got.get(pid)
        if cmd is None:
            continue
        info["cmd"] = cmd
        _CMD[pid] = (info.get("_created", 0.0), now, cmd)


def _proc_table() -> dict[int, dict]:
    """pid → {name, path, cmd, ppid}。内核直读 + 候选进程补命令行。

    以前这张表是一次 `Get-CimInstance Win32_Process`：约 1 秒 CPU、上百兆临时进程，
    为的只是"谁在跑、路径在哪"。名字/父进程/路径内核里都有；只有命令行必须问 WMI，
    而命令行只用来定位那几个代理内核的配置文件 —— 范围收到个位数，再按进程创建时间缓存。
    """
    table: dict[int, dict] = {}
    for pid, ppid, name in _toolhelp():
        path, created = _proc_info(pid)
        table[pid] = {"ppid": ppid, "name": name, "path": path, "cmd": "",
                      "_created": created}
    if not table:                                   # 内核这条路不通：退回老办法，别把功能弄丢
        return _ps_table_wmi()
    try:
        _fill_cmd(table)
    except Exception:
        pass
    for info in table.values():
        info.pop("_created", None)
    return table


def _ps_table_wmi() -> dict[int, dict]:
    """一次 WMI：pid → {name, path, cmd, ppid}。比逐进程查快，也比 PEB 稳妥。"""
    ps = ("[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); "
          "Get-CimInstance Win32_Process | ForEach-Object { "
          "\"$($_.ProcessId)|$($_.ParentProcessId)|$($_.Name)|$($_.ExecutablePath)|$($_.CommandLine)\" }")
    try:
        p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                           capture_output=True, timeout=20,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        out = (p.stdout or b"").decode("utf-8", "replace")
        if "\ufffd" in out:                        # 老系统仍按 ANSI 输出
            out = (p.stdout or b"").decode("gbk", "replace")
    except Exception:
        return {}
    table: dict[int, dict] = {}
    for line in out.splitlines():
        parts = line.split("|", 4)
        if len(parts) < 5 or not parts[0].strip().isdigit():
            continue
        pid = int(parts[0])
        table[pid] = {
            "ppid": int(parts[1] or 0) if parts[1].strip().isdigit() else 0,
            "name": (parts[2] or "").strip(),
            "path": (parts[3] or "").strip(),
            "cmd": (parts[4] or "").strip(),
        }
    return table


def _listen_map() -> dict[int, int]:
    """端口 → PID。内核里就有这张表，不必再 spawn netstat（80 ms 一次，还带一个进程）"""
    try:
        import hostflow
        m: dict[int, int] = {}
        for r in hostflow.tcp_all():
            if r["pid"]:
                m.setdefault(r["lport"], r["pid"])
        if m:
            return m
    except Exception:
        pass
    return _listen_map_netstat()


def _listen_map_netstat() -> dict[int, int]:
    """netstat 版：内核直读拿不到时兜底。标题行是本地化的，所以只认末列数字"""
    try:
        p = subprocess.run(["netstat", "-ano", "-p", "tcp"], capture_output=True, timeout=8,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        out = (p.stdout or b"").decode("gbk", "replace")
    except Exception:
        return {}
    m: dict[int, int] = {}
    for line in out.splitlines():
        f = line.split()
        if len(f) < 5 or not f[0].upper().startswith("TCP"):
            continue
        tail = f[-1]
        if not tail.isdigit():
            continue
        addr = f[1]
        port = addr.rsplit(":", 1)[-1]
        if port.isdigit():
            m.setdefault(int(port), int(tail))
    return m


def _stem(name: str) -> str:
    return re.sub(r"\.exe$", "", (name or "").strip().lower())


def _alive(pid: int) -> bool:
    """这个 PID 现在还活着吗。

    进程表 `_table()` 缓存 30 秒、监听表 `_ports()` 缓存 15 秒，缓存比进程活得久：
    客户端被 kill 掉之后，缓存里还留着它的名字和端口归属。判断"它此刻在转发"
    必须挂在活着的进程上，否则会出现"进程已经没了，面板还说在走 VPN"。
    查不到退出码时按"活着"算 —— 宁可少断言，不要冤枉一个可能还在转发的进程。
    """
    if not pid or int(pid) <= 0:
        return False
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        h = k32.OpenProcess(0x1000, False, int(pid))       # QUERY_LIMITED_INFORMATION
        if not h:
            return False
        try:
            code = ctypes.c_ulong()
            if not k32.GetExitCodeProcess(h, ctypes.byref(code)):
                return True
            return code.value == 259                        # STILL_ACTIVE
        finally:
            k32.CloseHandle(h)
    except Exception:
        return True


def _lookup(stem: str) -> str:
    """精确名 → 否则前缀匹配（mihomo-windows-amd64 → mihomo）"""
    if not stem:
        return ""
    if stem in DISPLAY:
        return DISPLAY[stem]
    for k in sorted(DISPLAY, key=len, reverse=True):
        if stem.startswith(k):
            return DISPLAY[k]
    return ""


_POOL = threading.local()


def _http_json(host_port: str, path: str, secret: str = "", timeout: float = 0.8):
    """问本地控制器要一份 JSON。走长连接。

    面板 0.5 秒一帧，这条连接一秒要问两三次；而本机建一次 TCP 要 6 ms、
    整个请求-关闭要 10 ms —— 比"取数据"本身（0.4 ms）贵二十倍。
    长连接按线程各留一条（互不抢锁），断了重建一次，仍不成才退回 urllib。
    """
    host, _, port = host_port.rpartition(":")
    if not host or not port.isdigit():
        return _http_json_urllib(host_port, path, secret, timeout)
    key = (host, int(port))
    pool = getattr(_POOL, "conns", None)
    if pool is None:
        pool = _POOL.conns = {}
    headers = {"Accept": "application/json", "User-Agent": "flow/1.0"}
    if secret:
        headers["Authorization"] = f"Bearer {secret}"
    for attempt in (0, 1):
        conn = pool.get(key)
        if conn is None:
            conn = pool[key] = http.client.HTTPConnection(key[0], key[1], timeout=timeout)
        try:
            conn.timeout = timeout            # 每次请求可能给不同的超时（0.6～2 秒）
            if conn.sock is not None:         # 复用的连接要把超时也落到那个 socket 上
                conn.sock.settimeout(timeout)
            conn.request("GET", path, headers=headers)
            r = conn.getresponse()
            body = r.read()
            if r.will_close:                  # 对方不想复用：别留一条死连接在池里
                try:
                    conn.close()
                except Exception:
                    pass
                pool.pop(key, None)
            if r.status >= 400:
                # 连接是好的，只是这个路径不对：交给 urllib 抛它原来的错（调用方按它分类）
                return _http_json_urllib(host_port, path, secret, timeout)
            return json.loads(body.decode("utf-8", "replace"))
        except Exception:
            try:
                conn.close()
            except Exception:
                pass
            pool.pop(key, None)
            if attempt:
                break
    return _http_json_urllib(host_port, path, secret, timeout)


def _http_json_urllib(host_port: str, path: str, secret: str = "", timeout: float = 0.8):
    url = f"http://{host_port}{path}"
    req = Request(url, headers={"Accept": "application/json", "User-Agent": "flow/1.0"})
    if secret:
        req.add_header("Authorization", f"Bearer {secret}")
    with DIRECT.open(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


# ---------------------------------------------------------------- 配置解析
def parse_clash_proxies(text: str) -> dict:
    """配置里 proxies: 段 → name → {name,server,port,type}。
    只认与 name 同级的键，ws-opts / reality-opts 里的同名键不会串进来。"""
    out: dict = {}
    m = re.search(r"^proxies:[ \t]*\r?\n", text or "", re.M)
    if not m:                                  # 文件开头就是 proxies: 也要认（以前会 IndexError）
        return out
    seg = text[m.end():]
    # 顶格的 `proxy-groups:` / `rules:` 等是下一个段落：不在这里收尾，
    # 策略组（- name: PROXY 这类）就会被当成节点，连"共 N 个节点"都会算多
    keep = []
    for raw in seg.splitlines():
        if raw and not raw[0].isspace() and ":" in raw and not raw.lstrip().startswith("#"):
            break
        keep.append(raw)
    seg = "\n".join(keep)
    cur = None
    base = -1
    for raw in seg.splitlines():
        line = raw.rstrip()
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if s.startswith("-"):
            # 两种写法都要认：块状（- name: x 换行接 server:）和行内（- {name: x, server: y}）
            head = s[1:].lstrip()
            base = indent + 1 + (len(s) - 1 - len(head))   # 键的起始列（- 后面可能不止一个空格）
            cur = None
            if head.startswith("{") and head.endswith("}"):
                cur = {"name": "", "server": "", "port": 0, "type": ""}
                for kv in head.strip("{}").split(","):
                    k, sep, v = kv.partition(":")
                    if not sep:
                        continue
                    k = k.strip().strip("\"'").lower()
                    v = v.strip().strip("\"'")
                    if k in ("name", "server"):
                        cur[k] = v
                    elif k == "type":
                        cur["type"] = v.upper()
                    elif k == "port":
                        cur["port"] = int(re.sub(r"\D", "", v) or 0)
                if not cur["name"]:
                    cur = None
                else:
                    out[cur["name"]] = cur
                continue
            if not head.startswith("name:"):
                continue
            name = head.split("name:", 1)[1].strip().strip("\"'")
            if not name:
                continue
            cur = {"name": name, "server": "", "port": 0, "type": ""}
            out[name] = cur
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


def parse_json_outbounds(text: str) -> dict:
    """sing-box / v2ray 的 outbounds → tag → {name,server,port,type}"""
    out: dict = {}
    try:
        data = json.loads(text)
    except Exception:
        return out
    for o in data.get("outbounds") or []:
        if not isinstance(o, dict):
            continue
        name = o.get("tag") or o.get("remarks") or ""
        srv = o.get("server") or ""
        if not name or not srv:
            continue
        out[name] = {"name": name, "server": srv,
                     "port": int(o.get("server_port") or o.get("port") or 0),
                     "type": (o.get("type") or "").upper()}
    return out


# ---------------------------------------------------------------- 节点命名
# 有的客户端不把"你选的那个节点"的名字交出来：
#   · 鹰云这类单节点配置，节点名就是字面的 proxy；
#   · v2rayN 生成的 config.json 里 outbound tag 也叫 proxy，真名在 guiNDB.db 的 remarks 里；
#   · sing-box 生成器常写 proxy / 自动选择 / 🚀 节点选择 这类名字。
# 这些名字照抄等于没说。于是统一判一遍：占位名 → 用"地域 + 协议"代替。
GROUP_TYPES = {
    "selector", "urltest", "fallback", "loadbalance", "load-balance", "relay",
    "direct", "reject", "block", "dns", "compatible", "pass", "hosts",
    "freedom", "blackhole", "proxy", "group",
    # mihomo 还会塞两个"不是节点"的内置项，名字随语言变，按 type 认最稳
    "rejectdrop", "reject-drop", "passrule", "pass-rule", "rematch",
}

PLACEHOLDER_NAMES = {
    "proxy", "proxies", "proxynode", "node", "nodes", "server", "outbound", "outbounds",
    "default", "select", "selected", "auto", "automatic", "global", "direct", "reject",
    "block", "dns", "group", "groups", "chain", "tunnel", "vpn", "main", "local",
    "socks", "http", "mixed", "ss", "ssr", "vmess", "vless", "trojan", "hysteria",
    "hysteria2", "hy2", "tuic", "wireguard", "wg", "relay", "config", "test", "remote",
    "节点", "代理", "代理节点", "自动", "自动选择", "手动", "手动切换", "直连", "全局",
    "未知", "默认", "测试", "本机", "分流", "节点选择", "代理模式",
}

# 两位国家/地区码（够用即可：不在表里的三字词/域名里仍能靠 REGION_WORDS 兜住）
REGION_CODES = {
    "jp", "us", "hk", "sg", "tw", "kr", "de", "nl", "gb", "uk", "fr", "ca", "au", "ru",
    "in", "tr", "br", "my", "th", "vn", "id", "ph", "ae", "ch", "se", "fi", "no", "pl",
    "it", "es", "ie", "at", "be", "dk", "cz", "ua", "kz", "mo", "nz", "za", "sa", "il",
    "ir", "ar", "cl", "mx", "co", "pe", "ve", "cn", "pt", "ro", "bg", "gr", "hu", "lt",
    "lv", "ee", "hr", "rs", "by", "am", "ge", "az", "mn", "np", "pk", "lk", "bd", "kh",
    "la", "mm", "bn", "jo", "kw", "qa", "om", "bh", "eg", "ma", "ng", "ke", "tz", "gh",
    "eu", "un",
}

# 地名 → 国家/地区码。英文优先按词边界匹配，中文直接子串匹配（"香港01" 也要认出来）
REGION_WORDS = [
    ("japan", "JP"), ("日本", "JP"), ("东京", "JP"), ("東京", "JP"), ("tokyo", "JP"),
    ("大阪", "JP"), ("osaka", "JP"), ("nrt", "JP"), ("hnd", "JP"), ("kix", "JP"),
    ("australia", "AU"), ("germany", "DE"), ("deutschland", "DE"), ("netherlands", "NL"),
    ("holland", "NL"), ("england", "GB"), ("britain", "GB"), ("france", "FR"),
    ("canada", "CA"), ("india", "IN"), ("turkey", "TR"), ("brazil", "BR"),
    ("malaysia", "MY"), ("thailand", "TH"), ("vietnam", "VN"), ("indonesia", "ID"),
    ("philippines", "PH"), ("switzerland", "CH"), ("sweden", "SE"), ("finland", "FI"),
    ("norway", "NO"), ("poland", "PL"), ("italy", "IT"), ("spain", "ES"), ("ireland", "IE"),
    ("austria", "AT"), ("belgium", "BE"), ("denmark", "DK"), ("czechia", "CZ"),
    ("ukraine", "UA"), ("russia", "RU"), ("kazakhstan", "KZ"), ("mexico", "MX"),
    ("israel", "IL"), ("iran", "IR"), ("argentina", "AR"), ("chile", "CL"),
    ("newzealand", "NZ"), ("southafrica", "ZA"), ("korea", "KR"), ("taiwan", "TW"),
    ("singapore", "SG"), ("hongkong", "HK"), ("japan", "JP"), ("china", "CN"),
    ("unitedstates", "US"), ("america", "US"), ("美国", "US"), ("美國", "US"),
    ("洛杉矶", "US"), ("losangeles", "US"), ("圣何塞", "US"), ("sanjose", "US"),
    ("西雅图", "US"), ("seattle", "US"), ("纽约", "US"), ("newyork", "US"),
    ("达拉斯", "US"), ("dallas", "US"), ("凤凰城", "US"), ("硅谷", "US"), ("芝加哥", "US"),
    ("lax", "US"), ("sfo", "US"), ("sjc", "US"), ("jfk", "US"), ("sea", "US"),
    ("香港", "HK"), ("hongkong", "HK"), ("hkg", "HK"),
    ("台湾", "TW"), ("台灣", "TW"), ("台北", "TW"), ("taipei", "TW"), ("tpe", "TW"),
    ("新加坡", "SG"), ("singapore", "SG"), ("狮城", "SG"), ("sin", "SG"),
    ("韩国", "KR"), ("韓國", "KR"), ("首尔", "KR"), ("首爾", "KR"), ("seoul", "KR"),
    ("icn", "KR"), ("gmp", "KR"),
    ("德国", "DE"), ("德國", "DE"), ("法兰克福", "DE"), ("frankfurt", "DE"), ("fra", "DE"),
    ("荷兰", "NL"), ("荷蘭", "NL"), ("阿姆斯特丹", "NL"), ("amsterdam", "NL"), ("ams", "NL"),
    ("英国", "GB"), ("英國", "GB"), ("伦敦", "GB"), ("倫敦", "GB"), ("london", "GB"),
    ("lhr", "GB"), ("法国", "FR"), ("法國", "FR"), ("巴黎", "FR"), ("paris", "FR"), ("cdg", "FR"),
    ("加拿大", "CA"), ("多伦多", "CA"), ("toronto", "CA"), ("yyz", "CA"),
    ("澳大利亚", "AU"), ("澳洲", "AU"), ("悉尼", "AU"), ("sydney", "AU"), ("syd", "AU"),
    ("俄罗斯", "RU"), ("莫斯科", "RU"), ("moscow", "RU"), ("印度", "IN"), ("孟买", "IN"),
    ("mumbai", "IN"), ("bom", "IN"), ("土耳其", "TR"), ("伊斯坦布尔", "TR"),
    ("istanbul", "TR"), ("ist", "TR"), ("巴西", "BR"), ("圣保罗", "BR"), ("saopaulo", "BR"),
    ("马来西亚", "MY"), ("吉隆坡", "MY"), ("kualalumpur", "MY"), ("泰国", "TH"),
    ("曼谷", "TH"), ("bangkok", "TH"), ("越南", "VN"), ("胡志明", "VN"), ("河内", "VN"),
    ("印尼", "ID"), ("印度尼西亚", "ID"), ("雅加达", "ID"), ("jakarta", "ID"),
    ("菲律宾", "PH"), ("马尼拉", "PH"), ("manila", "PH"), ("阿联酋", "AE"), ("迪拜", "AE"),
    ("dubai", "AE"), ("瑞士", "CH"), ("苏黎世", "CH"), ("zurich", "CH"), ("瑞典", "SE"),
    ("斯德哥尔摩", "SE"), ("stockholm", "SE"), ("芬兰", "FI"), ("赫尔辛基", "FI"),
    ("helsinki", "FI"), ("挪威", "NO"), ("奥斯陆", "NO"), ("oslo", "NO"), ("波兰", "PL"),
    ("华沙", "PL"), ("warsaw", "PL"), ("意大利", "IT"), ("米兰", "IT"), ("milan", "IT"),
    ("西班牙", "ES"), ("马德里", "ES"), ("madrid", "ES"), ("爱尔兰", "IE"), ("都柏林", "IE"),
    ("奥地利", "AT"), ("维也纳", "AT"), ("vienna", "AT"), ("比利时", "BE"),
    ("布鲁塞尔", "BE"), ("丹麦", "DK"), ("哥本哈根", "DK"), ("copenhagen", "DK"),
    ("捷克", "CZ"), ("布拉格", "CZ"), ("prague", "CZ"), ("乌克兰", "UA"), ("基辅", "UA"),
    ("kyiv", "UA"), ("哈萨克斯坦", "KZ"), ("almaty", "KZ"), ("澳门", "MO"), ("澳門", "MO"),
    ("macao", "MO"), ("macau", "MO"), ("新西兰", "NZ"), ("奥克兰", "NZ"),
    ("auckland", "NZ"), ("南非", "ZA"), ("约翰内斯堡", "ZA"), ("阿根廷", "AR"),
    ("布宜诺斯艾利斯", "AR"), ("智利", "CL"), ("圣地亚哥", "CL"), ("墨西哥", "MX"),
    ("以色列", "IL"), ("特拉维夫", "IL"), ("telaviv", "IL"), ("伊朗", "IR"), ("中国", "CN"),
    ("中国大陆", "CN"),
]


def _flag_cc(name: str) -> str:
    """🇯🇵 → JP：两个 regional indicator 就是一个国家/地区码"""
    pair = ""
    for ch in name or "":
        if "\U0001F1E6" <= ch <= "\U0001F1FF":
            pair += chr(ord(ch) - 0x1F1E6 + ord("A"))
            if len(pair) == 2:
                return pair
        else:
            pair = ""
    return ""


def _squash(name: str) -> str:
    """去掉 emoji、符号、空白与数字，留下真正带信息的字"""
    s = re.sub(r"[^0-9A-Za-z\u4e00-\u9fff]+", "", str(name or ""))
    return re.sub(r"\d+", "", s).lower()


def is_placeholder(name: str, groups=()) -> bool:
    """节点名是不是"等于没说"：占位词、等于某个策略组名、或只剩 emoji/数字"""
    low = str(name or "").strip().lower()
    if not low:
        return True
    if low in PLACEHOLDER_NAMES:
        return True
    gs = {str(g or "").strip().lower() for g in (groups or ())}
    if low in gs:
        return True
    sq = _squash(low)
    if not sq or sq in PLACEHOLDER_NAMES:
        return True
    return sq in {_squash(g) for g in gs}


def region_from_name(name: str) -> str:
    """从节点名里认地域：🇯🇵 / 东京 / Tokyo / JP 都算"""
    cc = _flag_cc(name)
    if cc:
        return cc
    low = str(name or "").lower()
    if not low:
        return ""
    tokens = {t for t in re.split(r"[^0-9a-z\u4e00-\u9fff]+", low) if t}
    for word, code in REGION_WORDS:
        if re.fullmatch(r"[a-z0-9]{2,3}", word):
            if word in tokens:                 # 短码只按整词认，别把 aus→us 认错
                return code
        elif word in low:
            return code
    # JP-01 / jp01 / us1 这类：两位码后面直接跟数字
    for t in tokens:
        m = re.fullmatch(r"([a-z]{2,3})\d+", t)
        if m and m.group(1) in REGION_CODES:
            return m.group(1).upper()
    # 最后才按整词认两字母码（jp / us / hk），顺序在长词之后
    for t in tokens:
        if t in REGION_CODES:
            return t.upper()
    return ""


def region_from_host(host: str) -> str:
    """从服务器地址里认地域：jp-xxx-aa-10077.node-yingyun.site / us1.example.net"""
    low = str(host or "").strip().lower()
    lab = low.split(".")[0]
    if not lab:
        return ""
    # 前缀必须是"码 + 分隔符/数字/结尾"：node.example.com 不能读成 NO
    m = re.match(r"([a-z]{2,3})(?:[-_]|\d|$)", lab)
    if m and m.group(1) in REGION_CODES:
        return m.group(1).upper()
    for m in re.finditer(r"(?:^|[-_])([a-z]{2})(?:[-_]|\d|$)", lab):
        if m.group(1) in REGION_CODES:
            return m.group(1).upper()
    return region_from_name(lab)


def node_region(name: str, host: str = "") -> str:
    """地域提示：先看节点名（🇯🇵 东京-01 最准），再看服务器域名"""
    return region_from_name(name) or region_from_host(host)


def is_pseudo_type(typ: str) -> bool:
    """策略组 / 直连 / 拒绝 / 内置规则项：都不是"节点" """
    t = str(typ or "").lower()
    return (t in GROUP_TYPES or t.startswith("reject") or t.startswith("pass-")
            or t.endswith("rule"))


def count_nodes(items) -> int:
    """真节点的数量：策略组、直连/拒绝这类不是节点"""
    n = 0
    for v in (items or {}).values() if isinstance(items, dict) else (items or []):
        if not isinstance(v, dict):
            continue
        if is_pseudo_type(v.get("type")):
            continue
        n += 1              # 控制器的 /proxies 不带 server 字段，只能靠 type 区分组和节点
    return n


def parse_clash_default_group(text: str) -> str:
    """rules 里最后一条 MATCH 指向的分组：没匹配上任何规则时就走它，也就是默认出口"""
    m = re.search(r"^rules:[ \t]*\r?\n", text or "", re.M)
    if not m:
        return ""
    seg = text[m.end():]
    best = ""
    for raw in seg.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if not s.startswith("- "):
            break
        body = s[2:].strip().strip("\"'")
        parts = [x.strip().strip("\"'") for x in body.split(",")]
        if parts and parts[0].upper() in ("MATCH", "FINAL") and parts[-1]:
            best = parts[-1]
    return best


def parse_json_default_outbound(text: str) -> str:
    """sing-box 的 route.final / v2ray 的 routing 末条：默认出口的 outbound 名

    route.final 经常指向一个 selector，而 selector 自己不是节点，
    所以要顺着 default（没有就取它第一个 outbound）一直走到真节点。
    """
    try:
        j = json.loads(text)
    except Exception:
        return ""
    if not isinstance(j, dict):
        return ""
    obs: dict = {}
    for o in j.get("outbounds") or []:
        if isinstance(o, dict) and o.get("tag"):
            obs[str(o["tag"])] = o
    want = ""
    route = j.get("route") or {}
    if isinstance(route, dict):
        want = str(route.get("final") or "")
        if not want:
            for r in reversed(route.get("rules") or []):
                if isinstance(r, dict) and r.get("outbound"):
                    want = str(r["outbound"])
                    break
    if not want:
        for r in reversed((j.get("routing") or {}).get("rules") or []):
            if isinstance(r, dict) and r.get("outboundTag"):
                want = str(r["outboundTag"])
                break
    seen = set()
    while want and want in obs and want not in seen:
        seen.add(want)
        o = obs[want]
        if str(o.get("type") or "").lower() not in ("selector", "urltest", "load-balance"):
            break
        nxt = str(o.get("default") or "")
        if not nxt:
            cand = [str(x) for x in (o.get("outbounds") or []) if str(x) in obs]
            nxt = cand[0] if cand else ""
        if not nxt or nxt == want:
            break
        want = nxt
    return want


def default_group(c: "Client") -> str:
    """这次能确定"默认走哪个组/outbound"就返回名字（读配置，不联网）"""
    text = _read(c.config) if c and c.config else ""
    if not text:
        return ""
    if c.config.lower().endswith(".json"):
        want = parse_json_default_outbound(text)
    else:
        want = parse_clash_default_group(text) or parse_json_default_outbound(text)
    name = str(want or "").strip()
    if not name:
        return ""
    low = name.lower()
    if low in ("direct", "block", "reject", "dns", "freedom", "blackhole"):
        return ""
    return name


def _conf_from_cmd(cmd: str) -> tuple[str, str]:
    """从内核命令行抠配置路径和数据目录"""
    conf = ""
    for pat in (r'(?:^|\s)-f\s+("[^"]+"|\S+)', r'(?:^|\s)--config\s+("[^"]+"|\S+)',
                r'(?:^|\s)-c\s+("[^"]+"|\S+)', r'(?:^|\s)-config\s+("[^"]+"|\S+)'):
        m = re.search(pat, cmd)
        if m:
            conf = m.group(1).strip('"')
            break
    ddir = ""
    m = re.search(r'(?:^|\s)(?:-d|--directory|-D)\s+("[^"]+"|\S+)', cmd)
    if m:
        ddir = m.group(1).strip('"')
    if not conf and ddir:
        for n in ("config.yaml", "config.yml", "config.json"):
            p = os.path.join(ddir, n)
            if os.path.exists(p):
                conf = p
                break
    return conf, ddir


def _read(path: str, limit: int = 8 << 20) -> str:
    try:
        if not path or not os.path.exists(path):
            return ""
        with open(path, "rb") as f:
            return f.read(limit).decode("utf-8", "replace")
    except Exception:
        return ""


# ---------------------------------------------------------------- 结论对象
class Client:
    __slots__ = ("kind", "name", "core", "version", "api", "secret", "config", "data_dir",
                 "exe", "pid", "mode", "nodes", "nodes_hash", "updated", "sub", "proxies",
                 "meta", "conf_mtime", "metrics", "local_proxy", "flow")

    def __init__(self):
        self.kind = "none"       # clash / singbox / v2ray / wireguard / openvpn / ssl / mesh / none
        self.name = ""           # 用户看到的软件名：鹰云 MyVPN / Clash Verge
        self.core = ""           # 内核：mihomo / sing-box / v2ray
        self.version = ""
        self.api = ""            # 127.0.0.1:7892
        self.secret = ""
        self.config = ""         # 配置文件路径
        self.data_dir = ""
        self.exe = ""
        self.pid = 0
        self.mode = ""           # rule / global / direct
        self.nodes = 0
        self.nodes_hash = ""
        self.updated = 0.0       # 上次发现节点表变化的时间
        self.sub: dict = {}      # {kind, name, updated, used, total, expire}
        self.proxies: dict = {}
        self.meta = False
        self.conf_mtime = 0.0
        self.metrics = ""        # 127.0.0.1:10085（Xray 的 /debug/vars 统计口）
        self.local_proxy = ""    # 本地混合代理口 127.0.0.1:10808
        self.flow = ""           # clash / xray / ""（流量数据从哪来）

    def pack(self) -> dict:
        return {
            "kind": self.kind, "name": self.name, "core": self.core, "version": self.version,
            "api": self.api, "config": self.config, "exe": self.exe, "pid": self.pid,
            "mode": self.mode, "nodes": self.nodes, "updated": self.updated,
            "sub": self.sub, "meta": self.meta, "flow": self.flow,
            "metrics": self.metrics, "local": self.local_proxy,
        }


# ---------------------------------------------------------------- 发现器
class Registry:
    _DNS_OK = 600.0        # 解析成功的缓存时间
    _DNS_FAIL = 120.0      # 解析失败的缓存时间（网络恢复后能重试）
    _DNS_MAX = 16          # 一次 tick 最多解析几个域名

    def __init__(self, hint: str = ""):
        self.hint = (hint or "").strip()
        self.client = Client()
        self._ps: dict[int, dict] = {}
        self._ps_at = 0.0
        self._listen: dict[int, int] = {}
        self._listen_at = 0.0
        self._last_tick = 0.0
        self._lock = threading.Lock()
        self._dns: dict[str, tuple[str, float]] = {}
        self._dns_rot = 0
        self._cfg_at = 0.0
        self._db_at = 0.0
        self._db_rows: list = []

    # -- 缓存
    def _table(self, force: bool = False) -> dict[int, dict]:
        if force or not self._ps or time.time() - self._ps_at > 30:
            t = _proc_table()
            if t:
                self._ps, self._ps_at = t, time.time()
        return self._ps

    def _ports(self, force: bool = False) -> dict[int, int]:
        if force or not self._listen or time.time() - self._listen_at > 15:
            m = _listen_map()
            if m:
                self._listen, self._listen_at = m, time.time()
        return self._listen

    # -- 认软件名：从内核往上找 2 层父进程，谁有像样的名字就用谁
    def _display(self, pid: int, table: dict[int, dict]) -> tuple[str, str, str]:
        """返回 (软件名, 内核名, 内核进程名)。内核往上两层的父进程才是用户认的那个软件"""
        cur, seen = pid, set()
        core = core_stem = ""
        for _ in range(3):
            info = table.get(cur) or {}
            st = _stem(info.get("name", ""))
            if not st or cur in seen:
                break
            seen.add(cur)
            disp = _lookup(st)
            if disp:
                if CORE_HINT.match(st):
                    core, core_stem = core or disp, core_stem or st
                else:
                    return disp, core or disp, core_stem or st
            cur = info.get("ppid", 0)
        return core, core, core_stem

    # -- 探控制器
    def _probe(self) -> tuple[str, dict]:
        ports = self._ports()
        cands: list[int] = []
        if ":" in self.hint:
            try:
                cands.append(int(self.hint.rsplit(":", 1)[1]))
            except Exception:
                pass
        table = self._table()
        for port, pid in ports.items():
            if port in cands:
                continue
            st = _stem((table.get(pid) or {}).get("name", ""))
            if CORE_HINT.search(st) or CORE_HINT.search((table.get(pid) or {}).get("path", "")):
                cands.append(port)
        for port in API_PORTS:
            if port not in cands:
                cands.append(port)
        deadline = time.time() + 2.5
        for port in cands:
            if port not in ports and f"127.0.0.1:{port}" != self.hint:
                continue
            if time.time() > deadline:      # 本机开了很多端口的开发机上别耗太久
                break
            try:
                v = _http_json(f"127.0.0.1:{port}", "/version", "", 0.6)
                if isinstance(v, dict) and (v.get("version") or v.get("meta") is not None):
                    return f"127.0.0.1:{port}", v
            except Exception:
                continue
        return "", {}

    def _nodes(self, c: Client):
        """读配置 → 节点表；顺带算指纹，用来判断订阅/节点表有没有变"""
        if not c.config or not os.path.exists(c.config):
            return
        try:
            c.conf_mtime = os.path.getmtime(c.config)
        except Exception:
            c.conf_mtime = 0.0
        text = _read(c.config)
        if not text:
            return
        if c.config.lower().endswith(".json"):
            c.proxies = parse_json_outbounds(text)
        else:
            c.proxies = parse_clash_proxies(text)
            if not c.proxies:                      # sing-box 也可能拿 yaml 糊弄
                c.proxies = parse_json_outbounds(text)
        c.nodes = len(c.proxies)
        h = hashlib.sha1("\n".join(sorted(c.proxies)).encode("utf-8", "replace")).hexdigest()[:12]
        if h != c.nodes_hash:
            if c.nodes_hash:                        # 不是第一次 → 节点表真的变了
                c.updated = time.time()
            c.nodes_hash = h
        m = re.search(r"^secret:[ \t]*(\S+)[ \t]*$", text, re.M)
        if m and not c.secret:
            s = m.group(1).strip().strip("\"'")
            if s and s not in ("", "null"):
                c.secret = s

    @staticmethod
    def _ts(v) -> float:
        if isinstance(v, (int, float)):
            return float(v) if v > 0 else 0.0
        if not isinstance(v, str) or not v or v.startswith("0001"):
            return 0.0
        try:
            import datetime as dt
            return dt.datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
        except Exception:
            return 0.0

    def _sub(self, c: Client):
        """订阅信息：优先问控制器（Clash 系 /providers/proxies），
        问不到就用配置文件 mtime 兜底（鹰云这类把订阅拉平成一个 yaml 的客户端）"""
        providers: dict = {}
        if c.api:
            try:
                providers = (_http_json(c.api, "/providers/proxies", c.secret, 1.2)
                             or {}).get("providers") or {}
            except Exception:
                providers = {}
        cands = []
        for name, p in (providers or {}).items():
            info = p.get("subscriptionInfo") or {}
            upd = self._ts(p.get("updatedAt") or p.get("T"))
            if info or upd or str(p.get("vehicleType", "")).upper() == "HTTP":
                cands.append((upd, name, info))
        if cands:
            cands.sort(key=lambda x: -x[0])
            upd, name, info = cands[0]
            c.sub = {
                "kind": "provider", "name": name, "updated": upd,
                "used": info.get("Upload") or info.get("upload") or 0,
                "total": info.get("Total") or info.get("total") or 0,
                "expire": self._ts(info.get("Expire") or info.get("expire")),
            }
            return
        if c.conf_mtime:
            c.sub = {"kind": "file", "name": os.path.basename(c.config),
                     "updated": c.updated or c.conf_mtime, "used": 0, "total": 0, "expire": 0}

    # -- 主入口
    def tick(self, force: bool = False) -> Client:
        with self._lock:
            if not force and time.time() - self._last_tick < 8:
                return self.client
            self._last_tick = time.time()
            c = self.client
            c.api, ver = self._probe() if (force or not c.api or not self._alive(c)) else (c.api, {})
            if ver:
                c.version = str(ver.get("version") or "")
                c.meta = bool(ver.get("meta"))
            table = self._table(force)
            if c.api:
                pid = self._ports().get(int(c.api.rsplit(":", 1)[1]), 0)
                if pid and pid != c.pid:
                    c.pid = pid
                    info = table.get(pid) or {}
                    c.exe = info.get("path", "")
                    name, core, core_stem = self._display(pid, table)
                    exe_stem = _stem(info.get("name", ""))
                    # 没见过的客户端：直接拿它自己的 exe 名当展示名，总比"未知"有用
                    c.name = name or core_stem or exe_stem or "未知客户端"
                    c.core = core or exe_stem
                    c.kind = KIND.get(core_stem or exe_stem, "clash")
                    c.config, c.data_dir = _conf_from_cmd(info.get("cmd", ""))
                try:
                    cfg = _http_json(c.api, "/configs", c.secret, 1.0)
                    c.mode = str(cfg.get("mode") or "")
                except Exception:
                    pass
            else:
                self._fallback(c, table)
                self._xray(c, table)
                # 进程真没了就别把上一秒的名字挂在面板上冒充"客户端还开着"：
                # 没有控制器、没有统计口、连 pid 都不在进程表里 —— 当它没跑
                if not c.api and not c.metrics and not (c.pid and table.get(c.pid)):
                    self._clear(c)
            if c.config and c.flow != "xray":
                self._nodes(c)
            self._sub(c)
            return c

    def _clear(self, c: Client):
        """客户端真的退出了：把身份清干净，让面板回到"没客户端"的本机模式

        不清会怎样：关掉软件后 pid、名字、kind 还留着，面板继续按 Clash 的路径去问
        一个已经不存在的控制器，然后把这当成"隧道异常"红着不动 —— 用户看到的就是
        "VPN 都关了，怎么还在报隧道坏"。
        """
        c.kind, c.name, c.core, c.version = "none", "", "", ""
        c.api, c.secret, c.config, c.data_dir, c.exe = "", "", "", "", ""
        c.pid, c.mode, c.nodes, c.nodes_hash = 0, "", 0, ""
        c.updated, c.sub, c.proxies = 0.0, {}, {}
        c.meta, c.conf_mtime, c.metrics, c.local_proxy, c.flow = False, 0.0, "", "", ""

    def _alive(self, c: Client) -> bool:
        if not c.api:
            return False
        try:
            _http_json(c.api, "/version", c.secret, 0.6)
            return True
        except Exception:
            return False

    def _fallback(self, c: Client, table: dict[int, dict]):
        """没有可用的控制器：退到进程 + 网卡层面，至少说出"谁在挂着"

        认不出的客户端不装懂：拿它自己的 exe 名当展示名，
        这样哪怕是个没见过的软件（比如只叫 proxy.exe），也不会显示成"未知"。
        """
        loose = None
        for pid, info in table.items():
            st = _stem(info.get("name", ""))
            if not st:
                continue
            if st in DISPLAY and st not in ("mihomo", "sing-box", "v2ray", "xray"):
                c.kind = KIND.get(st, "other")
                c.name = DISPLAY[st]
                c.core = st
                c.pid = pid
                c.exe = info.get("path", "")
                c.config, c.data_dir = _conf_from_cmd(info.get("cmd", ""))
                return
            if not loose and re.search(r"proxy|vpn|tunnel", st):
                loose = (pid, st, info)
        if loose:
            pid, st, info = loose
            c.kind = "other"
            c.name = st
            c.core = st
            c.pid = pid
            c.exe = info.get("path", "")
            c.config, c.data_dir = _conf_from_cmd(info.get("cmd", ""))

    # -- Xray 系（v2rayN / Xray-core）
    def _xray(self, c: Client, table: dict[int, dict]):
        """没有 Clash API 的客户端：读它自己生成的 config.json

        v2rayN 每次切节点都会重写这份文件，所以"当前用哪个节点"就在里面；
        需要时连 guiNDB.db 把节点备注（软件里的叫法）也捞出来。
        """
        path = c.config if (c.config and os.path.exists(c.config)) else ""
        if not path:
            base = os.path.dirname(c.exe or "")
            for cand in (os.path.join(base, "guiConfigs", "config.json"),
                         os.path.join(base, "config.json")):
                if os.path.exists(cand):
                    path = cand
                    break
        if not path:
            return
        info = parse_xray_config(_read(path) or "")
        if not info or not info.get("server"):
            return
        try:
            mtime = os.path.getmtime(path)
        except Exception:
            mtime = 0.0
        c.config = path
        c.conf_mtime = mtime
        if mtime != self._cfg_at:
            self._cfg_at = mtime
            c.updated = mtime
        c.local_proxy = info["local"] or c.local_proxy
        c.metrics = info["metrics"] or c.metrics
        if c.metrics:
            c.flow = "xray"
            c.kind = c.kind if c.kind not in ("none", "other") else "xray"
        tag = info["proxy_tag"] or "proxy"
        node = {"name": tag, "server": info["server"], "port": info["port"], "type": info["type"]}
        self._remarks(c, node)          # 查得到备注时会顺带数出节点总数
        c.proxies = {tag: node}
        c.nodes = max(int(c.nodes or 0), 1)     # 别把库里的总数盖成 1

    def _remarks(self, c: Client, node: dict):
        """v2rayN 的节点备注存在 guiNDB.db（SQLite）里，按 地址+端口 反查

        库里结构随版本变过，所以不假设表名/列名：只认"同时有 remarks、address 的列"。
        查不到就当没有；读库 2 分钟一次，绝不因为解析失败拖慢主循环。
        """
        if not self._db_at or time.time() - self._db_at > 120:
            self._db_at = time.time()
            # v2rayN 把节点备注放在 guiNDB.db，而 config.json 在 guiConfigs\ 里 ——
            # 只查 config 所在目录永远查不到，得往上找一级、再看 exe 目录
            dirs = []
            for d in (os.path.dirname(c.config or ""), os.path.dirname(c.exe or ""),
                      os.path.dirname(os.path.dirname(c.config or "")),
                      os.path.join(os.environ.get("APPDATA", ""), "v2rayN")):
                if d and d not in dirs:
                    dirs.append(d)
            self._db_rows = []
            for d in dirs:
                self._db_rows = self._read_db(os.path.join(d, "guiNDB.db"))
                if self._db_rows:
                    break
        rows = self._db_rows
        if not rows:
            return
        c.nodes = len(rows)                      # 软件里一共多少个节点
        want = str(node.get("server") or "").lower()
        port = int(node.get("port") or 0)
        for rem, addr, prt in rows:
            if str(addr or "").lower() != want:
                continue
            if port and prt and int(prt) != port:
                continue
            if rem:
                node["name"] = str(rem)
                return

    @staticmethod
    def _read_db(db: str) -> list:
        if not db or not os.path.exists(db):
            return []
        try:
            import sqlite3
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=1.0)
        except Exception:
            return []
        try:
            con.execute("PRAGMA query_only=ON")
            cur = con.cursor()
            for (t,) in cur.execute(
                    "select name from sqlite_master where type='table'").fetchall():
                try:
                    cols = [str(r[1]).lower() for r in cur.execute(f'pragma table_info("{t}")')]
                except Exception:
                    continue
                if "remarks" in cols and "address" in cols:
                    sel = "remarks,address" + (",port" if "port" in cols else ",0")
                    rows = cur.execute(f'select {sel} from "{t}"').fetchall()
                    if rows:
                        return rows
            return []
        except Exception:
            return []
        finally:
            try:
                con.close()
            except Exception:
                pass

    def xray_stats(self) -> dict:
        """Xray 的统计口：GET /debug/vars → 每个 outbound 的累计上下行字节

        返回 {tag: (上行字节, 下行字节)}；proxy / direct 两个 tag 正好就是
        "走没走代理"的字节级拆分。
        """
        c = self.client
        if not c.metrics:
            return {}
        try:
            js = _http_json(c.metrics, "/debug/vars", "", 1.0)
        except Exception:
            return {}
        out: dict[str, tuple[int, int]] = {}
        for tag, d in ((js or {}).get("stats") or {}).get("outbound", {}).items():
            if isinstance(d, dict):
                out[str(tag)] = (int(d.get("uplink") or 0), int(d.get("downlink") or 0))
        return out

    # -- 给节点名做的兜底：拿出口 IP 反查配置里的 server
    def match_exit(self, exit_ip: str) -> dict:
        c = self.client
        if not exit_ip or not c.proxies:
            return {}
        for p in c.proxies.values():
            if p.get("server") == exit_ip:
                return p
        # server 是域名时再解析一批：每次最多解析 _DNS_MAX 个、按 _dns_rot 轮着来，
        # 免得一次 tick 里对着几十个机场域名挨个 getaddrinfo 把线程卡住
        items = [(k, p) for k, p in (c.proxies or {}).items()
                 if isinstance(p, dict) and p.get("server")]
        if not items:
            return {}
        start = self._dns_rot % len(items)
        fresh = 0
        now = time.time()
        for i in range(len(items)):
            _, p = items[(start + i) % len(items)]
            srv = str(p.get("server") or "")
            if not srv or re.fullmatch(r"[\d.:]+", srv):
                continue
            hit = self._dns.get(srv)
            stale = (not hit or now - hit[1] >= (self._DNS_OK if hit[0] else self._DNS_FAIL))
            if stale:
                fresh += 1
                if fresh > self._DNS_MAX:
                    break
                hit = (self._resolve(srv, p.get("port") or 443), now)
            if hit[0] and hit[0] == exit_ip:
                return p
        self._dns_rot = start + self._DNS_MAX
        return {}

    def _resolve(self, host: str, port: int) -> str:
        """域名 → IP。成功缓 10 分钟、失败只缓 2 分钟：机场节点轮换后不能一直用旧答案"""
        now = time.time()
        hit = self._dns.get(host)
        if hit:
            ip, at = hit
            if now - at < (self._DNS_OK if ip else self._DNS_FAIL):
                return ip
        try:
            ip = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        except Exception:
            ip = ""
        self._dns[host] = (ip, now)
        return ip


def preview(client: Client) -> dict:
    return client.pack()


# ── Xray 系（v2rayN / Xray-core）─────────────────────────────────────────
# v2rayN 没有 Clash 那种连接表，但它做了一件很有用的事：为了让界面显示实时速率，
# 它在生成的 config.json 里开了 stats + metrics（见 ServiceLib/.../V2rayStatisticService.cs），
# metrics 监听 127.0.0.1:<port>，GET /debug/vars 回一份 JSON，
# 里面有按 outbound tag 累计的上下行字节（app/metrics/metrics.go）。
# 于是"走直连还是走代理"在这类客户端上也能精确到字节，只是拆不到域名。
SKIP_TAGS = {"direct", "block", "api", "metrics", "dns", "freedom", "blackhole"}


def parse_xray_config(text: str) -> dict:
    """从 Xray 配置里抠出：统计端口、本地代理端口、当前节点、出口地址。

    v2rayN 每切一次节点就重写这份配置，所以它本身就是"现在用的是哪个"的真相。
    """
    try:
        j = json.loads(text)
    except Exception:
        return {}
    if not isinstance(j, dict) or "outbounds" not in j:
        return {}
    out = {"metrics": "", "local": "", "proxy_tag": "", "server": "", "port": 0, "type": ""}
    m = (j.get("metrics") or {}).get("listen") or ""
    if m:
        out["metrics"] = m if ":" in m else f"127.0.0.1:{m}"
    for ib in j.get("inbounds") or []:
        proto = str(ib.get("protocol") or "").lower()
        if proto in ("mixed", "socks", "http") and ib.get("port"):
            listen = str(ib.get("listen") or "127.0.0.1")
            if listen in ("127.0.0.1", "0.0.0.0", "localhost", "::", ""):
                out["local"] = f"127.0.0.1:{ib['port']}"
                break
    # 有多个带地址的 outbound 时，信路由表：末条规则（MATCH）指向哪个 tag，就用哪个
    cands: dict[str, dict] = {}
    for ob in j.get("outbounds") or []:
        if not isinstance(ob, dict):
            continue
        tag = str(ob.get("tag") or "")
        proto = str(ob.get("protocol") or "").lower()
        if proto in ("freedom", "blackhole", "dns") or tag.lower() in SKIP_TAGS:
            continue
        st = ob.get("settings") or {}
        if not isinstance(st, dict):
            continue
        arr = st.get("vnext") or st.get("servers") or []
        if not arr or not isinstance(arr[0], dict):
            continue
        srv = str(arr[0].get("address") or "")
        if not srv:
            continue
        cands[tag or "proxy"] = {"server": srv, "port": int(arr[0].get("port") or 0),
                                 "type": proto.upper()}
    if cands:
        want = ""
        for r in reversed((j.get("routing") or {}).get("rules") or []):
            if isinstance(r, dict) and r.get("outboundTag"):
                want = str(r["outboundTag"])
                break
        tag = want if want in cands else next(iter(cands))
        out.update(cands[tag])
        out["proxy_tag"] = tag
    return out

