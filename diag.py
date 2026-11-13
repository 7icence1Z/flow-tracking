"""链路诊断的底层探针（标准库，Windows 优先）

它的活儿只有三件，但都是"到底哪一跳坏了"所必需的：

  1. 把异常翻译成人话     连不上到底是 DNS 没解析，还是 TCP 被重置，还是 TLS 证书不对
  2. 单独问某一块网卡     绑定源地址去连，Wi-Fi 和有线各自通不通互不干扰
  3. 把链路拆成几层       网关（物理链路）→ DNS（名字）→ TCP（端口）→ TLS（内容）

全部只读、只发探测包，不改任何系统状态。
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import errno
import os
import socket
import struct
import subprocess
import sys
import time

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# ── 错误分类 ────────────────────────────────────────────────
# kind 是给程序用的判别码，text 是给面板显示的中文
KINDS = {
    "dns": "DNS 解析失败",
    "refused": "连接被拒绝",
    "reset": "连接被重置",
    "timeout": "超时",
    "unreach": "网络不可达",
    "tls": "TLS 握手/证书错误",
    "http": "HTTP 错误",
    "bind": "绑不上这块网卡",
    "offline": "本机没有网络",
    "unknown": "未知错误",
}


KINDS_EN = {
    "dns": "DNS resolution failure",
    "refused": "Connection refused",
    "reset": "Connection reset",
    "timeout": "Timed out",
    "unreach": "Network unreachable",
    "tls": "TLS handshake / certificate error",
    "http": "HTTP error",
    "bind": "Cannot bind this interface",
    "offline": "No network on this machine",
    "unknown": "Unknown error",
}


def _winerr(e: BaseException) -> int:
    return getattr(e, "winerror", 0) or getattr(e, "errno", 0) or 0


def classify(exc: BaseException) -> str:
    """把异常归到 KINDS 里的某一类；宁可按"未知"处理也不瞎猜"""
    if exc is None:
        return "unknown"
    # HTTPError 自带 code，先认它，别被 reason 带偏
    if getattr(exc, "code", 0):
        return "http"
    # URLError 把真正的病因包在 .reason 里，剥一层再判
    reason = getattr(exc, "reason", None)
    if isinstance(reason, BaseException) and reason is not exc:
        return classify(reason)
    if isinstance(exc, socket.gaierror):
        return "dns"
    if isinstance(exc, socket.timeout) or isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return "reset"
    code = _winerr(exc)
    if code in (11001,):                                   # WSAHOST_NOT_FOUND
        return "dns"
    if code in (10061,):                                   # WSAECONNREFUSED
        return "refused"
    if code in (10054, 10053):                             # WSAECONNRESET / ABORTED
        return "reset"
    if code in (10060, 110, 10035):                        # WSAETIMEDOUT
        return "timeout"
    if code in (10051, 10065, 10050):                      # NETUNREACH / HOSTUNREACH
        return "unreach"
    if code in (10013,):                                   # WSAEACCES（源地址绑不上）
        return "bind"
    if code in (10038, 10049, 10047):                       # 本地地址不可用
        return "bind"
    name = type(exc).__name__
    if "SSL" in name or "Certificate" in name:
        return "tls"
    if "HTTPError" in name:
        return "http"
    msg = str(exc).lower()
    if "getaddrinfo" in msg or "name resolution" in msg or "no such host" in msg:
        return "dns"
    if "certificate" in msg or "ssl" in msg:
        return "tls"
    if "timed out" in msg:
        return "timeout"
    if "refused" in msg:
        return "refused"
    if "reset" in msg:
        return "reset"
    if "unreachable" in msg or "no route" in msg:
        return "unreach"
    return "unknown"


def label(kind: str, lang: str = "zh") -> str:
    """面板显示用的病因名；lang="en" 给英文版（中文是默认）"""
    src = KINDS_EN if lang == "en" else KINDS
    return src.get(kind, src["unknown"])


def detail(exc: BaseException, limit: int = 90) -> str:
    """给 tooltip 用的一行原始信息"""
    if exc is None:
        return ""
    reason = getattr(exc, "reason", None)
    text = f"{reason}" if reason is not None else f"{type(exc).__name__}: {exc}"
    text = " ".join(str(text).split())
    return text[:limit]


# ── 1) 网关：链路层到底通不通 ────────────────────────────────
_ICMP_OK = 0
_iphlp = None


class _IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte), ("Flags", ctypes.c_ubyte),
                ("OptionsSize", ctypes.c_ubyte), ("OptionsData", ctypes.c_void_p)]


class _ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [("Address", wt.ULONG), ("Status", wt.ULONG), ("RoundTripTime", wt.ULONG),
                ("DataSize", wt.USHORT), ("Reserved", wt.USHORT), ("Data", ctypes.c_void_p),
                ("Options", _IP_OPTION_INFORMATION)]


def _icmp_modules():
    """iphlpapi 的 ICMP 句柄。第一次用时才加载，探针本身失败也不影响别的"""
    global _iphlp
    if _iphlp is None:
        lib = ctypes.WinDLL("iphlpapi", use_last_error=True)
        lib.IcmpCreateFile.restype = ctypes.c_void_p
        lib.IcmpSendEcho.argtypes = [ctypes.c_void_p, wt.ULONG, ctypes.c_void_p, wt.USHORT,
                                     ctypes.c_void_p, ctypes.c_void_p, wt.DWORD, wt.DWORD]
        _iphlp = lib
    return _iphlp


def gateway(gw: str, timeout_ms: int = 900) -> dict:
    """ping 网关。走 iphlpapi 的 IcmpSendEcho：不起 ping.exe，900 ms 的等待不会再乘上进程启动

    以前是 `ping -n 1 -w 900`：一次约 0.5 秒、每 15 秒两个，等于常驻一个"谁也没在等"的进程。
    ICMP 回得比进程快得多，结论（通 / 不通 / 不可达）完全一样。
    """
    if not gw:
        return {"ok": False, "ms": 0, "kind": "unknown", "detail": "没有网关地址"}
    t0 = time.monotonic()
    try:
        lib = _icmp_modules()
        h = lib.IcmpCreateFile()
        if not h or h == ctypes.c_void_p(-1).value:
            raise OSError("IcmpCreateFile 失败")
        try:
            payload = ctypes.create_string_buffer(b"flow-tracking" * 2)
            reply = ctypes.create_string_buffer(ctypes.sizeof(_ICMP_ECHO_REPLY) + 128)
            dst = int.from_bytes(socket.inet_aton(gw), "little")
            n = lib.IcmpSendEcho(h, dst, ctypes.byref(payload), 26, None,
                                 ctypes.byref(reply), len(reply), int(timeout_ms))
            el = round((time.monotonic() - t0) * 1000)
            if not n:
                return {"ok": False, "ms": el, "kind": "unreach",
                        "detail": f"ping {gw} 没有回应"}
            got = ctypes.cast(reply, ctypes.POINTER(_ICMP_ECHO_REPLY)).contents
            if got.Status != _ICMP_OK:                 # 有回包但不是"通了"：不可达 / 被丢弃
                return {"ok": False, "ms": el, "kind": "unreach",
                        "detail": f"ping {gw} 返回状态 {got.Status}"}
            return {"ok": True, "ms": int(got.RoundTripTime) or el, "kind": "", "detail": ""}
        finally:
            lib.IcmpCloseHandle(ctypes.c_void_p(h))
    except Exception:                                          # noqa: BLE001
        return _gateway_ping(gw, timeout_ms)


def _gateway_ping(gw: str, timeout_ms: int = 900) -> dict:
    """兜底：真起一个 ping.exe。只在 ICMP 接口拿不到时用（一般是系统 API 缺失）"""
    t0 = time.monotonic()
    try:
        p = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), gw],
            capture_output=True, timeout=(timeout_ms / 1000) + 2.0,
            creationflags=CREATE_NO_WINDOW,
        )
        ms = round((time.monotonic() - t0) * 1000)
        if p.returncode == 0:
            return {"ok": True, "ms": ms, "kind": "", "detail": ""}
        return {"ok": False, "ms": ms, "kind": "unreach", "detail": f"ping {gw} 没有回应"}
    except Exception as e:                                       # noqa: BLE001
        return {"ok": False, "ms": round((time.monotonic() - t0) * 1000),
                "kind": classify(e), "detail": detail(e)}


# ── 2) 名字：系统解析 vs 直接问公共 DNS ─────────────────────
def resolve(host: str, timeout: float = 2.0) -> dict:
    """系统解析器（受 hosts、DNS 劫持、VPN 的 DNS 影响）"""
    if not host:
        return {"ok": False, "ms": 0, "ips": [], "kind": "dns", "detail": "没有主机名"}
    t0 = time.monotonic()
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        ips = sorted({i[4][0] for i in infos})
        return {"ok": bool(ips), "ms": round((time.monotonic() - t0) * 1000),
                "ips": ips[:4], "kind": "" if ips else "dns", "detail": ""}
    except Exception as e:                                       # noqa: BLE001
        return {"ok": False, "ms": round((time.monotonic() - t0) * 1000),
                "ips": [], "kind": classify(e), "detail": detail(e)}


def _parse_a(buf: bytes) -> list[str]:
    """从 DNS 响应里挑出 A 记录（只认 A / CNAME，够用）"""
    try:
        if len(buf) < 12:
            return []
        qd, an = struct.unpack("!HH", buf[4:8])
        i = 12
        for _ in range(qd):                                      # 跳过问题段
            while i < len(buf) and buf[i]:
                i += 1 + buf[i]
            i += 5
        out = []
        for _ in range(an):
            if i + 12 > len(buf):
                break
            if buf[i] & 0xC0 == 0xC0:                            # 压缩指针
                i += 2
            else:
                while i < len(buf) and buf[i]:
                    i += 1 + buf[i]
                i += 1
            if i + 10 > len(buf):
                break
            rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", buf[i:i + 10])
            i += 10
            if rtype == 1 and rdlen == 4 and i + 4 <= len(buf):
                out.append(".".join(str(b) for b in buf[i:i + 4]))
            i += rdlen
        return out
    except Exception:                                            # noqa: BLE001
        return []


def udp_dns(host: str, server: str = "223.5.5.5", timeout: float = 2.0) -> dict:
    """绕过系统解析器，直接问公共 DNS；用来区分"本地 DNS 坏了"和"域名本身有问题\""""
    t0 = time.monotonic()
    try:
        qid = int(time.time() * 1000) & 0xFFFF
        q = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
        for part in host.split("."):
            b = part.encode("idna")
            q += bytes([len(b)]) + b
        q += b"\x00" + struct.pack("!HH", 1, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(q, (server, 53))
            data, _ = s.recvfrom(1024)
            ips = _parse_a(data)
            return {"ok": bool(ips), "ms": round((time.monotonic() - t0) * 1000),
                    "ips": ips[:4], "kind": "" if ips else "dns", "server": server}
        finally:
            s.close()
    except Exception as e:                                       # noqa: BLE001
        return {"ok": False, "ms": round((time.monotonic() - t0) * 1000),
                "ips": [], "kind": classify(e), "server": server,
                "detail": detail(e)}


# ── 3) 绑定某块网卡去连 ─────────────────────────────────────
def tcp_from(src_ip: str, dst: str, port: int = 443, timeout: float = 2.5) -> dict:
    """把源地址钉死在这块网卡上，测"这块网卡到目标"这一段

    Windows 上带源地址的 connect 会按该地址选路由，所以它测的是这块网卡的真实通路，
    不是"系统默认走哪条就测哪条"。
    """
    t0 = time.monotonic()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if src_ip:
            try:
                s.bind((src_ip, 0))
            except OSError as e:
                return {"ok": False, "ms": round((time.monotonic() - t0) * 1000),
                        "kind": classify(e), "detail": f"绑定 {src_ip} 失败"}
        s.connect((dst, port))
        return {"ok": True, "ms": round((time.monotonic() - t0) * 1000), "kind": "", "detail": ""}
    except Exception as e:                                       # noqa: BLE001
        return {"ok": False, "ms": round((time.monotonic() - t0) * 1000),
                "kind": classify(e), "detail": detail(e)}
    finally:
        try:
            s.close()
        except Exception:                                        # noqa: BLE001
            pass


if __name__ == "__main__":                                        # 手动试一跑
    sys.stdout.reconfigure(encoding="utf-8")
    import json
    host = sys.argv[1] if len(sys.argv) > 1 else "www.baidu.com"
    print(json.dumps({
        "system_dns": resolve(host),
        "public_dns": udp_dns(host),
        "gateway": gateway("192.168.1.1"),
        "tcp_443": tcp_from("", resolve(host)["ips"][0] if resolve(host)["ips"] else host),
    }, ensure_ascii=False, indent=2))
    print("平台:", os.name, "解释器:", sys.version.split()[0])
