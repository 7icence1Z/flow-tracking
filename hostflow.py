"""没有代理客户端时（也就是没开 VPN 的时候），本机流量怎么看

Windows 上不用装任何东西就能拿到两样真东西：

  1. `GetIfTable2`（iphlpapi）：每块网卡的 64 位累计字节
     → 1 Hz 差分就是**真实的 ↓↑ 速率**，TCP / UDP / QUIC / 系统更新全都算在内。

  2. `GetExtendedTcpTable`：所有 TCP 连接（本地/远端地址、PID）
     → 配上进程表就知道"谁在连谁"，能数连接、能看见远端 IP。

拿不到的东西，面板会明说，不编：

  - **逐进程 / 逐域名的字节数**：内核 eStats（`GetPerTcpConnectionEStats`）和 DNS
    缓存（`ipconfig /displaydns`）在普通权限下都是 ERROR_ACCESS_DENIED，
    要管理员才能用。所以**普通权限**的本机模式下只给"连接数"，不给每行的字节速率。
  - **以管理员身份启动时**，eStats 可用：对每条已建立连接开统计、1 Hz 差分，
    就能给出和 VPN 那边一样的每进程 ↓↑ 速率曲线（数据来源见 `estats_*`）。
    这时仍然只有 TCP 净荷字节，UDP/QUIC 只体现在网卡总量里。
  - **进客户端的字节（"客户端入口"）**：客户端不给统计口（v2rayN 关了
    `enableStatistics`、Clash 关了 API）时，系统代理模式下应用是连到客户端的
    本地代理口再出去的 —— 那条回环 TCP 连接上的字节就是"进客户端"的量。
    `proxy_ports` 传进来，对这些"远端=代理口"的连接做同样的 eStats 差分，就得到它。
    **注意它不等于隧道字节**：客户端按规则可能把一部分直接放出去，所以面板只把它
    当"入口"展示，不拿来算经代理/直连。同理只要管理员，且只解释 TCP。
  - 逐域名归属同理：(Windows 的 DNS 缓存也要管理员) 。开了代理客户端时由它的
    控制器提供，那才是面板的强项。

全部是 ctypes 调 Win32，只用标准库。
"""

import ctypes
import ctypes.wintypes as wt
import re
import time

IF_MAX_STRING_SIZE = 256
IF_MAX_PHYS_ADDRESS_LENGTH = 32
IF_TYPE_SOFTWARE_LOOPBACK = 24
IF_TYPE_TUNNEL = 131
IF_OPER_STATUS_UP = 1

# 一块网卡在 IP 栈里会挂好几个过滤驱动（WFP / QoS / MAC Layer Filter），
# 它们的计数器和真网卡一模一样、名字长一截 —— 得排掉
_RE_FAKE_NIC = re.compile(r"(WFP|QoS Packet Scheduler|MAC Layer|Filter-0000)", re.I)


class MIB_IF_ROW2(ctypes.Structure):
    # 字段顺序照 MSDN 抄：In 组在前、Out 组在后（不是 in/out 交替，抄错就差一个 8 字节）
    _fields_ = [
        ("InterfaceLuid", ctypes.c_ulonglong),
        ("InterfaceIndex", wt.ULONG),
        ("InterfaceGuid", ctypes.c_byte * 16),
        ("Alias", wt.WCHAR * (IF_MAX_STRING_SIZE + 1)),
        ("Description", wt.WCHAR * (IF_MAX_STRING_SIZE + 1)),
        ("PhysicalAddressLength", ctypes.c_ulonglong),
        ("PhysicalAddress", ctypes.c_ubyte * IF_MAX_PHYS_ADDRESS_LENGTH),
        ("PermanentPhysicalAddress", ctypes.c_ubyte * IF_MAX_PHYS_ADDRESS_LENGTH),
        ("Mtu", wt.ULONG),
        ("Type", wt.ULONG),
        ("TunnelType", wt.ULONG),
        ("MediaType", wt.ULONG),
        ("PhysicalMediumType", wt.ULONG),
        ("AccessType", wt.ULONG),
        ("DirectionType", wt.ULONG),
        ("InterfaceAndOperStatusFlags", ctypes.c_ubyte),
        ("OperStatus", wt.ULONG),
        ("AdminStatus", wt.ULONG),
        ("MediaConnectState", wt.ULONG),
        ("NetworkGuid", ctypes.c_byte * 16),
        ("ConnectionType", wt.ULONG),
        ("TransmitLinkSpeed", ctypes.c_ulonglong),
        ("ReceiveLinkSpeed", ctypes.c_ulonglong),
        ("InOctets", ctypes.c_ulonglong),
        ("InUcastPkts", ctypes.c_ulonglong),
        ("InNUcastPkts", ctypes.c_ulonglong),
        ("InDiscards", ctypes.c_ulonglong),
        ("InErrors", ctypes.c_ulonglong),
        ("InUnknownProtos", ctypes.c_ulonglong),
        ("InUcastOctets", ctypes.c_ulonglong),
        ("InMulticastOctets", ctypes.c_ulonglong),
        ("InBroadcastOctets", ctypes.c_ulonglong),
        ("OutOctets", ctypes.c_ulonglong),
        ("OutUcastPkts", ctypes.c_ulonglong),
        ("OutNUcastPkts", ctypes.c_ulonglong),
        ("OutDiscards", ctypes.c_ulonglong),
        ("OutErrors", ctypes.c_ulonglong),
        ("OutUcastOctets", ctypes.c_ulonglong),
        ("OutMulticastOctets", ctypes.c_ulonglong),
        ("OutBroadcastOctets", ctypes.c_ulonglong),
        ("OutQLen", ctypes.c_ulonglong),
    ]


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwState", wt.DWORD), ("dwLocalAddr", wt.DWORD), ("dwLocalPort", wt.DWORD),
                ("dwRemoteAddr", wt.DWORD), ("dwRemotePort", wt.DWORD), ("dwOwningPid", wt.DWORD)]


class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
    # 有些客户端只绑 ::1 —— 端口归属必须把 v6 一起算，不然会"看不见监听者"
    _fields_ = [("ucLocalAddr", ctypes.c_ubyte * 16), ("dwLocalScopeId", wt.DWORD),
                ("dwLocalPort", wt.DWORD), ("ucRemoteAddr", ctypes.c_ubyte * 16),
                ("dwRemoteScopeId", wt.DWORD), ("dwRemotePort", wt.DWORD),
                ("dwState", wt.DWORD), ("dwOwningPid", wt.DWORD)]


TCP_TABLE_OWNER_PID_ALL = 5
AF_INET = 2
AF_INET6 = 23
STATE_ESTABLISHED = 5

# eStats：每条 TCP 连接的内核计数器。要管理员权限（普通权限 Set 返回 5 = ACCESS_DENIED）
TCP_ESTATS_DATA = 1


class MIB_TCPROW(ctypes.Structure):
    """eStats 的 key：五元组，和 OWNER_PID 行前五个字段一模一样"""
    _fields_ = [("dwState", wt.DWORD), ("dwLocalAddr", wt.DWORD), ("dwLocalPort", wt.DWORD),
                ("dwRemoteAddr", wt.DWORD), ("dwRemotePort", wt.DWORD)]


class TCP_ESTATS_DATA_RW(ctypes.Structure):
    _fields_ = [("EnableCollection", ctypes.c_ubyte)]


class TCP_ESTATS_DATA_ROD(ctypes.Structure):
    # 顺序照 MSDN：8 字节计数器一簇在前，然后 4 字节的序号，中间夹一个 8 字节累计
    _fields_ = [("DataBytesOut", ctypes.c_ulonglong),
                ("DataSegsOut", ctypes.c_ulonglong),
                ("DataBytesIn", ctypes.c_ulonglong),
                ("DataSegsIn", ctypes.c_ulonglong),
                ("SegsOut", ctypes.c_ulonglong),
                ("SegsIn", ctypes.c_ulonglong),
                ("SoftErrors", wt.ULONG),
                ("SoftErrorReason", wt.ULONG),
                ("SndUna", wt.ULONG),
                ("SndNxt", wt.ULONG),
                ("SndMax", wt.ULONG),
                ("ThruBytesAcked", ctypes.c_ulonglong),
                ("RcvNxt", wt.ULONG),
                ("ThruBytesReceived", ctypes.c_ulonglong)]

_ELEV = None

_IP = None


def _ip():
    global _IP
    if _IP is None:
        _IP = ctypes.WinDLL("iphlpapi", use_last_error=True)
        _IP.GetIfTable2.restype = wt.DWORD
        _IP.GetIfTable2.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        _IP.FreeMibTable.argtypes = [ctypes.c_void_p]
        _IP.SetPerTcpConnectionEStats.restype = wt.DWORD
        _IP.SetPerTcpConnectionEStats.argtypes = [
            ctypes.POINTER(MIB_TCPROW), ctypes.c_int, ctypes.c_void_p, wt.ULONG, wt.ULONG, wt.ULONG]
        _IP.GetPerTcpConnectionEStats.restype = wt.DWORD
        _IP.GetPerTcpConnectionEStats.argtypes = [
            ctypes.POINTER(MIB_TCPROW), ctypes.c_int,
            ctypes.c_void_p, wt.ULONG, wt.ULONG,
            ctypes.c_void_p, wt.ULONG, wt.ULONG,
            ctypes.c_void_p, wt.ULONG, wt.ULONG]
    return _IP


def elevated() -> bool:
    """是不是以管理员身份在跑 —— eStats 与 DNS 缓存的分水岭"""
    global _ELEV
    if _ELEV is None:
        try:
            _ELEV = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            _ELEV = False
    return _ELEV


def _row(c: dict) -> MIB_TCPROW:
    # 结构里的地址/端口字段就是网络字节序，原样塞回去（tcp_conns 里存了 raw）
    return MIB_TCPROW(c["state"], c["laddr"], c["lportn"], c["raddr"], c["rportn"])


def estats_on(c: dict) -> int:
    """给一条连接开统计。0 = 成功；5 = 没权限（普通权限就是这个）"""
    rw = TCP_ESTATS_DATA_RW(1)
    return _ip().SetPerTcpConnectionEStats(
        ctypes.byref(_row(c)), TCP_ESTATS_DATA, ctypes.byref(rw), 0, ctypes.sizeof(rw), 0)


def estats_bytes(c: dict):
    """(发出去, 收到) 的字节数；没开统计 / 连接已关返回 None"""
    rod = TCP_ESTATS_DATA_ROD()
    rc = _ip().GetPerTcpConnectionEStats(
        ctypes.byref(_row(c)), TCP_ESTATS_DATA, None, 0, 0, None, 0, 0,
        ctypes.byref(rod), 0, ctypes.sizeof(rod))
    if rc:
        return None
    return int(rod.DataBytesOut), int(rod.DataBytesIn)


_NAMES: dict[int, tuple[str, str]] = {}     # idx → (网卡名, 描述)，见 if_table
_NAMES_AT = 0.0


def if_table():
    """每块网卡的累计字节。name 就是 netsh 里那个网卡名（以太网 2 / WLAN）

    名字（Alias/Description）是宽字符串，逐行读一次要几十微秒；而这一帧真正会变的
    只有计数器。所以名字按网卡号缓存，半分钟对一次账（改名、插拔都还能跟上），
    每帧只读 ULONG 字段 —— 一帧的耗时从这里的大头变成零头。
    """
    global _NAMES_AT
    ip = _ip()
    p = ctypes.c_void_p()
    if ip.GetIfTable2(ctypes.byref(p)):
        return []
    try:
        n = ctypes.cast(p, ctypes.POINTER(wt.ULONG))[0]
        base = p.value + 8          # MIB_IF_TABLE2 = {ULONG NumEntries; ROW2 Table[]}，行按 8 字节对齐
        sz = ctypes.sizeof(MIB_IF_ROW2)
        now = time.monotonic()
        fresh = now - _NAMES_AT > 30
        out = []
        for i in range(n):
            r = MIB_IF_ROW2.from_address(base + i * sz)
            idx = r.InterfaceIndex
            nm = _NAMES.get(idx)
            if nm is None or fresh:
                nm = _NAMES[idx] = (r.Alias, r.Description)
            out.append({"name": nm[0], "idx": idx, "type": r.Type,
                        "oper": r.OperStatus, "media": r.MediaConnectState,
                        "in": r.InOctets, "out": r.OutOctets,
                        "desc": nm[1]})
        if fresh:
            _NAMES_AT = now
            live = {e["idx"] for e in out}
            for k in [k for k in _NAMES if k not in live]:
                _NAMES.pop(k, None)
        return out
    finally:
        ip.FreeMibTable(p)


class _SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [("lpSockaddr", ctypes.c_void_p), ("iSockaddrLength", ctypes.c_int)]


class _ADAPTER_ADDRESS(ctypes.Structure):
    # IP_ADAPTER_UNICAST_ADDRESS 与 IP_ADAPTER_GATEWAY_ADDRESS 的头三段布局一样
    _fields_ = [("Header", ctypes.c_ulonglong), ("Next", ctypes.c_void_p),
                ("Address", _SOCKET_ADDRESS)]


class _ADAPTER_ADDRESSES(ctypes.Structure):
    # 只抄到 Ipv6Metric：后面那堆字段用不上，抄多了容易错位（8 字节对齐）
    _fields_ = [("Header", ctypes.c_ulonglong),          # {Length, IfIndex}
                ("Next", ctypes.c_void_p),
                ("AdapterName", ctypes.c_char_p),
                ("FirstUnicastAddress", ctypes.c_void_p),
                ("FirstAnycastAddress", ctypes.c_void_p),
                ("FirstMulticastAddress", ctypes.c_void_p),
                ("FirstDnsServerAddress", ctypes.c_void_p),
                ("DnsSuffix", wt.LPWSTR),
                ("Description", wt.LPWSTR),
                ("FriendlyName", wt.LPWSTR),
                ("PhysicalAddress", ctypes.c_ubyte * 8),
                ("PhysicalAddressLength", wt.ULONG),
                ("Flags", wt.ULONG),
                ("Mtu", wt.ULONG),
                ("IfType", wt.ULONG),
                ("OperStatus", wt.ULONG),
                ("Ipv6IfIndex", wt.ULONG),
                ("ZoneIndices", wt.ULONG * 16),
                ("FirstPrefix", ctypes.c_void_p),
                ("TransmitLinkSpeed", ctypes.c_ulonglong),
                ("ReceiveLinkSpeed", ctypes.c_ulonglong),
                ("FirstWinsServerAddress", ctypes.c_void_p),
                ("FirstGatewayAddress", ctypes.c_void_p),
                ("Ipv4Metric", wt.ULONG),
                ("Ipv6Metric", wt.ULONG)]


def _sock_ip(p) -> str:
    """SOCKET_ADDRESS（sockaddr_in）→ 点分 IPv4。不是 v4 就返回空串"""
    if not p:
        return ""
    sa = ctypes.cast(p, ctypes.POINTER(wt.USHORT * 2)).contents
    if sa[0] != AF_INET:
        return ""
    raw = ctypes.string_at(p + 4, 4)
    return ".".join(str(b) for b in raw)


def adapters() -> dict[str, dict]:
    """网卡名 → {ip, gateway, metric}。GetAdaptersAddresses 直读。

    以前这两个数是 `netsh interface ipv4 show addresses` 的输出，每 20 秒起一个进程、
    还要认本地化的字段名（"IP 地址" / "IP Address"）。内核里同样有，且不分语言。
    """
    ip = _ip()
    ip.GetAdaptersAddresses.restype = wt.ULONG
    ip.GetAdaptersAddresses.argtypes = [wt.ULONG, wt.ULONG, ctypes.c_void_p,
                                        ctypes.c_void_p, ctypes.POINTER(wt.ULONG)]
    size = wt.ULONG(16 * 1024)
    GAA_FLAG_INCLUDE_GATEWAYS = 0x0080
    buf = None
    for _ in range(3):
        buf = ctypes.create_string_buffer(size.value)
        rc = ip.GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, None,
                                     buf, ctypes.byref(size))
        if rc == 0:                                    # NO_ERROR
            break
        if rc != 111:                                  # ERROR_BUFFER_OVERFLOW
            return {}
    else:
        return {}
    out: dict[str, dict] = {}
    p = ctypes.cast(buf, ctypes.POINTER(_ADAPTER_ADDRESSES))
    while p:
        a = p.contents
        name = a.FriendlyName or ""
        u = ctypes.cast(a.FirstUnicastAddress, ctypes.POINTER(_ADAPTER_ADDRESS))
        addr = ""
        while u:
            cand = _sock_ip(u.contents.Address.lpSockaddr)
            if cand:
                addr = cand
                if not cand.startswith("169.254."):
                    break
            if not u.contents.Next:
                break
            u = ctypes.cast(u.contents.Next, ctypes.POINTER(_ADAPTER_ADDRESS))
        g = ctypes.cast(a.FirstGatewayAddress, ctypes.POINTER(_ADAPTER_ADDRESS))
        gw = _sock_ip(g.contents.Address.lpSockaddr) if g else ""
        if name and addr:
            out[name] = {"ip": addr, "gateway": gw, "metric": str(a.Ipv4Metric)}
        p = ctypes.cast(a.Next, ctypes.POINTER(_ADAPTER_ADDRESSES))
    return out


def tcp_conns():
    """TCP 连接表（含 PID）。端口在结构里是网络字节序，这里翻成本机序"""
    ip = _ip()
    size = wt.ULONG(0)
    ip.GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    if not size.value:
        return []
    buf = ctypes.create_string_buffer(size.value)
    if ip.GetExtendedTcpTable(ctypes.byref(buf), ctypes.byref(size), False, AF_INET,
                              TCP_TABLE_OWNER_PID_ALL, 0):
        return []
    n = ctypes.cast(buf, ctypes.POINTER(wt.ULONG))[0]
    base = ctypes.addressof(buf) + ctypes.sizeof(wt.ULONG)
    sz = ctypes.sizeof(MIB_TCPROW_OWNER_PID)
    out = []
    for i in range(n):
        r = MIB_TCPROW_OWNER_PID.from_address(base + i * sz)
        if not r.dwRemoteAddr:
            continue
        out.append({"state": r.dwState,
                    "lip": a2s(r.dwLocalAddr), "lport": ntohs(r.dwLocalPort),
                    "rip": a2s(r.dwRemoteAddr), "rport": ntohs(r.dwRemotePort),
                    "pid": r.dwOwningPid,
                    # eStats 要拿原始 DWORD 当 key（网络字节序，别翻）
                    "laddr": r.dwLocalAddr, "lportn": r.dwLocalPort,
                    "raddr": r.dwRemoteAddr, "rportn": r.dwRemotePort})
    return out


def tcp_all():
    """TCP 表全部行，连"只听不连"的也算；v4 + v6。端口归属靠它，别用 netstat 起进程"""
    ip = _ip()
    out = []
    for family, row, sz in ((AF_INET, MIB_TCPROW_OWNER_PID, ctypes.sizeof(MIB_TCPROW_OWNER_PID)),
                            (AF_INET6, MIB_TCP6ROW_OWNER_PID, ctypes.sizeof(MIB_TCP6ROW_OWNER_PID))):
        size = wt.ULONG(0)
        ip.GetExtendedTcpTable(None, ctypes.byref(size), False, family, TCP_TABLE_OWNER_PID_ALL, 0)
        if not size.value:
            continue
        buf = ctypes.create_string_buffer(size.value)
        if ip.GetExtendedTcpTable(ctypes.byref(buf), ctypes.byref(size), False, family,
                                  TCP_TABLE_OWNER_PID_ALL, 0):
            continue
        n = ctypes.cast(buf, ctypes.POINTER(wt.ULONG))[0]
        base = ctypes.addressof(buf) + ctypes.sizeof(wt.ULONG)
        for i in range(n):
            r = row.from_address(base + i * sz)
            out.append({"state": r.dwState, "lport": ntohs(r.dwLocalPort),
                        "pid": r.dwOwningPid})
    return out


_A2S: dict[int, str] = {}


def a2s(a):
    """地址 → 点分字符串。同一秒里几百条连接只有几十个不同的地址，别重复拼"""
    s = _A2S.get(a)
    if s is None:
        if len(_A2S) > 4096:
            _A2S.clear()
        s = _A2S[a] = ".".join(str((a >> sh) & 0xFF) for sh in (0, 8, 16, 24))
    return s


def ntohs(p):
    return ((p & 0xFF) << 8) | ((p >> 8) & 0xFF)


def pick_nic(nics, name=""):
    """优先按名字找（直连泳道用的那块）；找不到就挑当前流量最大的物理网卡"""
    if name:
        for n in nics:
            if n["name"] == name:
                return n
    cand = [n for n in nics if n["oper"] == IF_OPER_STATUS_UP
            and n["type"] not in (IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL)
            and not _RE_FAKE_NIC.search(n["name"])]
    if not cand:
        return None
    return max(cand, key=lambda n: n["in"] + n["out"])


class HostFlow:
    """本机模式：网卡总量 + 谁在连谁。1 Hz 采样，不碰任何网络

    管理员权限下再上一层：给每条已建立连接开 eStats，差分出**每进程的 ↓↑ 速率**，
    这样本机模式的"进程"表和 VPN 那边的"站点"表长得一样（有曲线、有速率）；
    普通权限下 eStats 会回 ERROR_ACCESS_DENIED，就安静地退回"只数连接"。
    """

    MAX_ROWS = 6

    def __init__(self, nic_name="", proc_fn=None):
        self.nic_name = nic_name
        self.proc_fn = proc_fn          # () -> {pid: {name, ...}}
        self.procs = {}
        self.procs_ts = 0.0
        self.ts = 0.0
        self.base = {}
        self.cum = {"down": 0.0, "up": 0.0}
        self.ema = {}
        self.last = {"down": 0.0, "up": 0.0, "conns": 0, "nic": ""}
        # eStats（每进程字节）：只在管理员下可用，失败一次就认命，不再重试
        self.estats = elevated()
        self._estats_cum = {}           # 进程名 → [收, 发] 累计
        self._enabled = set()           # 已开统计的连接 key
        self._prev = {}                 # key → (发, 收)
        self._live = set()              # 这一秒还在的连接 key（用来清掉关掉的）
        self._eema = {}                 # 进程名 → [↓, ↑] 速率（带一点平滑）
        # 经代理：系统代理模式下，应用是连到客户端的本地代理口（回环）再出去的，
        # 那条回环连接上的字节就是隧道字节 —— 不用客户端开统计口也能数（要管理员）
        self.proxy_ports = set()        # 本地代理口（10808/10809/7890 …）
        self._pxema = [0.0, 0.0]        # 经代理 ↓↑ 速率（平滑）
        self._proxy_cum = {"down": 0.0, "up": 0.0}

    def _refresh_procs(self, now):
        if self.proc_fn and now - self.procs_ts > 8:
            try:
                self.procs = self.proc_fn() or {}
            except Exception:
                self.procs = {}
            self.procs_ts = now

    def _name(self, pid):
        info = self.procs.get(pid)
        if isinstance(info, dict):
            return (info.get("name") or f"pid {pid}").strip() or f"pid {pid}"
        if isinstance(info, str) and info:
            return info
        return f"pid {pid}"

    def sample(self, dt_min=0.05, want_procs=False, proxy_ports=None):
        now = time.time()
        dt = max(dt_min, now - self.ts if self.ts else 1.0)
        self.ts = now
        if proxy_ports is not None:
            try:
                self.proxy_ports = {int(p) for p in proxy_ports}
            except Exception:              # noqa: BLE001
                self.proxy_ports = set()
        if want_procs:
            self._refresh_procs(now)

        nics = if_table()
        nic = pick_nic(nics, self.nic_name)
        down = up = 0.0
        if nic:
            prev = self.base.get(nic["name"])
            if prev:
                d_in = nic["in"] - prev[0]
                d_out = nic["out"] - prev[1]
                # 计数器被重置 / 网卡重连：当成 0，别给一个天文数字
                down = (d_in / dt) if d_in >= 0 else 0.0
                up = (d_out / dt) if d_out >= 0 else 0.0
            self.base[nic["name"]] = (nic["in"], nic["out"])
            self.last["nic"] = nic["name"]
        self.cum["down"] += down * dt
        self.cum["up"] += up * dt

        conns = tcp_conns()
        self._live = set()
        # 回环连接（127.x）是本机进程间通信，不是"流量"，别让它霸榜
        established = [c for c in conns
                       if c["state"] == STATE_ESTABLISHED and not c["rip"].startswith("127.")]
        # 但回环里有一类恰恰是流量：应用 → 客户端本地代理口（10809 之类）。
        # 系统代理模式下，隧道里的字节全从这些连接上过，数它们就等于数隧道。
        # 只认"远端是代理口"那一侧的行：同一条连接在表里有两行，代理那一侧的
        # 远端是随机临时端口，不会混进来。
        pconns = [c for c in conns
                  if self.proxy_ports and c["state"] == STATE_ESTABLISHED
                  and c["rip"].startswith("127.") and c["rport"] in self.proxy_ports]
        pper = {}                       # 经代理：PID → {down, up} 速率
        if self.estats and pconns:
            self._rates(pconns, pper, dt)
        pxrate = [sum(e["down"] for e in pper.values()),
                  sum(e["up"] for e in pper.values())]
        rows = []
        if want_procs:
            per = {}
            for c in established:
                e = per.setdefault(c["pid"], {"n": 0, "remotes": set(), "down": 0.0, "up": 0.0,
                                              "px_down": 0.0, "px_up": 0.0})
                e["n"] += 1
                e["remotes"].add(c["rip"])
            for c in pconns:            # 经代理的连接也算它的连接数，只是远端都在本机
                e = per.setdefault(c["pid"], {"n": 0, "remotes": set(), "down": 0.0, "up": 0.0,
                                              "px_down": 0.0, "px_up": 0.0})
                e["n"] += 1
                e["remotes"].add(c["rip"])
            if self.estats:
                self._rates(established, per, dt)
            # 把经代理的字节并进这个进程自己的行：浏览器的 ↓↑ 就是它真正收发的量，
            # 不能因为"走的是回环"就当成 0（px_* 留一份，用来判断这行主要走哪边）
            for pid, e in pper.items():
                t = per.get(pid)
                if t:
                    t["px_down"] += e["down"]
                    t["px_up"] += e["up"]
                    t["down"] += e["down"]
                    t["up"] += e["up"]
            for pid, e in per.items():
                nm = self._name(pid)
                rows.append({"name": nm, "pid": pid, "conns": e["n"],
                             "remotes": len(e["remotes"]),
                             "sample": sorted(e["remotes"])[0] if e["remotes"] else "",
                             "down": e["down"], "up": e["up"],
                             "px_down": e["px_down"], "px_up": e["px_up"]})
            # 同名进程（浏览器多进程）合并
            merged = {}
            for r in rows:
                m = merged.setdefault(r["name"], {"name": r["name"], "pid": r["pid"], "conns": 0,
                                                  "remotes": 0, "sample": r["sample"],
                                                  "down": 0.0, "up": 0.0,
                                                  "px_down": 0.0, "px_up": 0.0})
                m["conns"] += r["conns"]
                m["remotes"] += r["remotes"]
                m["down"] += r["down"]
                m["up"] += r["up"]
                m["px_down"] += r["px_down"]
                m["px_up"] += r["px_up"]
            for nm, m in merged.items():
                e = self._eema.setdefault(nm, [0.0, 0.0])
                e[0] = e[0] * 0.4 + m["down"] * 0.6
                e[1] = e[1] * 0.4 + m["up"] * 0.6
                m["down"], m["up"] = e[0], e[1]
                c = self._estats_cum.setdefault(nm, [0.0, 0.0])
                c[0] += m["down"] * dt
                c[1] += m["up"] * dt
                m["cum_down"], m["cum_up"] = c[0], c[1]
            for nm in list(self._eema):
                if nm not in merged:
                    self._eema.pop(nm, None)
                    self._estats_cum.pop(nm, None)
            if self.estats:
                rows = sorted(merged.values(), key=lambda r: -(r["down"] + r["up"]))[:self.MAX_ROWS]
            else:
                rows = sorted(merged.values(),
                              key=lambda r: (-r["conns"], -r["remotes"]))[:self.MAX_ROWS]

        for k in [k for k in self._enabled if k not in self._live]:
            self._enabled.discard(k)
            self._prev.pop(k, None)

        self.last["down"] = self.last["down"] * 0.45 + down * 0.55
        self.last["up"] = self.last["up"] * 0.45 + up * 0.55
        self.last["conns"] = len(established)
        # 经代理的总量：有管理员 + 知道代理口，就一直给（闲置时自然掉到 0，
        # 不要忽有忽无，否则面板上的"经代理"那半行会闪）
        px = None
        if self.estats and self.proxy_ports:
            self._pxema[0] = self._pxema[0] * 0.4 + pxrate[0] * 0.6
            self._pxema[1] = self._pxema[1] * 0.4 + pxrate[1] * 0.6
            self._proxy_cum["down"] += self._pxema[0] * dt
            self._proxy_cum["up"] += self._pxema[1] * dt
            px = {"down": self._pxema[0], "up": self._pxema[1],
                  "cum_down": self._proxy_cum["down"], "cum_up": self._proxy_cum["up"],
                  "conns": len(pconns)}
        return {"total": (self.last["down"], self.last["up"]),
                "cum": dict(self.cum),
                "conns": len(established),
                "conns_all": len(conns),
                "proxy": px,                 # 经代理（None = 拿不到：非管理员 / 没开系统代理）
                "proxy_conns": len(pconns),
                "procs": rows,
                "estats": self.estats,
                "nic": nic["name"] if nic else "",
                "nics": len(nics)}

    def _rates(self, conns, per, dt):
        """每条连接查一次内核 eStats，差分出这一秒该进程收发了多少

        只在管理员下走到这里：普通权限 Set 回 5（ACCESS_DENIED），立刻关掉这条路，
        免得每秒白跑几百次系统调用。

        一帧里会被调用两次（普通连接一次、回环代理连接一次），所以"清掉关掉的连接"
        不在这里做 —— 记进 self._live，由 sample() 在本帧全采完之后统一清。
        """
        for c in conns:
            key = (c["laddr"], c["lportn"], c["raddr"], c["rportn"])
            self._live.add(key)
            if key not in self._enabled:
                rc = estats_on(c)
                if rc == 5:                    # 没有管理员权限：认命，退回只数连接
                    self.estats = False
                    self._enabled.clear()
                    self._prev.clear()
                    return
                if rc:
                    continue                   # 连接刚好关了之类：这一秒跳过
                self._enabled.add(key)
            cur = estats_bytes(c)
            if cur is None:
                continue
            prev = self._prev.get(key)
            self._prev[key] = cur
            if prev is None:
                continue
            e = per.get(c["pid"])
            if e is None:                  # 只会走代理连接的进程（比如刚起来的浏览器）
                e = per[c["pid"]] = {"n": 0, "remotes": set(), "down": 0.0, "up": 0.0,
                                     "px_down": 0.0, "px_up": 0.0}
            e["up"] += max(0, cur[0] - prev[0]) / dt
            e["down"] += max(0, cur[1] - prev[1]) / dt
