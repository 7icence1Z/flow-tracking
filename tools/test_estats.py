"""eStats 自检：本机模式下的"每进程字节数"这条路到底通不通

分两半看：

  · 结构体（纯本地，任何人可跑）：eStats 靠 ctypes 手搓三个结构，
    字段抄错一个就会读到垃圾 —— 这里核对大小和字段偏移。
  · 真读一次（要管理员）：自己开一条 TCP 连接，开统计、等半秒、再读，
    字节数必须涨。普通权限下 `SetPerTcpConnectionEStats` 会回 5(ACCESS_DENIED)，
    那就**跳过**这一半 —— 不是失败，是权限边界。

跑法：python -X utf8 tools\\test_estats.py
      （想跑完整的一半：右键终端「以管理员身份运行」再跑一次）
"""
import ctypes
import ctypes.wintypes as wt
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding="utf-8")

import hostflow  # noqa: E402

FAIL = 0


def check(name, cond, extra=""):
    global FAIL
    if not cond:
        FAIL += 1
    print(f"[{'ok ' if cond else 'FAIL'}] {name}" + (f"  {extra}" if extra else ""))


def part_structs():
    print("=== 结构体 ===")
    check("MIB_TCPROW = 5 × DWORD = 20 字节",
          ctypes.sizeof(hostflow.MIB_TCPROW) == 20,
          f"实际 {ctypes.sizeof(hostflow.MIB_TCPROW)}")
    check("TCP_ESTATS_DATA_RW = 1 字节（一个 BOOLEAN）",
          ctypes.sizeof(hostflow.TCP_ESTATS_DATA_RW) == 1,
          f"实际 {ctypes.sizeof(hostflow.TCP_ESTATS_DATA_RW)}")
    rod = hostflow.TCP_ESTATS_DATA_ROD
    check("TCP_ESTATS_DATA_ROD 里两个字节计数器在开头",
          [f[0] for f in rod._fields_][:4] ==
          ["DataBytesOut", "DataSegsOut", "DataBytesIn", "DataSegsIn"],
          f"{[f[0] for f in rod._fields_][:4]}")
    # 8*6 + 4*5 + 8 + 4 + 8 + 对齐 → 96；只核对"比 80 大、是 8 的倍数"这种硬约束
    sz = ctypes.sizeof(rod)
    check("TCP_ESTATS_DATA_ROD 大小合理（8 的倍数、≥ 88）", sz % 8 == 0 and sz >= 88, f"实际 {sz}")


def part_admin():
    print("\n=== 真读一次（要管理员） ===")
    if not hostflow.elevated():
        print("[skip] 当前不是管理员 —— eStats 与 DNS 缓存都拿不到，"
              "面板会退回「只数连接」；这一半要用管理员终端再跑一次")
        return
    # 自己连本机采集器，这条连接由本进程持有，肯定在 TCP 表里
    port = int(os.environ.get("PORT", "7717"))
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
    except OSError as e:
        print(f"[skip] 连不上本机 {port}（采集器没在跑？）：{e}")
        return
    try:
        s.sendall(b"GET /api/state HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        lport = s.getsockname()[1]
        time.sleep(0.3)
        rows = [c for c in hostflow.tcp_conns()
                if c["lport"] == lport and c["pid"] == os.getpid()]
        check("能在 TCP 表里找到自己这条连接", bool(rows), f"本地端口 {lport}")
        if not rows:
            return
        rc = hostflow.estats_on(rows[0])
        check("SetPerTcpConnectionEStats 成功（0）", rc == 0, f"返回 {rc}")
        if rc:
            return
        time.sleep(0.6)
        got = hostflow.estats_bytes(rows[0])
        check("读得到 eStats 字节", got is not None, f"{got}")
        if got:
            out, inn = got
            check("收发的字节数都 > 0（我们发过请求、也收到了响应）", out > 0 and inn > 0,
                  f"发 {out} / 收 {inn}")
    finally:
        s.close()


def part_degrade():
    print("\n=== 普通权限下的退化 ===")
    hf = hostflow.HostFlow()
    if not hostflow.elevated():
        check("HostFlow 自己认出没有权限", hf.estats is False, f"estats={hf.estats}")
        s = hf.sample(want_procs=True)
        check("sample 不炸，仍然给连接数", isinstance(s.get("conns"), int),
              f"conns={s.get('conns')} procs={len(s.get('procs') or [])}")
        check("procs 里没有编造的字节数",
              all("down" not in p or p["down"] == 0 for p in s.get("procs") or []))
    else:
        print("[skip] 管理员下不退化成「只数连接」")


def main():
    part_structs()
    part_degrade()
    part_admin()
    print("\n结论：" + ("全部通过" if not FAIL else f"{FAIL} 项不通过"))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
