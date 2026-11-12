import json, sys, urllib.request
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

s = json.load(urllib.request.urlopen("http://127.0.0.1:7717/api/state", timeout=5))
print("ok:", s.get("ok"), "err:", repr(s.get("error")))
print("path:", s.get("path"))
t = s.get("tunnel") or {}
print("tunnel:", {k: t.get(k) for k in ("mode", "tun", "conns", "version")})
print("iface:", s.get("iface"))
print("node:", s.get("node"))
print("mihomo:", s.get("mihomo"))
print("egress:", s.get("egress"))
print("total:", s.get("total"))
for x in s.get("sites", []):
    print("  site", x["label"], x["via"], x["down"], x["up"], "|", x["chain"], "|", x["ip"])
print("extras:", [(e["label"], e["down"]) for e in s.get("extras", [])])
pr = s.get("probes") or {}
print("probes:", {k: (v.get("ok"), v.get("ms"), v.get("kind") or "ok") for k, v in pr.items()})
dg = s.get("diag") or {}
if dg:
    print(f"诊断: [{dg.get('state')}] {dg.get('label')} —— {dg.get('why')}")
    for e in dg.get("evidence") or []:
        print("   ·", e)
lk = s.get("link") or {}
if lk.get("gw"):
    print("网关:", {k: (v.get("ip"), v.get("ok"), v.get("ms")) for k, v in lk["gw"].items()})
if (lk.get("dns") or {}).get("target"):
    d = lk["dns"]["target"]
    print("DNS :", "系统", d.get("system", {}).get("ips"), "公共", d.get("public", {}).get("ips"),
          "| 不一致" if lk["dns"].get("mismatch") else "")
if lk.get("by_nic"):
    print("网卡:", {k: (v.get("src"), v.get("ok"), v.get("kind") or "通") for k, v in lk["by_nic"].items()})

