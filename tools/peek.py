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
print("probes:", {k: (v.get("ok"), v.get("ms"), v.get("err")) for k, v in pr.items()})

