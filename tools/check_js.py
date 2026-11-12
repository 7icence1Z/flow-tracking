"""把 web/index.html 里的 <script> 块抠出来交给 node --check

面板的 JS 是内联的，语法错了只会表现为「连接中…」停在原地；打包/上线前跑一下。
用法：python -X utf8 tools\\check_js.py
"""
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
blocks = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.S)
if not blocks:
    sys.exit("没找到内联 <script>")

bad = 0
for i, js in enumerate(blocks, 1):
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(js)
        path = f.name
    p = subprocess.run(["node", "--check", path], capture_output=True, text=True)
    if p.returncode == 0:
        print(f"[ok ] script #{i} 语法通过（{len(js)} 字符）")
    else:
        bad += 1
        print(f"[FAIL] script #{i}:\n{p.stderr}")
    pathlib.Path(path).unlink(missing_ok=True)

sys.exit(1 if bad else 0)
