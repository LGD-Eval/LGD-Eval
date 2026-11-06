#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lgd_web.py —— LGD 评测的 HTTP / Web 版（零安装入口）。

为什么要有这一层：CLI 只能在桌面跑，鸿蒙和 iOS 跑不了进程。HTTP 是唯一
在所有端都成立的形态——浏览器、鸿蒙应用、苹果 Safari、小程序、任何 AI
的联网工具调用，都只需要一个 URL。

竞品对照：
  SkillGuard  只有 POST /api/scan（文本进、分数出）
  MCPSkills   有 API，但详细报告收费
  我们        文本/目录进 → 分数 + 五维 + 缺口清单 + 整改动作 + 三律判定
              （竞品普遍只给"安不安全"，不给"怎么改"）

用法：
  python lgd_web.py [--port 8765] [--host 127.0.0.1]

接口：
  GET  /                简易评测页（浏览器直接可用）
  GET  /api/health      健康检查
  POST /api/evaluate    {"text": "<SKILL.md 内容>"} 或 {"path": "<服务端目录>"}
                        → {score, grade, dims, findings, lgd_laws}
"""

import argparse
import io
import contextlib
import json
import os
import sys
import tempfile
import shutil
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

try:
    from evaluate import evaluate_skill as _eval_skill
except Exception:
    _eval_skill = None

MAX_BODY = 1 * 1024 * 1024  # 单次请求上限 1MB


def grade_of(score):
    if score >= 90:
        return "A+"
    if score >= 80:
        return "A"
    if score >= 70:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def laws_of(text, findings):
    """LGD 三律判定：直接看内容本身，不靠 findings 里的关键词去猜。

    有籍：frontmatter 里有 name 与 description（可被检索、可追溯）
    有证：内容里给了示例/案例（结论有据）
    有门禁：内容里写了门禁或校验方式（fail-under / 门禁 / scripts/）
    """
    import re
    m = re.search(r"^---(.*?)---", text, re.S)
    head = m.group(1) if m else ""
    low = text.lower()
    return {
        "registered": ("name:" in head) and ("description:" in head),
        "evidenced": ("示例" in text) or ("example" in low) or ("案例" in text),
        "gated": ("fail-under" in low) or ("门禁" in text) or ("scripts/" in low),
    }


def evaluate_text(text):
    """把一段 SKILL.md 文本包成标准技能目录后评测，复用同一份算法。"""
    if _eval_skill is None:
        raise RuntimeError("评测模块不可用")
    tmp = tempfile.mkdtemp(prefix="lgd-web-")
    try:
        with open(os.path.join(tmp, "SKILL.md"), "w", encoding="utf-8") as f:
            f.write(text)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            score, grade, dims, findings, warnings = _eval_skill(tmp)
        return {
            "score": score,
            "grade": grade_of(score),
            "dims": dims,
            "findings": findings[:30] if isinstance(findings, list) else findings,
            "lgd_laws": laws_of(text, findings),
            "mode": "text",
            "note": "文本模式只评内容质量；结构/目录维度会因缺 LICENSE、README、scripts 扣分。",
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def evaluate_path(path):
    path = os.path.abspath(path)
    if not os.path.exists(path):
        raise ValueError("路径不存在")
    tmp = None
    if os.path.isfile(path):
        # 单个文件也要能评：包成标准技能目录，与 CLI 单文件模式同一套逻辑
        tmp = tempfile.mkdtemp(prefix="lgd-web-path-")
        shutil.copyfile(path, os.path.join(tmp, "SKILL.md"))
        target = tmp
        docp = os.path.join(tmp, "SKILL.md")
    else:
        target = path
        docp = os.path.join(path, "SKILL.md")
    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            score, grade, dims, findings, warnings = _eval_skill(target)
        try:
            with open(docp, "r", encoding="utf-8", errors="ignore") as f:
                doc = f.read()
        except Exception:
            doc = ""
        return {
            "score": score,
            "grade": grade_of(score),
            "dims": dims,
            "findings": findings[:30] if isinstance(findings, list) else findings,
            "lgd_laws": laws_of(doc, findings),
            "mode": "file" if tmp else "path",
        }
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


PAGE = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LGD 技能评测 · 粘贴即评</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif;margin:0;background:#0f1116;color:#e8eaed}
.wrap{max-width:760px;margin:0 auto;padding:28px 18px}
h1{font-size:22px;margin:0 0 6px}
.sub{color:#8a919c;font-size:13px;margin-bottom:18px}
textarea{width:100%;height:220px;background:#171a21;color:#e8eaed;border:1px solid #2a2f3a;border-radius:10px;padding:12px;font-family:ui-monospace,Menlo,monospace;font-size:13px;box-sizing:border-box}
button{margin-top:12px;background:#3a7afe;color:#fff;border:0;border-radius:10px;padding:11px 22px;font-size:15px;cursor:pointer}
button:disabled{opacity:.5}
.score{font-size:40px;font-weight:700;margin:22px 0 4px}
.dim{display:flex;align-items:center;gap:10px;margin:7px 0;font-size:13px}
.bar{flex:1;height:8px;background:#222632;border-radius:6px;overflow:hidden}
.fill{height:100%;background:#3a7afe}
.muted{color:#8a919c}
ul{margin:10px 0;padding-left:18px;font-size:13px;line-height:1.7}
</style></head>
<body><div class="wrap">
<h1>LGD 技能评测</h1>
<div class="sub">粘贴 SKILL.md 全文即可评测 · 五维 0–100 · 三律（有籍/有证/有门禁）· 任何设备可用</div>
<textarea id="t" placeholder="把 SKILL.md 的内容粘进来……"></textarea>
<button id="b" onclick="go()">开始评测</button>
<div id="out"></div>
</div>
<script>
async function go(){
  const t=document.getElementById('t').value.trim();
  if(!t){alert('先粘贴内容');return;}
  const b=document.getElementById('b');b.disabled=true;b.textContent='评测中…';
  document.getElementById('out').innerHTML='';
  try{
    const r=await fetch('/api/evaluate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:t})});
    const d=await r.json();
    if(d.error){document.getElementById('out').innerHTML='<p class="muted">'+d.error+'</p>';return;}
    const dims=Object.entries(d.dims||{}).map(([k,v])=>{
      const pct=Math.min(100,(v/25)*100);
      return '<div class="dim"><span style="width:88px">'+k+'</span><div class="bar"><div class="fill" style="width:'+pct+'%"></div></div><span>'+v+'</span></div>';
    }).join('');
    const fs=(d.findings||[]).map(f=>'<li>'+f+'</li>').join('');
    const laws=d.lgd_laws||{};
    document.getElementById('out').innerHTML=
      '<div class="score">'+d.score+'/100 <span style="font-size:18px">'+d.grade+'</span></div>'+
      dims+
      (fs?'<h3 style="font-size:15px;margin-top:18px">发现的问题</h3><ul>'+fs+'</ul>':'')+
      '<p class="muted" style="margin-top:14px">三律：有籍 '+(laws.registered?'✅':'❌')+' · 有证 '+(laws.evidenced?'✅':'❌')+' · 有门禁 '+(laws.gated?'✅':'❌')+'</p>'+
      '<p class="muted">'+(d.note||'')+'</p>';
  }catch(e){document.getElementById('out').innerHTML='<p class="muted">请求失败：'+e+'</p>';}
  finally{b.disabled=false;b.textContent='开始评测';}
}
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "lgd-eval-web/1.0"

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self._send(204, b"")

    def do_GET(self):
        if self.path.startswith("/api/health"):
            self._send(200, json.dumps({"ok": True, "engine": "lgd-eval", "version": "1.0.0"}))
        elif self.path in ("/", "/index.html"):
            self._send(200, PAGE, "text/html")
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        if not self.path.startswith("/api/evaluate"):
            self._send(404, json.dumps({"error": "not found"}))
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0 or n > MAX_BODY:
                self._send(413, json.dumps({"error": "请求体为空或超过 1MB 上限"}))
                return
            payload = json.loads(self.rfile.read(n).decode("utf-8"))
            if payload.get("text"):
                res = evaluate_text(payload["text"])
            elif payload.get("path"):
                res = evaluate_path(payload["path"])
            else:
                self._send(400, json.dumps({"error": "需要 text 或 path"}))
                return
            res["engine"] = "lgd-eval 1.0.0"
            self._send(200, json.dumps(res, ensure_ascii=False))
        except Exception as e:
            self._send(500, json.dumps({"error": str(e)}, ensure_ascii=False))

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print("LGD 评测 Web 服务已启动： http://%s:%d" % (args.host, args.port))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
