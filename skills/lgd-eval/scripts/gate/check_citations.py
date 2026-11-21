#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_citations.py —— 引用链接直达核查（门禁工具骨架，非评测判定）。

定位
----
对外材料里的标准/竞品/论文链接必须逐条机器核查，不靠肉眼判断。
本脚本从 Markdown 提取 http(s) 链接，按可达性分类；网络不可达不等于链接失效，
必须区分 403/反爬、超时、真 404，前两类在发布材料里附注"本机不可达，需目标网络复核"。

红线
----
* 不修改被测内容、不回写分数、不参与授权判定；
* 默认离线模式（--offline 或缺省无网络时）只提取链接并标 UNCHECKED，不猜可达性；
* 超时/反爬不得记为失效；结论为 E1 本机核查，目标网络复核前不得当作引用已验证；
* 退出码恒 0（诊断工具），是否阻断由发布门禁另行判定。

用法：
  python check_citations.py <file.md|dir> [--offline] [--json] [--out report.json]
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

URL_RE = re.compile(r"https?://[^\s)>\]\"'`]+")

STATUS_REACHABLE = "REACHABLE"
STATUS_FORBIDDEN = "FORBIDDEN"        # 403/401 反爬或权限，不等于失效
STATUS_NOT_FOUND = "NOT_FOUND"        # 真 404
STATUS_UNREACHABLE = "UNREACHABLE"    # 超时/DNS/连接失败，需目标网络复核
STATUS_UNCHECKED = "UNCHECKED"        # 离线模式，未探测


def extract_urls(text: str) -> List[str]:
    seen: List[str] = []
    for m in URL_RE.findall(text):
        u = m.rstrip(".,;)")
        if u not in seen:
            seen.append(u)
    return seen


def _probe(url: str, timeout: float) -> Dict[str, str]:
    req = urllib.request.Request(url, method="HEAD",
                                 headers={"User-Agent": "lgd-gate-citation/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {"status": STATUS_REACHABLE, "detail": "HTTP %s" % resp.status}
    except urllib.error.HTTPError as e:
        if e.code in (403, 401):
            return {"status": STATUS_FORBIDDEN, "detail": "HTTP %s（反爬/权限，需复核）" % e.code}
        if e.code == 404:
            return {"status": STATUS_NOT_FOUND, "detail": "HTTP 404"}
        return {"status": STATUS_UNREACHABLE, "detail": "HTTP %s" % e.code}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"status": STATUS_UNREACHABLE,
                "detail": "%s: %s" % (type(e).__name__, str(e)[:120])}


def check_urls(urls: List[str], offline: bool, timeout: float = 5.0) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for url in urls:
        if offline:
            rows.append({"url": url, "status": STATUS_UNCHECKED, "detail": "离线模式未探测"})
        else:
            rows.append({"url": url, **_probe(url, timeout)})
    return rows


def scan_path(path: str, offline: bool, timeout: float) -> Dict[str, Any]:
    links: List[Dict[str, Any]] = []
    sources: List[str] = []
    if os.path.isfile(path):
        files = [path]
    else:
        files = [os.path.join(dp, f) for dp, _, fns in os.walk(path)
                 for f in fns if f.lower().endswith((".md", ".txt"))]
    for fp in sorted(files):
        try:
            with open(fp, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        sources.append(fp)
        for u in extract_urls(text):
            links.append({"url": u, "source": os.path.relpath(fp, path)})
    urls = []
    for l in links:
        if l["url"] not in urls:
            urls.append(l["url"])
    checked = {r["url"]: r for r in check_urls(urls, offline, timeout)}
    rows = [{**l, **checked[l["url"]]} for l in links]
    summary: Dict[str, int] = {}
    for r in rows:
        summary[r["status"]] = summary.get(r["status"], 0) + 1
    return {
        "gate_schema": "lgd-gate-citations/1.0",
        "evidence_level": "E1",
        "offline": offline,
        "note": "本机引用核查；FORBIDDEN/UNREACHABLE 不等于失效，发布前须在目标网络复核。",
        "source_files": sources,
        "links": rows,
        "summary": summary,
    }


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    offline = "--offline" in argv
    as_json = "--json" in argv
    out = None
    if "--out" in argv:
        out = argv[argv.index("--out") + 1]
    paths = [a for a in argv if not a.startswith("--") and a != out]
    if not paths:
        print("用法: python check_citations.py <file.md|dir> [--offline] [--json]")
        return 2
    report: Dict[str, Any] = {"gate_schema": "lgd-gate-citations/1.0", "evidence_level": "E1",
                              "sources": []}
    merged_links: List[Dict[str, Any]] = []
    for p in paths:
        part = scan_path(p, offline, timeout=5.0)
        merged_links.extend(part["links"])
    report = {
        "gate_schema": "lgd-gate-citations/1.0",
        "evidence_level": "E1",
        "offline": offline,
        "links": merged_links,
        "summary": {},
    }
    for r in merged_links:
        report["summary"][r["status"]] = report["summary"].get(r["status"], 0) + 1
    if out:
        with open(out, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
    if as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print("citations: %d 条；分类 %s" % (len(merged_links), report["summary"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
