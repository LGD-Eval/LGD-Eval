#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""eval_mcp.py —— MCP Server 专用评测。

为什么不复用五维技能评分：MCP server 没有 SKILL.md，套用技能尺子只会得到
"缺 SKILL.md、69 分 C"这类误判。MCP 有自己的质量结构：工具定义是否清晰、
权限范围是否收敛、能否跑起来、有没有配置示例。

五维（0–100）：
  工具定义 25 | 权限与安全 25 | 可运行性 20 | 文档与示例 15 | 生态兼容 15

用法：
  python eval_mcp.py <mcp目录> [--json] [--fail-under N]
"""

import argparse
import json
import os
import re
import sys

DIMS = [("工具定义", 25), ("权限与安全", 25), ("可运行性", 20), ("文档与示例", 15), ("生态兼容", 15)]
DANGER = [
    (r"\bexec\b|\bspawn\b|\bsystem\(", "执行外部命令"),
    (r"writeFile|write_file|unlink|rmdir|rm -rf|rmSync", "写/删文件"),
    (r"fetch\(|https?://|axios|requests\.", "网络外发"),
    (r"process\.env|os\.environ", "读取环境变量"),
    (r"eval\(|Function\(", "动态执行"),
]


def read_all(root):
    """拼接源码文本（限 .js/.ts/.py/.json/.md）。"""
    buf = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ("node_modules", "__pycache__", ".git")]
        for fn in filenames:
            if fn.lower().endswith((".js", ".ts", ".mjs", ".py", ".json", ".md")):
                p = os.path.join(dirpath, fn)
                try:
                    buf.append(open(p, "r", encoding="utf-8", errors="ignore").read())
                except Exception:
                    pass
    return "\n".join(buf)


def score_tools(root, text):
    score = 0
    notes = []
    files = []
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            if fn.lower().endswith((".js", ".ts", ".mjs", ".py")):
                files.append(os.path.join(dirpath, fn))
    names = re.findall(r"name\s*:\s*[\"']([A-Za-z0-9_\-]{2,64})[\"']", text)
    descs = re.findall(r"description\s*:\s*[\"'][^\"']{8,}[\"']", text)
    schemas = len(re.findall(r"inputSchema|input_schema|JSONSchema", text))
    names = [n for n in names if n.lower() not in ("demo-mcp", "server", "mcp")]
    n_tools = len(names)
    if n_tools:
        score += min(10, n_tools * 2)
        notes.append("识别到 %d 个工具定义" % n_tools)
    else:
        notes.append("未识别到工具定义（name 字段）")
    if len(descs) >= n_tools and n_tools:
        score += 8
        notes.append("每个工具都有描述")
    else:
        notes.append("工具有描述的比例不足")
    if schemas:
        score += min(7, schemas)
        notes.append("含 %d 处 inputSchema 声明" % schemas)
    else:
        notes.append("缺少 inputSchema（参数结构对调用方不可见）")
    return min(25, score), notes


def score_safety(text):
    score = 25
    hits = []
    for pat, label in DANGER:
        if re.search(pat, text):
            hits.append(label)
    if hits:
        score -= min(20, 5 * len(hits))
    notes = ["检测到能力：" + "、".join(hits)] if hits else ["未检测到高危能力调用"]
    if hits and re.search(r"permission|scope|readOnly|read_only|allow", text, re.I):
        score += 5
        notes.append("存在权限声明（有一定收敛）")
    return max(0, min(25, score)), notes


def score_runnable(root):
    score = 0
    notes = []
    pkg = os.path.join(root, "package.json")
    if os.path.isfile(pkg):
        try:
            j = json.load(open(pkg, "r", encoding="utf-8"))
        except Exception:
            j = {}
        if j.get("name"):
            score += 4
        if j.get("version"):
            score += 4
        if j.get("bin") or j.get("main") or j.get("exports"):
            score += 6
            notes.append("有入口声明")
        else:
            notes.append("缺 bin/main/exports 入口")
        if j.get("dependencies"):
            score += 4
            notes.append("依赖已声明")
    else:
        notes.append("缺 package.json")
    entry_ok = any(os.path.isfile(os.path.join(root, x)) for x in
                   ("index.js", "index.ts", "server.js", "main.py", "index.mjs"))
    if entry_ok:
        score += 2
        notes.append("入口文件存在")
    return min(20, score), notes


def score_docs(root, text):
    score = 0
    notes = []
    readme = ""
    for fn in ("README.md", "readme.md", "README.MD"):
        p = os.path.join(root, fn)
        if os.path.isfile(p):
            readme = open(p, "r", encoding="utf-8", errors="ignore").read()
            break
    if readme:
        score += 5
        notes.append("有 README")
        if re.search(r"npm i|npm install|npx|pip install|docker", readme, re.I):
            score += 4
            notes.append("有安装命令")
        if re.search(r"mcpServers|mcp\.json|command\"", readme) or "command" in text:
            score += 4
            notes.append("有客户端配置示例")
        if re.search(r"^- |\* |tools?：(|\n)", readme, re.M):
            score += 2
    else:
        notes.append("缺 README")
    return min(15, score), notes


def score_eco(root):
    score = 0
    notes = []
    pkg = os.path.join(root, "package.json")
    j = {}
    if os.path.isfile(pkg):
        try:
            j = json.load(open(pkg, "r", encoding="utf-8"))
        except Exception:
            j = {}
    if j.get("license"):
        score += 5
        notes.append("有 license")
    if j.get("repository") or j.get("homepage"):
        score += 4
        notes.append("有仓库/主页")
    if j.get("keywords"):
        score += 3
        notes.append("有 keywords")
    if j.get("description"):
        score += 3
        notes.append("有一句话描述")
    if not os.path.isfile(os.path.join(root, "LICENSE")):
        notes.append("缺 LICENSE 文件")
    return min(15, score), notes


def grade_of(s):
    if s >= 90:
        return "🏆 A+"
    if s >= 80:
        return "🥇 A"
    if s >= 70:
        return "🥈 B"
    if s >= 60:
        return "🥉 C"
    if s >= 40:
        return "D"
    return "F"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-under", type=int, default=0)
    args = ap.parse_args()
    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print("目录不存在：%s" % root)
        sys.exit(2)

    text = read_all(root)
    dims = {}
    notes = {}
    dims["工具定义"], notes["工具定义"] = score_tools(root, text)
    dims["权限与安全"], notes["权限与安全"] = score_safety(text)
    dims["可运行性"], notes["可运行性"] = score_runnable(root)
    dims["文档与示例"], notes["文档与示例"] = score_docs(root, text)
    dims["生态兼容"], notes["生态兼容"] = score_eco(root)
    total = sum(dims.values())
    grade = grade_of(total)

    if args.json:
        print(json.dumps({"target": root, "kind": "mcp-server", "score": total,
                          "grade": grade, "dims": dims, "notes": notes},
                         ensure_ascii=False, indent=2))
    else:
        print("=" * 62)
        print("  LGD MCP Server 评测报告")
        print("=" * 62)
        for name, mx in DIMS:
            print("  %-8s %2d/%2d" % (name, dims[name], mx))
            for n in notes[name]:
                print("      · %s" % n)
        print("-" * 62)
        print("  Trust Score: %d/100" % total)
        print("  等级: %s" % grade)
        print("=" * 62)

    if args.fail_under and total < args.fail_under:
        print("⛔ 门禁未通过：%d < %d" % (total, args.fail_under))
        sys.exit(1)


if __name__ == "__main__":
    main()
