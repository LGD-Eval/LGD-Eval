#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scorecard.py —— 为一个或多个技能包生成可公开索引的评分卡页面。

每一页都是独立 Markdown，可托管在 GitHub（仓库页 / Pages / raw 都可被搜索引擎与
AI 抓取），解决"评测结果活在一次对话里、外人看不到"的问题。

用法：
  python scorecard.py <dir1> [dir2 ...] [--out score] [--index scores.md]
"""

import argparse
import contextlib
import io
import json
import os
import re
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from evaluate import evaluate_skill, build_fix_plan  # noqa: E402

DIMS = ["结构完整性", "目录结构", "文档质量", "安全", "生态兼容性"]
MAXS = {"结构完整性": 25, "目录结构": 15, "文档质量": 20, "安全": 25, "生态兼容性": 15}
DANGER = ("危险", "风险", "泄", "密钥", "注入", "绕过")


def slug(name):
    s = re.sub(r"[^a-z0-9\-]+", "-", name.lower()).strip("-")
    return s or "skill"


def tri_state(path, findings):
    l1 = os.path.exists(os.path.join(path, "README.md")) and \
        os.path.exists(os.path.join(path, "CHANGELOG.md"))
    l2 = os.path.isdir(os.path.join(path, "examples")) or os.path.isdir(os.path.join(path, "tests"))
    l3 = not any(any(k in f for k in DANGER) for f in findings)
    return {"有籍": "✅ 达标" if l1 else "❌ 待补",
            "有证": "✅ 达标" if l2 else "❌ 待补",
            "有门禁": "✅ 达标" if l3 else "❌ 待补"}


def collect(path):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        score, grade, dims, findings, warnings = evaluate_skill(os.path.abspath(path))
    plan = build_fix_plan(findings, warnings)
    return {"score": score, "grade": grade, "dims": dims, "findings": findings,
            "plan": plan, "tri": tri_state(os.path.abspath(path), findings)}


def render(name, r, ts):
    L = []
    L.append("# %s —— LGD 评分卡\n" % name)
    L.append("> 评测器：`lgd-eval`（五维 0–100：结构 25 / 目录 15 / 文档 20 / 安全 25 / 生态 15）  ")
    L.append("> 评测时间：%s  " % ts)
    L.append("> 任何人可用文末命令复跑验证。\n")
    L.append("## 结论\n")
    L.append("| 总分 | 等级 |")
    L.append("|---|---|")
    L.append("| **%d/100** | **%s** |\n" % (r["score"], r["grade"]))
    L.append("## 五维明细\n")
    L.append("| 维度 | 得分 | 满分 |")
    L.append("|---|---|---|")
    for d in DIMS:
        L.append("| %s | %d | %d |" % (d, r["dims"].get(d, 0), MAXS[d]))
    L.append("")
    if r["findings"]:
        L.append("## 发现的问题\n")
        for i, f in enumerate(r["findings"], 1):
            L.append("%d. %s" % (i, f))
        L.append("")
    else:
        L.append("## 发现的问题\n\n未发现缺口。\n")
    items = r["plan"].get("fix_plan", [])
    if items:
        L.append("## 整改清单（每条含可判定验收）\n")
        for i, it in enumerate(items, 1):
            L.append("%d. **%s**" % (i, it.get("issue", "")))
            L.append("   - 动作：%s" % it.get("action", ""))
            L.append("   - 落点：`%s`" % it.get("target", ""))
            L.append("   - 验收：%s" % it.get("acceptance", ""))
        L.append("")
    L.append("## LGD 三律\n")
    L.append("| 律 | 状态 |")
    L.append("|---|---|")
    for k, v in r["tri"].items():
        L.append("| %s | %s |" % (k, v))
    L.append("")
    L.append("## 复跑验证\n")
    L.append("```bash")
    L.append("npx lgd-eval . --fail-under 90")
    L.append("```\n")
    L.append("低于阈值即以退出码 1 结束，可直接用于 CI 门禁。\n")
    L.append("---\n")
    L.append("评测口径与源码完全一致：https://github.com/LGD-Eval/lgd-gate\n")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs", nargs="+")
    ap.add_argument("--out", default="score")
    ap.add_argument("--index", default="scores.md")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows = []
    for d in args.dirs:
        name = re.sub(r"^\d+-", "", os.path.basename(os.path.abspath(d)))
        r = collect(d)
        md = render(name, r, ts)
        fn = slug(name) + ".md"
        with open(os.path.join(args.out, fn), "w", encoding="utf-8") as f:
            f.write(md)
        rows.append((name, r["score"], r["grade"], fn))
        print("WROTE %s/%s  %d/100 %s" % (args.out, fn, r["score"], r["grade"]))

    rows.sort(key=lambda x: -x[1])
    idx = ["# LGD 评分榜\n",
           "> 每行对应一页可点开的评分卡，含五维明细、整改清单与复跑命令。\n",
           "> 更新时间：%s\n" % ts,
           "| 技能 | 总分 | 等级 | 评分卡 |",
           "|---|---|---|---|"]
    for name, score, grade, fn in rows:
        idx.append("| %s | %d/100 | %s | [查看](score/%s) |" % (name, score, grade, fn))
    idx.append("")
    idx.append("复跑：`npx lgd-eval <技能目录> --fail-under 90`\n")
    with open(args.index, "w", encoding="utf-8") as f:
        f.write("\n".join(idx))
    print("WROTE %s  (%d entries)" % (args.index, len(rows)))


if __name__ == "__main__":
    main()
