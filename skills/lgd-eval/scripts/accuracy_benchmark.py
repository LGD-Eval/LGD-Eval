#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""accuracy_benchmark.py —— 评测器自身的标注样本基准（独立于被评测对象）。

目的
----
任务书 §2 要求"增加评测器自身的独立准确性基准"。评测器不能只给自己打分，
必须在一批**人工标注过期望结论**的样本上复跑，统计判定与标注是否一致，
防止"评测器越调越自洽、却与真实对错脱节"。

样本在临时目录现场生成，不依赖网络、不读取仓库外数据；每例标注期望的
授权状态（见 ``CASES``）。基准只校验"评测器是否把样本判到了标注的那一档"，
不把分数高低当作正确性本身。

判定口径与 `scorecard.collect` 一致：先取 evaluate_skill 的分数/等级/封顶结论，
再交 `authz.authorize` 独立出授权状态。

跑法：
    python tools/accuracy_benchmark.py            # 打印逐例对照与汇总
    python -m pytest tests/test_accuracy_benchmark.py
"""
from __future__ import annotations

import contextlib
import io
import os
import shutil
import tempfile
from typing import Any, Dict, List

import authz
from evaluate import evaluate_skill

CLEAN_SKILL_MD = """---
name: demo-skill
description: 一个结构完整、无可疑行为的示例技能
version: 1.0.0
license: MIT
author: LGD-Eval Benchmark
---

# demo-skill

干净示例：只做本地文本整理，不读取凭证、不发起网络请求、不执行外部命令。
"""

CLEAN_SCRIPT = """\
def summarize(text: str) -> str:
    \"\"\"纯本地文本整理，无网络、无命令执行。\"\"\"
    return " ".join(text.split())
"""

# 标注为"高危命令注入"：shell=True 命中 R-SEC-03（HIGH），必须被否决授权。
MALICIOUS_SCRIPT = """\
import subprocess

def run(cmd):
    subprocess.run(cmd, shell=True)
"""

README = "# demo-skill\n\n本地文本整理示例技能。\n"
CHANGELOG = "# Changelog\n\n## 1.0.0\n\n初始版本。\n"
LICENSE = "MIT License\n"
EXAMPLE = "示例：summarize('  a  b  ') -> 'a b'\n"


def _write(root: str, rel: str, content: str) -> None:
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)


def _build_clean(root: str) -> None:
    _write(root, "SKILL.md", CLEAN_SKILL_MD)
    _write(root, "README.md", README)
    _write(root, "CHANGELOG.md", CHANGELOG)
    _write(root, "LICENSE", LICENSE)
    _write(root, "scripts/clean.py", CLEAN_SCRIPT)
    _write(root, "examples/example.md", EXAMPLE)


def _build_malicious(root: str) -> None:
    # 结构齐全（避免被"证据不全"掩盖安全否决），但脚本含 shell=True。
    _build_clean(root)
    _write(root, "scripts/evil.py", MALICIOUS_SCRIPT)


def _build_bare(root: str) -> None:
    # 残缺：无 README/CHANGELOG、无 examples/tests，证据不齐。
    _write(root, "SKILL.md", "name: bare\n")


# 标注样本：expect = 人工标注的期望授权状态。
CASES: List[Dict[str, Any]] = [
    {"id": "clean-well-formed", "build": _build_clean, "expect": authz.GRANTED},
    {"id": "shell-injection-high", "build": _build_malicious, "expect": authz.NOT_GRANTED},
    {"id": "missing-evidence", "build": _build_bare, "expect": authz.INCOMPLETE},
]


def run_case(case: Dict[str, Any], root: str) -> Dict[str, Any]:
    """在 root 下生成样本并跑评测，返回评测器实际结论。"""
    case_dir = os.path.join(root, case["id"])
    case["build"](case_dir)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        score, grade, dims, findings, warnings, veto = evaluate_skill(case_dir)
    evidence = {
        "registered": os.path.exists(os.path.join(case_dir, "README.md")) and
                       os.path.exists(os.path.join(case_dir, "CHANGELOG.md")),
        "evidenced": os.path.isdir(os.path.join(case_dir, "examples")) or
                      os.path.isdir(os.path.join(case_dir, "tests")),
    }
    decision = authz.authorize(score=score, grade=grade, veto_info=veto,
                                evidence=evidence, verdict_present=score is not None)
    return {
        "id": case["id"],
        "expect": case["expect"],
        "actual": decision["state"],
        "score": score,
        "grade": grade,
        "veto_level": (veto or {}).get("level", ""),
        "findings": findings,
        "match": decision["state"] == case["expect"],
    }


def evaluate_cases() -> List[Dict[str, Any]]:
    tmp = tempfile.mkdtemp(prefix="lgd-eval-bench-")
    try:
        return [run_case(c, tmp) for c in CASES]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def summary(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(rows)
    matched = sum(1 for r in rows if r["match"])
    return {
        "total": total,
        "matched": matched,
        "accuracy": round(matched / total, 4) if total else 0.0,
        "all_match": matched == total,
        "rows": rows,
    }


def main() -> int:
    rows = evaluate_cases()
    s = summary(rows)
    for r in rows:
        flag = "OK  " if r["match"] else "FAIL"
        print("[%s] %-24s expect=%-12s actual=%-12s score=%s veto=%s" %
              (flag, r["id"], r["expect"], r["actual"], r["score"], r["veto_level"]))
    print("\naccuracy = %d/%d = %.2f%%" % (s["matched"], s["total"], s["accuracy"] * 100))
    return 0 if s["all_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
