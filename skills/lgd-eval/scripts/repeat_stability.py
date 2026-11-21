#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""repeat_stability.py —— 基准重复运行稳定性（pass^k，纯观测，不改判定）。

定位
----
硬基准每例单次运行；本脚本对同一批标注样本现场重建夹具、重复 k 次，记录：
授权状态是否逐次一致、是否每次都与标注匹配、分数波动范围。用于补方法学缺口
F-2（pass^k 重复稳定性）的本地可观测位。

红线
----
* 不改门槛、不改阻断级、不改授权映射；只重复调用既有 `accuracy_benchmark.run_case`；
* 样本为合成夹具、规则为确定性正则/静态分析；本 pass^k 度量的是**同输入下代码路径
  的可复现性**，不代表跨真实样本、硬件、规则版本的稳定性，也不度量 token/成本；
* 不联网、不读仓库外数据；临时目录跑完即删；
* 单次基础设施异常（infra_error）按未匹配处理，不记稳定通过。

用法：
  python repeat_stability.py [--k 5] [--json]
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from typing import Any, Dict, List, Optional

import accuracy_benchmark as ab


def _repeat_one(case: Dict[str, Any], k: int, root: str) -> Dict[str, Any]:
    states: List[Optional[str]] = []
    scores: List[Optional[float]] = []
    matches: List[bool] = []
    vetos: List[str] = []
    case_dir = os.path.join(root, case["id"])
    for _ in range(k):
        if os.path.exists(case_dir):
            shutil.rmtree(case_dir, ignore_errors=True)
        r = ab.run_case(case, root)
        states.append(r["actual"])
        scores.append(r["score"])
        matches.append(bool(r["match"]) and not r.get("infra_error"))
        vetos.append(r["veto_level"])
    state_set = sorted({s for s in states if s is not None})
    score_variation: Optional[float] = None
    scored = [s for s in scores if s is not None]
    if scored:
        score_variation = round(max(scored) - min(scored), 4)
    return {
        "id": case["id"],
        "expect": case["expect"],
        "repeats": k,
        "states": states,
        "state_set": state_set,
        "match_all": all(matches),
        "stable": len(state_set) == 1 and all(matches),
        "score_variation": score_variation,
        "veto_levels": vetos,
    }


def run_repeat(k: int = 5) -> Dict[str, Any]:
    tmp = tempfile.mkdtemp(prefix="lgd-eval-repeat-")
    try:
        cases = [_repeat_one(c, k, tmp) for c in ab.CASES]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    stable = sum(1 for c in cases if c["stable"])
    total = len(cases)
    return {
        "gate_schema": "lgd-eval-repeat-stability/1.0",
        "evidence_level": "E1",
        "note": "合成夹具确定性复跑；pass^k 仅度量同输入可复现性，不外推真实场景稳定性，不含 token/成本测量。",
        "repeats": k,
        "summary": {
            "total": total,
            "stable_cases": stable,
            "unstable_cases": total - stable,
            "all_stable": stable == total,
            "pass_k_rate": round(stable / total, 4) if total else 0.0,
        },
        "cases": cases,
    }


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    k = 5
    if "--k" in argv:
        k = int(argv[argv.index("--k") + 1])
    as_json = "--json" in argv
    report = run_repeat(k)
    if as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        s = report["summary"]
        print("repeat stability k=%d: %d/%d 稳定（pass^k 率 %s）" % (
            k, s["stable_cases"], s["total"], s["pass_k_rate"]))
        for c in report["cases"]:
            flag = "STABLE" if c["stable"] else "UNSTABLE"
            print("  [%s] %-24s states=%s variation=%s" % (
                flag, c["id"], c["state_set"], c["score_variation"]))
    return 0 if report["summary"]["all_stable"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
