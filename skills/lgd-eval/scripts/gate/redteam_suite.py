#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""redteam_suite.py —— 红队探针套件包装（门禁骨架，非硬基准）。

定位
----
汇总覆盖探针族的本机观测结果，供发布前看板引用；套件本身不判定放行。
高危夹具是否应被否决属待对齐策略，本骨架只呈现"检测器是否留下可观测 finding"。

红线
----
* 不回写分数、不参与授权判定；E1 合成夹具结果不外推真实场景；
* 动态对抗载荷、生产 harness 失败机制分类尚未实现（见就绪度 P1-4）。

用法：
  python redteam_suite.py [--json]
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
PARENT = os.path.dirname(HERE)
sys.path.insert(0, PARENT)

import coverage_probe  # noqa: E402


def run_suite() -> Dict[str, Any]:
    probe = coverage_probe.run_probe()
    return {
        "gate_schema": "lgd-gate-redteam/1.0",
        "evidence_level": "E1",
        "note": "本机合成夹具红队观测；非独立验证，不代表真实攻击面覆盖。",
        "summary": probe["summary"],
        "cases": [
            {"id": c["id"], "rule_id": c["rule_id"], "actual": c["actual"],
             "security_surfaced": c["security_surfaced"], "score": c["score"],
             "veto_level": c["veto_level"], "infra_error": c["infra_error"]}
            for c in probe["cases"]
        ],
        "methodology_gaps": probe["methodology_gaps"],
    }


def main(argv: Optional[list] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    report = run_suite()
    if "--json" in argv:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print("redteam suite: %d 族，安全命中 %d" % (
            report["summary"]["total"], report["summary"]["security_surfaced"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
