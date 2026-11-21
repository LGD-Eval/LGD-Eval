#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""outsider_run.py —— 外部实跑记录包装（门禁骨架）。

定位
----
在干净克隆上由外部/独立角色实跑时，记录操作者、克隆来源、时点与一致性结论；
回执必须能回溯"谁、在哪个克隆、什么时间、读到什么结果"。当前未接真实独立角色，
操作者留空，结论沿用 external_node_check 的 fail-closed 判定。

红线
----
* 无读取证据的外部意见只能记"文本自洽性意见"，不得作为独立复核通过依据；
* 操作者身份、利益关系披露待 E4 通道建立（见就绪度 P2-1）。

用法：
  python outsider_run.py <clone_dir> --label local|public [--operator <id>] [--json]
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
PARENT = os.path.dirname(HERE)
sys.path.insert(0, PARENT)

import external_node_check as enc  # noqa: E402


def record(clone_dir: str, label: str, operator: Optional[str]) -> Dict[str, Any]:
    check = enc.evaluate(clone_dir, label)
    return {
        "gate_schema": "lgd-gate-outsider-run/1.0",
        "evidence_level": "E1",
        "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "operator": operator or None,
        "operator_note": "操作者留空：尚未接入独立复核身份；不得记为第三方复核。",
        "clone_source": label,
        "check": check,
        "status": check["status"],
    }


def main(argv: Optional[list] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in argv
    label = "local"
    operator = None
    if "--label" in argv:
        label = argv[argv.index("--label") + 1]
    if "--operator" in argv:
        operator = argv[argv.index("--operator") + 1]
    paths = [a for a in argv if not a.startswith("--") and a not in (label, operator or "")]
    if not paths:
        print("用法: python outsider_run.py <clone_dir> [--label local|public] [--operator <id>]")
        return 2
    report = record(paths[0], label, operator)
    if as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print("outsider run: %s（来源=%s，操作者=%s）" % (
            report["status"], report["clone_source"], report["operator"] or "未登记"))
    return {"CONSISTENT": 0, "DISCREPANCY": 3, "INCONCLUSIVE": 2}[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
