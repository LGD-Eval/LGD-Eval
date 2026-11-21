#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""push_safe.py —— 唯一受认可的推送路径（门禁骨架，默认 dry-run）。

定位
----
推送必须走本包装器，先过 pre_push_gate；默认 dry-run，不执行任何 git push。
真实推送须同时满足：pre-push 非 BLOCKED、显式 --confirm、且已获负责人明确授权。

红线
----
* 无 --confirm 绝不推送；骨架不内置绕过门禁的路径；
* 对外推送属对外动作，须 Steven Zhao 明确允许；推送前提交作者须改为评测号；
* 本文件不记录/打印任何凭证。

用法：
  python push_safe.py <remote> <branch> [--confirm] [--repo <dir>]
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
PARENT = os.path.dirname(HERE)
sys.path.insert(0, PARENT)

import pre_push_gate as ppg  # noqa: E402


def plan(remote: str, branch: str, repo: str, confirm: bool) -> Dict[str, Any]:
    gate = ppg.check(repo)
    will_push = confirm and gate["status"] != "BLOCKED"
    return {
        "gate_schema": "lgd-gate-push-safe/1.0",
        "evidence_level": "E1",
        "remote": remote,
        "branch": branch,
        "dry_run": not confirm,
        "gate": gate,
        "will_push": will_push,
        "action": "push" if will_push else "hold",
        "note": ("dry-run：未执行推送。" if not confirm else
                 "门禁通过，待负责人授权后由唯一推送路径执行。" if will_push else
                 "门禁 BLOCKED，禁止推送。"),
    }


def main(argv: Optional[list] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    confirm = "--confirm" in argv
    repo = argv[argv.index("--repo") + 1] if "--repo" in argv else os.getcwd()
    positional = [a for a in argv if not a.startswith("--") and a != repo]
    if len(positional) < 2:
        print("用法: python push_safe.py <remote> <branch> [--confirm] [--repo <dir>]")
        return 2
    remote, branch = positional[0], positional[1]
    report = plan(remote, branch, repo, confirm)
    if "--json" in argv:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print("push-safe: %s → %s (%s)" % (remote, branch, report["action"]))
        print("  门禁: %s；dry_run=%s" % (report["gate"]["status"], report["dry_run"]))
        print("  %s" % report["note"])
    if report["gate"]["status"] == "BLOCKED":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
