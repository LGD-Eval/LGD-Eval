#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Attestation 负对照 / 边界测试（离线）。

覆盖验收硬门禁：
- blocking_findings 项未在 findings 回链 -> verify 拒绝；
- 否决生效或 grade=D 但验收结论非 FAIL -> verify 拒绝；
- 评测器身份（commit / 树哈希）空值 -> verify 拒绝（不得冒充可复现）；
- 授权状态非法 -> verify 拒绝；
- 合法干净报告 verify 通过。
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.abspath(os.path.join(HERE, "..", "scripts"))
sys.path.insert(0, SCRIPTS)

import evaluate as ev  # noqa: E402
import verify_attestation as va  # noqa: E402


def _report():
    root = tempfile.mkdtemp()
    with open(os.path.join(root, "SKILL.md"), "w", encoding="utf-8") as f:
        f.write("# sample\n")
    return ev.build_attestation(root, 79, "B", {}, [], None)


def test_clean_report_passes():
    assert va.verify(_report()) == []


def test_blocking_without_finding_link_rejected():
    rep = _report()
    rep["blocking_findings"].append({"rule_id": "R-SEC-99", "level": "critical",
                                     "dimension": "安全", "file": "x.py", "line": 1,
                                     "evidence": "未在 findings 回链"})
    assert va.verify(rep)


def test_veto_but_outcome_not_fail_rejected():
    rep = _report()
    rep["safety_veto"] = {"applied": True}
    rep["assessment_outcome"] = "PASS"
    rep["verdict"] = "PASS"
    assert va.verify(rep)


def test_grade_d_but_outcome_not_fail_rejected():
    rep = _report()
    rep["grade"] = "D"
    rep["assessment_outcome"] = "PASS"
    rep["verdict"] = "PASS"
    assert va.verify(rep)


def test_empty_evaluator_identity_rejected():
    rep = _report()
    rep["evaluator_commit"] = ""
    rep["evaluator_tree_sha256"] = None
    assert va.verify(rep)


def test_invalid_auth_status_rejected():
    rep = _report()
    rep["authorization_status"] = "MAYBE"
    assert va.verify(rep)
