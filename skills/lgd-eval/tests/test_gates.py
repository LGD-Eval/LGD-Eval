#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""评测器侧安全否决与三态负对照测试（离线，纯函数断言）。

覆盖：
- NC-01：高分对象存在 Critical -> 必须阻断（封顶 49）
- Critical/High 封顶阈值
- 干净对象是否决不封顶
- NC-08：SKIPPED / BLOCKED / NOT_VERIFIED 不得当作 PASS
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.abspath(os.path.join(HERE, "..", "scripts"))
sys.path.insert(0, SCRIPTS)

import evaluate as ev  # noqa: E402
import authorization as az  # noqa: E402


def test_critical_finding_caps_at_49():
    # 命中凭证外泄类 Critical 规则
    findings = ["combo.py:8: 凭证文件读取后网络外发（同文件污点）"]
    cap, level, reason = ev.safety_cap(findings)
    assert cap == ev.VETO_CRITICAL
    assert level == "critical"
    # 即使原始分高，也被封到 49，不得放行
    assert cap < 60


def test_high_finding_caps_at_69():
    findings = ["run.py:5: subprocess shell=True 命令执行"]
    cap, level, _ = ev.safety_cap(findings)
    assert cap == ev.VETO_HIGH
    assert level == "high"


def test_clean_findings_no_cap():
    cap, level, _ = ev.safety_cap([])
    assert cap == 100
    assert level == ""


def test_safety_non_pass_status_not_allowed():
    for status in ["NOT_VERIFIED", "BLOCKED", "SKIPPED"]:
        assert az._safety_policy_pass({"status": status, "veto": {"active": False}}) is False


def test_safety_pass_required():
    assert az._safety_policy_pass({"status": "PASS", "veto": {"active": False}}) is True


def test_safety_active_veto_blocks():
    safety = {"status": "FAIL", "veto": {"active": True, "level": "HIGH"}}
    assert az._safety_policy_pass(safety) is False


def test_attestation_binds_evidence_metadata():
    att = ev.build_attestation(os.path.abspath("."), 79, "B", {}, [], None)
    assert att["affiliation"] == "AFFILIATED"
    assert att["rule_version"]
    assert att["engine_version"]
    assert att["authorization"]["status"] == "NOT GRANTED"
    assert att["inputs"]["tree_sha256"]
    assert att["fingerprint"].startswith("sha256:")
