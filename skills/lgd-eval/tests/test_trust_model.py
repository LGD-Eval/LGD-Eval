#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""三轴信任模型 + 统一 Subject 硬规则负对照（离线）。

覆盖：
- 枚举合法性；非法证据等级 / 授权状态 / 结论 / 执行决策必须报错；
- INCOMPLETE 不得 ALLOW；执行场景 UNKNOWN 必须 DENY；
- E4 无外部复核不可达；E4 不自动授权；
- Subject 指纹子集剔除绝对路径与目录名，保证可复现；
- attestation 报告携带三轴与 Subject，且受指纹保护（篡改后 verify 失败）。
"""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.abspath(os.path.join(HERE, "..", "scripts"))
sys.path.insert(0, SCRIPTS)

import evaluate as ev  # noqa: E402
import verify_attestation as va  # noqa: E402
import trust_model as tm  # noqa: E402


def _report():
    root = tempfile.mkdtemp()
    with open(os.path.join(root, "SKILL.md"), "w", encoding="utf-8") as f:
        f.write("# sample\n")
    return ev.build_attestation(root, 79, "B", {}, [], None)


def test_valid_default_fields_present():
    rep = _report()
    assert rep["evidence_grade"] in tm.EVIDENCE_GRADES
    assert rep["authorization_status"] in tm.AUTH_STATUSES
    assert rep["verdict"] in tm.VERDICTS
    assert rep["execution_decision"] in tm.EXEC_DECISIONS
    assert rep["subject"]["tree_sha256"]
    # 本地无外部复核，不可记 E4
    assert rep["evidence_grade"] != "E4"
    # 评测报告非执行动作
    assert rep["execution_decision"] == "NOT_APPLICABLE"


def test_invalid_enum_rejected():
    errs = tm.validate_trust_fields("E9", "MAYBE", "MAYBE", "MAYBE")
    assert len(errs) >= 4


def test_incomplete_cannot_allow():
    errs = tm.validate_trust_fields("E2", "UNKNOWN", "INCOMPLETE", "ALLOW",
                                    is_execution_scope=True)
    assert any("INCOMPLETE" in e for e in errs)


def test_unknown_auth_must_deny_in_execution_scope():
    errs = tm.validate_trust_fields("E2", "UNKNOWN", "FAIL", "ALLOW",
                                    is_execution_scope=True)
    assert any("UNKNOWN" in e for e in errs)


def test_e4_unreachable_without_external_review():
    errs = tm.validate_trust_fields("E4", "UNKNOWN", "PASS", "NOT_APPLICABLE",
                                    has_external_review=False)
    assert any("E4" in e for e in errs)


def test_e4_does_not_auto_authorize():
    errs = tm.validate_trust_fields("E4", "VALID", "PASS", "ALLOW",
                                    has_external_review=True)
    assert any("E4" in e and "授权" in e for e in errs)


def test_subject_fp_subset_drops_path_and_name():
    subject = tm.build_subject(name="tmpdir", source_entry="C:/abs/path",
                               tree_sha256="sha256:abc")
    fp = tm.fingerprint_subject(subject)
    assert "source_entry" not in fp
    assert "name" not in fp
    assert fp["tree_sha256"] == "sha256:abc"


def test_attestation_verify_passes():
    rep = _report()
    assert va.verify(rep) == []


def test_tampered_evidence_grade_fails_verify():
    rep = _report()
    rep["evidence_grade"] = "E4"  # 篡改证据等级
    assert va.verify(rep)  # 指纹不匹配 -> 非空错误


def test_blocking_findings_list_only_critical_high():
    root = tempfile.mkdtemp()
    with open(os.path.join(root, "SKILL.md"), "w", encoding="utf-8") as f:
        f.write("# sample\n")
    evidence = [
        {"rule_id": "R-SEC-01", "dimension": "安全检查", "file": "a.py",
         "line": 3, "evidence": "硬编码凭证", "fix": "", "verify": "", "severity": "finding"},
        {"rule_id": "R-STR-01", "dimension": "结构完整性", "file": "SKILL.md",
         "line": 0, "evidence": "缺少 name 字段", "fix": "", "verify": "", "severity": "finding"},
    ]
    rep = ev.build_attestation(root, 79, "B", {}, evidence, None)
    blocking = rep["blocking_findings"]
    assert len(blocking) == 1
    assert blocking[0]["rule_id"] == "R-SEC-01"
    assert blocking[0]["level"] == "high"
    # 结构类普通 finding 不进阻断清单
    assert all(b["rule_id"] != "R-STR-01" for b in blocking)
    assert va.verify(rep) == []


def test_not_granted_is_valid_auth_status():
    assert "NOT_GRANTED" in tm.AUTH_STATUSES


def test_non_valid_auth_must_deny_in_execution_scope():
    for status in ("INVALID", "EXPIRED", "REVOKED", "NOT_GRANTED"):
        errs = tm.validate_trust_fields("E2", status, "FAIL", "ALLOW",
                                        is_execution_scope=True)
        assert any(status in e for e in errs), status


def test_not_applicable_cannot_allow():
    errs = tm.validate_trust_fields("E2", "VALID", "PASS", "ALLOW",
                                   execution_applicability="NOT_APPLICABLE")
    assert any("NOT_APPLICABLE" in e for e in errs)


def test_report_carries_new_trust_fields():
    rep = _report()
    for key in ("evaluation_status", "assessment_outcome", "safety_check_status",
                "safety_clear", "execution_applicability", "evaluator_tree_sha256"):
        assert key in rep, key
    # 过渡期 verdict 镜像 assessment_outcome
    assert rep["assessment_outcome"] == rep["verdict"]


def test_grade_d_is_fail_even_without_veto():
    root = tempfile.mkdtemp()
    with open(os.path.join(root, "SKILL.md"), "w", encoding="utf-8") as f:
        f.write("# sample\n")
    rep = ev.build_attestation(root, 55, "D", {}, [], None)
    assert rep["assessment_outcome"] == "FAIL"


def test_veto_applied_is_fail():
    root = tempfile.mkdtemp()
    with open(os.path.join(root, "SKILL.md"), "w", encoding="utf-8") as f:
        f.write("# sample\n")
    veto = {"applied": True, "level": "critical", "reason": "凭证外泄", "cap": 49}
    rep = ev.build_attestation(root, 80, "B", {}, [], veto)
    assert rep["assessment_outcome"] == "FAIL"
    assert rep["safety_veto"]["applied"] is True
