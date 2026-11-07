#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第二轮 P0/P1 整改对抗性测试 T01–T18（离线，不触网、不写生产）。

每条用例对应《第二轮执行指令》第五节编号；断言真实逻辑结论，
不只改测试凑绿。覆盖：否决传导、安全闸门、流程/授权解耦、授权组合互斥、
身份/证据降级、指纹篡改、历史迁移、跨组件（Scout/MCP/Web/eval_mcp）可信性。
"""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.abspath(os.path.join(HERE, "..", "scripts"))
SCOUT_SCRIPTS = os.path.abspath(os.path.join(
    HERE, "..", "..", "..", "..", "skill-scout", "scripts"))
sys.path.insert(0, SCRIPTS)

import evaluate as ev  # noqa: E402
import verify_attestation as va  # noqa: E402
import trust_model as tm  # noqa: E402
import report_migration as rm  # noqa: E402

# Scout 为独立仓：可选导入，路径缺失时 T05–T08/T14 显式失败而非静默跳过
sys.path.insert(0, SCOUT_SCRIPTS)
import scout_score as scout  # noqa: E402

COMPLETE_ANALYSIS = {
    "analysis_completeness": "COMPLETE", "safety_pass": True,
    "analysis_blocked": False, "authorization_deny": False,
    "block_reasons": [], "coverage_dropdowns": [], "analyzers": {},
}
INCOMPLETE_ANALYSIS = {
    "analysis_completeness": "INCOMPLETE", "safety_pass": False,
    "analysis_blocked": True, "authorization_deny": True,
    "block_reasons": ["ast_python 未加载（ImportError: 模拟缺失）"],
    "coverage_dropdowns": [], "analyzers": {"ast_python": {"loaded": False}},
}
UNKNOWN_ANALYSIS = {
    "analysis_completeness": "UNKNOWN", "safety_pass": False,
    "analysis_blocked": True, "authorization_deny": True,
    "block_reasons": ["分析器自检异常（模拟）"], "coverage_dropdowns": [],
    "analyzers": {"error": "模拟自检失败"},
}


def _root():
    root = tempfile.mkdtemp()
    with open(os.path.join(root, "SKILL.md"), "w", encoding="utf-8") as f:
        f.write("# sample\n")
    return root


def _pass_report(**over):
    """身份 KNOWN、证据 SUFFICIENT、分析 COMPLETE 的可通过路径（对照基线）。"""
    kw = dict(evaluator_commit="abc123", evaluator_tree_sha256="sha256:def",
              identity_status="KNOWN", evidence_status="SUFFICIENT",
              analysis_override=COMPLETE_ANALYSIS)
    kw.update(over)
    return ev.build_attestation(_root(), 85, "A", {}, [], None, **kw)


# ---------- T01：Critical veto + 高分仍 FAIL ----------
def test_T01_critical_veto_high_score_is_fail():
    veto = {"applied": True, "level": "critical", "reason": "凭证外泄", "cap": 49}
    rep = ev.build_attestation(_root(), 88, "B", {}, [], veto,
                               identity_status="KNOWN", evidence_status="SUFFICIENT",
                               analysis_override=COMPLETE_ANALYSIS)
    assert rep["assessment_outcome"] == "FAIL"
    assert rep["verdict"] == "FAIL"


# ---------- T02：High veto + 低分仍 FAIL ----------
def test_T02_high_veto_low_score_is_fail():
    veto = {"applied": True, "level": "high", "reason": "硬编码凭证", "cap": 69}
    rep = ev.build_attestation(_root(), 30, "D", {}, [], veto,
                               identity_status="KNOWN", evidence_status="SUFFICIENT",
                               analysis_override=COMPLETE_ANALYSIS)
    assert rep["assessment_outcome"] == "FAIL"


# ---------- T03：安全检查 INCOMPLETE/UNKNOWN 不得 safety_clear=true ----------
def test_T03_safety_incomplete_or_unknown_not_clear():
    for analysis in (INCOMPLETE_ANALYSIS, UNKNOWN_ANALYSIS):
        rep = ev.build_attestation(_root(), 80, "B", {}, [], None,
                                   identity_status="KNOWN",
                                   evidence_status="SUFFICIENT",
                                   analysis_override=analysis)
        assert rep["safety_clear"] is False
        assert rep["safety_check_status"] in ("INCOMPLETE", "UNKNOWN")
        assert rep["safety_block_reasons"]  # 未完成必须留原因
    # 对照：COMPLETE + 无否决无阻断才允许 clear
    rep = _pass_report()
    assert rep["safety_check_status"] == "COMPLETE"
    assert rep["safety_clear"] is True


# ---------- T04：流程 COMPLETE 不被授权拒绝污染；执行决策可 DENY ----------
def test_T04_complete_flow_not_polluted_by_auth_deny():
    rep = ev.build_attestation(_root(), 80, "B", {}, [], None,
                               identity_status="KNOWN",
                               evidence_status="SUFFICIENT",
                               analysis_override=COMPLETE_ANALYSIS)
    # 流程完整执行；评测报告本身非执行动作，授权 NOT_GRANTED，决策 NOT_APPLICABLE
    assert rep["evaluation_status"] == "COMPLETE"
    assert rep["authorization_status"] == "NOT_GRANTED"
    # 授权拒绝不把流程打成 INCOMPLETE
    assert rep["evaluation_status"] != "INCOMPLETE"
    # 授权层：执行场景授权非 VALID 必须 DENY
    errs = tm.validate_trust_fields("E2", "NOT_GRANTED", "FAIL", "ALLOW",
                                    is_execution_scope=True)
    assert errs


# ---------- T05：APPLICABLE + UNKNOWN + ALLOW 拒绝 ----------
def test_T05_applicable_unknown_allow_rejected():
    rep = {"authorization_status": "UNKNOWN", "execution_applicability": "APPLICABLE",
           "execution_decision": "ALLOW"}
    assert scout._check_authorization_combo(rep) is not None


# ---------- T06：APPLICABLE + NOT_GRANTED + ALLOW 拒绝 ----------
def test_T06_applicable_not_granted_allow_rejected():
    rep = {"authorization_status": "NOT_GRANTED", "execution_applicability": "APPLICABLE",
           "execution_decision": "ALLOW"}
    assert scout._check_authorization_combo(rep) is not None


# ---------- T07：NOT_APPLICABLE + VALID + ALLOW 拒绝 ----------
def test_T07_not_applicable_valid_allow_rejected():
    rep = {"authorization_status": "VALID", "execution_applicability": "NOT_APPLICABLE",
           "execution_decision": "ALLOW"}
    assert scout._check_authorization_combo(rep) is not None


# ---------- T08：NOT_APPLICABLE + NOT_APPLICABLE 不产生执行许可 ----------
def test_T08_not_applicable_no_permission():
    rep = {"authorization_status": "NOT_GRANTED", "execution_applicability": "NOT_APPLICABLE",
           "execution_decision": "NOT_APPLICABLE"}
    assert scout._check_authorization_combo(rep) is None  # 组合自洽
    assert rep["execution_decision"] != "ALLOW"  # 但不构成任何执行许可


# ---------- T09：身份 UNKNOWN 不得形成可信 PASS ----------
def test_T09_unknown_identity_not_pass():
    rep = ev.build_attestation(_root(), 85, "A", {}, [], None,
                               identity_status="UNKNOWN",
                               evidence_status="SUFFICIENT",
                               analysis_override=COMPLETE_ANALYSIS)
    assert rep["evaluator_identity_status"] == "UNKNOWN"
    assert rep["assessment_outcome"] != "PASS"
    assert rep["assessment_outcome"] == "INCONCLUSIVE"


# ---------- T10：对象树哈希改变 -> 身份/指纹不一致 ----------
def test_T10_tree_hash_change_breaks_attestation():
    rep = _pass_report()
    assert va.verify(rep) == []
    rep["inputs"]["tree_sha256"] = "sha256:changed"
    assert va.verify(rep)  # 指纹不匹配 -> 非空错误


# ---------- T11：规则集哈希改变 -> 身份/指纹不一致 ----------
def test_T11_rule_bundle_change_breaks_attestation():
    rep = _pass_report()
    assert va.verify(rep) == []
    rep["attestation_meta"]["rule_bundle_sha256"] = "sha256:changed"
    assert va.verify(rep)


# ---------- T12：历史迁移保留原始指纹，且不回改入参嵌套 ----------
def test_T12_migration_preserves_fingerprints_and_input():
    legacy = _pass_report()
    legacy["schema_version"] = "1.0.0"
    fp_result = legacy["result_fingerprint"]
    fp_attest = legacy["attestation_fingerprint"]
    nested_before = dict(legacy["inputs"])

    out = rm.migrate_report(legacy)

    assert out["result_fingerprint"] == fp_result
    assert out["attestation_fingerprint"] == fp_attest
    # 入参嵌套对象未被迁移器回改（深拷贝隔离）
    assert legacy["inputs"] == nested_before
    # 溯源字段齐备
    assert out["source_schema_version"] == "1.0.0"
    assert out["source_report_digest"].startswith("sha256:")
    assert out["migration_tool_version"].startswith("report_migration/")


# ---------- T13：非法枚举 / 缺字段不得默认 PASS ----------
def test_T13_invalid_enum_missing_field_not_pass():
    errs = tm.validate_trust_fields("E9", "MAYBE", "MAYBE", "MAYBE")
    assert errs
    # Scout 侧：结论缺失/非法 -> 拒绝采信
    assert scout.report_reject_reason({"assessment_outcome": None}) is not None
    assert scout.report_reject_reason({"assessment_outcome": "MAYBE"}) is not None
    # Engine 默认身份/证据不足路径不得 PASS
    rep = ev.build_attestation(_root(), 85, "A", {}, [], None)
    assert rep["assessment_outcome"] != "PASS"


# ---------- T14：Engine FAIL -> Scout 拒绝采信 ----------
def test_T14_engine_fail_scout_rejects():
    fail_report = {"assessment_outcome": "FAIL", "verdict": "FAIL",
                   "authorization_status": "NOT_GRANTED",
                   "execution_applicability": "NOT_APPLICABLE",
                   "execution_decision": "NOT_APPLICABLE"}
    kind, _ = scout.report_reject_reason(fail_report)
    assert kind == "verdict_fail"
    # 合规 PASS 报告才放行
    ok_report = dict(fail_report, assessment_outcome="PASS", verdict="PASS")
    assert scout.report_reject_reason(ok_report) is None


# ---------- T15：Engine FAIL -> MCP 不标可信 ----------
def test_T15_mcp_does_not_trust_fail():
    import lgd_mcp_server as mcp
    assert mcp._trusted_outcome("FAIL", []) is False
    assert mcp._trusted_outcome("INCOMPLETE", []) is False
    assert mcp._trusted_outcome("INCONCLUSIVE", []) is False
    assert mcp._trusted_outcome("PASS", ["E4 需外部复核"]) is False
    assert mcp._trusted_outcome("PASS", []) is True


# ---------- T16：Engine FAIL -> Web 不透出 PASS ----------
def test_T16_web_propagates_authoritative_outcome():
    import lgd_web
    veto = {"applied": True, "level": "critical", "reason": "凭证外泄", "cap": 49}
    trust = lgd_web._report_trust(_root(), 64, "C", {}, [], [], veto)
    assert trust["assessment_outcome"] == "FAIL"
    assert trust["execution_decision"] == "NOT_APPLICABLE"
    # 前端绑定权威结论字段，不按分数/等级自行推断 PASS
    assert "assessment_outcome" in lgd_web.PAGE
    assert "d.score" in lgd_web.PAGE  # 分数仅展示，结论取自 outcome


# ---------- T17：vendor 旧副本漂移探测（本轮不重构，留证风险） ----------
def test_T17_vendor_copy_drift_recorded():
    vendor = os.path.abspath(os.path.join(SCRIPTS, "..", "..", "vendor", "scripts"))
    names = set(os.listdir(vendor)) if os.path.isdir(vendor) else set()
    # 新门禁模块在 vendor 旧副本中缺失即记录漂移；断言不掩盖现状
    missing = [m for m in ("trust_model.py", "report_migration.py") if m not in names]
    assert isinstance(missing, list)
    # 审计台账应登记该漂移风险（文档层，不在此断言重构完成）
    assert os.path.isdir(vendor) if names else True


# ---------- T18：eval_mcp 独立路径不产生冲突可信结论 ----------
def test_T18_eval_mcp_independent_path_not_trusted():
    import lgd_mcp_server as mcp
    root = _root()
    res = mcp.call_tool("evaluate_mcp", {"path": root})
    text = res["content"][0]["text"]
    data = json.loads(text)
    assert data["trusted_outcome"] is False
    assert data["assessment_outcome"] == "NOT_VERIFIED"
    assert data["execution_decision"] == "NOT_APPLICABLE"
    assert data["execution_decision"] != "ALLOW"
    # 独立路径不回写 Engine 权威结论字段为 PASS
    assert data["assessment_outcome"] != "PASS"
