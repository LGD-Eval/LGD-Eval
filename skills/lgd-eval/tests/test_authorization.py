#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""授权策略负对照测试（离线，不触网、不写生产）。

覆盖 NC-03/04/05/06 与 LT-02/03/04 的授权侧断言：
- 无评测记录 -> 拒绝
- 授权未批准 / 撤销 / 过期 -> 拒绝
- 安全否决 active / 三态非 PASS -> 拒绝
- 动作 / 范围 / 环境 / 对象 SHA 不匹配 -> 拒绝
- 对象 SHA 变化后旧授权失效
- 关联项目不得自动获得 L0
- mock 执行入口不产生真实写动作
"""
import os
import sys
import pytest
from datetime import datetime, timezone, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.abspath(os.path.join(HERE, "..", "scripts"))
sys.path.insert(0, SCRIPTS)

import authorization as az  # noqa: E402

_SHA = "a" * 64


def _record(**kw):
    defaults = dict(
        authorization_id="auth-test-001",
        subject_id="skill-a",
        subject_sha256=_SHA,
        action_type="PRODUCTION_WRITE",
        target_scope="repo/x",
        environment="staging",
        status=az.APPROVED,
    )
    defaults.update(kw)
    return az.AuthorizationRecord(**defaults)


def _request(**kw):
    defaults = dict(
        action_type="PRODUCTION_WRITE",
        target_scope="repo/x",
        environment="staging",
        subject_sha256=_SHA,
    )
    defaults.update(kw)
    return defaults


def _evaluation():
    return {"evaluation_id": "eval-1", "score": 96}


def _evaluation_full():
    """P0-2 全维度齐备的评测证明（对象绑定/结论/证据/身份/版本齐备）。"""
    return {
        "evaluation_id": "eval-1",
        "score": 96,
        "assessment_outcome": "PASS",
        "evidence_status": "SUFFICIENT",
        "evaluator_identity_status": "KNOWN",
        "subject_sha256": _SHA,
        "rule_version": "rules-2026-11-07",
        "engine_version": "1.1.0",
    }


def _safety_pass():
    return {"status": "PASS", "veto": {"active": False}}


def test_allow_when_all_conditions_met():
    rec = _record()
    out = az.evaluate_authorization(rec, _evaluation_full(), _safety_pass(), _request())
    assert out["decision"] == "ALLOW"
    assert out["allowed"] is True


def test_deny_without_evaluation():
    rec = _record()
    out = az.evaluate_authorization(rec, None, _safety_pass(), _request())
    assert out["decision"] == "DENY"
    assert any("EVALUATION_VALID" in r for r in out["reasons"])


def test_deny_pending_record():
    rec = _record(status=az.PENDING)
    out = az.evaluate_authorization(rec, _evaluation(), _safety_pass(), _request())
    assert out["decision"] == "DENY"
    assert any("AUTHORIZATION_VALID" in r for r in out["reasons"])


def test_deny_revoked_record():
    rec = _record(status=az.REVOKED, revocation_reason="复核不通过")
    out = az.evaluate_authorization(rec, _evaluation(), _safety_pass(), _request())
    assert out["decision"] == "DENY"
    assert any("撤销" in r for r in out["reasons"])


def test_deny_expired_record():
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    rec = _record(expires_at=past)
    out = az.evaluate_authorization(rec, _evaluation(), _safety_pass(), _request())
    assert out["decision"] == "DENY"
    assert any("过期" in r for r in out["reasons"])


def test_deny_safety_veto_active():
    safety = {"status": "FAIL", "veto": {"active": True, "level": "CRITICAL"}}
    rec = _record()
    out = az.evaluate_authorization(rec, _evaluation(), safety, _request())
    assert out["decision"] == "DENY"
    assert any("SAFETY_POLICY_PASS" in r for r in out["reasons"])


@pytest.mark.parametrize("status", ["NOT_VERIFIED", "BLOCKED", "SKIPPED"])
def test_deny_safety_non_pass_status(status):
    safety = {"status": status, "veto": {"active": False}}
    rec = _record()
    out = az.evaluate_authorization(rec, _evaluation(), safety, _request())
    assert out["decision"] == "DENY"


def test_scope_mismatch_action():
    rec = _record()
    out = az.evaluate_authorization(
        rec, _evaluation(), _safety_pass(), _request(action_type="RELEASE_DEPLOY"))
    assert out["decision"] == "DENY"
    assert any("EXECUTION_SCOPE_MATCH" in r for r in out["reasons"])


def test_scope_mismatch_environment():
    rec = _record()
    out = az.evaluate_authorization(
        rec, _evaluation(), _safety_pass(), _request(environment="production"))
    assert out["decision"] == "DENY"


def test_subject_sha_change_invalidates_old_auth():
    """NC-05 / T01：对象 SHA 变化后，旧授权不得继续放行。"""
    rec = _record(subject_sha256="b" * 64)
    out = az.evaluate_authorization(
        rec, _evaluation(), _safety_pass(), _request(subject_sha256="c" * 64))
    assert out["decision"] == "DENY"
    assert any("SHA" in r for r in out["reasons"])


@pytest.mark.parametrize("affiliation,blocked", [
    ("SELF-EVALUATION", True),
    ("AFFILIATED", True),
    ("EXTERNAL", False),
])
def test_affiliated_blocks_l0(affiliation, blocked):
    assert az.affiliated_self_l0_block(affiliation) is blocked


def test_mock_execute_does_not_run():
    rec = _record()
    decision = {"decision": "DENY", "allowed": False}
    mock = az.mock_execute(rec, decision)
    assert mock["mock"] is True
    assert mock["executed"] is False
    assert "未执行真实写动作" in mock["note"]


# ---------- 第二批 P0-1：T04 / T05 / T06 / T08 / T09 / T10 / T11 / T14 ----------

def test_t04_missing_field_denies():
    rec = _record(authorization_id="")
    out = az.evaluate_authorization(rec, _evaluation(), _safety_pass(), _request())
    assert out["decision"] == "DENY"
    assert any("RECORD_FIELDS" in r for r in out["reasons"])


def test_t04_malformed_sha_denies():
    rec = _record(subject_sha256="not-a-sha")
    out = az.evaluate_authorization(rec, _evaluation(), _safety_pass(), _request())
    assert out["decision"] == "DENY"
    assert any("SHA-256" in r for r in out["reasons"])


def test_t05_unknown_action_type_denies():
    rec = _record(action_type="DEPLOY_TO_MOON")
    out = az.evaluate_authorization(rec, _evaluation(), _safety_pass(), _request())
    assert out["decision"] == "DENY"
    assert any("ACTION_TYPE_UNKNOWN" in r for r in out["reasons"])


def test_t06_scope_target_change_denies():
    rec = _record(target_scope="repo/x")
    out = az.evaluate_authorization(
        rec, _evaluation(), _safety_pass(), _request(target_scope="repo/y"))
    assert out["decision"] == "DENY"
    assert any("EXECUTION_SCOPE_MATCH" in r for r in out["reasons"])


def test_t08_replay_consumed_record_denies():
    rec = _record()
    first = az.evaluate_authorization(rec, _evaluation_full(), _safety_pass(), _request())
    assert first["decision"] == "ALLOW"
    second = az.evaluate_authorization(rec, _evaluation_full(), _safety_pass(), _request())
    assert second["decision"] == "DENY"
    assert any("REPLAY" in r for r in second["reasons"])


def test_t08_nonce_mismatch_denies():
    rec = _record(nonce="nonce-abc")
    out = az.evaluate_authorization(
        rec, _evaluation(), _safety_pass(), _request(nonce="nonce-wrong"))
    assert out["decision"] == "DENY"
    assert any("nonce" in r for r in out["reasons"])


def test_t09_pre_exec_recheck_passes_when_unchanged():
    rec = _record(tree_sha256="d" * 64)
    req = _request()
    out = az.pre_execution_recheck(rec, req, current_tree_sha256="d" * 64)
    assert out["allowed"] is True
    assert out["reasons"] == []


def test_t09_t10_pre_exec_recheck_rejects_on_tree_change():
    rec = _record(tree_sha256="d" * 64)
    req = _request()
    out = az.pre_execution_recheck(rec, req, current_tree_sha256="e" * 64)
    assert out["allowed"] is False
    assert any("树指纹" in r for r in out["reasons"])


def test_t11_medium_restriction_levels():
    assert az.medium_action_restriction(0) == "none"
    assert "L2" in az.medium_action_restriction(1)
    assert "L3" in az.medium_action_restriction(5)


@pytest.mark.parametrize("status", ["ERROR", "INCOMPLETE", "STALE", "UNKNOWN", ""])
def test_t14_non_pass_states_never_grant(status):
    safety = {"status": status, "veto": {"active": False}}
    rec = _record()
    out = az.evaluate_authorization(rec, _evaluation(), safety, _request())
    assert out["decision"] == "DENY"


# ---------- 第三批 R3 P0-1：树指纹缺失 / 格式 / 计算失败 / TOCTOU ----------

def test_p01_record_tree_fingerprint_missing_denies():
    """P0-1 / NC-06：授权记录未绑定树指纹 -> 拒绝。"""
    rec = _record(tree_sha256=None)
    out = az.pre_execution_recheck(rec, _request(), current_tree_sha256="d" * 64)
    assert out["allowed"] is False
    assert any("未绑定对象树指纹" in r for r in out["reasons"])


def test_p01_current_tree_fingerprint_missing_denies():
    """P0-1：执行前取不到当前树指纹 -> 拒绝。"""
    rec = _record(tree_sha256="d" * 64)
    out = az.pre_execution_recheck(rec, _request(), current_tree_sha256=None)
    assert out["allowed"] is False
    assert any("未取得当前对象树指纹" in r for r in out["reasons"])


def test_p01_record_tree_fingerprint_malformed_denies():
    """P0-1：记录树指纹非 64-hex -> 拒绝。"""
    rec = _record(tree_sha256="not-a-tree-sha")
    out = az.pre_execution_recheck(rec, _request(), current_tree_sha256="d" * 64)
    assert out["allowed"] is False
    assert any("格式非法" in r for r in out["reasons"])


def test_p01_current_tree_fingerprint_malformed_denies():
    """P0-1：当前树指纹非 64-hex -> 拒绝。"""
    rec = _record(tree_sha256="d" * 64)
    out = az.pre_execution_recheck(rec, _request(), current_tree_sha256="zzz")
    assert out["allowed"] is False
    assert any("格式非法" in r for r in out["reasons"])


def test_p01_tree_fingerprint_compute_error_denies():
    """P0-1：树指纹计算抛异常 -> 拒绝，不得跳过校验。"""
    rec = _record(tree_sha256="d" * 64)
    out = az.pre_execution_recheck(
        rec, _request(), tree_fingerprint_error=RuntimeError("hash unavailable"))
    assert out["allowed"] is False
    assert any("计算失败" in r for r in out["reasons"])


def test_p01_toctou_object_change_after_recheck_denies():
    """P0-1 / TOCTOU：recheck 通过后对象被替换，执行点二次复核必须拒绝。

    旧 recheck 结果不得跨执行复用；执行前重新取指纹比对，变化即拒绝。
    """
    rec = _record(tree_sha256="d" * 64)
    req = _request()
    first = az.pre_execution_recheck(rec, req, current_tree_sha256="d" * 64)
    assert first["allowed"] is True
    second = az.recheck_before_execute(rec, req, current_tree_sha256="f" * 64)
    assert second["allowed"] is False
    assert any("不一致" in r for r in second["reasons"])


# ---------- 第三批 R3 P0-2：评测证明完整性校验 ----------

def test_p02_weak_evaluation_only_id_denies():
    """P0-2 / NC-03：仅含 evaluation_id 的弱证明进入判定必须 DENY。"""
    rec = _record()
    out = az.evaluate_authorization(rec, _evaluation(), _safety_pass(), _request())
    assert out["decision"] == "DENY"
    assert any("EVALUATION_VALID" in r for r in out["reasons"])


def test_p02_non_pass_outcome_denies():
    ev = _evaluation_full(); ev["assessment_outcome"] = "INCOMPLETE"
    assert len(az._evaluation_validation(ev, _request())) > 0


def test_p02_insufficient_or_invalid_evidence_denies():
    for status in ("INSUFFICIENT", "INVALID"):
        ev = _evaluation_full(); ev["evidence_status"] = status
        reasons = az._evaluation_validation(ev, _request())
        assert any("不得采信" in r for r in reasons)


def test_p02_unknown_identity_denies():
    ev = _evaluation_full(); ev["evaluator_identity_status"] = "UNKNOWN"
    reasons = az._evaluation_validation(ev, _request())
    assert any("UNKNOWN" in r for r in reasons)


def test_p02_subject_sha_mismatch_denies():
    ev = _evaluation_full(); ev["subject_sha256"] = "c" * 64
    reasons = az._evaluation_validation(ev, _request())
    assert any("对象 SHA 与授权请求不一致" in r for r in reasons)


def test_p02_missing_version_fields_denies():
    ev = _evaluation_full()
    ev.pop("rule_version"); ev.pop("engine_version")
    reasons = az._evaluation_validation(ev, _request())
    assert any("规则版本" in r for r in reasons)
    assert any("引擎版本" in r for r in reasons)


def test_p02_evidence_binding_break_denies():
    """P0-2：证据条目回链到别的对象 SHA -> 绑定断裂判无效。"""
    ev = _evaluation_full()
    ev["evidence"] = [{"subject_sha256": "0" * 64, "rule_version": "rules-2026-11-07"}]
    reasons = az._evaluation_validation(ev, _request())
    assert any("证据 #0 对象 SHA 与报告不一致" in r for r in reasons)


def test_p02_full_evaluation_validates():
    """P0-2 正向：全维度齐备评测证明通过完整性校验。"""
    reasons = az._evaluation_validation(_evaluation_full(), _request())
    assert reasons == []
