#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""authorization.py — 授权状态机（P0-2 骨架，DRAFT，未接入远端仓）。

职责边界（红线）：
- 本模块**不读取评测分数作为授予授权的条件**；GRANTED 只能由独立决策方
  （decision_by 非空）且策略校验通过后产生。
- 评测结果（result）与授权决策（authorization）严格分轨；assert_separation
  负责守住这条边界。
- 失败关闭：证据缺失、覆盖不足、缺独立决策方、CRITICAL 命中，一律落到
  INCOMPLETE / UNKNOWN / NOT_GRANTED，绝不回退 PASS/GRANTED。

状态口径对齐《TrustLifecycle状态机与EvidenceSchema》与 P0 文件级清单 2.1。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional


class AuthStatus(str, Enum):
    NOT_GRANTED = "NOT_GRANTED"
    INCOMPLETE = "INCOMPLETE"
    UNKNOWN = "UNKNOWN"
    GRANTED = "GRANTED"


class SeparationViolation(Exception):
    """评测结果与授权结论混轨，或授权由分数自动导出时抛出。"""


# 覆盖诚实度归一化取值
COVERAGE_LIVE = "live"
COVERAGE_SOURCE = "source"
COVERAGE_MANIFEST = "manifest"
COVERAGE_METADATA = "metadata-only"
COVERAGE_EMPTY = "empty"


@dataclass
class AuthorizationDecision:
    status: AuthStatus
    decision_by: Optional[str] = None
    policy_ref: Optional[str] = None
    scope: Optional[str] = None
    decision_at: Optional[str] = None
    expires_at: Optional[str] = None
    reason: str = ""
    evidence_id: Optional[str] = None
    # 复核者独立性；independent 为空/False 时证据等级上限 L2
    reviewer_independent: Optional[bool] = None
    revoked: bool = False
    revoke_reason: Optional[str] = None
    revoked_at: Optional[str] = None


def classify_coverage(inspected: str) -> str:
    """归一化被检查对象的覆盖深度。

    empty / metadata-only 归为不可据此授权的低覆盖；返回取值见模块常量。
    """
    value = (inspected or "").strip().lower()
    if not value:
        return COVERAGE_EMPTY
    if value in (COVERAGE_EMPTY, COVERAGE_METADATA):
        return COVERAGE_METADATA if value == COVERAGE_METADATA else COVERAGE_EMPTY
    if value in (COVERAGE_LIVE, COVERAGE_SOURCE, COVERAGE_MANIFEST):
        return value
    return COVERAGE_METADATA


def _has_required_provenance(result: Mapping[str, Any]) -> tuple[bool, str]:
    """校验授权前置的评测/溯源要素是否齐备。"""
    required = ("evaluator", "rule_version", "subject_fingerprint", "provenance")
    missing = [k for k in required if not result.get(k)]
    if missing:
        return False, "missing provenance/evaluation fields: " + ", ".join(missing)
    return True, ""


def build_authorization(
    result: Mapping[str, Any],
    *,
    policy: Optional[Mapping[str, Any]] = None,
    decision_by: Optional[str] = None,
    fingerprint: Optional[str] = None,
    provenance: Optional[Mapping[str, Any]] = None,
    reviewer: Optional[Mapping[str, Any]] = None,
) -> AuthorizationDecision:
    """组装授权决策。不依据 result 中的分数授予授权。

    失败关闭顺序：
      1. 评测/溯源要素缺失 -> INCOMPLETE
      2. 覆盖为空/仅元数据 -> UNKNOWN
      3. 命中 CRITICAL -> NOT_GRANTED
      4. 无独立决策方 -> NOT_GRANTED
      5. 策略校验未通过 -> NOT_GRANTED
      6. 以上齐备且决策方独立 -> GRANTED（决策方与策略留痕）
    """
    policy = policy or {}
    reviewer = reviewer or {}
    evidence_id = result.get("evidence_id")

    ok_prov, prov_reason = _has_required_provenance(result)
    if not ok_prov:
        return AuthorizationDecision(
            status=AuthStatus.INCOMPLETE,
            reason=prov_reason,
            evidence_id=evidence_id,
        )

    coverage = classify_coverage(str(result.get("coverage", "")))
    if coverage in (COVERAGE_EMPTY, COVERAGE_METADATA):
        return AuthorizationDecision(
            status=AuthStatus.UNKNOWN,
            reason=f"coverage={coverage}; insufficient evidence to authorize",
            evidence_id=evidence_id,
        )

    findings = result.get("findings") or []
    critical = any(
        (f.get("severity") if isinstance(f, Mapping) else None) == "CRITICAL"
        for f in findings
    )
    if critical:
        return AuthorizationDecision(
            status=AuthStatus.NOT_GRANTED,
            reason="CRITICAL finding present; authorization blocked",
            evidence_id=evidence_id,
        )

    if not decision_by:
        return AuthorizationDecision(
            status=AuthStatus.NOT_GRANTED,
            reason="no independent decision_by; score alone cannot grant",
            evidence_id=evidence_id,
        )

    # 策略校验：骨架期仅做存在性/引用一致性占位；正式策略由策略模块提供。
    if policy and not policy.get("policy_ref") and not policy.get("id"):
        return AuthorizationDecision(
            status=AuthStatus.NOT_GRANTED,
            reason="policy reference missing; cannot satisfy policy gate",
            evidence_id=evidence_id,
        )

    independent = bool(reviewer.get("independent")) if reviewer else None
    return AuthorizationDecision(
        status=AuthStatus.GRANTED,
        decision_by=decision_by,
        policy_ref=policy.get("policy_ref") or policy.get("id"),
        scope=result.get("scope"),
        reason="granted by independent decision party under recorded policy",
        evidence_id=evidence_id,
        reviewer_independent=independent,
    )


def assert_separation(
    result: Mapping[str, Any],
    authorization: AuthorizationDecision,
) -> None:
    """断言评测结果与授权结论分轨。违例抛 SeparationViolation。

    - result 中不得携带授权结论字段；
    - authorization.status 不得由 result 分数阈值自动导出（本模块构造时已
      不读分数；此处兜底拦截 result 内夹带的授权标记）。
    """
    leaked = {"authorization", "granted", "permission", "access_granted"}
    for key in result:
        if key in leaked:
            raise SeparationViolation(f"result must not carry authorization field: {key}")
    if authorization.status is AuthStatus.GRANTED and not authorization.decision_by:
        raise SeparationViolation("GRANTED without independent decision_by is forbidden")


def revoke(
    decision: AuthorizationDecision,
    reason: str,
    revoked_at: Optional[str] = None,
) -> AuthorizationDecision:
    """生成撤销记录；旧记录保留，撤销后的决策不可被新引用默认采纳。"""
    return AuthorizationDecision(
        status=AuthStatus.NOT_GRANTED,
        decision_by=decision.decision_by,
        policy_ref=decision.policy_ref,
        scope=decision.scope,
        decision_at=decision.decision_at,
        expires_at=decision.expires_at,
        reason="revoked: " + reason,
        evidence_id=decision.evidence_id,
        reviewer_independent=decision.reviewer_independent,
        revoked=True,
        revoke_reason=reason,
        revoked_at=revoked_at,
    )
