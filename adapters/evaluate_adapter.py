#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""evaluate_adapter.py — 主引擎分轨适配层示例（DRAFT，未接入远端仓）。

用途：演示旧 `evaluate_skill` 6 元组如何拆成「评测结果 result」与「授权决策
authorization」两条轨道，并装入 EvidenceObject。本文件是落地时的调用点模板，
不 import 基线脚本；真实接入时把 from_tuple 接到 evaluate.py 的返回值上。

红线（与 authorization.py 一致）：
- result 只承载评测口径；授权状态由 build_authorization 独立产出，不读分数阈值。
- 溯源要素（evaluator/rule_version/subject_fingerprint/provenance/evidence_id/
  coverage/scope）由适配层补齐，缺要素即 INCOMPLETE，不回退 PASS/GRANTED。
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from authorization import (
    AuthorizationDecision,
    AuthStatus,
    assert_separation,
    build_authorization,
)
from evidence import EvidenceObject, build_result


def from_tuple(
    score: int,
    grade: str,
    dims: Mapping[str, int],
    findings: list,
    warnings: list,
    veto_info: dict,
    *,
    evaluator: str,
    rule_version: str,
    subject_fingerprint: str,
    provenance: Mapping[str, Any],
    evidence_id: str,
    coverage: str,
    scope: Optional[str] = None,
    confidence: Optional[float] = None,
    coverage_honesty: Optional[str] = None,
) -> dict:
    """把旧 6 元组转成分轨后的 result 容器（不含授权结论）。

    接入点：evaluate.py 第 801–813 行的分数直通 L0–L5 段删除后，返回值先经
    本函数落 result；授权另走 authorize()。
    """
    result = build_result(
        score=score,
        grade=grade,
        dims=dims,
        findings=findings,
        confidence=confidence,
        coverage_honesty=coverage_honesty,
    )
    # 溯源/覆盖要素并入 result，供授权前置校验与证据对象留痕；不携带授权字段。
    result.update(
        {
            "evaluator": evaluator,
            "rule_version": rule_version,
            "subject_fingerprint": subject_fingerprint,
            "provenance": dict(provenance),
            "evidence_id": evidence_id,
            "coverage": coverage,
            "scope": scope,
            "warnings": list(warnings),
            "veto": dict(veto_info),
        }
    )
    return result


def authorize(
    result: Mapping[str, Any],
    *,
    decision_by: Optional[str] = None,
    policy: Optional[Mapping[str, Any]] = None,
    reviewer: Optional[Mapping[str, Any]] = None,
) -> AuthorizationDecision:
    """独立产出授权决策；不依据 result['score'] 授予授权。"""
    decision = build_authorization(
        result,
        policy=policy,
        decision_by=decision_by,
        fingerprint=result.get("subject_fingerprint"),
        provenance=result.get("provenance"),
        reviewer=reviewer,
    )
    assert_separation(result, decision)
    return decision


def assemble_evidence(
    result: Mapping[str, Any],
    decision: AuthorizationDecision,
    *,
    subject_id: str,
    subject_type: str,
    evidence_level: str = "L1",
    chain: Optional[Mapping[str, Any]] = None,
) -> EvidenceObject:
    """把 result 与 authorization 装入 EvidenceObject；授权字段独立留痕。"""
    evidence = EvidenceObject(
        evidence_id=str(result.get("evidence_id") or ""),
        subject_id=subject_id,
        subject_type=subject_type,
        subject_fingerprint=str(result.get("subject_fingerprint") or ""),
        result=dict(result),
        evidence_level=evidence_level,
        provenance=dict(result.get("provenance") or {}),
        authorization=decision.__dict__.copy(),
        reviewer={},
        chain=dict(chain or {}),
    )
    return evidence


# 接入后必须满足（对齐 INTEGRATION_SPEC_DRAFT 验收断言）：
# 1. result 与 authorization 分轨，assert_separation 通过；
# 2. 高分无独立决策方 -> NOT_GRANTED，不出现 L0 免审批直通；
# 3. CRITICAL 命中 -> result 封顶且 NOT_GRANTED；
# 4. 缺 evaluator/rule_version/fingerprint/provenance -> INCOMPLETE；
# 5. 重复成员/非法 UTF-8/控制字符先于 parse 扫描；
# 6. 双副本逐字节一致，缺一即 parity FAIL。
