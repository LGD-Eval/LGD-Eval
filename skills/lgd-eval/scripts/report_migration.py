#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""report_migration.py —— 旧版 Trust Report 兼容迁移器。

边界（与 P1-8 整改设计一致）：
- 只补缺失字段的默认值，记录迁移来源；**不重算**历史结论与指纹；
- 历史报告的 result_fingerprint / attestation_fingerprint 原样保留，不被新规则覆盖；
- 旧 `verdict` 作为兼容镜像，不作为新的事实来源；新结论以 `assessment_outcome` 为准；
- 缺新字段按 UNKNOWN / false / INCOMPLETE 降级，不臆造。
"""

from __future__ import annotations

from typing import Any, Dict

_VERDICTS = ("PASS", "FAIL", "INCOMPLETE")


def migrate_report(report: Dict[str, Any]) -> Dict[str, Any]:
    """返回迁移后的新 dict；不修改入参。

    :param report: 旧版 Trust Report dict
    :return: 补齐当前 Schema 默认字段的报告副本
    """
    out: Dict[str, Any] = dict(report)

    # 记录迁移来源；历史 schema_version 原样保留
    out.setdefault("migrated_from", report.get("schema_version"))

    # 结论兼容：旧 verdict 镜像到 assessment_outcome；非法/缺失记 INCOMPLETE
    verdict = report.get("verdict")
    if "assessment_outcome" not in out:
        out["assessment_outcome"] = verdict if verdict in _VERDICTS else "INCOMPLETE"
    out.setdefault("evaluation_status",
                   "INCOMPLETE" if out["assessment_outcome"] == "INCOMPLETE" else "COMPLETE")

    # 安全三态默认降级
    out.setdefault("safety_check_status", "UNKNOWN")
    out.setdefault("safety_clear", False)

    # 授权 / 执行分层默认值
    out.setdefault("authorization_status", "UNKNOWN")
    out.setdefault("execution_applicability", "NOT_APPLICABLE")
    out.setdefault("execution_decision", "NOT_APPLICABLE")

    # 评测器身份缺省记 UNKNOWN，不写 null、不伪造
    out.setdefault("evaluator_commit", "UNKNOWN")
    out.setdefault("evaluator_tree_sha256", "UNKNOWN")

    # 历史指纹原样保留（显式说明：迁移器不触碰这两个键）
    # result_fingerprint / attestation_fingerprint 不在此重算
    return out
