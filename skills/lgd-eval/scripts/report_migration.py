#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""report_migration.py —— 旧版 Trust Report 兼容迁移器。

边界（与 P1-4 整改要求一致）：
- 原始历史报告只读保留；迁移产物作为**新报告**，不冒充历史原始报告；
- 只补缺失字段的默认值，记录迁移来源；**不重算**历史结论与指纹；
- 历史 result_fingerprint / attestation_fingerprint 原样保留，不被新规则覆盖；
- 旧 `verdict` 作为兼容镜像，不作为新的事实来源；新结论以 `assessment_outcome` 为准；
- 缺新字段按 UNKNOWN / false / INCOMPLETE 降级，不臆造；
- 深拷贝隔离嵌套对象：迁移过程不得回改入参的嵌套结构。
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Dict

_MIGRATION_TOOL_VERSION = "report_migration/1.1.0"
_VERDICTS = ("PASS", "FAIL", "INCOMPLETE", "INCONCLUSIVE")


def _canonical(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def migrate_report(report: Dict[str, Any]) -> Dict[str, Any]:
    """返回迁移后的新报告 dict；深拷贝，不修改入参及其嵌套对象。

    :param report: 旧版 Trust Report dict
    :return: 补齐当前 Schema 默认字段的报告副本（新报告）
    """
    # 迁移前原始报告整体摘要：用于回溯来源，不重算原始结论指纹
    source_digest = "sha256:" + hashlib.sha256(
        _canonical(report).encode("utf-8")).hexdigest()
    out: Dict[str, Any] = copy.deepcopy(report)

    # 迁移来源溯源（P1-4）
    out.setdefault("source_schema_version", report.get("schema_version"))
    out["source_report_digest"] = source_digest
    out["migration_tool_version"] = _MIGRATION_TOOL_VERSION
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

    # 证据状态 / 评测器身份缺省记 UNKNOWN/INSUFFICIENT，不写 null、不伪造
    out.setdefault("evidence_status", "INSUFFICIENT")
    out.setdefault("evaluator_identity_status", "UNKNOWN")
    out.setdefault("evaluator_commit", "UNKNOWN")
    out.setdefault("evaluator_tree_sha256", "UNKNOWN")

    # 历史指纹原样保留（显式说明：迁移器不触碰这两个键）
    # result_fingerprint / attestation_fingerprint 不在此重算
    return out
