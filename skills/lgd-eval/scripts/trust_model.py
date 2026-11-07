#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""trust_model.py —— 统一信任模型：证据等级 / 授权状态 / 结论 / 执行决策 / 评测对象。

定位：把外部研判采纳的三轴模型、统一 Evaluation Subject 与硬规则收敛到一处，
供 Engine 报告、授权判定与 Scout 结果共用同一套枚举与校验口径。

边界（不夸大）：
- 本模块只做字段模型与规则校验，不签发生产授权、不接生产写接口。
- E4 必须有非关联外部复核证据；同生态账号不算第三方，本地自测不得记 E4。
- 哈希一致只证明完整性，不证明来源真实性；无签名机制不宣称不可抵赖。
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

# 统一 Trust Report JSON Schema 版本（语义化；新增可选字段不破坏旧消费者）
REPORT_SCHEMA_VERSION = "1.1.0"

# ---- 三轴 + 执行决策枚举（R2 第二轮整改） ----

EVIDENCE_GRADES = ("E0", "E1", "E2", "E3", "E4")
# 授权状态：NOT_REQUESTED=未请求授权；NOT_GRANTED=需要授权但未获得；UNKNOWN=无法确认
AUTH_STATUSES = ("VALID", "INVALID", "EXPIRED", "REVOKED", "UNKNOWN",
                 "NOT_GRANTED", "NOT_REQUESTED")
SOURCE_IDENTITY_STATUSES = ("KNOWN", "UNKNOWN")
EXEC_APPLICABILITY = ("APPLICABLE", "NOT_APPLICABLE")
# 验收层结论：过渡期保留 INCOMPLETE；INCONCLUSIVE 为证据/状态不足的新口径
VERDICTS = ("PASS", "FAIL", "INCOMPLETE", "INCONCLUSIVE")
# 流程层评测状态
EVAL_STATUSES = ("COMPLETE", "INCOMPLETE", "ERROR")
# 证据状态：SUFFICIENT/INSUFFICIENT/INVALID
EVIDENCE_STATUSES = ("SUFFICIENT", "INSUFFICIENT", "INVALID")
# 评测器身份状态：KNOWN 可解析；UNKNOWN 仅作诊断，不得据此形成可信 PASS
IDENTITY_STATUSES = ("KNOWN", "UNKNOWN")
EXEC_DECISIONS = ("ALLOW", "DENY", "NOT_APPLICABLE")

# 非有效授权（执行场景必须 DENY）
NON_VALID_AUTH = ("UNKNOWN", "NOT_GRANTED", "INVALID", "EXPIRED",
                  "REVOKED", "NOT_REQUESTED")

# Scout 推荐状态机八态
SCOUT_STATES = (
    "DISCOVERED", "REVIEWED", "EVALUATED", "RECOMMENDED",
    "VERIFIED", "REJECTED", "UNKNOWN", "INCOMPLETE",
)

# 本地模拟器 / 未接生产阶段必须随报告披露的残余风险
LOCAL_SIMULATION_RISKS = [
    "授权判定为策略层断言，未接入真实执行端强制拦截",
    "nonce 一次性消费当前为进程内状态，未持久化原子消费",
    "未做容器/进程隔离，运行时行为探测不等同隔离沙箱",
    "无数字签名，当前不具备不可抵赖性；哈希一致不证明来源真实性",
    "同生态账号自评，尚未获得非关联第三方独立复核",
]


def default_evidence_grade(has_local_artifacts: bool,
                           reproducible_locally: bool,
                           external_review: bool = False) -> str:
    """按现有证据默认定级。外部复核缺失时不得返回 E4。

    - E0：无证据。
    - E1：自述 / 配置 / 元数据。
    - E2：本地哈希、日志、版本与报告（默认本地评测级别）。
    - E3：完整输入、环境、命令与可重复结果。
    - E4：非关联复核者独立复现并形成差异报告。
    """
    if external_review:
        return "E4"
    if reproducible_locally and has_local_artifacts:
        return "E3"
    if has_local_artifacts:
        return "E2"
    return "E1"


def validate_trust_fields(evidence_grade: Optional[str],
                          authorization_status: Optional[str],
                          verdict: Optional[str],
                          execution_decision: Optional[str],
                          *,
                          is_execution_scope: bool = False,
                          has_external_review: bool = False,
                          execution_applicability: Optional[str] = None,
                          evaluator_identity_status: Optional[str] = None,
                          evidence_status: Optional[str] = None) -> List[str]:
    """硬规则校验，返回错误原因列表（空即通过）。

    向后兼容：新增可选参数缺省时不报错；一旦传入即按枚举与互斥规则校验。
    """
    errors: List[str] = []

    if evidence_grade not in EVIDENCE_GRADES:
        errors.append("EVIDENCE_GRADE: 非法证据等级 %r（应为 E0–E4）" % evidence_grade)
    if authorization_status not in AUTH_STATUSES:
        errors.append("AUTH_STATUS: 非法授权状态 %r" % authorization_status)
    if verdict not in VERDICTS:
        errors.append("VERDICT: 非法结论 %r（应为 PASS/FAIL/INCOMPLETE/INCONCLUSIVE）" % verdict)
    if execution_decision not in EXEC_DECISIONS:
        errors.append("EXEC_DECISION: 非法执行决策 %r" % execution_decision)
    if execution_applicability is not None and execution_applicability not in EXEC_APPLICABILITY:
        errors.append("EXEC_APPLICABILITY: 非法适用性 %r" % execution_applicability)
    if evaluator_identity_status is not None and evaluator_identity_status not in IDENTITY_STATUSES:
        errors.append("IDENTITY_STATUS: 非法评测器身份状态 %r" % evaluator_identity_status)
    if evidence_status is not None and evidence_status not in EVIDENCE_STATUSES:
        errors.append("EVIDENCE_STATUS: 非法证据状态 %r" % evidence_status)

    # INCOMPLETE/INCONCLUSIVE 不得按 PASS 处理
    if verdict in ("INCOMPLETE", "INCONCLUSIVE") and execution_decision == "ALLOW":
        errors.append("RULE: 评测未完成/结论不确定（%s）不得 ALLOW 执行" % verdict)
    # 执行授权场景下，授权非 VALID 必须 DENY
    non_valid_auth = set(NON_VALID_AUTH)
    if is_execution_scope and authorization_status in non_valid_auth and execution_decision != "DENY":
        errors.append("RULE: 授权状态 %r 在执行场景必须 DENY" % authorization_status)
    # NOT_APPLICABLE 是非执行场景，不得产生 ALLOW
    if execution_applicability == "NOT_APPLICABLE" and execution_decision == "ALLOW":
        errors.append("RULE: NOT_APPLICABLE 场景不得 ALLOW 执行")
    # 评测器身份未知：只能作诊断，不得形成可信 PASS，也不得作为 ALLOW 依据
    if evaluator_identity_status == "UNKNOWN" and verdict == "PASS":
        errors.append("RULE: 评测器身份 UNKNOWN 不得形成可信 PASS")
    if evaluator_identity_status == "UNKNOWN" and execution_decision == "ALLOW":
        errors.append("RULE: 评测器身份 UNKNOWN 不得作为 ALLOW 依据")
    # 证据 INVALID 不得通过；证据不足（INSUFFICIENT）不得形成可信 PASS
    if evidence_status == "INVALID" and verdict == "PASS":
        errors.append("RULE: 证据 INVALID 不得通过验证")
    if evidence_status == "INSUFFICIENT" and verdict == "PASS":
        errors.append("RULE: 证据不足（INSUFFICIENT）不得形成可信 PASS")
    # E4 必须有外部复核；无复核证据不得记 E4
    if evidence_grade == "E4" and not has_external_review:
        errors.append("RULE: E4 需非关联外部复核证据，当前不得记 E4")
    # E4 不代表自动授权
    if evidence_grade == "E4" and execution_decision == "ALLOW":
        errors.append("RULE: E4 证据等级不构成自动执行授权")

    return errors


# 进入 attestation 指纹的 Subject 字段：路径等不可复现项不纳入
FP_SAFE_SUBJECT_KEYS = (
    "source_identity_status", "object_version", "tree_sha256",
    "engine_version", "engine_commit", "rule_version", "analyzer_integrity",
    "evidence_grade", "evidence_status", "verdict", "assessment_outcome",
    "authorization_status", "recommendation", "execution_decision",
    "execution_applicability", "evaluator_identity_status",
)


def fingerprint_subject(subject: Dict[str, Any]) -> Dict[str, Any]:
    """剔除绝对路径等不可复现字段，返回进指纹的 Subject 子集。"""
    return {k: subject.get(k) for k in FP_SAFE_SUBJECT_KEYS}


def build_subject(*,
                  name: Optional[str] = None,
                  source_entry: Optional[str] = None,
                  source_identity_status: str = "UNKNOWN",
                  object_version: Optional[str] = None,
                  tree_sha256: Optional[str] = None,
                  engine_version: Optional[str] = None,
                  engine_commit: Optional[str] = None,
                  rule_version: Optional[str] = None,
                  analyzer_integrity: Optional[Dict[str, Any]] = None,
                  evidence_grade: Optional[str] = None,
                  verdict: Optional[str] = None,
                  assessment_outcome: Optional[str] = None,
                  authorization_status: Optional[str] = None,
                  recommendation: Optional[str] = None,
                  execution_decision: Optional[str] = None,
                  execution_applicability: Optional[str] = None,
                  evidence_status: Optional[str] = None,
                  evaluator_identity_status: Optional[str] = None) -> Dict[str, Any]:
    """统一评测对象（Evaluation Subject）。

    Engine 评测对象、Scout 推荐对象、执行端对象必须引用同一组绑定字段，
    避免"A 版本通过、B 版本推荐、C 版本执行"。缺项记 None / UNKNOWN，不臆造。
    """
    return {
        "name": name,
        "source_entry": source_entry,
        "source_identity_status": source_identity_status or "UNKNOWN",
        "object_version": object_version,
        "tree_sha256": tree_sha256,
        "engine_version": engine_version,
        "engine_commit": engine_commit,
        "rule_version": rule_version,
        "analyzer_integrity": analyzer_integrity,
        "evidence_grade": evidence_grade,
        "evidence_status": evidence_status,
        "verdict": verdict,
        "assessment_outcome": assessment_outcome,
        "authorization_status": authorization_status,
        "recommendation": recommendation,
        "execution_decision": execution_decision,
        "execution_applicability": execution_applicability,
        "evaluator_identity_status": evaluator_identity_status,
    }
