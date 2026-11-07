#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""authorization.py —— 评测侧 / 授权侧分离的授权策略骨架。

边界（与 P0 整改设计一致）：
- 评测侧只产出 Trust Score、风险等级、测试覆盖与**建议档位（advisory）**，
  不签发生产授权凭证，不调用生产写接口，不把分数解释为执行许可。
- 授权侧在实际执行动作的控制边界上逐次校验授权；默认拒绝。
- 本模块当前为**接口设计 + mock 执行入口**；当前没有真实生产授权链路，
  不虚构一个已经运行的 Authorization Gate。将来接入生产执行系统时，
  再验证执行侧的强制拦截。

判定条件（任一不满足即 DENY）：
    ALLOW = EVALUATION_VALID
            AND AUTHORIZATION_VALID
            AND SAFETY_POLICY_PASS
            AND EXECUTION_SCOPE_MATCH

授权必须绑定对象 SHA-256、动作类型、目标范围、环境与有效期；
对象变化后旧授权失效，不允许仅凭旧评测分数继续执行。
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from trust_model import (
    LOCAL_SIMULATION_RISKS, VERDICTS, EVIDENCE_STATUSES, IDENTITY_STATUSES,
    EVAL_STATUSES,
)

# 授权记录状态
PENDING = "PENDING"
APPROVED = "APPROVED"
REJECTED = "REJECTED"
REVOKED = "REVOKED"
EXPIRED = "EXPIRED"
AUTH_STATUSES = {PENDING, APPROVED, REJECTED, REVOKED, EXPIRED}

# 必须单独授权的高风险动作（高分不免单独授权）
HIGH_RISK_ACTIONS = {
    "RELEASE_DEPLOY",      # 对外发布 / 部署 / 上线 / 创建 Release
    "PRODUCTION_WRITE",   # 生产环境写入 / 修改 / 删除
    "PERMISSION_CHANGE",  # 账号 / 仓库 / 组织权限或安全策略变更
    "SECRET_ACCESS",       # 读取 / 导出 / 传输 / 使用凭证、密钥及敏感数据
    "UNTRUSTED_EXEC",      # 执行不可信代码 / 插件 / Skill / 外部脚本
    "RULE_CHANGE",         # 修改评测规则 / 评分器 / 安全检测器 / 授权策略
    "IP_CHANGE",           # 修改 License / 版权 / 署名 / 归属 / 知识产权声明
    "EXTERNAL_SEND",       # 向外部系统发送有实际业务影响的请求
}

# 允许的动作类型白名单：未登记动作类型默认拒绝
KNOWN_ACTIONS = HIGH_RISK_ACTIONS | {
    "READ_ONLY",          # 只读 / 只读调用
    "EVALUATE",           # 评测动作本身
}

# 不得视为 PASS 的安全状态（含历史 / 未完成 / 不完整 / 陈旧 / 错误）
NON_PASS_STATUSES = {
    "NOT_VERIFIED", "BLOCKED", "SKIPPED", "ERROR", "INCOMPLETE",
    "STALE", "UNKNOWN", "",
}

import re as _re
_SHA_RE = _re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass
class AuthorizationRecord:
    """授权记录最小字段模型。"""

    authorization_id: str
    subject_id: str
    subject_sha256: str
    action_type: str
    target_scope: str
    environment: str
    evaluation_id: Optional[str] = None
    evaluation_score: Optional[int] = None
    evaluation_rule_version: Optional[str] = None
    policy_version: Optional[str] = None
    evidence_hashes: List[str] = field(default_factory=list)
    issuer: Optional[str] = None
    reviewer: Optional[str] = None
    approver: Optional[str] = None
    issued_at: Optional[str] = None
    expires_at: Optional[str] = None
    status: str = PENDING
    revocation_reason: Optional[str] = None
    audit_reference: Optional[str] = None
    decision_reason: Optional[str] = None
    tree_sha256: Optional[str] = None
    nonce: Optional[str] = None
    consumed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def is_expired(record: AuthorizationRecord, now: Optional[datetime] = None) -> bool:
    now = now or datetime.now(timezone.utc)
    exp = _parse_ts(record.expires_at)
    return exp is not None and now >= exp


def _evaluation_validation(evaluation: Optional[Dict[str, Any]],
                           request: Optional[Dict[str, Any]] = None) -> List[str]:
    """逐项核验评测证明完整性，返回拒绝原因列表（空即有效）。

    授权侧只承认"可绑定对象、结论/证据/身份齐备、版本可追溯、指纹可复算"
    的评测证明；任何关键字段缺失、非法、矛盾或无法复算均不得通过授权门禁。
    本函数只做口径判定，不签发生产授权，也不重复实现指纹计算。
    """
    reasons: List[str] = []
    if not evaluation:
        reasons.append("EVALUATION_VALID: 缺少评测记录")
        return reasons

    # 1. 评测编号
    if not evaluation.get("evaluation_id"):
        reasons.append("EVALUATION_VALID: 缺少 evaluation_id")

    # 2. 验收结论：须属合法枚举；非 PASS 不得作为放行依据
    outcome = evaluation.get("assessment_outcome") or evaluation.get("verdict")
    if outcome not in VERDICTS:
        reasons.append("EVALUATION_VALID: 验收结论缺失或非法（%r）" % outcome)
    elif outcome != "PASS":
        reasons.append("EVALUATION_VALID: 验收结论非 PASS，不得作为放行依据")

    # 3. 证据状态：INVALID/INSUFFICIENT 不得采信
    ev = evaluation.get("evidence_status")
    if ev not in EVIDENCE_STATUSES:
        reasons.append("EVALUATION_VALID: 证据状态缺失或非法（%r）" % ev)
    elif ev in ("INSUFFICIENT", "INVALID"):
        reasons.append("EVALUATION_VALID: 证据 %s 不得采信" % ev)

    # 3b. 评测状态：仅 COMPLETE 可作为放行依据
    es = evaluation.get("evaluation_status")
    if es not in EVAL_STATUSES:
        reasons.append("EVALUATION_VALID: 评测状态缺失或非法（%r）" % es)
    elif es != "COMPLETE":
        reasons.append("EVALUATION_VALID: 评测状态非 COMPLETE，不得作为放行依据")

    # 4. 评测器身份：UNKNOWN 仅作诊断，不得作为放行依据
    ident = evaluation.get("evaluator_identity_status")
    if ident not in IDENTITY_STATUSES:
        reasons.append("EVALUATION_VALID: 评测器身份缺失或非法（%r）" % ident)
    elif ident == "UNKNOWN":
        reasons.append("EVALUATION_VALID: 评测器身份 UNKNOWN 仅作诊断，不得作为放行依据")

    # 5. 被评对象 SHA：合法 64-hex 且与授权请求一致
    eval_sha = evaluation.get("subject_sha256")
    if not eval_sha or not _SHA_RE.match(eval_sha):
        reasons.append("EVALUATION_VALID: 被评对象 SHA 缺失或非 64-hex")
    elif request and eval_sha != request.get("subject_sha256"):
        reasons.append("EVALUATION_VALID: 评测对象 SHA 与授权请求不一致")

    # 6. 版本可追溯：规则版本 + 引擎版本或 commit 非空
    if not evaluation.get("rule_version"):
        reasons.append("EVALUATION_VALID: 缺少规则版本（rule_version）")
    if not (evaluation.get("engine_version") or evaluation.get("engine_commit")):
        reasons.append("EVALUATION_VALID: 缺少引擎版本或 commit")

    # 7. 报告-证据绑定：证据条目须回链同一评测记录/对象/规则版本
    evidence = evaluation.get("evidence") or evaluation.get("evidence_items") or []
    if isinstance(evidence, list):
        for idx, item in enumerate(evidence):
            if not isinstance(item, dict):
                continue
            if item.get("evaluation_id") and \
                    item.get("evaluation_id") != evaluation.get("evaluation_id"):
                reasons.append("EVALUATION_VALID: 证据 #%d 未回链同一评测记录" % idx)
            if item.get("subject_sha256") and eval_sha and \
                    item.get("subject_sha256") != eval_sha:
                reasons.append("EVALUATION_VALID: 证据 #%d 对象 SHA 与报告不一致" % idx)
            if item.get("rule_version") and \
                    item.get("rule_version") != evaluation.get("rule_version"):
                reasons.append("EVALUATION_VALID: 证据 #%d 规则版本与报告不一致" % idx)

    # 8. 报告双指纹独立复算（携带完整报告时复用独立校验器）
    report = evaluation.get("report")
    if isinstance(report, dict):
        try:
            from verify_attestation import verify as _verify_attestation
            for ve in _verify_attestation(report):
                reasons.append("EVALUATION_VALID: 报告证明校验失败：%s" % ve)
        except Exception as exc:  # 校验器异常同样不得放行
            reasons.append("EVALUATION_VALID: 报告证明校验异常：%s" % type(exc).__name__)

    return reasons


def _evaluation_valid(evaluation: Optional[Dict[str, Any]],
                      request: Optional[Dict[str, Any]] = None) -> bool:
    return len(_evaluation_validation(evaluation, request)) == 0


def _authorization_valid(record: AuthorizationRecord) -> bool:
    if record.status != APPROVED:
        return False
    if record.revocation_reason:
        return False
    if is_expired(record):
        return False
    return True


def _safety_policy_pass(safety: Optional[Dict[str, Any]]) -> bool:
    """安全策略是否放行。

    - 存在 active Critical / High veto -> 不放行。
    - 非 PASS 状态（NOT_VERIFIED/BLOCKED/SKIPPED/ERROR/INCOMPLETE/STALE/
      UNKNOWN/空）一律不放行，不得当作 PASS。
    """
    if not safety:
        return False
    veto = safety.get("veto") or {}
    if veto.get("active"):
        return False
    status = (safety.get("status") or "").upper()
    if status in NON_PASS_STATUSES:
        return False
    return status == "PASS"


def _record_fields_valid(record: AuthorizationRecord) -> List[str]:
    """关键字段完整性 / 格式校验，返回错误原因列表（空即通过）。"""
    errors: List[str] = []
    required = {
        "authorization_id": record.authorization_id,
        "subject_id": record.subject_id,
        "subject_sha256": record.subject_sha256,
        "action_type": record.action_type,
        "target_scope": record.target_scope,
        "environment": record.environment,
    }
    for name, value in required.items():
        if value is None or (isinstance(value, str) and not value.strip()):
            errors.append("RECORD_FIELDS: 字段 %s 缺失或为空" % name)
    if record.subject_sha256 and not _SHA_RE.match(record.subject_sha256):
        errors.append("RECORD_FIELDS: subject_sha256 不是合法 SHA-256（64 hex）")
    if record.tree_sha256 and not _SHA_RE.match(record.tree_sha256):
        errors.append("RECORD_FIELDS: tree_sha256 不是合法 SHA-256（64 hex）")
    return errors


def _action_known(action_type: str) -> bool:
    return action_type in KNOWN_ACTIONS


def pre_execution_recheck(record: AuthorizationRecord, request: Dict[str, Any],
                          current_tree_sha256: Optional[str] = None,
                          tree_fingerprint_error: Optional[Exception] = None) -> Dict[str, Any]:
    """执行前二次校验：对象 SHA 与对象树指纹必须仍与授权时一致。

    评测结束后、真实执行前再跑一次；对象被替换 / 增删文件导致树指纹变化，
    旧授权即失效。树指纹缺失、格式非法或计算失败均按不可复核处置，不放行。
    """
    reasons: List[str] = []
    if record.subject_sha256 != request.get("subject_sha256"):
        reasons.append("RECHECK: 对象 SHA 与授权记录不一致")
    if not record.tree_sha256 or not str(record.tree_sha256).strip():
        reasons.append("RECHECK: 授权记录未绑定对象树指纹（证据不足）")
    elif not _SHA_RE.match(record.tree_sha256):
        reasons.append("RECHECK: 授权记录树指纹格式非法（非 64-hex）")
    if tree_fingerprint_error:
        reasons.append("RECHECK: 对象树指纹计算失败，无法复核一致性")
    elif not current_tree_sha256 or not str(current_tree_sha256).strip():
        reasons.append("RECHECK: 执行前未取得当前对象树指纹，无法复核一致性")
    elif not _SHA_RE.match(current_tree_sha256):
        reasons.append("RECHECK: 当前对象树指纹格式非法（非 64-hex）")
    elif record.tree_sha256 and current_tree_sha256 and \
            record.tree_sha256 != current_tree_sha256:
        reasons.append("RECHECK: 对象树指纹与授权记录不一致")
    return {"allowed": len(reasons) == 0, "reasons": reasons}


def recheck_before_execute(record: AuthorizationRecord, request: Dict[str, Any],
                           current_tree_sha256: Optional[str] = None,
                           tree_fingerprint_error: Optional[Exception] = None) -> Dict[str, Any]:
    """执行点二次复核（TOCTOU 防护）。

    recheck 阶段通过的旧结果不得跨执行复用；进入实际执行前，必须在执行点
    重新取当前对象指纹并与授权记录比对，不一致 / 取不到 / 计算失败即拒绝。
    本辅助返回与 `pre_execution_recheck` 相同的结构。
    """
    return pre_execution_recheck(record, request, current_tree_sha256,
                                 tree_fingerprint_error)


def medium_action_restriction(medium_count: int) -> str:
    """Medium 风险对应的动作限制档位（不自动放行，按具体动作管理）。"""
    if medium_count <= 0:
        return "none"
    if medium_count <= 2:
        return "L2-REVIEW: 限人工复核后受限运行"
    return "L3-SANDBOX: 仅隔离环境只读 / 受限调用"


def _scope_match(record: AuthorizationRecord, request: Dict[str, Any]) -> bool:
    if record.action_type != request.get("action_type"):
        return False
    if record.target_scope != request.get("target_scope"):
        return False
    if record.environment != request.get("environment"):
        return False
    if record.subject_sha256 != request.get("subject_sha256"):
        return False
    return True


def evaluate_authorization(
    record: AuthorizationRecord,
    evaluation: Optional[Dict[str, Any]] = None,
    safety: Optional[Dict[str, Any]] = None,
    request: Optional[Dict[str, Any]] = None,
    current_tree_sha256: Optional[str] = None,
    tree_fingerprint_error: Optional[Exception] = None,
) -> Dict[str, Any]:
    """逐次授权判定。返回决策与逐条原因；默认拒绝。

    :param record: 授权记录
    :param evaluation: 评测结论 {evaluation_id, score, rule_version, ...}
    :param safety: 安全策略结论 {status, veto: {active, level, reason}}
    :param request: 本次执行请求 {action_type, target_scope, environment, subject_sha256}
    """
    reasons: List[str] = []
    request = request or {}

    # T04：关键字段缺失 / 为空 / 格式错误 -> DENY
    reasons.extend(_record_fields_valid(record))
    # T05：未登记的动作类型 -> DENY（未知动作默认拒绝）
    if not _action_known(record.action_type):
        reasons.append("ACTION_TYPE_UNKNOWN: 未登记的动作类型（%s）" % record.action_type)
    # T08：一次性授权重复使用（重放）-> DENY；nonce 必须匹配
    if record.consumed:
        reasons.append("REPLAY: 该授权记录已被使用，不得重复调用")
    if record.nonce and request.get("nonce") != record.nonce:
        reasons.append("REPLAY: nonce 不匹配，拒绝重放")

    reasons.extend(_evaluation_validation(evaluation, request))
    if not _authorization_valid(record):
        if record.status == REVOKED:
            reasons.append("AUTHORIZATION_VALID: 授权已撤销")
        elif record.status == EXPIRED or is_expired(record):
            reasons.append("AUTHORIZATION_VALID: 授权已过期")
        else:
            reasons.append("AUTHORIZATION_VALID: 授权未批准（status=%s）" % record.status)
    if not _safety_policy_pass(safety):
        reasons.append("SAFETY_POLICY_PASS: 安全否决未解除或状态非 PASS")
    if not _scope_match(record, request):
        reasons.append("EXECUTION_SCOPE_MATCH: 动作 / 范围 / 环境 / 对象 SHA 不匹配")

    # P0-1：执行前/执行点复核失败（对象或树指纹变化、取不到、格式非法、
    # 计算失败）必须进入拒绝原因，授权判定不得放行。仅当调用方显式提供
    # 执行点快照或计算异常时才复核；未提供快照不把"缺当前指纹"计入授权拒绝。
    if current_tree_sha256 is not None or tree_fingerprint_error:
        recheck = pre_execution_recheck(record, request, current_tree_sha256,
                                        tree_fingerprint_error)
        reasons.extend(recheck["reasons"])

    allowed = len(reasons) == 0
    # 放行前标记一次性授权已消费（仅在内存，不写生产）
    if allowed:
        record.consumed = True
    # 只读 / 评测类动作不产生执行决策；其余动作按判定映射 ALLOW/DENY
    non_exec = record.action_type in {"READ_ONLY", "EVALUATE"}
    execution_decision = ("NOT_APPLICABLE" if non_exec
                          else ("ALLOW" if allowed else "DENY"))
    return {
        "decision": "ALLOW" if allowed else "DENY",
        "execution_decision": execution_decision,
        "allowed": allowed,
        "reasons": reasons,
        "authorization_id": record.authorization_id,
        "subject_id": record.subject_id,
        "residual_risks": LOCAL_SIMULATION_RISKS,
        "note": "本地策略层断言；未接入生产执行端强制拦截，残余风险见 residual_risks",
    }


def affiliated_self_l0_block(affiliation: str) -> bool:
    """同主体 / 关联项目的 L0 限制（策略层，不只在报告展示层）。

    关联项目即使评分达到 100，也不得自动获得免审批执行权限；
    外部复核可作为额外证据，但不等同于第三方认证。
    """
    return affiliation.upper() in {"SELF-EVALUATION", "AFFILIATED"}


def mock_execute(record: AuthorizationRecord, decision: Dict[str, Any]) -> Dict[str, Any]:
    """mock 执行入口。

    仅记录决策与入参，**不调用任何生产写接口、不发放凭证、不产生副作用**。
    用于在无真实生产链路时验证授权判定路径；生产强制拦截须另行接入并验证。
    """
    return {
        "mock": True,
        "executed": False,
        "authorization_id": record.authorization_id,
        "decision": decision.get("decision"),
        "execution_decision": decision.get("execution_decision"),
        "action_type": record.action_type,
        "environment": record.environment,
        "note": "mock 执行入口：未连接生产环境，未执行真实写动作。",
    }
