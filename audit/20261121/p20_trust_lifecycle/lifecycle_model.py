# -*- coding: utf-8 -*-
"""XLGD Trust Lifecycle 原型：统一状态机 + 撤销传播 + 版本兼容（本地原型，非产品）。

设计要点：
1. 状态转换必须由 evidence + rule 双触发；评分不是授权依据。
2. 撤销按 EVIDENCE / IDENTITY / AUTHORIZATION / VERSION 四类，向下游级联。
3. 版本兼容对未知一律 fail-closed。
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

# ---------- 状态 ----------
STATES = {
    "REGISTERED", "EVIDENCE_PENDING", "VERIFIED", "EVALUATED",
    "AUTHORIZATION_PENDING", "AUTHORIZED", "MONITORED",
    "UNKNOWN", "INCOMPLETE", "EXPIRED", "REVOKED", "SUSPENDED", "FAILED",
}
TERMINAL = {"REVOKED", "FAILED"}
ABNORMAL = {"UNKNOWN", "INCOMPLETE", "EXPIRED", "REVOKED", "SUSPENDED", "FAILED"}

# 合法转换：目标 -> 允许的来源集合
ALLOWED: Dict[str, set] = {
    "EVIDENCE_PENDING": {"REGISTERED"},
    "VERIFIED": {"EVIDENCE_PENDING"},
    "EVALUATED": {"VERIFIED"},
    "AUTHORIZATION_PENDING": {"EVALUATED"},
    "AUTHORIZED": {"AUTHORIZATION_PENDING"},
    "MONITORED": {"AUTHORIZED"},
    "EXPIRED": {"VERIFIED", "EVALUATED", "AUTHORIZED", "MONITORED"},
    "SUSPENDED": {"AUTHORIZED", "MONITORED", "EVALUATED"},
    "REVOKED": {"REGISTERED", "EVIDENCE_PENDING", "VERIFIED", "EVALUATED",
                "AUTHORIZATION_PENDING", "AUTHORIZED", "MONITORED", "SUSPENDED",
                "UNKNOWN", "INCOMPLETE", "EXPIRED"},
    "FAILED": {"REGISTERED", "EVIDENCE_PENDING", "VERIFIED"},
    "UNKNOWN": {"REGISTERED"},
    "INCOMPLETE": {"EVIDENCE_PENDING"},
    "REGISTERED": {"EXPIRED", "SUSPENDED"},  # 仅可经重新登记回到起点
}

# 不允许仅凭评分得到的边
SCORE_CANNOT_GRANT = {"AUTHORIZED"}


class TransitionError(Exception):
    pass


@dataclass
class TransitionRequest:
    from_state: str
    to_state: str
    evidence: Optional[dict] = None
    rule_id: Optional[str] = None
    score: Optional[float] = None
    authorization: Optional[dict] = None


def transition(req: TransitionRequest) -> Tuple[bool, str]:
    """返回 (ok, reason)。所有拒绝都是 fail-closed。"""
    if req.from_state not in STATES or req.to_state not in STATES:
        return False, f"unknown state: {req.from_state}->{req.to_state}"
    if req.to_state in SCORE_CANNOT_GRANT and req.score is not None and req.authorization is None:
        return False, "score cannot grant authorization (Evaluation != Authorization)"
    if req.from_state in TERMINAL and req.to_state != "REVOKED":
        return False, f"terminal state {req.from_state} cannot transition to {req.to_state}"
    if req.to_state == "AUTHORIZED":
        if not req.authorization or not req.authorization.get("subject") \
           or not req.authorization.get("scope") or not req.authorization.get("expires_at"):
            return False, "authorization requires subject/scope/expires_at"
    if req.to_state in {"VERIFIED", "EVALUATED", "AUTHORIZED"} and not req.evidence:
        return False, f"{req.to_state} requires evidence"
    if req.to_state in {"VERIFIED", "EVALUATED"} and not req.rule_id:
        return False, f"{req.to_state} requires rule_id"
    if req.from_state not in ALLOWED.get(req.to_state, set()):
        return False, f"illegal transition {req.from_state} -> {req.to_state}"
    return True, "ok"


def is_usable(state: str, expires_at: Optional[datetime], now: Optional[datetime] = None) -> Tuple[bool, str]:
    now = now or datetime.now(timezone.utc)
    if state in ABNORMAL:
        return False, f"state={state}"
    if state not in {"AUTHORIZED", "MONITORED"}:
        return False, f"state={state} insufficient"
    if expires_at is None:
        return False, "missing expires_at (fail-closed)"
    if expires_at <= now:
        return False, "expired"
    return True, "usable"


# ---------- 撤销 ----------
@dataclass
class Revocation:
    rev_id: str
    kind: str                 # EVIDENCE | IDENTITY | AUTHORIZATION | VERSION
    target: str               # evidence_id / subject / auth_id / version
    reason: str
    at: str
    scope: List[str] = field(default_factory=list)
    recover_condition: str = "re-register + re-evaluate"
    propagates_to: List[str] = field(default_factory=list)  # 依赖它的对象


class RevocationRegistry:
    def __init__(self) -> None:
        self.records: List[Revocation] = []

    def revoke(self, rev: Revocation) -> List[str]:
        """登记撤销并返回受影响的全部对象（含级联）。"""
        self.records.append(rev)
        affected = [rev.target] + list(rev.propagates_to)
        for downstream in rev.propagates_to:
            affected.extend(self._cascade(downstream))
        return affected

    def _cascade(self, obj: str) -> List[str]:
        out = []
        for r in self.records:
            if obj in r.propagates_to:
                out.append(r.target)
                out.extend(self._cascade(r.target))
        return out

    def is_revoked(self, obj: str) -> Tuple[bool, str]:
        for r in self.records:
            if obj == r.target or obj in r.propagates_to:
                return True, f"{r.kind}:{r.reason}"
        return False, "ok"


# ---------- 版本兼容 ----------
# (evidence_version, rule_version) -> 兼容的 engine 版本集合
COMPAT: Dict[Tuple[str, str], set] = {
    ("uibc/0.2.x", "rules/1"): {"engine/1"},
    ("uibc/0.3.x", "rules/1"): {"engine/1"},
    ("uibc/0.3.x", "rules/2"): {"engine/2"},
    ("uibc/0.4.0", "rules/2"): {"engine/2", "engine/3"},
}
RE_EVAL_TRIGGERS = {"rule_major_change", "engine_major_change", "evidence_version_mismatch"}


def compat(evidence_ver: str, rule_ver: str, engine_ver: str) -> Tuple[str, bool, str]:
    """返回 (status, need_re_eval, reason)。未知一律 UNKNOWN + 需复评。"""
    key = (evidence_ver, rule_ver)
    if key not in COMPAT:
        return "UNKNOWN", True, "evidence/rule pair not registered"
    if engine_ver not in COMPAT[key]:
        return "INCOMPATIBLE", True, "engine not in compatible set"
    return "COMPATIBLE", False, "ok"
