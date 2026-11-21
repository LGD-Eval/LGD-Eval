# -*- coding: utf-8 -*-
"""Evaluation / Authorization 分离（LGD-Eval P0-2 候选补丁核心模块）。

铁律：
1. **评分永不授予执行权限**。score 只影响"建议档位"，不产生 authorization。
2. **默认 NOT GRANTED**。没有显式、有界、可撤销的授权对象，一律拒绝。
3. UNKNOWN / INCOMPLETE / 缺失证据 → fail-closed，不交给下游策略。
4. 授权必须绑定：artifact 摘要、范围、批准人、有效期，缺一不可。
5. 即便授权成立，执行档位也**封顶 L1**（L0 只是评分档，不是权限档）。

纯函数、无网络、无文件 IO（除传入的 dict），可直接单测。
"""
import datetime
from typing import Optional

# 授权结论（正/负）
GRANTED = "GRANTED"
NOT_GRANTED = "NOT_GRANTED"
EXPIRED = "EXPIRED"
REVOKED = "REVOKED"
UNKNOWN = "UNKNOWN"
INCOMPLETE = "INCOMPLETE"

NEGATIVE = {NOT_GRANTED, EXPIRED, REVOKED, UNKNOWN, INCOMPLETE}

# 评分 → 建议档位（仅建议，不含权限语义）
TIERS = [(96, "L0"), (81, "L1"), (51, "L2"), (31, "L3"), (11, "L4"), (0, "L5")]

# 执行档位上限：授权成立也最多到 L1
EXEC_CEILING = "L1"

REQUIRED_GRANT_FIELDS = ("grant_id", "approved_by", "approved_at",
                         "expires_at", "artifact_digest", "scope")


def tier_for(score: int) -> str:
    for lo, t in TIERS:
        if score >= lo:
            return t
    return "L5"


def _parse(dt) -> Optional[datetime.datetime]:
    if not dt or not isinstance(dt, str):
        return None
    try:
        return datetime.datetime.fromisoformat(dt.replace("Z", "+00:00"))
    except ValueError:
        return None


def _now(now=None) -> datetime.datetime:
    n = now or datetime.datetime.now(datetime.timezone.utc)
    return n if n.tzinfo else n.replace(tzinfo=datetime.timezone.utc)


def decide(score, evaluation_status="COMPLETE", grant=None,
           artifact_digest=None, requested_scope=None,
           revoked_grants=(), now=None) -> dict:
    """返回授权结论。**任何路径都不会因为 score 高而放行。**

    score: 0-100，可为 None（缺失）
    evaluation_status: COMPLETE / INCOMPLETE / UNKNOWN / FAILED
    grant: 授权对象 dict 或 None
    """
    now = _now(now)
    reasons = []
    suggested_tier = tier_for(int(score)) if isinstance(score, (int, float)) else "L5"

    # ① 评测本身不可信 → fail-closed，连"建议档位"都不给权限含义
    if evaluation_status not in ("COMPLETE",):
        return _reject(UNKNOWN if evaluation_status == "UNKNOWN" else INCOMPLETE,
                       f"evaluation_status={evaluation_status}", suggested_tier)
    if score is None:
        return _reject(INCOMPLETE, "score_missing", suggested_tier)
    if not isinstance(score, (int, float)) or not (0 <= score <= 100):
        return _reject(INCOMPLETE, "score_out_of_range", suggested_tier)

    if grant is None:
        # 关键：高分也不放行，只是"建议档位"更高
        reasons.append(f"score={score} 仅用于建议档位 {suggested_tier}，不构成授权")
        return _reject(NOT_GRANTED, "no_grant_object", suggested_tier, reasons)

    # ② 授权对象完整性
    missing = [f for f in REQUIRED_GRANT_FIELDS if not grant.get(f)]
    if missing:
        return _reject(NOT_GRANTED, "grant_missing_fields:" + ",".join(missing),
                       suggested_tier, reasons)

    gid = grant.get("grant_id")
    if gid in set(revoked_grants):
        return _reject(REVOKED, f"grant {gid} revoked", suggested_tier, reasons)

    exp = _parse(grant.get("expires_at"))
    if exp is None:
        return _reject(NOT_GRANTED, "grant_expires_at_invalid", suggested_tier, reasons)
    if exp <= now:
        return _reject(EXPIRED, f"grant expired at {grant.get('expires_at')}",
                       suggested_tier, reasons)

    # ③ 绑定：摘要必须一致，范围必须是子集
    if artifact_digest and grant.get("artifact_digest") != artifact_digest:
        return _reject(NOT_GRANTED, "artifact_digest_mismatch", suggested_tier, reasons)
    if not artifact_digest:
        return _reject(NOT_GRANTED, "artifact_digest_unverifiable", suggested_tier, reasons)

    gscope = set(grant.get("scope") or [])
    if requested_scope:
        extra = set(requested_scope) - gscope
        if extra:
            return _reject(NOT_GRANTED, "scope_exceeds_grant:" + ",".join(sorted(extra)),
                           suggested_tier, reasons)

    # ④ 授权成立：执行档位由**授权对象**决定，与 score 无关；且永不为 L0
    exec_tier = grant.get("exec_tier") or "L1"
    if exec_tier not in ("L1", "L2", "L3", "L4", "L5"):
        return _reject(NOT_GRANTED, f"grant_exec_tier_invalid:{exec_tier}",
                       suggested_tier, reasons)
    if exec_tier == "L0":
        return _reject(NOT_GRANTED, "grant_exec_tier_L0_not_allowed",
                       suggested_tier, reasons)
    reasons.append(f"grant {gid} by {grant.get('approved_by')} valid until {exp.isoformat()}")
    reasons.append(f"exec_tier={exec_tier} 由授权决定；score={score} 仅建议 {suggested_tier}")
    return {
        "authorization": GRANTED,
        "suggested_tier": suggested_tier,
        "exec_tier": exec_tier,
        "requires_human": exec_tier != "L1" or True,   # L1 亦需一次性确认
        "grant_id": gid,
        "reasons": reasons,
    }


def _reject(status, reason, suggested_tier, reasons=None):
    r = list(reasons or [])
    r.append(reason)
    return {
        "authorization": status,
        "suggested_tier": suggested_tier,
        "exec_tier": "L5",              # 拒绝即 L5，不给"部分可用"
        "requires_human": True,
        "grant_id": None,
        "reasons": r,
    }
