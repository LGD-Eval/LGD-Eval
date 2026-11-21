#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""external_review.py — L4 第三方外部复核回传通道骨架（P0，DRAFT，未接外部节点）。

红线：
- 本模块**不发起任何网络请求**，不主动联系外部复核者；只做回传记录的结构校验、
  独立性核验、指纹绑定与摘要留痕。
- 外部复核结论只作为「证据输入」装入 EvidenceObject；**不直接导出授权**。
  GRANTED 仍由 authorization 状态机经独立决策方另行产出，评测/授权分轨不变。
- 失败关闭：缺主体、复核者与评测者同体、指纹绑定错位、结论非法、未锚定签名/
  外部锚点，一律不采信为 L4 证据；不得把骨架记录写成已通过第三方验证（L4）。
- 签名与时间戳密码学校验为占位：待接入独立签名验证实现（如 cryptography）后，
  再把 signature / external_anchor 校验从结构占位升级为密码学校验。

证据等级口径（与成熟度自评表一致）：
  L1 自我复现 / L2 异体对抗 / L3 独立第二实现 / L3.5 外部语料 / L4 第三方外部节点。
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping, Optional

try:  # 复用证据链的规范化序列化与摘要口径，保证可复算
    from evidence import canonical_dumps, self_digest
except Exception:  # pragma: no cover - evidence 不可用时的骨架容错
    import hashlib
    import json

    def canonical_dumps(obj: Any) -> str:
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, default=str,
        )

    def self_digest(obj: Any) -> str:
        return hashlib.sha256(canonical_dumps(obj).encode("utf-8")).hexdigest()


VALID_VERDICTS = {"pass", "fail", "inconclusive"}

# L4 成立必须具备的外部锚点：签名（复核者身份不可抵赖）+ 外部锚点（可公开回溯）。
L4_REQUIRED_ANCHORS = ("signature", "external_anchor")


@dataclass
class ExternalReviewRecord:
    """一条外部复核回传记录（骨架字段，不绑定任何外部协议）。"""

    review_id: str
    reviewer_id: str          # 外部复核者主体标识（须与评测者不同体）
    reviewer_org: str          # 复核者所属组织
    evaluator_id: str         # 被对齐的评测者主体标识（独立性比对基准）
    subject_fingerprint: str   # 绑定的被测对象指纹，须与证据对象一致
    verdict: str              # pass / fail / inconclusive
    rationale: str = ""
    signature: Optional[Mapping[str, Any]] = None      # 占位：算法 + 签名值，待密码学校验
    external_anchor: Optional[Mapping[str, Any]] = None  # 占位：公开注册表/时间戳锚点
    reviewed_at: Optional[str] = None
    evidence_level: str = "L4"

    def digest(self) -> str:
        """记录摘要（SHA-256 of canonical serialization），可复算、可钉扎。"""
        return self_digest(asdict(self))


def _missing(record: Mapping[str, Any], field: str) -> bool:
    value = record.get(field)
    return value is None or (isinstance(value, str) and not value.strip())


def validate_external_review(
    record: Mapping[str, Any],
    *,
    expected_fingerprint: Optional[str] = None,
) -> dict[str, Any]:
    """校验外部复核回传记录。

    返回 ``{accepted_for_l4, independence_ok, anchored, reasons, digest}``。

    失败关闭顺序：
      1. 主体标识缺失（review_id / reviewer_id / reviewer_org / evaluator_id /
         subject_fingerprint / verdict）-> 不采信；
      2. 独立性：reviewer_id 与 evaluator_id 同体 -> 不采信；
      3. 指纹绑定：record.subject_fingerprint 与 expected_fingerprint 不一致 -> 不采信；
      4. verdict 非法 -> 不采信；
      5. 缺签名或外部锚点 -> 结构可留档，但 ``accepted_for_l4=False``（未锚定，不计 L4）。
    """
    reasons: list[str] = []
    accepted = True
    independence_ok = True
    anchored = True

    required = ("review_id", "reviewer_id", "reviewer_org", "evaluator_id",
                "subject_fingerprint", "verdict")
    for field in required:
        if _missing(record, field):
            reasons.append(f"missing required field: {field}")
            accepted = False

    reviewer_id = str(record.get("reviewer_id") or "").strip()
    evaluator_id = str(record.get("evaluator_id") or "").strip()
    if reviewer_id and evaluator_id and reviewer_id == evaluator_id:
        independence_ok = False
        reasons.append("reviewer is not independent: reviewer_id == evaluator_id")
        accepted = False

    fingerprint = str(record.get("subject_fingerprint") or "").strip()
    if expected_fingerprint and fingerprint and fingerprint != expected_fingerprint:
        reasons.append("subject_fingerprint mismatch: review bound to a different subject")
        accepted = False

    verdict = str(record.get("verdict") or "").strip().lower()
    if verdict and verdict not in VALID_VERDICTS:
        reasons.append(
            f"invalid verdict: {verdict!r}; expected one of {sorted(VALID_VERDICTS)}"
        )
        accepted = False

    for anchor in L4_REQUIRED_ANCHORS:
        if not record.get(anchor):
            anchored = False
            reasons.append(
                f"missing {anchor}: record not cryptographically/external anchored; "
                "cannot count as L4"
            )
    if not anchored:
        accepted = False

    return {
        "accepted_for_l4": accepted,
        "independence_ok": independence_ok,
        "anchored": anchored,
        "reasons": reasons,
        "digest": self_digest(record),
    }
