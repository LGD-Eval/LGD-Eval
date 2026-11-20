#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""evidence.py — Evidence Object 与哈希链（P0 骨架，DRAFT，未接入远端仓）。

对齐《TrustLifecycle状态机与EvidenceSchema》与 P0 文件级清单 2.2：
- Evidence Object 承载评测结果、授权决策、复核者、生命周期、过期/撤销、
  哈希链与外部锚点；
- 摘要可复算：规范化序列化（键排序、无空格、不转义中文）后取 SHA-256；
- 指纹不符或过期置 STALE；链断链可检出。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional


def canonical_dumps(obj: Any) -> str:
    """JCS 风格规范化序列化：键排序、无空格、不转义非 ASCII。"""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def self_digest(obj: Any) -> str:
    """计算对象摘要（SHA-256 of canonical serialization）。"""
    return hashlib.sha256(canonical_dumps(obj).encode("utf-8")).hexdigest()


def link_previous(prev_evidence_id: Optional[str], prev_digest: Optional[str]) -> dict:
    """生成哈希链上一条链接字段。"""
    return {
        "prev_evidence_id": prev_evidence_id,
        "prev_digest": prev_digest,
    }


@dataclass
class EvidenceObject:
    evidence_id: str
    subject_id: str
    subject_type: str
    subject_fingerprint: str
    result: dict
    evidence_level: str = "L1"
    provenance: dict = field(default_factory=dict)
    authorization: dict = field(default_factory=dict)
    lifecycle: str = "COLLECTED"
    reviewer: dict = field(default_factory=dict)
    expiration: Optional[dict] = None
    revocation: Optional[dict] = None
    chain: dict = field(default_factory=dict)
    external_anchor: Optional[dict] = None

    def digest(self) -> str:
        return self_digest(self.__dict__)

    def mark_stale(self, reason: str) -> "EvidenceObject":
        """指纹不符或过期时置 STALE；旧证据不参与当前判定。"""
        self.lifecycle = "STALE"
        self.provenance["stale_reason"] = reason
        return self

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def build_result(
    score: int,
    grade: str,
    dims: Mapping[str, int],
    findings: list,
    confidence: Optional[float] = None,
    coverage_honesty: Optional[str] = None,
) -> dict:
    """组装评测结果容器；只承载评测口径，不含授权结论。"""
    return {
        "score": score,
        "grade": grade,
        "dims": dict(dims),
        "findings": findings,
        "confidence": confidence,
        "coverage_honesty": coverage_honesty,
    }
