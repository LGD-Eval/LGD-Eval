#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""evidence_integrity.py —— 评测证明的防篡改 / 漂移 / 过期校验（fail-closed 纯函数）。

为什么单独一层
--------------
证明一旦可以事后改分数、改结论而不留痕，整套评分卡就不可信。本模块只做
"证明与当前被测代码、规则版本、时间是否还对得上"的校验，不改分数、不反推
授权。缺字段 / 解析失败一律记 INCOMPLETE，不得默认 MATCH。

校验项
------
* **TAMPERED**：按证明内的 score/grade/dims/findings/veto 重算指纹，与登记
  fingerprint 不一致 → 证明被事后改动。
* **DRIFTED**：当前代码树哈希 / 提交 / 规则版本与证明绑定的不一致 → 证明
  已不代表当前被测对象。
* **STALE**：证据年龄超过允许上限（max_age_days）→ 须重新评测。
* **INCOMPLETE**：证明缺关键字段或时间戳不可解析，无法完成校验。
* **MATCH**：以上都通过，且提供了当前基线做比对。

状态优先级（就严不就宽）：TAMPERED > DRIFTED > STALE > INCOMPLETE > MATCH。
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

MATCH = "MATCH"
DRIFTED = "DRIFTED"
STALE = "STALE"
TAMPERED = "TAMPERED"
INCOMPLETE = "INCOMPLETE"

_REQUIRED = ("fingerprint", "evaluated_at", "rule_version", "engine_version")


def _canonical(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def recompute_fingerprint(att: Mapping[str, Any]) -> Optional[str]:
    """按证明内可见字段重建 payload 并计算指纹；与登记 fingerprint 比对。

    与 ``evaluate.build_attestation`` 的 payload 口径保持一致：
    object / dims / findings / 可选 veto。
    """
    if not all(k in att for k in ("score", "grade", "dims", "findings")):
        return None
    payload = {
        "object": {"score": att["score"], "grade": att["grade"]},
        "dims": {k: att["dims"].get(k, 0) for k in sorted(att["dims"])},
        "findings": [{"rule_id": f.get("rule_id"), "dimension": f.get("dimension"),
                      "file": f.get("file"), "line": f.get("line"),
                      "evidence": f.get("evidence"), "fix": f.get("fix"),
                      "verify": f.get("verify")} for f in att["findings"]],
    }
    veto = att.get("safety_veto")
    if veto and veto.get("applied"):
        payload["veto"] = veto
    return "sha256:" + hashlib.sha256(
        _canonical(payload).encode("utf-8")).hexdigest()


def _parse_ts(ts: str) -> Optional[datetime]:
    if not isinstance(ts, str):
        return None
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def verify(
    att: Mapping[str, Any],
    *,
    current_tree_sha: Optional[str] = None,
    current_commit: Optional[str] = None,
    current_rule_version: Optional[str] = None,
    current_engine_version: Optional[str] = None,
    max_age_days: Optional[int] = None,
    now: Optional[datetime] = None,
) -> dict:
    """校验一份证明是否仍可采信。返回 ``status`` / ``reasons`` / ``details``。

    任何无法确认的情况都不得返回 MATCH；未提供当前基线时不做漂移断言，
    但仍做指纹与完整性校验。
    """
    reasons: list[str] = []
    status = MATCH

    # 1. 必填字段完整性（fail-closed）。
    missing = [k for k in _REQUIRED if not att.get(k)]
    if missing:
        reasons.append("证明缺关键字段：%s" % "、".join(missing))
        return {"status": INCOMPLETE, "reasons": reasons, "details": {}}

    details: dict[str, Any] = {}

    # 2. 防篡改：重算指纹比对。
    fp = att["fingerprint"]
    recomputed = recompute_fingerprint(att)
    if recomputed is None:
        reasons.append("证明内 score/grade/dims/findings 不完整，无法重算指纹。")
        status = INCOMPLETE
    elif recomputed != fp:
        reasons.append("指纹不一致：登记 %s，重算 %s（证明可能被事后改动）。"
                       % (fp, recomputed))
        status = TAMPERED
    details["fingerprint"] = fp

    # 3. 代码树 / 提交漂移。
    tree = (att.get("inputs") or {}).get("tree_sha256")
    if current_tree_sha is not None:
        if not tree:
            reasons.append("证明未记录 tree_sha256，无法核对代码树。")
            status = _raise(status, INCOMPLETE)
        elif tree != current_tree_sha:
            reasons.append("代码树漂移：证明绑定 %s，当前 %s。" % (tree, current_tree_sha))
            status = _raise(status, DRIFTED)
    details["tree_sha256"] = tree

    commit = att.get("target_commit")
    if current_commit is not None:
        if not commit:
            reasons.append("证明未记录 target_commit，无法核对提交。")
            status = _raise(status, INCOMPLETE)
        elif commit != current_commit:
            reasons.append("提交漂移：证明绑定 %s，当前 %s。" % (commit, current_commit))
            status = _raise(status, DRIFTED)
    details["target_commit"] = commit

    # 4. 规则 / 引擎版本漂移。
    if current_rule_version and att.get("rule_version") != current_rule_version:
        reasons.append("规则版本漂移：证明 %s，当前 %s。"
                       % (att.get("rule_version"), current_rule_version))
        status = _raise(status, DRIFTED)
    if current_engine_version and att.get("engine_version") != current_engine_version:
        reasons.append("引擎版本漂移：证明 %s，当前 %s。"
                       % (att.get("engine_version"), current_engine_version))
        status = _raise(status, DRIFTED)

    # 5. 过期校验。
    evaluated = _parse_ts(att.get("evaluated_at", ""))
    if evaluated is None:
        reasons.append("evaluated_at 不可解析，无法判断是否过期。")
        status = _raise(status, INCOMPLETE)
    elif max_age_days is not None:
        now = now or datetime.now(timezone.utc)
        age_days = (now - evaluated).days
        details["age_days"] = age_days
        if age_days > max_age_days:
            reasons.append("证据过期：已 %d 天，超过上限 %d 天。"
                           % (age_days, max_age_days))
            status = _raise(status, STALE)

    if status == MATCH and not reasons:
        reasons.append("指纹、版本与当前基线一致，未发现漂移或过期。")
    return {"status": status, "reasons": reasons, "details": details}


def _raise(current: str, candidate: str) -> str:
    """按就严优先级取更严重的状态。"""
    order = [MATCH, STALE, DRIFTED, INCOMPLETE, TAMPERED]
    return candidate if order.index(candidate) > order.index(current) else current


def same_target(a: Mapping[str, Any], b: Mapping[str, Any]) -> bool:
    """判断两份证明是否指向同一被测对象（树 + 提交 + 规则版本）。"""
    ta = (a.get("inputs") or {}).get("tree_sha256")
    tb = (b.get("inputs") or {}).get("tree_sha256")
    return (ta == tb and ta is not None
            and a.get("target_commit") == b.get("target_commit")
            and a.get("rule_version") == b.get("rule_version"))
