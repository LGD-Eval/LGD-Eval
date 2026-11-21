#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""authz.py —— 评测分数与授权状态的分离判定（fail-closed 纯函数）。

为什么单独一层
--------------
竞品通常只给一个总分 / 等级，分数高就被默认可用。这里把两件事拆开：

* **score（分数）**：五维加权的数值度量，0–100，描述"质量有多高"；
* **authorization（授权状态）**：独立的可否执行决定，描述"能不能放行"。

分数高不自动授予执行权限；安全否决、证据不全、评测未完成都必须独立成态。
本模块不修改分数，也不从分数反推授权；授权只依据显式传入的封顶结论、
证据完整性与阈值规则判定。

状态枚举（与对外口径一致，禁止引入口语态）：

* ``GRANTED``        —— 证据齐备、无阻断性安全否决、分数达到阈值，可放行。
* ``NOT_GRANTED``    —— 存在阻断性安全否决，或分数未达阈值，拒绝放行。
* ``INCOMPLETE``     —— 评测跑了，但证据不足（缺档案 / 缺证据样本），无法下授权结论。
* ``UNKNOWN``        —— 评测器没有给出可采信结论（未运行 / 无分数 / 异常），不得猜测。
* ``NOT_APPLICABLE`` —— 经合理说明本项不适用；须显式说明理由，不得用于掩盖失败。
* ``BLOCKED``        —— 被前置条件阻断（如隔离后端不可用、缺运行环境），当前不能判定。

判定顺序（fail-closed，先卡死最不确定 / 最危险的一档）：
``BLOCKED`` → ``UNKNOWN`` → ``NOT_APPLICABLE`` → ``NOT_GRANTED``（安全否决）
→ ``INCOMPLETE``（证据缺口）→ ``NOT_GRANTED``（分数不足）→ ``GRANTED``。
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

GRANTED = "GRANTED"
NOT_GRANTED = "NOT_GRANTED"
INCOMPLETE = "INCOMPLETE"
UNKNOWN = "UNKNOWN"
NOT_APPLICABLE = "NOT_APPLICABLE"
BLOCKED = "BLOCKED"

#: 安全否决中必须直接拒绝授权的级别（与 evaluate.safety_cap 对齐）。
_BLOCKING_VETO_LEVELS = {"critical", "high"}

#: 达到放行所需的最低分数（与 L1 一次性确认档对齐，可被调用方覆盖）。
DEFAULT_GRANT_THRESHOLD = 81


def is_blocking_veto(veto_info: Optional[Mapping[str, Any]]) -> bool:
    """是否存在必须拒绝授权的安全否决（critical / high）。"""
    if not veto_info:
        return False
    if not veto_info.get("applied"):
        return False
    return str(veto_info.get("level", "")).lower() in _BLOCKING_VETO_LEVELS


def authorize(
    *,
    score: Optional[float] = None,
    grade: Optional[str] = None,
    veto_info: Optional[Mapping[str, Any]] = None,
    evidence: Optional[Mapping[str, bool]] = None,
    verdict_present: bool = True,
    grant_threshold: int = DEFAULT_GRANT_THRESHOLD,
    blocked: bool = False,
    applicable: bool = True,
    blocked_reason: str = "",
    napplicable_reason: str = "",
) -> dict:
    """给出独立于分数的授权结论。

    参数
    ----
    score:
        五维信任分（0–100）。``None`` 表示评测器未给出分数。
    grade:
        等级（A+/A/B/C/D），仅随结论回显，不参与授权推导。
    veto_info:
        ``evaluate.evaluate_skill`` 返回的 ``veto_info``；含 ``applied`` / ``level``。
    evidence:
        三律证据完整性，键：``registered``（有籍：README+CHANGELOG）、
        ``evidenced``（有证：examples/tests）、``gated``（有门禁）。
        缺键按 ``False`` 处理（fail-closed）。
    verdict_present:
        评测器是否产出了可采信结论；``False`` 直接 ``UNKNOWN``。
    grant_threshold:
        放行分数阈值。

    返回
    ----
    dict
        ``state`` / ``reason`` / ``score`` / ``grade`` / ``threshold`` /
        ``separation``。本函数不改动入参分数。
    """
    evidence = dict(evidence or {})
    registered = bool(evidence.get("registered", False))
    evidenced = bool(evidence.get("evidenced", False))

    separation = (
        "score 是五维数值度量；authorization 是独立的放行/拒绝决定。"
        "分数不自动授予权限，授权也不回写分数；二者按各自规则分别得出。"
    )

    # 0. 前置条件阻断（隔离后端不可用 / 缺运行环境）→ 明确 BLOCKED，
    #    不得静默降级为安全执行。
    if blocked:
        return {
            "state": BLOCKED,
            "reason": blocked_reason or "前置条件未满足，当前不能判定授权。",
            "score": score,
            "grade": grade,
            "threshold": grant_threshold,
            "separation": separation,
        }

    # 1. 评测器没有给出可采信结论 → 不得猜测。
    if not verdict_present or score is None:
        return {
            "state": UNKNOWN,
            "reason": "评测器未产出可采信结论（未运行 / 无分数 / 异常），无法判定授权。",
            "score": score,
            "grade": grade,
            "threshold": grant_threshold,
            "separation": separation,
        }

    # 1b. 经合理说明不适用 → NOT_APPLICABLE（须显式理由，不得用于掩盖失败）。
    if not applicable:
        return {
            "state": NOT_APPLICABLE,
            "reason": napplicable_reason or "本项经说明不适用。",
            "score": score,
            "grade": grade,
            "threshold": grant_threshold,
            "separation": separation,
        }

    # 2. 阻断性安全否决优先于一切分数结论。
    if is_blocking_veto(veto_info):
        level = str(veto_info.get("level", "")).lower()
        reason = "命中阻断性安全否决（%s）：%s。" % (
            level,
            veto_info.get("reason", "未提供原因"),
        )
        return {
            "state": NOT_GRANTED,
            "reason": reason,
            "score": score,
            "grade": grade,
            "threshold": grant_threshold,
            "separation": separation,
        }

    # 3. 证据不齐 → 不能下授权结论，记 INCOMPLETE，而不是凭分数放行。
    if not registered or not evidenced:
        missing = [name for name, ok in
                   (("有籍(README/CHANGELOG)", registered),
                    ("有证(examples/tests)", evidenced)) if not ok]
        return {
            "state": INCOMPLETE,
            "reason": "证据不齐，缺少：%s；补齐证据前不予授权。" % "、".join(missing),
            "score": score,
            "grade": grade,
            "threshold": grant_threshold,
            "separation": separation,
        }

    # 4. 证据齐备、无安全否决，但分数未达阈值 → 拒绝。
    if score < grant_threshold:
        return {
            "state": NOT_GRANTED,
            "reason": "证据齐备且无安全否决，但分数 %d 低于放行阈值 %d。"
            % (score, grant_threshold),
            "score": score,
            "grade": grade,
            "threshold": grant_threshold,
            "separation": separation,
        }

    # 5. 全部满足 → 放行。
    return {
        "state": GRANTED,
        "reason": "证据齐备、无阻断性安全否决、分数达到阈值。",
        "score": score,
        "grade": grade,
        "threshold": grant_threshold,
        "separation": separation,
    }
