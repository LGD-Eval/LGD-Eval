#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""evidence_grade.py —— 评测证据的独立复核等级（E0–E4，fail-closed 纯函数）。

为什么单独一层
--------------
执行令要求区分"作者自测 / 本机复跑 / CI 复跑 / 独立第三方复核"，禁止把
自评写成独立验证。证据等级只描述**证据由谁、在什么环境下产生**，不改分数、
不反推授权；等级不足时由调用方/授权层决定如何处理。

等级定义（从弱到强）：

* ``E0`` —— 无可采信证据（未运行 / 无结论 / 异常）。
* ``E1`` —— 作者本机自测：合成夹具或作者本人在本机跑出的结果。
* ``E2`` —— 干净环境本机复跑：不同目录 / 干净虚拟环境按公开说明复现。
* ``E3`` —— CI 自动化复跑：固定版本的 GitHub Actions 等流水线实跑并留日志。
* ``E4`` —— 独立第三方复核：无关联开发者/评测机构按统一测试向量独立验证。

判定顺序（就高不就低，但证据不足不得上浮）：
``third_party(E4) → ci_passed(E3) → clean_repro(E2) → author_local(E1) → E0``。

红线：
* 内部第二实现不算 E4；同一控制主体不同仓不算第三方采用。
* E1/E2 不得对外表述为"第三方认证"或"独立采用"。
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

E0 = "E0"
E1 = "E1"
E2 = "E2"
E3 = "E3"
E4 = "E4"

LEVEL_DESC = {
    E0: "无可采信证据（未运行 / 无结论 / 异常）",
    E1: "作者本机自测（合成夹具或作者本机结果），非独立验证",
    E2: "干净环境本机复跑（按公开说明在干净环境复现）",
    E3: "CI 自动化复跑（固定版本流水线实跑并留存日志）",
    E4: "独立第三方复核（无关联主体按统一测试向量独立验证）",
}

#: 哪些等级才可对外称"独立验证"；其余一律不得。
INDEPENDENT_LEVELS = {E3, E4}


def grade_evidence(
    *,
    verdict_present: bool = True,
    author_local: bool = True,
    clean_repro: bool = False,
    ci_passed: bool = False,
    third_party: bool = False,
    independent_impl: bool = False,
) -> dict:
    """根据实际发生的验证动作给出证据等级。

    参数
    ----
    verdict_present:
        评测器是否产出可采信结论；False 直接 E0。
    author_local:
        结果是否来自作者本机（合成夹具/本机自测）。
    clean_repro:
        是否在干净环境（不同目录/干净 venv）按公开说明复现。
    ci_passed:
        是否由固定版本 CI 流水线实跑通过并留存日志。
    third_party:
        是否有无关联第三方独立复核（必须可提供复核者与原始证据）。
    independent_impl:
        是否存在非原作者的独立代码实现；仅独立实现不自动升 E4，
        须配合 third_party 复核记录。

    返回
    ----
    dict
        ``level`` / ``description`` / ``independent`` / ``basis``。
    """
    if not verdict_present:
        return _result(E0, "评测未产出可采信结论，无法评定证据等级。")

    if third_party:
        return _result(E4, "有无关联第三方独立复核记录。")
    if ci_passed:
        return _result(E3, "固定版本 CI 流水线实跑通过并留存日志。")
    if clean_repro:
        return _result(E2, "干净环境本机按公开说明复现。")
    if author_local:
        return _result(E1, "作者本机自测；不构成独立第三方验证。")
    return _result(E0, "未记录任何可采信的验证动作。")


def _result(level: str, basis: str) -> dict:
    return {
        "level": level,
        "description": LEVEL_DESC[level],
        "independent": level in INDEPENDENT_LEVELS,
        "basis": basis,
    }


def assert_independent(grade: Mapping[str, Any]) -> Optional[str]:
    """若当前等级不构成独立验证，返回禁止对外宣称的提示；否则 None。"""
    if grade.get("independent"):
        return None
    return ("当前证据等级 %s 不构成独立第三方验证，不得对外宣称认证 / 独立采用。"
            % grade.get("level", E0))
