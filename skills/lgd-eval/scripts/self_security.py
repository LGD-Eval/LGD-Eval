#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""self_security.py —— 评测器自身安全的策略层断言。

边界：本模块只提供受保护清单、规则版本比对等策略判定；
运行时强制写保护、评测中规则替换中止须在真实执行边界接入并验证，
当前未接入生产执行链路，相关强制拦截标记 NOT VERIFIED。
"""

from __future__ import annotations

import os
from typing import Dict, List

# 评测器核心文件：评测期间不得被被测对象修改；受保护清单（策略层）
PROTECTED_CORE_FILES: List[str] = [
    "evaluate.py", "skillgate.py", "ast_analyzer.py", "js_analyzer.py",
    "authorization.py", "scorecard.py", "verify_attestation.py",
    "analyzers.py", "sandbox.py",
]


def rule_version_changed(meta_a: Dict, meta_b: Dict) -> bool:
    """规则版本 / 规则文件哈希任一变化即识别为规则变更。"""
    if meta_a.get("rule_version") != meta_b.get("rule_version"):
        return True
    if meta_a.get("rule_files_hash") != meta_b.get("rule_files_hash"):
        return True
    return False


def is_protected_path(filename: str) -> bool:
    """该文件名是否属于受保护核心文件。"""
    return os.path.basename(filename) in PROTECTED_CORE_FILES
