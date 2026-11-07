#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P0-4 评测器自身安全测试（离线可断言部分）。

覆盖：
- 规则版本 / 规则文件哈希变化可被识别；
- 受保护核心文件清单覆盖评分器 / 扫描器 / 授权 / 报告 / 规则模块；
- 评测器自身 Critical 命中同一否决封顶；
- 结果文件被篡改可被证明校验发现（verify 侧已覆盖，此处补断言入口）。

未覆盖（NOT VERIFIED / BLOCKED，须在真实执行边界接入后验证）：
- 评测期间被测对象改写核心文件的运行时强制拦截；
- 规则文件被替换时中止 / 重启评测的执行侧强制行为。
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.abspath(os.path.join(HERE, "..", "scripts"))
sys.path.insert(0, SCRIPTS)

import self_security as ss  # noqa: E402
import evaluate as ev  # noqa: E402


def test_rule_version_change_detected():
    a = {"rule_version": "rules-2026-11-07", "rule_files_hash": "h1"}
    b = {"rule_version": "rules-2026-11-08", "rule_files_hash": "h1"}
    assert ss.rule_version_changed(a, b) is True
    c = {"rule_version": "rules-2026-11-07", "rule_files_hash": "h2"}
    assert ss.rule_version_changed(a, c) is True


def test_unchanged_rule_version_not_changed():
    a = {"rule_version": "r1", "rule_files_hash": "h1"}
    b = {"rule_version": "r1", "rule_files_hash": "h1"}
    assert ss.rule_version_changed(a, b) is False


def test_protected_core_files_cover_key_modules():
    for name in ("evaluate.py", "skillgate.py", "authorization.py",
                 "scorecard.py", "verify_attestation.py"):
        assert name in ss.PROTECTED_CORE_FILES


def test_protected_path_match():
    assert ss.is_protected_path("C:/x/evaluate.py") is True
    assert ss.is_protected_path("C:/x/attacker_notes.md") is False


def test_self_critical_triggers_same_veto():
    # 评测器自身若出现同类 Critical 命中，走同一 safety_cap 否决封顶
    findings = ["combo.py:8: 凭证文件读取后网络外发（同文件污点）"]
    cap, level, _ = ev.safety_cap(findings)
    assert cap == ev.VETO_CRITICAL
    assert level == "critical"
