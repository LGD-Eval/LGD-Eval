"""安全否决（safety_cap）的纯函数断言。

口径问题（Issue #10 附带发现）：对外 total 100/A+ 与内审 89/100 并存时，
必须能说清"封顶规则到底在什么条件下触发"。这里把触发条件钉成可执行断言。
"""
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import evaluate  # noqa: E402


def test_clean_findings_no_cap():
    cap, level, reason = evaluate.safety_cap([])
    assert cap == 100
    assert level == ""
    assert reason == ""


def test_critical_rule_caps_to_l3():
    """凭证外泄类规则命中 → 封顶到 VETO_CRITICAL（文案取自 EVIDENCE_RULES 真实条目）。"""
    cap, level, _ = evaluate.safety_cap(["凭证文件读取后网络外发"])
    assert cap == evaluate.VETO_CRITICAL
    assert level == "critical"


def test_high_rule_caps_below_c():
    """凭证暴露/命令执行类 → VETO_HIGH（取真实规则文案 R-SEC-02）。"""
    cap, level, _ = evaluate.safety_cap(["硬编码密钥赋值"])
    assert cap == evaluate.VETO_HIGH
    assert level == "high"


def test_keyword_fallback_still_works_when_no_rule_id():
    """规则表覆盖不到时，必须仍有关键词兜底（真实 crit key：安装期脚本含下载执行）。"""
    cap, level, _ = evaluate.safety_cap(["安装期脚本含下载执行"])
    assert cap == evaluate.VETO_CRITICAL
    assert level == "critical"


def test_cap_never_exceeds_100():
    for f in ([], ["R-SEC-01"], ["完全无关的一条发现"]):
        assert evaluate.safety_cap(f)[0] <= 100
