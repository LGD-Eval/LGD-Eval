#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P0-2 分析器加载自检与静默降级测试（离线）。

覆盖：
- 本地环境必要/可选分析器加载状态登记；
- 必要分析器未加载 -> INCOMPLETE，Safety 不得 PASS，授权必须 DENY；
- 可选分析器未加载 -> 标注覆盖范围下降；
- 正常 Python / JS 文件能进入对应分析器；
- 人工构造危险代码触发规则。
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.abspath(os.path.join(HERE, "..", "scripts"))
sys.path.insert(0, SCRIPTS)

import analyzers  # noqa: E402


def test_local_analyzers_load():
    report = analyzers.load_analyzers()
    assert "ast_python" in report and "js" in report
    # 本地源码包内两模块均应可导入
    assert report["ast_python"]["loaded"] is True
    assert report["js"]["loaded"] is True


def test_completeness_complete_when_necessary_loaded():
    report = analyzers.load_analyzers()
    assert analyzers.completeness(report) == "COMPLETE"
    gate = analyzers.safety_gate(report)
    assert gate["safety_pass"] is True
    assert gate["authorization_deny"] is False


def test_missing_necessary_analyzer_is_incomplete():
    report = {"ast_python": {"loaded": False, "optional": False, "reason": "ImportError: x"},
              "js": {"loaded": True, "optional": True, "reason": None}}
    assert analyzers.completeness(report) == "INCOMPLETE"
    gate = analyzers.safety_gate(report)
    assert gate["safety_pass"] is False
    assert gate["authorization_deny"] is True


def test_missing_optional_analyzer_flags_dropdown():
    report = {"ast_python": {"loaded": True, "optional": False, "reason": None},
              "js": {"loaded": False, "optional": True, "reason": "ImportError: y"}}
    drops = analyzers.coverage_dropdowns(report)
    assert any("js" in d for d in drops)
    # 可选缺失不把必要分析器判为失败
    assert analyzers.completeness(report) == "COMPLETE"


def test_python_file_enters_ast_analysis():
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write("import os\nos.system('echo hi')\n")
        path = f.name
    try:
        from ast_analyzer import analyze_python_file
        findings = analyze_python_file(path)
        assert any(f.severity == "CRITICAL" for f in findings)
    finally:
        os.unlink(path)


def test_js_file_enters_js_analysis():
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write("const { execSync } = require('child_process');\n")
        path = f.name
    try:
        from js_analyzer import scan_js_file
        findings = scan_js_file(path)
        assert any(sev == "HIGH" for sev, *_ in findings)
    finally:
        os.unlink(path)
