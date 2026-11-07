#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""analyzers.py —— 安全分析器加载自检与覆盖完整性判定。

修复"分析器静默降级"：
- 导入失败 / 加载异常时，不得静默跳过后继续报安全 PASS。
- 每个分析器登记加载状态与失败原因。
- 必要分析器未加载 -> ANALYSIS_COMPLETENESS = INCOMPLETE；
  此时 Safety Status 不得为 PASS，授权必须 DENY。
- 可选分析器未加载 -> 明确标注覆盖范围下降，不冒充完整分析。

边界：本模块只做加载自检与完整性判定，不替代各分析器的真实检测逻辑。
"""

from __future__ import annotations

from typing import Any, Dict, List

# 必要分析器：缺失即判 INCOMPLETE
NECESSARY = ("ast_python",)
# 可选分析器：缺失只标注覆盖下降
OPTIONAL = ("js",)


def _try_import(module_name: str, attr: str) -> Dict[str, Any]:
    try:
        mod = __import__(module_name, fromlist=[attr])
        getattr(mod, attr)
        return {"loaded": True, "reason": None}
    except ImportError as exc:
        return {"loaded": False, "reason": "ImportError: %s" % exc}
    except Exception as exc:  # pragma: no cover - 防御性登记
        return {"loaded": False, "reason": "%s: %s" % (type(exc).__name__, exc)}


def load_analyzers() -> Dict[str, Dict[str, Any]]:
    """返回各分析器加载健康报告。"""
    report: Dict[str, Dict[str, Any]] = {}
    report["ast_python"] = _try_import("ast_analyzer", "analyze_python_file")
    report["ast_python"]["optional"] = False
    report["js"] = _try_import("js_analyzer", "scan_js_file")
    report["js"]["optional"] = True
    # Shell 分析当前为 skillgate 内联正则规则，无独立可导入模块；
    # 登记为内联规则，避免被误判为"已加载独立模块"。
    report["shell_inline"] = {"loaded": True, "optional": True,
                              "reason": "内联规则，无独立加载点"}
    return report


def completeness(report: Dict[str, Dict[str, Any]]) -> str:
    """COMPLETE / INCOMPLETE：必要分析器任一未加载即 INCOMPLETE。"""
    for name, info in report.items():
        if not info.get("optional") and not info.get("loaded"):
            return "INCOMPLETE"
    return "COMPLETE"


def coverage_dropdowns(report: Dict[str, Dict[str, Any]]) -> List[str]:
    """可选分析器缺失时的覆盖范围下降说明。"""
    drops: List[str] = []
    for name, info in report.items():
        if info.get("optional") and not info.get("loaded"):
            drops.append("%s 未加载：对应语言/规则覆盖下降（%s）"
                         % (name, info.get("reason") or "未知原因"))
    return drops


def safety_gate(report: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """完整性对安全闸门的影响。

    INCOMPLETE -> 不得 PASS、必须 DENY；返回结构化结论供评测器/授权层读取。
    """
    complete = completeness(report) == "COMPLETE"
    return {
        "analysis_completeness": complete and "COMPLETE" or "INCOMPLETE",
        "safety_pass": complete,
        "authorization_deny": not complete,
        "coverage_dropdowns": coverage_dropdowns(report),
        "analyzers": report,
    }
