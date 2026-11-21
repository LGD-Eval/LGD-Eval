#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gold_runner.py — gold 基准集加载、引擎实测观测与不可用兜底（P0，DRAFT）。

边界（红线）：
- 阈值未标定前（baseline.json thresholds 全 null），runner 只输出计数、结构校验与
  **观测性** 引擎结果，**不产出 PASS/FAIL 门禁结论**；不得把当前观测写成精度/召回达标。
- 引擎实测 verdict 仅用于校准检出方向（TP/FP/FN/TN 观测）；样本规模扩大、回测稳定后，
  再标定 baseline.json 的 min_precision / min_recall / max_false_positive_rate。
- 引擎不可用（导入失败 / 评测异常）时回退 class 占位期望，仅作结构自检；此时
  engine_connected=False，占位结果不是真实准确性结果，不计入 L3/L4 证据。
混淆矩阵口径（正类 = 高危样本，即 gold/negative）：
- TP：negative 样本被检出（verdict == FAIL）
- FN：negative 样本漏检（未判 FAIL）
- FP：positive 样本被误判 FAIL
- TN：positive 样本判 PASS
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
from typing import Any, Mapping, Optional

GOLD_DIR = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.path.join(GOLD_DIR, "MANIFEST.json")
BASELINE = os.path.join(GOLD_DIR, "baseline.json")

# class -> 占位期望 verdict / authorization（与样本 JSON expected 对齐）
_CLASS_EXPECTED = {
    "positive": {"verdict": "PASS", "authorization": "NOT_GRANTED"},
    "negative": {"verdict": "FAIL", "authorization": "NOT_GRANTED"},
    "boundary": {"verdict": "INCONCLUSIVE", "authorization": "UNKNOWN"},
}

_REQUIRED_SAMPLE_FIELDS = ("id", "class", "expected", "path")

# 安全发现关键词：命中即视为高危检出（与 evaluate.py R-SEC 族规则名口径对齐）。
# findings 文本形如 `scripts/x.py:6: 动态执行（eval / exec）`，不含 R-SEC 编号，
# 故同时收录规则名核心词与代码层特征，避免检出已发生却被关键词表漏记为 FN。
_SECURITY_HINTS = (
    "R-SEC", "外发", "外泄", "凭证", "密钥", "token", "命令注入", "os.system",
    "shell=True", "注入", "私钥", "pickle", "eval(", "exec(",
    "动态执行", "环境变量批量", "批量外发", "硬编码", "反序列化", "递归删除",
    "凭证文件读取", "跨文件", "动态构造", "基址被改写", "代理被指向",
    "免确认", "越权指令", "隐瞒用户", "绕过安全",
)
_FAIL_GRADES = {"D", "F"}

_engine_module = None
_engine_load_error: Optional[str] = None


def _read_json(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_manifest(manifest_path: str = MANIFEST) -> dict[str, Any]:
    return _read_json(manifest_path)


def load_baseline(baseline_path: str = BASELINE) -> dict[str, Any]:
    return _read_json(baseline_path)


def _engine_scripts_dir() -> Optional[str]:
    """定位主引擎 scripts 目录：<repo>/skills/lgd-eval/scripts。"""
    # GOLD_DIR = <repo>/tests/fixtures/gold，向上三级到仓根。
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(GOLD_DIR)))
    scripts = os.path.join(repo_root, "skills", "lgd-eval", "scripts")
    return scripts if os.path.isdir(scripts) else None


def _load_engine() -> tuple[Any, Optional[str]]:
    """导入主引擎 evaluate 模块；缓存结果。返回 (module, error)。"""
    global _engine_module, _engine_load_error
    if _engine_module is not None or _engine_load_error is not None:
        return _engine_module, _engine_load_error
    scripts = _engine_scripts_dir()
    if not scripts:
        _engine_load_error = "engine scripts dir not found"
        return None, _engine_load_error
    try:
        if scripts not in sys.path:
            sys.path.insert(0, scripts)
        import evaluate  # type: ignore
        _engine_module = evaluate
    except Exception as exc:  # 失败关闭：引擎不可用即回退占位
        _engine_load_error = f"{type(exc).__name__}: {exc}"
        return None, _engine_load_error
    return _engine_module, None


def _run_engine(fixture_dir: str) -> dict[str, Any]:
    """对夹具目录跑一次主引擎评测，返回观测记录；异常不抛出。"""
    module, err = _load_engine()
    if module is None:
        return {"available": False, "error": err}
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            score, grade, dims, findings, warnings, veto = module.evaluate_skill(fixture_dir)
        auth = (veto or {}).get("authorization") or {}
        status = auth.get("status")
        auth_status = getattr(status, "value", status)
        return {
            "available": True,
            "score": score,
            "grade": grade,
            "findings": list(findings),
            "warnings": list(warnings),
            "auth_status": auth_status,
            "auth_reason": auth.get("reason"),
        }
    except Exception as exc:  # 单样本异常不阻断整批
        return {"available": False, "error": f"{type(exc).__name__}: {exc}"}


def _is_security_hit(findings: list[str]) -> bool:
    return any(any(hint in str(f) for hint in _SECURITY_HINTS) for f in findings)


def _verdict_from_record(cls: str, rec: Mapping[str, Any]) -> str:
    """引擎观测 verdict 映射（非门禁）。boundary 恒 INCONCLUSIVE。"""
    if cls == "boundary":
        return "INCONCLUSIVE"
    if not rec.get("available"):
        return _CLASS_EXPECTED[cls]["verdict"]
    if "CRITICAL" in str(rec.get("auth_reason") or ""):
        return "FAIL"
    if rec.get("grade") in _FAIL_GRADES or _is_security_hit(rec.get("findings") or []):
        return "FAIL"
    return "PASS"


def _sample_fixture_dir(sample: Mapping[str, Any], gold_dir: str) -> str:
    rel = sample.get("fixture_path") or sample.get("path", "")
    return os.path.join(gold_dir, rel)


def validate_sample(sample: Mapping[str, Any], gold_dir: str) -> list[str]:
    """返回结构问题清单；空列表即结构合法。"""
    issues: list[str] = []
    for field in _REQUIRED_SAMPLE_FIELDS:
        if not sample.get(field):
            issues.append(f"missing field: {field}")
    cls = sample.get("class")
    if cls not in _CLASS_EXPECTED:
        issues.append(f"unknown class: {cls!r}")
    expected = sample.get("expected") or {}
    for key in ("verdict", "authorization"):
        if not expected.get(key):
            issues.append(f"expected.{key} missing")
    fixture_dir = _sample_fixture_dir(sample, gold_dir)
    if not os.path.isdir(fixture_dir):
        issues.append(f"fixture dir not found: {fixture_dir}")
    return issues


def placeholder_verdict(sample: Mapping[str, Any]) -> dict[str, str]:
    """占位判定：按 class 回退期望。引擎不可用时兜底，仅作结构自检。"""
    cls = sample["class"]
    return dict(_CLASS_EXPECTED[cls])


def evaluate_gold(gold_dir: str = GOLD_DIR) -> dict[str, Any]:
    """加载样本、结构校验、引擎实测观测；阈值未标定不判门禁。"""
    manifest = load_manifest(os.path.join(gold_dir, "MANIFEST.json"))
    baseline = load_baseline(os.path.join(gold_dir, "baseline.json"))
    thresholds = baseline.get("thresholds", {})
    calibrated = any(v is not None for v in thresholds.values())

    # 引擎连通性：成功导入即视为观测路径可用（单样本异常另记）。
    _, engine_err = _load_engine()
    engine_connected = engine_err is None

    rows: list[dict[str, Any]] = []
    tp = fp = fn = tn = 0
    structural_issues: list[str] = []

    for sample in manifest.get("samples", []):
        issues = validate_sample(sample, gold_dir)
        structural_issues.extend(f"{sample.get('id', '?')}: {i}" for i in issues)
        expected = sample.get("expected", {})
        cls = sample["class"]
        fixture_dir = _sample_fixture_dir(sample, gold_dir)

        rec = _run_engine(fixture_dir) if engine_connected else {"available": False, "error": engine_err}
        if rec.get("available"):
            verdict = _verdict_from_record(cls, rec)
            if cls == "boundary":
                # 证据不足边界：授权恒 UNKNOWN，不采用引擎的授权结论。
                auth_status = _CLASS_EXPECTED[cls]["authorization"]
            else:
                auth_status = rec.get("auth_status") or _CLASS_EXPECTED[cls]["authorization"]
            source = "engine"
        else:
            placeholder = placeholder_verdict(sample)
            verdict = placeholder["verdict"]
            auth_status = placeholder["authorization"]
            source = "placeholder"

        match = verdict == expected.get("verdict")
        detected = verdict == "FAIL"
        if cls == "negative":
            tp += int(detected)
            fn += int(not detected)
        elif cls == "positive":
            fp += int(detected)
            tn += int(not detected)
        rows.append(
            {
                "id": sample.get("id"),
                "class": cls,
                "expected_verdict": expected.get("verdict"),
                "verdict": verdict,
                "verdict_source": source,
                "expected_authorization": expected.get("authorization"),
                "authorization": auth_status,
                "engine": {k: rec.get(k) for k in ("available", "score", "grade", "auth_reason", "error")},
                "match": match,
                "issues": issues,
            }
        )

    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None

    return {
        "engine_connected": engine_connected,
        "thresholds_calibrated": calibrated,
        "thresholds": thresholds,
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "precision": precision,
        "recall": recall,
        "sample_count": len(rows),
        "rows": rows,
        "structural_issues": structural_issues,
        "note": "引擎实测仅为观测口径；阈值标定前不产出 PASS/FAIL 门禁。样本规模扩大并回测稳定后再标定 baseline。",
    }


if __name__ == "__main__":
    import pprint

    pprint.pp(evaluate_gold())
