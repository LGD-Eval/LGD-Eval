#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gold_runner.py — gold 基准集加载与占位对照骨架（P0，DRAFT，未接入主引擎）。

边界（红线）：
- 本骨架**不接主引擎规则**；verdict 由样本 class 按期望映射，仅用于自检样本结构
  可加载、字段齐备、指纹可钉扎；**不是真实准确性结果**，不计入 L3/L4 证据。
- 基线阈值未标定前（baseline.json thresholds 全 null），runner 只输出计数与结构
  校验，**不产出 PASS/FAIL 门禁结论**；不得把占位对照结果写成精度/召回达标。
- 真实接入：把 ``placeholder_verdict`` 替换为主引擎对 fixture 目录的实测 verdict，
  再用回测结果标定 baseline.json 的 min_precision / min_recall / max_false_positive_rate。

混淆矩阵口径（正类 = 高危样本，即 gold/negative）：
- TP：negative 样本被检出（verdict == FAIL）
- FN：negative 样本漏检（未判 FAIL）
- FP：positive 样本被误判 FAIL
- TN：positive 样本判 PASS
"""

from __future__ import annotations

import json
import os
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


def _read_json(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_manifest(manifest_path: str = MANIFEST) -> dict[str, Any]:
    return _read_json(manifest_path)


def load_baseline(baseline_path: str = BASELINE) -> dict[str, Any]:
    return _read_json(baseline_path)


def _sample_fixture_dir(sample: Mapping[str, Any], gold_dir: str) -> str:
    return os.path.join(gold_dir, sample.get("path", ""))


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
    """占位判定：按 class 回退期望。接入主引擎后删除本函数，改调引擎实测。"""
    cls = sample["class"]
    return dict(_CLASS_EXPECTED[cls])


def evaluate_gold(gold_dir: str = GOLD_DIR) -> dict[str, Any]:
    """加载样本、做结构校验与占位对照；阈值未标定不判门禁。"""
    manifest = load_manifest(os.path.join(gold_dir, "MANIFEST.json"))
    baseline = load_baseline(os.path.join(gold_dir, "baseline.json"))
    thresholds = baseline.get("thresholds", {})
    calibrated = any(v is not None for v in thresholds.values())

    rows: list[dict[str, Any]] = []
    tp = fp = fn = tn = 0
    structural_issues: list[str] = []

    for sample in manifest.get("samples", []):
        issues = validate_sample(sample, gold_dir)
        structural_issues.extend(f"{sample.get('id', '?')}: {i}" for i in issues)
        expected = sample.get("expected", {})
        placeholder = placeholder_verdict(sample)
        # 占位对照：期望与占位一致（结构自检）；真实引擎接入后以实测 verdict 替换。
        match = placeholder["verdict"] == expected.get("verdict")
        cls = sample["class"]
        detected = placeholder["verdict"] == "FAIL"
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
                "placeholder_verdict": placeholder["verdict"],
                "expected_authorization": expected.get("authorization"),
                "match": match,
                "issues": issues,
            }
        )

    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None

    return {
        "engine_connected": False,
        "thresholds_calibrated": calibrated,
        "thresholds": thresholds,
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "precision": precision,
        "recall": recall,
        "sample_count": len(rows),
        "rows": rows,
        "structural_issues": structural_issues,
        "note": "占位对照仅自检样本结构；非真实准确性结果。阈值标定前不产出 PASS/FAIL 门禁。",
    }


if __name__ == "__main__":
    import pprint

    pprint.pp(evaluate_gold())
