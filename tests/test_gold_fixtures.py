#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gold 夹具结构校验桩（DRAFT，对应 N8 结构口径）。

只校验：MANIFEST/样本可加载、字段齐备、fixture 目录存在、基线阈值未标定。
**不**把占位对照的 precision/recall 当作真实准确性达标；真实引擎接入后再标定阈值。

运行：python -m unittest tests.test_gold_fixtures -v
"""

import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
GOLD = os.path.join(HERE, "fixtures", "gold")
sys.path.insert(0, GOLD)

import gold_runner  # noqa: E402


class GoldFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = gold_runner.evaluate_gold(GOLD)

    def test_manifest_samples_load(self) -> None:
        self.assertEqual(self.report["sample_count"], 3)
        classes = {r["class"] for r in self.report["rows"]}
        self.assertEqual(classes, {"positive", "negative", "boundary"})

    def test_no_structural_issues(self) -> None:
        self.assertEqual(self.report["structural_issues"], [])

    def test_placeholders_match_expected(self) -> None:
        for row in self.report["rows"]:
            self.assertTrue(row["match"], f"{row['id']} 占位 verdict 与期望不一致")

    def test_baseline_thresholds_not_calibrated(self) -> None:
        # 阈值未标定：不得把当前计数写成达标基线。
        self.assertFalse(self.report["thresholds_calibrated"])
        for key in ("min_precision", "min_recall", "max_false_positive_rate"):
            self.assertIsNone(self.report["thresholds"].get(key))

    def test_runner_marks_engine_disconnected(self) -> None:
        # 骨架期未接主引擎；占位对照不是 L3/L4 证据。
        self.assertFalse(self.report["engine_connected"])

    def test_sample_fingerprint_placeholder_null(self) -> None:
        manifest = gold_runner.load_manifest(os.path.join(GOLD, "MANIFEST.json"))
        for sample in manifest["samples"]:
            self.assertIsNone(sample["fingerprint"], f"{sample['id']} 指纹应待钉扎")

    def test_baseline_json_parseable(self) -> None:
        baseline = gold_runner.load_baseline(os.path.join(GOLD, "baseline.json"))
        self.assertIn("thresholds", baseline)
        self.assertEqual(baseline["current"]["sample_count"], 0)


if __name__ == "__main__":
    unittest.main()
