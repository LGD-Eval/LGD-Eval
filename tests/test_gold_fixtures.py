#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gold 夹具结构与引擎观测校验桩（DRAFT，对应 N8 结构口径）。

校验：MANIFEST/样本可加载、字段齐备、夹具目录存在、引擎观测路径连通、
阈值仍未标定。**不**把观测到的 precision/recall 当作真实准确性达标；
阈值标定前 runner 不产 PASS/FAIL 门禁结论。

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
        self.assertEqual(self.report["sample_count"], 8)
        classes = {r["class"] for r in self.report["rows"]}
        self.assertEqual(classes, {"positive", "negative", "boundary"})

    def test_no_structural_issues(self) -> None:
        self.assertEqual(self.report["structural_issues"], [])

    def test_observation_matches_expected(self) -> None:
        # 引擎观测 verdict 与期望对齐（观测口径，非门禁达标宣称）。
        for row in self.report["rows"]:
            self.assertTrue(row["match"], f"{row['id']} 观测 verdict 与期望不一致")

    def test_engine_observation_path_connected(self) -> None:
        # 引擎可导入并跑通观测；与「阈值未标定」红线相互独立。
        self.assertTrue(self.report["engine_connected"])
        for row in self.report["rows"]:
            self.assertEqual(row["verdict_source"], "engine", row["id"])
            self.assertTrue(row["engine"]["available"], row["id"])

    def test_boundary_authorization_unknown(self) -> None:
        boundary = next(r for r in self.report["rows"] if r["class"] == "boundary")
        self.assertEqual(boundary["verdict"], "INCONCLUSIVE")
        self.assertEqual(boundary["authorization"], "UNKNOWN")

    def test_observation_confusion_matrix(self) -> None:
        # 固定八样本观测：TP=5（五条 negative 检出）、TN=1（positive 放行）、FP/FN=0。
        # 仅为当前样本集观测值；样本规模扩大并回测稳定前，不得写成达标基线。
        c = self.report["confusion"]
        self.assertEqual(c, {"tp": 5, "fp": 0, "fn": 0, "tn": 1})

    def test_baseline_thresholds_not_calibrated(self) -> None:
        # 阈值未标定：不得把当前观测计数写成达标基线。
        self.assertFalse(self.report["thresholds_calibrated"])
        for key in ("min_precision", "min_recall", "max_false_positive_rate"):
            self.assertIsNone(self.report["thresholds"].get(key))

    def test_sample_fingerprint_placeholder_null(self) -> None:
        manifest = gold_runner.load_manifest(os.path.join(GOLD, "MANIFEST.json"))
        for sample in manifest["samples"]:
            self.assertIsNone(sample["fingerprint"], f"{sample['id']} 指纹应待钉扎")

    def test_baseline_json_parseable(self) -> None:
        baseline = gold_runner.load_baseline(os.path.join(GOLD, "baseline.json"))
        self.assertIn("thresholds", baseline)
        # runner 观测值只在报告内存中，不回写 baseline.json；current 仍为空基线。
        self.assertEqual(baseline["current"]["sample_count"], 0)


if __name__ == "__main__":
    unittest.main()
