#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_accuracy_benchmark.py —— 评测器自身标注样本基准的 pytest 包装。

校验：
  * 三条人工标注样本（干净 / 高危注入 / 证据残缺）的授权判定与标注一致；
  * 基准汇总 all_match，accuracy=1.0；
  * 高危样本必须带 high/critical 封顶，且授权 NOT_GRANTED（安全否决优先于分数）；
  * 干净样本证据齐备、无否决且分数达阈值才 GRANTED。

跑法：python -m pytest tests/test_accuracy_benchmark.py
"""
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "lgd-eval" / "scripts"))

import accuracy_benchmark  # noqa: E402
import authz  # noqa: E402


class AccuracyBenchmark(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = accuracy_benchmark.evaluate_cases()
        cls.summary = accuracy_benchmark.summary(cls.rows)
        cls.by_id = {r["id"]: r for r in cls.rows}

    def test_all_cases_match_labels(self):
        self.assertTrue(self.summary["all_match"],
                        "存在标注与判定不符的样本：%s" %
                        [(r["id"], r["expect"], r["actual"]) for r in self.rows if not r["match"]])
        self.assertEqual(self.summary["accuracy"], 1.0)

    def test_clean_granted(self):
        r = self.by_id["clean-well-formed"]
        self.assertEqual(r["actual"], authz.GRANTED)
        self.assertGreaterEqual(r["score"], authz.DEFAULT_GRANT_THRESHOLD)
        self.assertEqual(r["veto_level"], "")

    def test_malicious_blocked_by_security(self):
        r = self.by_id["shell-injection-high"]
        self.assertEqual(r["actual"], authz.NOT_GRANTED)
        self.assertIn(r["veto_level"], ("high", "critical"))

    def test_incomplete_not_granted_on_missing_evidence(self):
        r = self.by_id["missing-evidence"]
        self.assertEqual(r["actual"], authz.INCOMPLETE)


if __name__ == "__main__":
    unittest.main()
