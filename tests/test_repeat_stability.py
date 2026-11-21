#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_repeat_stability.py —— pass^k 重复稳定性测量的结构自测。

只校验：k 次重复后状态集合唯一、逐次匹配、汇总口径自洽；
本测量为 E1 合成夹具确定性复跑，不替代真实场景稳定性验证。

跑法：python -m pytest tests/test_repeat_stability.py
"""
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "lgd-eval" / "scripts"))

import repeat_stability  # noqa: E402


class RepeatStability(unittest.TestCase):
    def test_schema_and_all_stable_k2(self):
        report = repeat_stability.run_repeat(k=2)
        self.assertEqual(report["gate_schema"], "lgd-eval-repeat-stability/1.0")
        self.assertEqual(report["evidence_level"], "E1")
        self.assertEqual(report["repeats"], 2)
        self.assertEqual(report["summary"]["total"], len(report["cases"]))
        self.assertTrue(report["summary"]["all_stable"])
        self.assertEqual(report["summary"]["pass_k_rate"], 1.0)

    def test_each_case_state_unique_and_match_all(self):
        report = repeat_stability.run_repeat(k=2)
        for c in report["cases"]:
            self.assertEqual(len(c["state_set"]), 1, c["id"])
            self.assertTrue(c["match_all"], c["id"])
            self.assertTrue(c["stable"], c["id"])


if __name__ == "__main__":
    unittest.main()
