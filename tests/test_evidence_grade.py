#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_evidence_grade.py —— E0–E4 证据等级 fail-closed 判定（纯函数，不联网）。"""
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "lgd-eval" / "scripts"))

import evidence_grade as eg  # noqa: E402


class EvidenceGradeTest(unittest.TestCase):
    def test_e0_when_no_verdict(self):
        g = eg.grade_evidence(verdict_present=False)
        self.assertEqual(g["level"], eg.E0)
        self.assertFalse(g["independent"])

    def test_e1_author_local_only(self):
        g = eg.grade_evidence(author_local=True)
        self.assertEqual(g["level"], eg.E1)
        self.assertFalse(g["independent"])

    def test_e2_clean_repro(self):
        g = eg.grade_evidence(author_local=True, clean_repro=True)
        self.assertEqual(g["level"], eg.E2)
        self.assertFalse(g["independent"])

    def test_e3_ci_passed(self):
        g = eg.grade_evidence(ci_passed=True)
        self.assertEqual(g["level"], eg.E3)
        self.assertTrue(g["independent"])

    def test_e4_third_party(self):
        g = eg.grade_evidence(third_party=True)
        self.assertEqual(g["level"], eg.E4)
        self.assertTrue(g["independent"])

    def test_third_party_beats_ci(self):
        g = eg.grade_evidence(ci_passed=True, third_party=True)
        self.assertEqual(g["level"], eg.E4)

    def test_independent_impl_alone_is_not_third_party(self):
        # 有独立代码实现但无第三方复核记录，不得自动升 E4。
        g = eg.grade_evidence(author_local=True, independent_impl=True)
        self.assertEqual(g["level"], eg.E1)

    def test_assert_independent_message(self):
        e1 = eg.grade_evidence(author_local=True)
        self.assertIsNotNone(eg.assert_independent(e1))
        e4 = eg.grade_evidence(third_party=True)
        self.assertIsNone(eg.assert_independent(e4))


if __name__ == "__main__":
    unittest.main(verbosity=2)
