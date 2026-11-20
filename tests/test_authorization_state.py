#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""授权状态机负向测试桩（DRAFT，对应 N1/N2/N3/N4/N10）。

运行：python -m unittest discover -s tests -v
骨架期断言失败关闭口径；正式实现接入后以 gold 基准回归。
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(HERE, "..", "skills", "lgd-eval", "scripts")
sys.path.insert(0, os.path.abspath(SCRIPTS))

import authorization  # noqa: E402
from authorization import AuthStatus, build_authorization, revoke  # noqa: E402


def _base_result(**over):
    base = {
        "evidence_id": "ev-001",
        "evaluator": "lgd-eval",
        "rule_version": "1.1.0",
        "subject_fingerprint": "sha256:abc",
        "provenance": {"source": "local", "env": "draft"},
        "coverage": "source",
        "findings": [],
    }
    base.update(over)
    return base


class AuthorizationStateTests(unittest.TestCase):
    # N1 缺 fingerprint/rule_version 等前置要素 -> INCOMPLETE，非 PASS/GRANTED
    def test_n1_missing_provenance_is_incomplete(self):
        res = {"evidence_id": "ev-x", "findings": []}
        dec = build_authorization(res)
        self.assertEqual(dec.status, AuthStatus.INCOMPLETE)
        self.assertNotEqual(dec.status, AuthStatus.GRANTED)

    # N2 仅 metadata/空目录扫描 -> UNKNOWN
    def test_n2_metadata_only_is_unknown(self):
        res = _base_result(coverage="metadata-only")
        dec = build_authorization(res)
        self.assertEqual(dec.status, AuthStatus.UNKNOWN)

    # N3 CRITICAL 命中 -> NOT_GRANTED（封顶只写入 result，授权阻断）
    def test_n3_critical_is_not_granted(self):
        res = _base_result(findings=[{"severity": "CRITICAL", "rule": "R-SEC-09"}])
        dec = build_authorization(res)
        self.assertEqual(dec.status, AuthStatus.NOT_GRANTED)

    # N4 高分但无独立决策方 -> NOT_GRANTED，授权不随分数授予
    def test_n4_high_score_without_decisioner_not_granted(self):
        res = _base_result(score=96, findings=[])
        dec = build_authorization(res)
        self.assertEqual(dec.status, AuthStatus.NOT_GRANTED)

    # N10 撤销后引用 -> REVOKED 决策不可被默认采纳
    def test_n10_revoked_not_adopted(self):
        res = _base_result()
        granted = build_authorization(res, policy={"policy_ref": "p-1"}, decision_by="reviewer-x")
        self.assertEqual(granted.status, AuthStatus.GRANTED)
        revoked = revoke(granted, "evidence stale", revoked_at="2026-11-20T00:00:00Z")
        self.assertTrue(revoked.revoked)
        self.assertEqual(revoked.status, AuthStatus.NOT_GRANTED)


if __name__ == "__main__":
    unittest.main()
