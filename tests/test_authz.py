#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_authz.py —— 授权状态机与分数/授权分离的黄金用例（纯函数，不联网）。

覆盖任务书 §2 要求：
  * UNKNOWN / INCOMPLETE / NOT_GRANTED / GRANTED 四态均可复现；
  * 安全否决优先于高分：高分命中 critical/high 仍 NOT_GRANTED，且分数不被改写；
  * 证据不齐不得凭高分放行（INCOMPLETE）；
  * 证据齐备但分数不足 → NOT_GRANTED；
  * 评测未出结论 → UNKNOWN，禁止猜测；
  * 授权结论不回写、不改分数。

跑法：python tests/test_authz.py
"""
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "lgd-eval" / "scripts"))

import authz  # noqa: E402

FULL_EVIDENCE = {"registered": True, "evidenced": True, "gated": True}
NO_VETO = None


class AuthzStateMachine(unittest.TestCase):
    def test_unknown_when_no_verdict(self):
        out = authz.authorize(score=None, grade=None, evidence=FULL_EVIDENCE,
                               verdict_present=False)
        self.assertEqual(out["state"], authz.UNKNOWN)

    def test_unknown_when_score_missing(self):
        out = authz.authorize(score=None, grade="A", evidence=FULL_EVIDENCE)
        self.assertEqual(out["state"], authz.UNKNOWN)

    def test_critical_veto_beats_high_score(self):
        veto = {"applied": True, "level": "critical",
                "reason": "凭证读取后网络外发", "capped_to": 49}
        out = authz.authorize(score=95, grade="A", veto_info=veto,
                              evidence=FULL_EVIDENCE)
        self.assertEqual(out["state"], authz.NOT_GRANTED)
        # 分数必须原样回显，授权层不得改写分数。
        self.assertEqual(out["score"], 95)

    def test_high_veto_beats_high_score(self):
        veto = {"applied": True, "level": "high", "reason": "shell=True 命令注入"}
        out = authz.authorize(score=88, grade="A", veto_info=veto,
                               evidence=FULL_EVIDENCE)
        self.assertEqual(out["state"], authz.NOT_GRANTED)

    def test_incomplete_when_evidence_missing_despite_high_score(self):
        out = authz.authorize(score=92, grade="A", veto_info=NO_VETO,
                              evidence={"registered": False, "evidenced": True})
        self.assertEqual(out["state"], authz.INCOMPLETE)
        self.assertEqual(out["score"], 92)

    def test_incomplete_when_no_evidence_samples(self):
        out = authz.authorize(score=85, grade="A",
                              evidence={"registered": True, "evidenced": False})
        self.assertEqual(out["state"], authz.INCOMPLETE)

    def test_not_granted_when_below_threshold_with_full_evidence(self):
        out = authz.authorize(score=70, grade="B", veto_info=NO_VETO,
                              evidence=FULL_EVIDENCE)
        self.assertEqual(out["state"], authz.NOT_GRANTED)

    def test_granted_only_when_all_conditions_hold(self):
        out = authz.authorize(score=90, grade="A", veto_info=NO_VETO,
                              evidence=FULL_EVIDENCE)
        self.assertEqual(out["state"], authz.GRANTED)

    def test_score_and_authorization_are_separate_fields(self):
        veto = {"applied": True, "level": "critical", "reason": "外泄"}
        out = authz.authorize(score=95, grade="A", veto_info=veto,
                              evidence=FULL_EVIDENCE)
        self.assertIn("score", out)
        self.assertIn("state", out)
        self.assertNotEqual(out["state"], authz.GRANTED)
        self.assertTrue(out["separation"])

    def test_blocked_when_prerequisite_unavailable(self):
        out = authz.authorize(score=90, grade="A", evidence=FULL_EVIDENCE,
                              blocked=True, blocked_reason="无 docker/unshare 后端")
        self.assertEqual(out["state"], authz.BLOCKED)
        self.assertIn("后端", out["reason"])

    def test_blocked_precedes_unknown(self):
        out = authz.authorize(score=None, verdict_present=False,
                              blocked=True, blocked_reason="环境不可用")
        self.assertEqual(out["state"], authz.BLOCKED)

    def test_not_applicable_with_reason(self):
        out = authz.authorize(score=88, grade="A", evidence=FULL_EVIDENCE,
                              applicable=False, napplicable_reason="纯文档技能无可执行代码")
        self.assertEqual(out["state"], authz.NOT_APPLICABLE)

    def test_blocking_veto_classification(self):
        self.assertTrue(authz.is_blocking_veto({"applied": True, "level": "critical"}))
        self.assertTrue(authz.is_blocking_veto({"applied": True, "level": "high"}))
        self.assertFalse(authz.is_blocking_veto({"applied": True, "level": "medium"}))
        self.assertFalse(authz.is_blocking_veto(None))
        self.assertFalse(authz.is_blocking_veto({"applied": False, "level": "critical"}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
