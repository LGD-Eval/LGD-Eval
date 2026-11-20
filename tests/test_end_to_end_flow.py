#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""端到端流程桩（DRAFT）：分轨授权 + 证据链 + 撤销 完整路径。

运行：python -m unittest discover -s tests -v
覆盖：N1/N2/N4/N5/N9/N10 的端到端串联；正式接入后以 gold 基准回归。
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
SCRIPTS = os.path.join(ROOT, "skills", "lgd-eval", "scripts")
ADAPTERS = os.path.join(ROOT, "adapters")
sys.path.insert(0, SCRIPTS)
sys.path.insert(0, ADAPTERS)

import authorization  # noqa: E402
import evidence  # noqa: E402
import evaluate_adapter as adapter  # noqa: E402
from authorization import AuthStatus, revoke  # noqa: E402


def _result(**over):
    base = {
        "score": 99,
        "grade": "A+",
        "dims": {"structure": 24, "manifest": 14, "docs": 19, "security": 24, "compat": 14},
        "findings": [],
        "warnings": [],
        "veto_info": {"cap": 100, "level": "NONE", "reason": ""},
        "evaluator": "lgd-eval",
        "rule_version": "1.1.0",
        "subject_fingerprint": "fp-abc123",
        "provenance": {"source": "local-draft", "captured_at": "2026-11-20"},
        "evidence_id": "ev-e2e-001",
        "coverage": "source",
        "scope": "read-only",
        "confidence": 0.9,
        "coverage_honesty": "source",
    }
    base.update(over)
    return base


class EndToEndFlowTest(unittest.TestCase):
    def test_high_score_without_decision_party_is_not_granted(self) -> None:
        result = _result()
        decision = adapter.authorize(result)  # 无 decision_by
        self.assertEqual(decision.status, AuthStatus.NOT_GRANTED)
        # 高分（99）不得自动导出授权；result 不夹带授权字段。
        adapter.assert_separation(result, decision)

    def test_granted_path_requires_independent_party_and_policy(self) -> None:
        result = _result()
        decision = adapter.authorize(
            result,
            decision_by="independent-reviewer-01",
            policy={"policy_ref": "POL-TRUST-01"},
            reviewer={"independent": True},
        )
        self.assertEqual(decision.status, AuthStatus.GRANTED)
        self.assertEqual(decision.decision_by, "independent-reviewer-01")
        self.assertEqual(decision.policy_ref, "POL-TRUST-01")
        adapter.assert_separation(result, decision)

    def test_evidence_chain_and_revocation(self) -> None:
        prev = evidence.EvidenceObject(
            evidence_id="ev-prev",
            subject_id="subj-01",
            subject_type="skill",
            subject_fingerprint="fp-abc123",
            result=_result(),
            chain=evidence.link_previous(None, None),
        )
        cur = evidence.EvidenceObject(
            evidence_id="ev-cur",
            subject_id="subj-01",
            subject_type="skill",
            subject_fingerprint="fp-abc123",
            result=_result(evidence_id="ev-cur"),
            chain=evidence.link_previous(prev.evidence_id, prev.digest()),
        )
        self.assertEqual(cur.chain["prev_evidence_id"], "ev-prev")
        self.assertEqual(cur.chain["prev_digest"], prev.digest())

        granted = adapter.authorize(
            _result(),
            decision_by="independent-reviewer-01",
            policy={"policy_ref": "POL-TRUST-01"},
            reviewer={"independent": True},
        )
        revoked = revoke(granted, reason="fingerprint mismatch", revoked_at="2026-11-20T10:00:00Z")
        self.assertEqual(revoked.status, AuthStatus.NOT_GRANTED)
        self.assertTrue(revoked.revoked)
        self.assertIn("fingerprint mismatch", revoked.reason)
        # 撤销后旧决策不可被新引用默认采纳。
        self.assertEqual(revoked.status, AuthStatus.NOT_GRANTED)

    def test_missing_provenance_is_incomplete(self) -> None:
        result = _result(evaluator=None)
        decision = adapter.authorize(result, decision_by="x", policy={"policy_ref": "P"})
        self.assertEqual(decision.status, AuthStatus.INCOMPLETE)


if __name__ == "__main__":
    unittest.main()
