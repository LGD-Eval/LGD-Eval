#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""适配层 · 外部复核挂载衔接桩（DRAFT，对应 #61 L4 骨架衔接）。

校验：已采信外部复核才挂 reviewer/external_anchor；未采信只在 provenance 留痕；
外部 verdict 不回写授权状态（评测—授权分轨不变）。不接真实外部节点、不发网络请求。

运行：python -m unittest tests.test_adapter_external -v
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

import evaluate_adapter as adapter  # noqa: E402
import external_review  # noqa: E402


def _result(**over):
    base = {
        "evidence_id": "ev-ad-001",
        "evaluator": "lgd-eval",
        "rule_version": "1.1.0",
        "subject_fingerprint": "sha256:abc123",
        "provenance": {"source": "local-draft"},
        "coverage": "source",
        "findings": [],
    }
    base.update(over)
    return base


def _review(**over):
    base = {
        "review_id": "rev-ad-001",
        "reviewer_id": "external-node-07",
        "reviewer_org": "independent-cert-body",
        "evaluator_id": "lgd-eval",
        "subject_fingerprint": "sha256:abc123",
        "verdict": "pass",
        "signature": {"alg": "placeholder-ed25519", "value": "placeholder"},
        "external_anchor": {"type": "placeholder-registry", "ref": "placeholder"},
        "reviewed_at": "2026-11-20T00:00:00Z",
        "evidence_level": "L4",
    }
    base.update(over)
    return base


class AdapterExternalReviewTests(unittest.TestCase):
    def _evidence(self):
        result = _result()
        decision = adapter.authorize(result)  # 无决策方 → NOT_GRANTED
        return adapter.assemble_evidence(
            result, decision, subject_id="skill-demo", subject_type="skill"
        )

    def test_accepted_review_attaches_reviewer_and_anchor(self):
        review = _review()
        validation = external_review.validate_external_review(
            review, expected_fingerprint="sha256:abc123"
        )
        self.assertTrue(validation["accepted_for_l4"])
        ev = self._evidence()
        adapter.attach_external_review(ev, review, validation)
        self.assertEqual(ev.reviewer["id"], "external-node-07")
        self.assertEqual(ev.reviewer["org"], "independent-cert-body")
        self.assertTrue(ev.reviewer["independent"])
        self.assertEqual(ev.external_anchor["review_id"], "rev-ad-001")
        self.assertEqual(ev.external_anchor["verdict"], "pass")
        self.assertEqual(ev.external_anchor["evidence_level"], "L4")
        self.assertTrue(ev.provenance["external_review"]["accepted"])
        # 骨架期签名/锚点为占位：挂载锚点留痕，但不自动抬高证据等级
        self.assertEqual(ev.evidence_level, "L1")

    def test_rejected_review_does_not_attach_anchor(self):
        review = _review(reviewer_id="lgd-eval")  # 同体 → 不独立
        validation = external_review.validate_external_review(
            review, expected_fingerprint="sha256:abc123"
        )
        self.assertFalse(validation["accepted_for_l4"])
        ev = self._evidence()
        adapter.attach_external_review(ev, review, validation)
        self.assertEqual(ev.reviewer, {})
        self.assertIsNone(ev.external_anchor)
        self.assertFalse(ev.provenance["external_review"]["accepted"])
        self.assertTrue(ev.provenance["external_review"]["reasons"])

    def test_external_verdict_does_not_grant_authorization(self):
        review = _review(verdict="pass")
        validation = external_review.validate_external_review(
            review, expected_fingerprint="sha256:abc123"
        )
        ev = self._evidence()
        # 挂载前授权即为 NOT_GRANTED（无独立决策方）
        self.assertEqual(ev.authorization["status"], "NOT_GRANTED")
        adapter.attach_external_review(ev, review, validation)
        # 外部 pass 复核不得把授权抬成 GRANTED
        self.assertEqual(ev.authorization["status"], "NOT_GRANTED")
        # 分轨：result 不夹带授权字段
        for leaked in ("authorization", "granted", "permission", "access_granted"):
            self.assertNotIn(leaked, ev.result)


if __name__ == "__main__":
    unittest.main()
