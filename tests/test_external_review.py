#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""external_review 骨架校验桩（DRAFT，对应 L4 第三方外部回传通道）。

红线口径：本桩只校验结构、独立性、指纹绑定与锚定留痕；不接入真实外部节点，
不发起网络请求，不把外部复核结论直接当作授权（GRANTED 仍走 authorization 状态机）。

运行：python -m unittest tests.test_external_review -v
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(HERE, "..", "skills", "lgd-eval", "scripts")
sys.path.insert(0, os.path.abspath(SCRIPTS))

import external_review  # noqa: E402
from external_review import ExternalReviewRecord, validate_external_review  # noqa: E402


def _record(**over):
    base = {
        "review_id": "rev-2026-001",
        "reviewer_id": "external-node-07",
        "reviewer_org": "independent-cert-body",
        "evaluator_id": "lgd-eval",
        "subject_fingerprint": "sha256:abc123",
        "verdict": "pass",
        "rationale": "独立复核未见未决高危项",
        "signature": {"alg": "placeholder-ed25519", "value": "placeholder"},
        "external_anchor": {"type": "placeholder-registry", "ref": "placeholder"},
        "reviewed_at": "2026-11-20T00:00:00Z",
        "evidence_level": "L4",
    }
    base.update(over)
    return base


class ExternalReviewTests(unittest.TestCase):
    def test_compliant_record_accepted_for_l4(self):
        rec = _record()
        out = validate_external_review(rec, expected_fingerprint="sha256:abc123")
        self.assertTrue(out["accepted_for_l4"])
        self.assertTrue(out["independence_ok"])
        self.assertTrue(out["anchored"])
        self.assertEqual(out["reasons"], [])

    def test_reviewer_same_as_evaluator_is_not_independent(self):
        rec = _record(reviewer_id="lgd-eval")
        out = validate_external_review(rec, expected_fingerprint="sha256:abc123")
        self.assertFalse(out["independence_ok"])
        self.assertFalse(out["accepted_for_l4"])
        self.assertTrue(any("independent" in r for r in out["reasons"]))

    def test_fingerprint_mismatch_rejected(self):
        out = validate_external_review(_record(), expected_fingerprint="sha256:zzz")
        self.assertFalse(out["accepted_for_l4"])
        self.assertTrue(any("fingerprint mismatch" in r for r in out["reasons"]))

    def test_missing_reviewer_identity_rejected(self):
        rec = _record(reviewer_id="", reviewer_org="")
        out = validate_external_review(rec, expected_fingerprint="sha256:abc123")
        self.assertFalse(out["accepted_for_l4"])
        self.assertTrue(any("reviewer_id" in r for r in out["reasons"]))

    def test_unanchored_record_not_counted_l4(self):
        rec = _record(signature=None, external_anchor=None)
        out = validate_external_review(rec, expected_fingerprint="sha256:abc123")
        self.assertFalse(out["anchored"])
        self.assertFalse(out["accepted_for_l4"])
        self.assertEqual(len(out["reasons"]), 2)  # 缺签名 + 缺外部锚点

    def test_invalid_verdict_rejected(self):
        out = validate_external_review(_record(verdict="approved"),
                                        expected_fingerprint="sha256:abc123")
        self.assertFalse(out["accepted_for_l4"])
        self.assertTrue(any("invalid verdict" in r for r in out["reasons"]))

    def test_digest_is_deterministic_and_tamper_visible(self):
        rec = _record()
        first = ExternalReviewRecord(**rec).digest()
        second = ExternalReviewRecord(**rec).digest()
        self.assertEqual(first, second)
        tampered = _record(rationale="changed after seal")
        self.assertNotEqual(ExternalReviewRecord(**tampered).digest(), first)

    def test_review_record_carries_no_authorization_field(self):
        # 分轨红线：外部复核记录不得夹带授权结论字段。
        rec = _record()
        for leaked in ("authorization", "granted", "permission", "access_granted"):
            self.assertNotIn(leaked, rec)


if __name__ == "__main__":
    unittest.main()
