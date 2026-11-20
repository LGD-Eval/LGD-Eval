#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""证据链 / 过期测试桩（DRAFT，对应 N5/N9）。"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(HERE, "..", "skills", "lgd-eval", "scripts")
sys.path.insert(0, os.path.abspath(SCRIPTS))

from evidence import EvidenceObject, link_previous, self_digest  # noqa: E402


def _ev(evidence_id="ev-1", fingerprint="sha256:aaa"):
    return EvidenceObject(
        evidence_id=evidence_id,
        subject_id="skill-demo",
        subject_type="skill",
        subject_fingerprint=fingerprint,
        result={"score": 80, "grade": "A", "dims": {}, "findings": []},
    )


class EvidenceChainTests(unittest.TestCase):
    # N5 指纹已变、复用旧证据 -> 旧证据 STALE，不参与当前判定
    def test_n5_changed_fingerprint_marks_stale(self):
        ev = _ev()
        digest_before = ev.digest()
        ev.mark_stale("subject fingerprint changed after seal")
        self.assertEqual(ev.lifecycle, "STALE")
        self.assertNotEqual(digest_before, ev.digest())

    # 链链接字段可复算并可串联
    def test_chain_link_links_previous(self):
        prev = _ev("ev-0")
        link = link_previous(prev.evidence_id, prev.digest())
        self.assertEqual(link["prev_evidence_id"], "ev-0")
        self.assertEqual(link["prev_digest"], prev.digest())

    # N9 证据过期 -> STALE/EXPIRED，须复跑续期
    def test_n9_expired_is_stale(self):
        ev = _ev()
        ev.expiration = {"expires_at": "2026-11-01T00:00:00Z", "reason": "ttl"}
        ev.mark_stale("evidence expired; rerun to renew")
        self.assertEqual(ev.lifecycle, "STALE")
        self.assertIn("expired", ev.provenance["stale_reason"])

    # 摘要确定性：同对象两次 self_digest 一致
    def test_digest_is_deterministic(self):
        ev = _ev()
        self.assertEqual(self_digest(ev.to_dict()), self_digest(ev.to_dict()))


if __name__ == "__main__":
    unittest.main()
