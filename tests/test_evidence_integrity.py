#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_evidence_integrity.py —— 防篡改 / 漂移 / 过期校验（fail-closed，纯本地）。"""
import json
import os
import pathlib
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "lgd-eval" / "scripts"))

import evaluate  # noqa: E402
import evidence_integrity as ei  # noqa: E402


def _make_att(content="# demo\n"):
    tmp = tempfile.mkdtemp(prefix="lgd-int-")
    with open(os.path.join(tmp, "SKILL.md"), "w", encoding="utf-8") as f:
        f.write(content)
    evidence = [{
        "rule_id": "R-SEC-01", "dimension": "安全", "file": "SKILL.md",
        "line": 1, "evidence": "示例发现", "fix": "修复建议", "verify": "复验步骤",
    }]
    att = evaluate.build_attestation(tmp, 87, "A",
                                     {"结构完整性": 20, "目录结构": 10,
                                      "文档质量": 15, "安全": 22, "生态兼容性": 20},
                                     evidence)
    return att, tmp


class IntegrityTest(unittest.TestCase):
    def test_match_against_current_baseline(self):
        att, _ = _make_att()
        res = ei.verify(att, current_tree_sha=att["inputs"]["tree_sha256"],
                         current_commit=att["target_commit"],
                         current_rule_version=att["rule_version"],
                         current_engine_version=att["engine_version"],
                         max_age_days=30)
        self.assertEqual(res["status"], ei.MATCH)

    def test_tampered_score_detected(self):
        att, _ = _make_att()
        att["score"] = 99  # 事后改分
        res = ei.verify(att)
        self.assertEqual(res["status"], ei.TAMPERED)

    def test_tree_drift_detected(self):
        att, _ = _make_att()
        res = ei.verify(att, current_tree_sha="deadbeef")
        self.assertEqual(res["status"], ei.DRIFTED)

    def test_stale_detected(self):
        att, _ = _make_att()
        old = (datetime.now(timezone.utc) - timedelta(days=40)).strftime("%Y-%m-%dT%H:%M:%SZ")
        att["evaluated_at"] = old
        res = ei.verify(att, max_age_days=30)
        self.assertEqual(res["status"], ei.STALE)

    def test_missing_field_incomplete(self):
        att, _ = _make_att()
        del att["fingerprint"]
        res = ei.verify(att)
        self.assertEqual(res["status"], ei.INCOMPLETE)

    def test_same_target(self):
        a, _ = _make_att("# demo\n")
        b, _ = _make_att("# other content\n")
        # 内容不同 → 树哈希不同，非同一目标
        self.assertFalse(ei.same_target(a, b))
        self.assertTrue(ei.same_target(a, a))


if __name__ == "__main__":
    unittest.main(verbosity=2)
