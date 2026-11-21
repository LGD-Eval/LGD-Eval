#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_gate_tools.py —— 门禁骨架结构自测（不联网、不推送、不接判定）。

只校验工具结构完整、fail-closed 默认值正确、计数自洽；
门禁是否真正放行须待干净环境实跑、CI E3 与独立复核 E4，本测试不替代。

跑法：python -m pytest tests/test_gate_tools.py
"""
import json
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "lgd-eval" / "scripts"
GATE = SCRIPTS / "gate"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(GATE))

import check_citations  # noqa: E402
import external_node_check  # noqa: E402
import redteam_suite  # noqa: E402
import publish_gate  # noqa: E402
import pre_push_gate  # noqa: E402
import push_safe  # noqa: E402


class CheckCitations(unittest.TestCase):
    def test_extract_urls_dedup(self):
        text = "见 https://a.example/x 和 https://a.example/x 与 https://b.example/y."
        urls = check_citations.extract_urls(text)
        self.assertEqual(urls, ["https://a.example/x", "https://b.example/y"])

    def test_offline_unchecked(self):
        rows = check_citations.check_urls(["https://example.com"], offline=True)
        self.assertEqual(rows[0]["status"], check_citations.STATUS_UNCHECKED)

    def test_scan_offline_summary(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.md")
            with open(p, "w", encoding="utf-8") as f:
                f.write("link https://example.com/a\n")
            report = check_citations.scan_path(d, offline=True, timeout=1.0)
            self.assertEqual(report["gate_schema"], "lgd-gate-citations/1.0")
            self.assertEqual(report["summary"].get("UNCHECKED"), 1)


class ExternalNodeCheck(unittest.TestCase):
    def test_missing_dir_inconclusive(self):
        report = external_node_check.evaluate(os.path.join(tempfile.gettempdir(), "no-such-dir-xyz"), "local")
        self.assertEqual(report["status"], external_node_check.INCONCLUSIVE)
        self.assertTrue(report["reasons"])

    def test_bad_label_inconclusive(self):
        with tempfile.TemporaryDirectory() as d:
            report = external_node_check.evaluate(d, "remote")
            self.assertEqual(report["status"], external_node_check.INCONCLUSIVE)

    def test_mirror_is_not_independent_impl(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "skills", "lgd-eval", "scripts"))
            os.makedirs(os.path.join(d, "vendor", "scripts"))
            open(os.path.join(d, "skills", "lgd-eval", "scripts", "evaluate.py"), "w").close()
            report = external_node_check.evaluate(d, "local")
            self.assertTrue(report["mirror_present"])
            self.assertFalse(report["independent_present"])
            self.assertEqual(report["status"], external_node_check.INCONCLUSIVE)
            self.assertTrue(any("独立第三方" in r for r in report["reasons"]))


class RedteamSuite(unittest.TestCase):
    def test_schema_and_summary(self):
        report = redteam_suite.run_suite()
        self.assertEqual(report["gate_schema"], "lgd-gate-redteam/1.0")
        self.assertEqual(report["evidence_level"], "E1")
        self.assertEqual(report["summary"]["total"], len(report["cases"]))


class PublishGate(unittest.TestCase):
    def test_missing_inputs_not_synced(self):
        board = publish_gate.build(None, None, None, local_head="3e64f0e", public_head=None)
        self.assertEqual(board["head"]["status"], "NOT_SYNCED")
        self.assertFalse(board["benchmark"]["present"])
        self.assertFalse(board["readiness"]["present"])
        html = publish_gate.render(board)
        self.assertIn("NOT_SYNCED", html)

    def test_synced_when_heads_equal(self):
        board = publish_gate.build(None, None, None, local_head="abc", public_head="abc")
        self.assertEqual(board["head"]["status"], "SYNCED")

    def test_bench_rows_stripped_to_aggregate(self):
        bench = {"summary": {"total": 20, "matched": 20, "all_match": True,
                             "confusion": {"TP": 14, "TN": 5}, "rows": [{"id": "x"}]}}
        board = publish_gate.build(bench, None, None, local_head="a", public_head=None)
        summary = board["benchmark"]["summary"]
        self.assertNotIn("rows", summary)
        self.assertEqual(summary["total"], 20)
        self.assertEqual(summary["confusion"]["TP"], 14)


class PrePushGate(unittest.TestCase):
    def test_clean_repo_warns_identity_unverified(self):
        with tempfile.TemporaryDirectory() as d:
            report = pre_push_gate.check(d)
            self.assertEqual(report["status"], "WARN")
            self.assertEqual(report["identity"]["status"], "IDENTITY_UNVERIFIED")

    def test_secret_blocks(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "leak.py"), "w", encoding="utf-8") as f:
                f.write('TOKEN = "ghp_' + "a" * 36 + '"\n')
            report = pre_push_gate.check(d)
            self.assertEqual(report["status"], "BLOCKED")
            self.assertTrue(report["secret_findings"])


class PushSafe(unittest.TestCase):
    def test_dry_run_holds(self):
        with tempfile.TemporaryDirectory() as d:
            plan = push_safe.plan("origin", "main", d, confirm=False)
            self.assertTrue(plan["dry_run"])
            self.assertFalse(plan["will_push"])
            self.assertEqual(plan["action"], "hold")

    def test_secret_blocks_push(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "leak.py"), "w", encoding="utf-8") as f:
                f.write('KEY = "AKIA' + "B" * 16 + '"\n')
            plan = push_safe.plan("origin", "main", d, confirm=True)
            self.assertFalse(plan["will_push"])
            self.assertEqual(plan["gate"]["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
