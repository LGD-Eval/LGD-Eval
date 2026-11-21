#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_accuracy_benchmark.py —— 评测器自身标注样本基准的 pytest 包装。

校验：
  * 三条人工标注样本（干净 / 高危注入 / 证据残缺）的授权判定与标注一致；
  * 基准汇总 all_match，accuracy=1.0；
  * 高危样本必须带 high/critical 封顶，且授权 NOT_GRANTED（安全否决优先于分数）；
  * 干净样本证据齐备、无否决且分数达阈值才 GRANTED。

跑法：python -m pytest tests/test_accuracy_benchmark.py
"""
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "lgd-eval" / "scripts"))

import accuracy_benchmark  # noqa: E402
import authz  # noqa: E402


class AccuracyBenchmark(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = accuracy_benchmark.evaluate_cases()
        cls.summary = accuracy_benchmark.summary(cls.rows)
        cls.by_id = {r["id"]: r for r in cls.rows}

    def test_all_cases_match_labels(self):
        self.assertTrue(self.summary["all_match"],
                        "存在标注与判定不符的样本：%s" %
                        [(r["id"], r["expect"], r["actual"]) for r in self.rows if not r["match"]])
        self.assertEqual(self.summary["accuracy"], 1.0)

    def test_confusion_matrix_and_prf(self):
        m = self.summary["confusion"]
        # 14 高危应拒绝 / 5 干净应放行 / 1 证据残缺单列排除。
        self.assertEqual((m["TP"], m["FP"], m["FN"], m["TN"]), (14, 0, 0, 5))
        self.assertEqual(m["excluded"], ["missing-evidence"])
        self.assertEqual(self.summary["precision"], 1.0)
        self.assertEqual(self.summary["recall"], 1.0)
        self.assertEqual(self.summary["f1"], 1.0)

    def test_clean_granted(self):
        r = self.by_id["clean-well-formed"]
        self.assertEqual(r["actual"], authz.GRANTED)
        self.assertGreaterEqual(r["score"], authz.DEFAULT_GRANT_THRESHOLD)
        self.assertEqual(r["veto_level"], "")

    def test_malicious_blocked_by_security(self):
        r = self.by_id["shell-injection-high"]
        self.assertEqual(r["actual"], authz.NOT_GRANTED)
        self.assertIn(r["veto_level"], ("high", "critical"))

    def test_incomplete_not_granted_on_missing_evidence(self):
        r = self.by_id["missing-evidence"]
        self.assertEqual(r["actual"], authz.INCOMPLETE)

    def test_secret_and_injection_blocked_high(self):
        for cid in ("hardcoded-secret-high", "prompt-injection-high"):
            r = self.by_id[cid]
            self.assertEqual(r["actual"], authz.NOT_GRANTED, cid)
            self.assertEqual(r["veto_level"], "high", cid)

    def test_benign_doc_control_not_false_positive(self):
        r = self.by_id["benign-doc-control"]
        self.assertEqual(r["actual"], authz.GRANTED)
        self.assertEqual(r["veto_level"], "")

    def test_cross_file_taint_blocked_critical(self):
        r = self.by_id["cross-file-taint-critical"]
        self.assertEqual(r["actual"], authz.NOT_GRANTED)
        self.assertEqual(r["veto_level"], "critical")

    def test_eval_exec_and_os_system_blocked_high(self):
        for cid in ("eval-exec-high", "os-system-high"):
            r = self.by_id[cid]
            self.assertEqual(r["actual"], authz.NOT_GRANTED, cid)
            self.assertEqual(r["veto_level"], "high", cid)

    def test_environ_bulk_blocked_critical(self):
        r = self.by_id["environ-bulk-critical"]
        self.assertEqual(r["actual"], authz.NOT_GRANTED)
        self.assertEqual(r["veto_level"], "critical")

    def test_base_url_blocked_by_score_threshold(self):
        # R-SEC-19 当前未封顶；证据齐备、无否决，但分数低于阈值仍拒绝。
        r = self.by_id["base-url-below-threshold"]
        self.assertEqual(r["actual"], authz.NOT_GRANTED)
        self.assertEqual(r["veto_level"], "")
        self.assertLess(r["score"], authz.DEFAULT_GRANT_THRESHOLD)

    def test_postinstall_download_blocked_critical(self):
        r = self.by_id["postinstall-download-critical"]
        self.assertEqual(r["actual"], authz.NOT_GRANTED)
        self.assertEqual(r["veto_level"], "critical")

    def test_node_dynamic_code_blocked_high(self):
        for cid in ("child-process-js-high", "new-function-js-high"):
            r = self.by_id[cid]
            self.assertEqual(r["actual"], authz.NOT_GRANTED, cid)
            self.assertEqual(r["veto_level"], "high", cid)

    def test_text_high_speech_blocked_high(self):
        for cid in ("read-credential-high", "no-confirmation-high"):
            r = self.by_id[cid]
            self.assertEqual(r["actual"], authz.NOT_GRANTED, cid)
            self.assertEqual(r["veto_level"], "high", cid)

    def test_rebuild_payload_blocked_high(self):
        r = self.by_id["rebuild-payload-high"]
        self.assertEqual(r["actual"], authz.NOT_GRANTED)
        self.assertEqual(r["veto_level"], "high")

    def test_infra_error_is_fail_closed(self):
        # 评测器自身抛异常：必须记 infra_error、UNKNOWN、不计通过，并留异常摘要。
        import shutil
        import tempfile
        orig = accuracy_benchmark.evaluate_skill

        def _boom(_dir):
            raise RuntimeError("simulated infra failure")

        case = {"id": "infra-boom", "build": lambda _d: None, "expect": authz.GRANTED}
        tmp = tempfile.mkdtemp()
        try:
            accuracy_benchmark.evaluate_skill = _boom
            try:
                r = accuracy_benchmark.run_case(case, tmp)
            finally:
                accuracy_benchmark.evaluate_skill = orig
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        self.assertTrue(r["infra_error"])
        self.assertEqual(r["actual"], authz.UNKNOWN)
        self.assertFalse(r["match"])
        self.assertIn("RuntimeError", r["infra_error_note"])
        self.assertIsInstance(r["latency_ms"], float)

    def test_wilson_ci_brackets_point_estimate(self):
        ci = self.summary["ci"]
        for name in ("precision", "recall", "fpr"):
            c = ci[name]
            self.assertIsNotNone(c["point"])
            self.assertLessEqual(c["lo"], c["point"] + 1e-9)
            self.assertGreaterEqual(c["hi"], c["point"] - 1e-9)
            self.assertGreaterEqual(c["lo"], 0.0)
            self.assertLessEqual(c["hi"], 1.0)
        self.assertEqual(ci["recall"]["n"], 14)
        self.assertEqual(ci["fpr"]["n"], 5)
        # 小样本 0/5 的 FPR 点估计为 0，但上界必须 >0，不得把 0 误读为真实零误报。
        self.assertGreater(ci["fpr"]["hi"], 0.0)

    def test_latency_and_infra_error_observability(self):
        # 每例都留墙钟耗时；干净基线无基础设施异常；汇总给出 mean/max。
        for r in self.rows:
            self.assertIsInstance(r["latency_ms"], float)
            self.assertGreaterEqual(r["latency_ms"], 0)
            self.assertFalse(r["infra_error"], r["id"])
        self.assertEqual(self.summary["infra_errors"], 0)
        self.assertEqual(self.summary["infra_error_ids"], [])
        self.assertIsNotNone(self.summary["latency_ms"]["mean"])
        self.assertIsNotNone(self.summary["latency_ms"]["max"])
        self.assertEqual(self.summary["latency_ms"]["count"], len(self.rows))


if __name__ == "__main__":
    unittest.main()
