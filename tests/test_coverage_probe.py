#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_coverage_probe.py —— 覆盖探针结构自测（不硬断言安全命中）。

探针是诊断工具：规则是否升阻断、门槛 81→90 属待对齐策略，因此本测试只校验
报告结构完整、字段齐全、无基础设施异常、汇总计数自洽；不要求某族必须被否决。

跑法：python -m pytest tests/test_coverage_probe.py
"""
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "lgd-eval" / "scripts"))

import coverage_probe  # noqa: E402


class CoverageProbe(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = coverage_probe.run_probe()

    def test_schema_and_level(self):
        self.assertEqual(self.report["probe_schema"], "lgd-eval-coverage-probe/1.0")
        self.assertEqual(self.report["evidence_level"], "E1")

    def test_case_count(self):
        self.assertEqual(len(self.report["cases"]), len(coverage_probe.PROBE_CASES))
        self.assertGreaterEqual(len(self.report["methodology_gaps"]), 7)

    def test_case_fields_present(self):
        required = {"id", "rule_id", "pattern", "actual", "score", "veto_level",
                     "findings", "security_findings", "security_surfaced",
                     "infra_error", "latency_ms"}
        for case in self.report["cases"]:
            self.assertTrue(required <= set(case), msg="缺字段: %s" % case.get("id"))

    def test_no_infra_error(self):
        self.assertFalse(any(c["infra_error"] for c in self.report["cases"]))

    def test_summary_consistent(self):
        s = self.report["summary"]
        self.assertEqual(s["total"], len(self.report["cases"]))
        sec = sum(1 for c in self.report["cases"] if c["security_surfaced"])
        self.assertEqual(s["security_surfaced"], sec)
        self.assertEqual(s["not_security_surfaced"], s["total"] - sec)

    def test_security_split_not_doc_only(self):
        # 安全命中必须来自安全类 finding；文档完整性缺口不计入 security_findings。
        for c in self.report["cases"]:
            for m in c["security_findings"]:
                self.assertTrue(any(k in m.lower() for k in
                                    coverage_probe._SECURITY_KEYWORDS), msg=m)


if __name__ == "__main__":
    unittest.main()
