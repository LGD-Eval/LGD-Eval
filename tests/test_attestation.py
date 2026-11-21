#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_attestation.py —— 评测证明记录字段完整性测试（纯本地，不联网）。

覆盖执行令 §一 证据记录要求：规则版本、引擎版本、执行时间、被测 commit、
证据位置、可否复验、失败原因、红线声明；fingerprint 仍只绑定被测内容。
"""
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "lgd-eval" / "scripts"))

import evaluate  # noqa: E402


class AttestationFieldsTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="lgd-att-")
        with open(os.path.join(self._tmp, "SKILL.md"), "w", encoding="utf-8") as f:
            f.write("# demo\n")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_required_record_fields_present(self):
        evidence = [{
            "rule_id": "R-SEC-01", "dimension": "安全", "file": "SKILL.md",
            "line": 1, "evidence": "示例发现", "fix": "修复建议", "verify": "复验步骤",
        }]
        att = evaluate.build_attestation(self._tmp, 87, "A",
                                         {"结构完整性": 20, "目录结构": 10,
                                          "文档质量": 15, "安全": 22, "生态兼容性": 20},
                                         evidence)
        # 版本与时间记录
        self.assertTrue(att["engine_version"])
        self.assertTrue(att["rule_version"])
        self.assertRegex(att["evaluated_at"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        # 被测 commit：临时目录非 git 仓，必须为 None，不得伪造
        self.assertIsNone(att["target_commit"])
        # 证据位置与复验标记
        self.assertIn("evidence", att)
        self.assertIsNone(att["evidence"]["location"])
        self.assertTrue(att["evidence"]["reverify_allowed"])
        # 红线与过期口径
        self.assertIn("不等于", att["red_lines"])
        self.assertTrue(att["stale_policy"])
        # 运行时沙箱可用性必须显式记录，不得静默当作已隔离
        self.assertIn("runtime_sandbox", att)
        self.assertIn("available", att["runtime_sandbox"])
        # 证据等级：本机默认 E1，不构成独立验证
        self.assertIn("evidence_grade", att)
        self.assertEqual(att["evidence_grade"]["level"], "E1")
        self.assertFalse(att["evidence_grade"]["independent"])
        # 失败原因：无否决时为空
        self.assertEqual(att["failure_reason"], "")
        # 指纹与树哈希仍在
        self.assertTrue(att["fingerprint"].startswith("sha256:"))
        self.assertTrue(att["inputs"]["tree_sha256"])

    def test_failure_reason_carries_veto(self):
        veto = {"applied": True, "level": "high", "reason": "shell=True 命令注入"}
        att = evaluate.build_attestation(self._tmp, 69, "C", {}, [], veto)
        self.assertEqual(att["failure_reason"], "shell=True 命令注入")

    def test_llm_review_defaults_to_skipped(self):
        # 未提供复核结果时，证明必须显式记 skipped，不得暗示二次复核已完成
        att = evaluate.build_attestation(self._tmp, 87, "A", {}, [])
        self.assertIn("llm_review", att)
        self.assertFalse(att["llm_review"]["enabled"])
        self.assertEqual(att["llm_review"]["status"], "skipped")

    def test_llm_review_failure_is_recorded(self):
        review = {"enabled": True, "status": "failed",
                  "error": "connection timed out", "model": "gpt-4o-mini"}
        att = evaluate.build_attestation(self._tmp, 87, "A", {}, [], llm_review=review)
        self.assertEqual(att["llm_review"]["status"], "failed")
        self.assertEqual(att["llm_review"]["error"], "connection timed out")
        self.assertEqual(att["llm_review"]["model"], "gpt-4o-mini")


if __name__ == "__main__":
    unittest.main(verbosity=2)
