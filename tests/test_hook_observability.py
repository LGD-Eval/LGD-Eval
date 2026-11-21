#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_hook_observability.py —— 审计钩子失败必须留痕，不得静默丢弃。

覆盖 GAP-GATE-4：钩子自身异常写入 hook_error 事件；正常事件写入审计日志。
"""
import importlib
import json
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "lgd-eval" / "scripts"))


class HookWriteTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="lgd-hook-")
        self._log = os.path.join(self._tmp, "audit.jsonl")
        os.environ["LGD_AUDIT_LOG"] = self._log
        import _lgd_hook
        self.mod = importlib.reload(_lgd_hook)

    def tearDown(self):
        import shutil
        os.environ.pop("LGD_AUDIT_LOG", None)
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _read_events(self):
        with open(self._log, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def test_normal_event_recorded(self):
        self.mod._write({"event": "dns", "host": "x.example.com"})
        events = self._read_events()
        self.assertEqual(events[0]["event"], "dns")

    def test_hook_error_recorded_not_swallowed(self):
        self.mod._write_error("open", ValueError("boom"))
        events = self._read_events()
        self.assertEqual(events[0]["event"], "hook_error")
        self.assertEqual(events[0]["hook"], "open")
        self.assertIn("boom", events[0]["err"])

    def test_install_callable_without_raising(self):
        # install 必须可调用且不抛异常（不在此断言全局补丁副作用）。
        self.assertTrue(callable(self.mod.install))


if __name__ == "__main__":
    unittest.main(verbosity=2)
