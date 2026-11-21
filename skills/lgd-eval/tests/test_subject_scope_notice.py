#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""口径提示的回归钉子：扫"仓库根目录"与扫"技能包"必须能一眼分清。

背景：2026-11-21 发布前审查里，外人按 README 在仓库根目录跑一次 scanner，
得到 0/F 且报告不解释，读起来像"这个仓很危险"。这属于口径差异，不是安全结论，
所以必须在输出最前面写清楚，而不是让读者自己猜。
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(ROOT, "scripts", "skillgate.py")


def _scan(path):
    p = subprocess.run([sys.executable, GATE, "scan", path],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=180)
    return (p.stdout or "") + (p.stderr or "")


class TestScopeNotice(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp(prefix="lgd_scope_")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def test_directory_without_skill_md_prints_scope_notice(self):
        d = os.path.join(self.root, "repo_like")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "AGENTS.md"), "w", encoding="utf-8") as f:
            f.write("# Repo agent notes\n")
        out = _scan(d)
        self.assertIn("没有 SKILL.md", out)
        self.assertIn("口径", out)

    def test_directory_with_skill_md_has_no_scope_notice(self):
        d = os.path.join(self.root, "pkg_like")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "SKILL.md"), "w", encoding="utf-8") as f:
            f.write("# Notes Tool\n\nSummarises notes.\n")
        out = _scan(d)
        self.assertNotIn("没有 SKILL.md", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
