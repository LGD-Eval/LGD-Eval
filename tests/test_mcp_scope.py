#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MCP 路径作用域测试桩（DRAFT，对应 N11）。

正式落点：lgd_mcp_server.call_tool 在扫描前做路径白名单校验；
本桩先固化期望行为——白名单外绝对路径必须拒绝，不返回 findings。
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(HERE, "..", "skills", "lgd-eval", "scripts")
sys.path.insert(0, os.path.abspath(SCRIPTS))

# 草案期内联作用域判定；接入时移入 lgd_mcp_server 并复用同一实现。
ALLOWED_ROOTS = [os.path.abspath(os.path.join(HERE, "..", "sandbox-root"))]


def _is_within_allowed(path: str) -> bool:
    norm = os.path.abspath(path)
    return any(norm == root or norm.startswith(root + os.sep) for root in ALLOWED_ROOTS)


class McpScopeTests(unittest.TestCase):
    # N11 白名单外绝对路径 -> 拒绝扫描，不返回 findings
    def test_n11_outside_path_rejected(self):
        outside = os.path.abspath(r"C:\Windows\System32\config\SAM")
        self.assertFalse(_is_within_allowed(outside))

    def test_n11_inside_path_allowed(self):
        inside = os.path.join(ALLOWED_ROOTS[0], "skill-a", "SKILL.md")
        self.assertTrue(_is_within_allowed(inside))


if __name__ == "__main__":
    unittest.main()
