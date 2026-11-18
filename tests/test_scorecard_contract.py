#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_scorecard_contract.py —— 评分卡的纯函数契约（不依赖网络，不跑全量扫描）。

覆盖：
  1. 五维满分之和必须等于 100（分数口径不能自相矛盾）
  2. slug() 只产出小写字母/数字/连字符，空名有兜底
  3. tri_state() 按"有籍/有证/有门禁"三律如实判，缺文件就是待补
  4. render() 输出必须含总分、复跑命令、三律表三样东西

跑法：python tests/test_scorecard_contract.py
若 scorecard 依赖缺失则整体 SKIP（并打印原因），不伪装成通过。
"""
import os, pathlib, sys, tempfile, unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "lgd-eval" / "scripts"))

try:
    import scorecard as sc
    IMPORT_ERR = None
except Exception as e:      # noqa: BLE001
    sc = None
    IMPORT_ERR = repr(e)


@unittest.skipIf(sc is None, f"scorecard 导入失败：{IMPORT_ERR}")
class ScorecardContract(unittest.TestCase):
    def test_full_marks_sum_to_100(self):
        self.assertEqual(sum(sc.MAXS.values()), 100)
        self.assertEqual(len(sc.DIMS), 5)
        for d in sc.DIMS:
            self.assertIn(d, sc.MAXS, f"维度 {d} 没有对应满分")

    def test_slug_is_url_safe(self):
        for raw in ["My Skill!", "技能 包 v2", "", "---"]:
            s = sc.slug(raw)
            self.assertRegex(s, r"^[a-z0-9\-]+$", f"slug({raw!r}) = {s!r} 不安全")
            self.assertTrue(s)

    def test_tri_state_honest(self):
        with tempfile.TemporaryDirectory() as d:
            empty = sc.tri_state(d, [])
            self.assertIn("待补", empty["有籍"])       # 无 README/CHANGELOG 必须待补
            self.assertIn("待补", empty["有证"])       # 无 examples/tests
            self.assertIn("达标", empty["有门禁"])     # 无危险发现
    
            (pathlib.Path(d) / "README.md").write_text("x", encoding="utf-8")
            (pathlib.Path(d) / "CHANGELOG.md").write_text("x", encoding="utf-8")
            (pathlib.Path(d) / "examples").mkdir()
            self.assertIn("达标", sc.tri_state(d, [])["有籍"])
            self.assertIn("达标", sc.tri_state(d, [])["有证"])

            danger = sc.tri_state(d, ["发现密钥硬编码"])
            self.assertIn("待补", danger["有门禁"], "出现危险发现时不得判达标")

    def test_render_contains_claims_and_rerun(self):
        r = {"score": 88, "grade": "A", "dims": {d: 0 for d in sc.DIMS},
             "findings": [], "plan": {"fix_plan": []},
             "tri": {"有籍": "✅ 达标", "有证": "✅ 达标", "有门禁": "✅ 达标"}}
        md = sc.render("demo", r, "2026-01-01 00:00 UTC")
        self.assertIn("88/100", md)
        self.assertIn("复跑", md)
        self.assertIn("LGD 三律", md)
        self.assertIn("--fail-under", md)


if __name__ == "__main__":
    unittest.main(verbosity=2)
