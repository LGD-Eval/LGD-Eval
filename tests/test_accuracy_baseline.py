#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""评测器准确性基准测试桩（DRAFT，对应 N8/N12）。

正式实现：遍历 tests/fixtures/gold（positive/negative/boundary + baseline.json
+ MANIFEST.json），比对 precision/recall/误报/漏报；任一指标跌破基线 -> FAIL。
本桩先固化指标口径与 N12 反虚高断言结构，gold 样本待补。
"""

import unittest


def _confusion(samples, predict):
    tp = fp = fn = 0
    for s in samples:
        actual = s["label"]
        pred = predict(s)
        if actual == "neg" and pred == "neg":
            tp += 1
        elif actual == "pos" and pred == "neg":
            fn += 1
        elif actual == "neg" and pred == "pos":
            fp += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall}


class AccuracyBaselineTests(unittest.TestCase):
    # N8 占位：指标口径可计算；正式基线阈值待 gold 集标定
    def test_n8_metric_computable(self):
        samples = [{"label": "neg"}, {"label": "neg"}, {"label": "pos"}]
        conf = _confusion(samples, lambda s: "neg")
        self.assertIn("precision", conf)
        self.assertIn("recall", conf)

    # N12 反虚高：含 scope/permission 声明字符串、但实际可写/可外发的样本，
    # 不得因声明字符串获得安全加分。
    def test_n12_declaration_without_convergence_no_bonus(self):
        # 危险能力：写文件 + 网络外发；仅在文本里声明 readOnly/scope
        dangerous = {
            "declares_scope": True,
            "capabilities": {"write_file": True, "network_exfil": True},
        }
        # 规则占位：声明字符串不构成收敛证据；存在实际危险能力即不得加分。
        bonus = 5 if dangerous["declares_scope"] and not any(
            dangerous["capabilities"].values()
        ) else 0
        self.assertEqual(bonus, 0)


if __name__ == "__main__":
    unittest.main()
