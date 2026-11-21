"""校准契约：门槛该定在哪，用带标签语料算出来，不用猜。

这个测试只测算术（tally），不跑评测器——快、稳、失败指向明确。
真正的数字来自 calibrate.py 对带标签语料的实跑，写在 docs/CALIBRATION.md。
"""
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "scripts"))

import calibrate  # noqa: E402


def _sample(label, score, veto=False):
    return {"path": label + "-" + str(score), "label": label, "score": score,
            "grade": "B", "sec": 25, "veto": veto}


def test_a_gate_above_the_benign_band_kills_clean_skills():
    """门槛高于良性样本能到的分，就是把干净技能当风险拦下——这才是误杀的定义。"""
    samples = [_sample("benign", 100), _sample("benign", 75), _sample("benign", 75),
               _sample("malicious", 49, veto=True), _sample("malicious", 49, veto=True)]
    rows = {r["threshold"]: r for r in calibrate.tally(samples, [60, 90])}
    assert rows[90]["fpr"] == pytest.approx(66.7, abs=0.1), "90 门槛应拦掉 2/3 良性"
    assert rows[90]["fnr"] == 0.0
    assert rows[60]["fpr"] == 0.0
    assert rows[60]["fnr"] == 0.0


def test_a_vetoed_sample_is_never_counted_as_passed():
    """否决样本就算总分够高也必须算被拦——否则"封顶只改分数"就成了漏洞。"""
    samples = [_sample("benign", 100), _sample("malicious", 95, veto=True)]
    rows = {r["threshold"]: r for r in calibrate.tally(samples, [90])}
    assert rows[90]["fnr"] == 0.0
    assert rows[90]["fn"] == 0


def test_empty_label_groups_do_not_divide_by_zero():
    rows = calibrate.tally([_sample("benign", 90)], [90])
    assert rows[0]["fpr"] == 0.0
    assert rows[0]["fnr"] == 0.0
