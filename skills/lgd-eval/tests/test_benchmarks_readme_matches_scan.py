"""benchmarks/README 里的自扫数字必须等于当日实跑结果。

缘由：那份表曾写着「0 findings，100 / A+，可上架」，而同一包实测是 89/A、8 条
（1 MEDIUM + 7 LOW）。改规则就会改分数，改完不重跑就写结论，等于把过期数字
当承诺发布——G5 守的正是"图/表/徽章的数字与实际一致"。

这里把它变成可执行断言：文档里的数字跑一遍比对，不一致就红。
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]          # skills/lgd-eval
DOC = ROOT / "benchmarks" / "README.md"

CLAIM_RE = re.compile(r"自扫 \*\*(\d+) / (A\+|[A-D])\*\*")
SCAN_RE = re.compile(r"Trust Score: (\d+)/100")


def _claimed():
    text = DOC.read_text(encoding="utf-8")
    m = CLAIM_RE.search(text)
    assert m, "benchmarks/README 里找不到「自扫 **NN / X**」这条声称"
    return int(m.group(1)), m.group(2)


def _actual():
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "skillgate.py"), "scan", str(ROOT)],
                       capture_output=True, text=True, encoding="utf-8")
    m = SCAN_RE.search(r.stdout or "")
    assert m, "扫描未产出 Trust Score：%s" % (r.stdout or r.stderr)[-300:]
    return int(m.group(1))


def test_claimed_score_matches_today():
    claimed, _grade = _claimed()
    actual = _actual()
    assert claimed == actual, (
        "benchmarks/README 声称自扫 %d 分，今日实跑是 %d 分。"
        "改规则后请重跑并更新文档，不要把旧数字留在对外材料里。" % (claimed, actual)
    )


def test_no_stale_zero_findings_claim():
    text = DOC.read_text(encoding="utf-8")
    assert "0 findings，100 / A+" not in text, "仍在声称 0 findings / 100 A+"
