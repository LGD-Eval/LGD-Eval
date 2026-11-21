"""良性基线：把"评分器能不能给一份干净的技能打高分"钉成回归测试。

A-15 里发现的现象是"良性样本 79 分，期望 96/99"。量下来原因不在安全维度
（六份良性样本安全维度全是满分 25），而在文档章节缺失——也就是说，
那 17~20 分差是**样本自己没写清楚**，不是评分器误报。

这个测试做两件事：
  1. 一份完全合规的良性技能必须 ≥96，且零安全发现（说明刻度能到顶）
  2. 一份文档不全但同样干净无害的技能，分数应低于前者，且**仍然零安全发现**
     ——把"扣的是文档分"与"扣的是安全分"分开，防止以后用放宽阈值的方式
     掩饰误报（那是评分膨胀，不是校准）

若第一条失败，说明评分器刻度坏了；若第二条的安全发现不为空，说明出现了
良性误报。两种都是真问题，不该靠调阈值糊过去。
"""
import json
import os
import subprocess
import sys
import textwrap

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
EVAL = os.path.join(os.path.dirname(HERE), "scripts", "evaluate.py")

GOLD_SKILL_MD = """---
name: csv-digest
version: 1.2.0
author: Steven Zhao
license: MIT
description: Compute a sha256 digest for a CSV file and report column counts.
tags: [csv, digest, checksum, tooling]
---

# CSV Digest

## When to Use

Use this when you need to prove a CSV has not changed between runs.

## Usage

```bash
python scripts/digest.py data.csv
```

## Examples

```bash
python scripts/digest.py data.csv
# sha256: 3f2a…  rows: 2  cols: 3
```

## Known Limits

- Reads the whole file into memory.
- No line-ending normalisation.
"""

GOLD_FILES = {
    "README.md": "# CSV Digest\n\n## Install\n\nNone.\n\n## Usage\n\n`python scripts/digest.py f.csv`\n",
    "LICENSE": "MIT License\n\nCopyright (c) 2026 Steven Zhao\n",
    "scripts/digest.py": textwrap.dedent('''
        """Print a digest for a file named on the command line."""
        import hashlib
        import sys


        def digest_of(path):
            with open(path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()


        def main(argv):
            if len(argv) != 2:
                return 2
            print(digest_of(argv[1]))
            return 0


        if __name__ == "__main__":
            sys.exit(main(sys.argv))
    ''').lstrip(),
    "examples/example-run.md": "# Example\n\n```\nsha256: 3f2a…\n```\n",
    "tests/test_digest.py": "import hashlib\n\n\ndef test_x():\n    assert len(hashlib.sha256(b'x').hexdigest()) == 64\n",
}


def _make(root, skill_md=None, files=None):
    os.makedirs(root, exist_ok=True)
    with open(os.path.join(root, "SKILL.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write(skill_md if skill_md is not None else GOLD_SKILL_MD)
    for rel, content in (files if files is not None else GOLD_FILES).items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
    return root


def _evaluate(root, tmpdir):
    out = os.path.join(tmpdir, "ev.json")
    r = subprocess.run([sys.executable, EVAL, root, "--ascii",
                        "--evidence-json", out],
                       capture_output=True, text=True)
    assert os.path.exists(out), "评测没有产出 evidence json：%s" % (r.stderr[-400:])
    with open(out, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def workdir(tmp_path_factory):
    return str(tmp_path_factory.mktemp("benign"))


def test_a_well_documented_benign_skill_reaches_the_top_of_the_scale(workdir):
    """刻度必须能到顶：结构、文档、生态全齐的干净技能 ≥96 分。"""
    root = _make(os.path.join(workdir, "gold"))
    ev = _evaluate(root, workdir)
    assert ev["score"] >= 96, "良性金标准只拿到 %s 分：%s" % (ev["score"], ev.get("findings"))
    assert ev["grade"] in ("A", "A+")
    assert not (ev.get("safety_veto") or {}).get("applied"), ev.get("safety_veto")
    assert ev["authorization_status"] == "NOT_GRANTED"


def test_an_undocumented_but_harmless_skill_loses_documentation_points_only(workdir):
    """文档不全可以扣分，但不许把它算成"不安全"。"""
    thin = "---\nname: csv-digest\n---\n\n# CSV Digest\n\nPrints a digest.\n"
    root = _make(os.path.join(workdir, "thin"), skill_md=thin,
                 files={"README.md": "# CSV Digest\n"})
    ev = _evaluate(root, workdir)
    assert ev["score"] < 96, "文档不全不该拿满分"
    security_findings = [f for f in ev["findings"]
                         if f.get("dimension") == "安全"]
    assert not security_findings, "良性技能出现安全误报：%s" % security_findings
    assert ev["dims"]["安全"] == 25, "干净技能的安全维度应满分，实际 %s" % ev["dims"]["安全"]


def test_the_gold_skill_never_reaches_a_veto(workdir):
    """安全否决只对真凭证外泄生效，不能对干净技能触发。"""
    root = _make(os.path.join(workdir, "gold2"))
    ev = _evaluate(root, workdir)
    assert not (ev.get("safety_veto") or {}).get("applied"), ev.get("safety_veto")
