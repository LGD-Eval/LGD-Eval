# -*- coding: utf-8 -*-
"""多语种盲测聚合门禁（2026-11-22）：把 v2–v6 的命中下限写死进 CI。

目的：任何一次规则改动，只要让任一盲测套件的召回倒退，CI 直接红。
阈值取「当前实测值」，只升不降；新增语种先建 v7 盲测测基线，再补规则。

用法：python holdout_all.py            # 默认阈值
      python holdout_all.py --verbose  # 打印每个套件原文
退出码：0 全部达标 / 1 有倒退或脚本报错
"""
import os
import re
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8")
HERE = os.path.dirname(os.path.abspath(__file__))

SUITES = [
    # (脚本, 门槛命中, 门槛总数, 标签)
    ("holdout_v2_20261118.py", 20, 20, "v2 英中基础"),
    ("holdout_v3_20261118.py", 19, 20, "v3 真盲测"),
    ("holdout_v4_20261118.py", 7, 7, "v4 跨语言跨载体"),
    ("holdout_v5_20261118.py", 6, 6, "v5 西/日/俄/葡"),
    ("holdout_v6_20261122.py", 6, 6, "v6 阿/韩/泰"),
]
PAIR = re.compile(r"(\d+)/(\d+)")


def parse(out, total_wanted):
    """从输出里找最后一个 X/M 形式，且 M 等于期望总数（避开无关数字）"""
    best = None
    for line in out.splitlines():
        for a, b in PAIR.findall(line):
            if int(b) == total_wanted:
                best = (int(a), int(b))
    return best


def main():
    verbose = "--verbose" in sys.argv
    fails = []
    for script, need_hit, total, label in SUITES:
        path = os.path.join(HERE, script)
        if not os.path.exists(path):
            print("  %-22s SKIP（脚本不存在）" % label)
            fails.append("%s 缺脚本" % label)
            continue
        p = subprocess.run([sys.executable, path], capture_output=True, text=True, encoding="utf-8")
        out = (p.stdout or "") + (p.stderr or "")
        got = parse(out, total)
        if verbose:
            print(out.strip())
        if got is None:
            print("  %-22s FAIL（无法解析结果）" % label)
            fails.append("%s 解析失败" % label)
            continue
        ok = got[0] >= need_hit
        print("  %-22s %s %d/%d（门槛 %d/%d）" % (label, "PASS" if ok else "FAIL",
                                            got[0], got[1], need_hit, total))
        if not ok:
            fails.append("%s %d/%d < %d/%d" % (label, got[0], got[1], need_hit, total))
    print("-" * 60)
    if fails:
        print("VERDICT: FAIL — " + "；".join(fails))
        return 1
    print("VERDICT: PASS — 五套盲测全部不低于门槛（多语种召回不倒退）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
