#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_copy_parity.py —— 检出「同一脚本存在两份副本」的漂移。

背景：`skills/lgd-eval/scripts/` 与 `vendor/scripts/` 各存一份同名同构的脚本。
两份副本一旦悄悄分叉，用户装哪一份就会得到不同结论。

判定方式：逐文件比对 sha256。允许存在差异的文件必须登记在
`tests/known_divergence.txt`（一行一个路径，`#` 开头为注释）。
本测试的作用是：**新增的任何一处分叉都会被立刻拦下**，已登记的分叉肉眼可见。

跑法：python tests/test_copy_parity.py
"""
import hashlib, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
A = ROOT / "skills" / "lgd-eval" / "scripts"
B = ROOT / "vendor" / "scripts"
ALLOW = ROOT / "tests" / "known_divergence.txt"


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def load_allow():
    if not ALLOW.exists():
        return set()
    out = set()
    for line in ALLOW.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out.add(s)
    return out


def main():
    if not A.is_dir() or not B.is_dir():
        print("SKIP: 两处脚本目录不都存在")
        return 0
    allow = load_allow()
    names = sorted({p.name for p in A.glob("*.py")} | {p.name for p in B.glob("*.py")})
    new_drift, missing, known = [], [], []
    for n in names:
        pa, pb = A / n, B / n
        if not pa.exists() or not pb.exists():
            missing.append(n); continue
        if sha(pa) != sha(pb):
            (known if n in allow else new_drift).append(n)

    for n in missing:
        print(f"  - {n}: 只存在于一侧")
    for n in known:
        print(f"  ~ {n}: 已登记的分叉（见 tests/known_divergence.txt）")

    if missing or new_drift:
        print("FAIL")
        for n in new_drift:
            print(f"  ! {n}: 未登记的新分叉")
        return 1

    print(f"OK: {len(names)} 个同名脚本中，{len(known)} 个为已登记分叉，其余逐字节一致")
    return 0


if __name__ == "__main__":
    sys.exit(main())
