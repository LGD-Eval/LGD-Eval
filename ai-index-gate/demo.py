#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""demo.py — 一条命令跑通 AI-Index Gate 的全部关键断言。

用法:
    python demo.py

退出码: 0 = 全部断言通过；1 = 有断言失败。
只读本地夹具，不联网、不写对方仓库、不需要密钥（签名步骤因缺 cryptography 而跳过）。
"""
import subprocess
import sys
import os

BASE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
ROWS = []


def run(args):
    p = subprocess.run([PY] + args, cwd=BASE, capture_output=True, text=True, encoding="utf-8", timeout=600)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def check(name, ok, detail):
    ROWS.append((name, "PASS" if ok else "FAIL", detail))
    return ok


def main():
    print("AI-Index Gate · self-demo")
    print("=" * 74)

    # 1) 引擎自检
    rc, out = run(["scanner.py", "--self-test"])
    check("引擎自检（规则/模式装载）", rc == 0 and "SELF-TEST PASS" in out,
          [l for l in out.splitlines() if "SELF-TEST" in l][-1:] and
          [l for l in out.splitlines() if "SELF-TEST" in l][-1])

    # 2) 良性文档：不应出现 P0（门禁能过）
    rc, out = run(["gate.py", "--file", os.path.join("fixtures", "benign.md"),
                   "--context-aware", "--adjudicate"])
    route = [l for l in out.splitlines() if l.startswith("路由")]
    check("良性文档 → 不阻断（BLOCK=0）", rc == 0 and route and "BLOCK=0" in route[0],
          route[0] if route else "no route line")

    # 3) 攻击样本：必须阻断
    rc, out = run(["gate.py", "--file", os.path.join("fixtures", "attack.md"),
                   "--context-aware", "--adjudicate"])
    route = [l for l in out.splitlines() if l.startswith("路由")]
    nb = 0
    if route:
        try:
            nb = int(route[0].split("BLOCK=")[1].split("｜")[0].strip())
        except Exception:
            nb = 0
    check("攻击样本 → 阻断（BLOCK≥8）", rc != 0 and nb >= 8, route[0] if route else "no route line")

    # 4) 红队：伪装成文档的攻击不得静默放行
    rc, out = run(["gate.py", "--file", os.path.join("fixtures", "redteam.md"),
                   "--context-aware", "--adjudicate"])
    route = [l for l in out.splitlines() if l.startswith("路由")]
    ok = bool(route) and "PASS=0" in route[0]
    check("红队 10 条伪装攻击 → 静默放行 0", ok, route[0] if route else "no route line")

    # 5) 离线复验既有取证包
    packs = sorted([p for p in os.listdir(BASE) if p.startswith("pack-") and p.endswith(".json")])
    if packs:
        rc, out = run(["gate.py", "--verify", packs[0]])
        line = [l for l in out.splitlines() if "MATCH" in l or "MISMATCH" in l]
        check("离线复验取证包（%s）" % packs[0], "MATCH" in out and "MISMATCH" not in out,
              line[-1] if line else "no verdict")
    else:
        check("离线复验取证包", False, "no pack-*.json found")

    # 6) 发布关：未签发产物必须被判 BLOCKED
    if os.path.exists(os.path.join(BASE, "release.py")):
        rc, out = run(["release.py", "--file", os.path.join("fixtures", "benign.md")])
        verdict = [l for l in out.splitlines() if "BLOCKED" in l or "READY" in l]
        check("未签发产物 → release 判 BLOCKED（签发隔离生效）",
              "BLOCKED" in out, verdict[-1] if verdict else "no verdict")
    else:
        check("release 四关", False, "release.py missing")

    print("")
    width = max(len(r[0]) for r in ROWS)
    for name, res, detail in ROWS:
        print("  %-*s  %-5s  %s" % (width, name, res, detail[:88]))
    print("=" * 74)
    failed = [r for r in ROWS if r[1] == "FAIL"]
    if failed:
        print("DEMO: FAIL — %d 项未通过" % len(failed))
        return 1
    print("DEMO: ALL PASS — %d 项断言全部通过（纯离线，无需密钥）" % len(ROWS))
    print("注意：签名步骤（Ed25519）需 `pip install cryptography`，本 demo 未包含，")
    print("      用 `python sign.py --help` 查看签发与验签用法。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
