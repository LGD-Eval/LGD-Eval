# -*- coding: utf-8 -*-
"""发布前综合检查（四道关一次跑完）

    python release.py --file <产物> [--sig <签名>]

四道关：
  1. 引擎自检      scanner --self-test 必须 PASS
  2. 双侧回归      20 条攻击样本 0 丢失 + 文档误报 0
  3. 门禁扫描      --context-aware：不得有 P0；uncertain 计为待裁（不静默放行）
  4. 人类签发      验签通过才允许进入发布流程（未签 = BLOCKED）

输出：release-manifest.json（含每关结果、文件哈希、引擎指纹、判定）
退出码：0=READY，1=BLOCKED，2=参数/文件错误
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gate  # noqa: E402
import scanner  # noqa: E402


def _run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", cwd=HERE)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def main():
    ap = argparse.ArgumentParser(description="发布前四道关综合检查")
    ap.add_argument("--file", required=True)
    ap.add_argument("--sig")
    args = ap.parse_args()

    if not os.path.exists(args.file):
        print("文件不存在：%s" % args.file)
        return 2

    gates, ok = [], True

    # 1) 引擎自检
    rc, out = _run([sys.executable, "scanner.py", "--self-test"])
    pass1 = rc == 0
    ok &= pass1
    gates.append({"gate": "1_engine_selftest", "pass": pass1,
                  "detail": out.strip().splitlines()[0] if out.strip() else ""})

    # 2) 双侧回归
    rc, out = _run([sys.executable, "gate.py", "--regression"])
    pass2 = rc == 0
    ok &= pass2
    last = [l for l in out.strip().splitlines() if l.startswith("汇总")]
    gates.append({"gate": "2_two_sided_regression", "pass": pass2,
                  "detail": last[0] if last else ""})

    # 3) 门禁扫描（context-aware + 裁决器）
    text = open(args.file, encoding="utf-8", errors="replace").read().replace("\r\n", "\n")
    pack = gate.make_pack(text, os.path.basename(args.file), True, True)
    s = pack["expected"]["summary"]
    uncertain = sum(1 for f in pack["findings"]
                    if (f.get("adjudication") or {}).get("verdict") == "uncertain")
    pass3 = s["P0"] == 0
    ok &= pass3
    gates.append({"gate": "3_context_aware_scan", "pass": pass3,
                  "detail": "P0=%d P1=%d P2=%d P3=%d ｜ uncertain=%d ｜ 原因检查器 v%s"
                            % (s["P0"], s["P1"], s["P2"], s["P3"], uncertain, scanner.VERSION)})

    # 4) 人类签发
    rc, out = _run([sys.executable, "sign.py", "verify", args.file] +
                   (["--sig", args.sig] if args.sig else []))
    pass4 = rc == 0
    ok &= pass4
    gates.append({"gate": "4_human_signature", "pass": pass4,
                  "detail": [l for l in out.strip().splitlines() if l.startswith("VERDICT")][-1][:80]
                  if "VERDICT" in out else out.strip()[:80]})

    manifest = {
        "artifact": os.path.basename(args.file),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "chars": len(text),
        "engine": {"version": scanner.VERSION,
                   "file_sha256": hashlib.sha256(open(scanner.__file__, "rb").read()).hexdigest()},
        "gates": gates,
        "verdict": "READY" if ok else "BLOCKED",
    }
    out_path = os.path.join(HERE, "release-manifest.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    for g in gates:
        print("%-6s %-26s %s" % ("PASS" if g["pass"] else "FAIL", g["gate"],
                                 (g["detail"] or "")[:70]))
    print("-" * 78)
    print("VERDICT: %s ｜ manifest → %s" % (manifest["verdict"], out_path))
    if not ok:
        print("未通过：", [g["gate"] for g in gates if not g["pass"]])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
