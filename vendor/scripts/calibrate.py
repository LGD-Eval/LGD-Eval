"""按门槛算误杀率与漏放率，把"门槛该定在哪"从意见变成数字。

为什么需要它：
  评分器给的是一个复合分（结构 + 文档 + 安全 + 生态 + 可运行性）。
  一句"低于 90 就拦"听起来负责，实际会把文档写得薄的干净技能全拦掉——
  那是误杀，不是安全。误杀率高到一定程度，使用者就会把门禁关掉，
  于是门禁等于不存在。

用法：
  python calibrate.py corpus.json [--samples 6]

corpus.json 形态：
  {
    "evaluator": "../scripts/evaluate.py",
    "samples": [
      {"path": "benign/gold", "label": "benign"},
      {"path": "malicious/js-env-exfil", "label": "malicious"}
    ]
  }

输出：一张按门槛的表——每个门槛上误杀几个良性、漏放几个恶意。
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

THRESHOLDS = [40, 49, 50, 60, 70, 75, 80, 89, 90, 96]


def score_of(evaluator, target):
    """跑一次评测，拿分数。走 CLI 而不是 import——评测器会打印，不该被 import 干扰。"""
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "ev.json")
        r = subprocess.run([sys.executable, evaluator, target, "--ascii",
                            "--evidence-json", out],
                           capture_output=True, text=True)
        if not os.path.exists(out):
            raise SystemExit("评测没有产出 evidence json：%s\n%s"
                             % (target, r.stderr[-400:]))
        with open(out, encoding="utf-8") as f:
            return json.load(f)


def tally(samples, thresholds=THRESHOLDS):
    """纯计算：每个门槛上误杀几个良性、漏放几个恶意。不跑评测，好测。"""
    benign = [s for s in samples if s["label"] == "benign"]
    malicious = [s for s in samples if s["label"] == "malicious"]
    rows = []
    for t in thresholds:
        fp = [s for s in benign if s["score"] < t]
        fn = [s for s in malicious if s["score"] >= t and not s.get("veto")]
        rows.append({
            "threshold": t,
            "fp": len(fp), "benign": len(benign),
            "fn": len(fn), "malicious": len(malicious),
            "fpr": (len(fp) / len(benign) * 100) if benign else 0.0,
            "fnr": (len(fn) / len(malicious) * 100) if malicious else 0.0,
        })
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description="按门槛算误杀率与漏放率")
    ap.add_argument("corpus")
    ap.add_argument("--evaluator", default=None, help="默认取 corpus.json 里的 evaluator")
    args = ap.parse_args(argv)

    base = os.path.dirname(os.path.abspath(args.corpus))
    with open(args.corpus, encoding="utf-8") as f:
        corpus = json.load(f)

    evaluator = args.evaluator or os.path.join(base, corpus["evaluator"])
    if not os.path.isabs(evaluator):
        evaluator = os.path.join(base, evaluator)

    samples = []
    for s in corpus["samples"]:
        path = s["path"]
        if not os.path.isabs(path):
            path = os.path.join(base, path)
        ev = score_of(evaluator, path)
        samples.append({"path": s["path"], "label": s["label"],
                        "score": ev["score"], "grade": ev["grade"],
                        "veto": bool((ev.get("safety_veto") or {}).get("applied")),
                        "sec": ev["dims"].get("安全")})

    benign = [s for s in samples if s["label"] == "benign"]
    malicious = [s for s in samples if s["label"] == "malicious"]

    print("样本")
    for s in samples:
        print("  %-28s %-10s %3d  %-2s  安全=%s  否决=%s"
              % (s["path"], s["label"], s["score"], s["grade"],
                 s["sec"], "Y" if s["veto"] else "N"))
    print()
    print("按门槛（低于门槛即拦）")
    print("  门槛  误杀(良性被拦)  漏放(恶意放行)  误杀率  漏放率")
    for row in tally(samples):
        print("  %4d  %d/%-12d %d/%-12d %5.1f%%  %5.1f%%"
              % (row["threshold"], row["fp"], row["benign"],
                 row["fn"], row["malicious"], row["fpr"], row["fnr"]))
    print()
    print("注：分数是复合分（含文档与结构）。门槛越低，误杀越少，但要求门禁")
    print("    在看安全维度与否决标记上，而不只是看总分。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
