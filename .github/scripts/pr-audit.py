#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PR Review Bot audit script — 审核机器人审计逻辑（LGD-Eval）

Called by .github/workflows/pr-review.yml. Performs on every PR:
  mojibake scan · key-file completeness · size limits ·
  bilingual-terminology check · link check
Outputs GITHUB_OUTPUT result JSON + GITHUB_STEP_SUMMARY markdown.
Exit code: 1 if any blocking error (mojibake/encoding), else 0.
"""
import os
import re
import sys
import json
import subprocess


def subprocess_check(args):
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr[:200])
    return r.stdout.splitlines()


def main() -> int:
    base = os.environ.get("GITHUB_BASE_REF", "main") or "main"
    head = os.environ.get("GITHUB_SHA", "HEAD") or "HEAD"

    issues = []
    errors = []

    try:
        changed = subprocess_check(["git", "diff", "--name-only", "origin/%s...%s" % (base, head)])
    except Exception as e:
        # Fallback: scan the whole working tree (robust when git diff is unavailable)
        changed = []
        for root, dirs, files in os.walk("."):
            dirs[:] = [d for d in dirs if d != ".git"]
            for f in files:
                changed.append(os.path.join(root, f).replace(os.sep, "/")[2:] if os.path.join(root, f).startswith("./") else os.path.join(root, f).replace(os.sep, "/").lstrip("./"))
    changed = [c for c in changed if c.strip()]
    changed_md = [c for c in changed if c.lower().endswith((".md", ".txt", ".cff", ".jsonld", ".yml", ".yaml"))]
    issues.append("Changed files (%d): %s" % (len(changed), ", ".join(changed[:20]) or "none"))

    # 1) mojibake / encoding scan
    BAD = re.compile(r"\?\?\?\?\?|\ufffd|锟斤拷")
    for f in changed_md:
        try:
            with open(f, "r", encoding="utf-8", errors="strict") as fh:
                content = fh.read()
            for i, line in enumerate(content.splitlines(), 1):
                if BAD.search(line):
                    errors.append("Mojibake/乱码: %s:%d -> %s" % (f, i, line.strip()[:80]))
        except UnicodeDecodeError:
            errors.append("Encoding/编码: %s is not valid UTF-8" % f)

    # 2) key-file completeness
    KEYFILES = ["README.md", "AGENTS.md", "LICENSE", "SECURITY.md"]
    for k in KEYFILES:
        if not os.path.exists(k):
            issues.append("Missing key file/关键文件缺失: %s" % k)

    # 3) size limit
    if len(changed) > 50:
        issues.append("Large PR/超大 PR: %d files — split into focused PRs" % len(changed))

    # 4) bilingual terminology (Chinese term should have nearby English)
    TERMS = ["LGD", "自治之物", "有籍", "有证", "有门禁", "Governance", "Registry", "Evidence", "Gates"]
    for f in changed_md:
        if not f.lower().endswith(".md"):
            continue
        try:
            with open(f, "r", encoding="utf-8") as fh:
                c = fh.read()
        except Exception:
            continue
        for t in TERMS:
            if t in c and re.match(r"[\u4e00-\u9fff]", t):
                pos = c.find(t)
                ctx = c[max(0, pos - 200):pos + 200]
                if not re.search(r"[A-Za-z]{4,}", ctx):
                    issues.append("Term/术语: '%s' in %s without nearby English counterpart (bilingual rule)" % (t, f))

    # 5) anchor discipline: README must link LGD-Eval cross-repos
    for f in changed_md:
        if "README" not in f.upper():
            continue
        try:
            with open(f, "r", encoding="utf-8") as fh:
                c = fh.read()
        except Exception:
            continue
        if "github.com/LGD-Eval" not in c and os.environ.get("EXPECT_LINKS", "1") == "1":
            issues.append("README %s has no LGD-Eval cross-repo links (anchor discipline/内锚)" % f)

    result = {"errors": errors[:30], "issues": issues[:40], "changed_count": len(changed)}

    out_path = os.environ.get("GITHUB_OUTPUT", "out.txt")
    with open(out_path, "a", encoding="utf-8") as fh:
        fh.write("result=%s\n" % json.dumps(result))

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "summary.md")
    with open(summary_path, "a", encoding="utf-8") as fh:
        fh.write("## PR Review Bot — %s\n" % os.environ.get("GITHUB_REPOSITORY", ""))
        fh.write("- Errors/阻断: %d | Warnings/提示: %d | Changed/变更: %d\n" % (len(errors), len(issues), len(changed)))
        for e in errors[:15]:
            fh.write("- :red_circle: %s\n" % e)
        for i in issues[:20]:
            fh.write("- :yellow_circle: %s\n" % i)

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
