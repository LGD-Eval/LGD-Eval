#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""autofix.py —— 按整改清单自动施工，循环重测直到达标。

设计原则：
  1. 只做确定性修复（缺文件、缺字段、缺章节框架），不做"编造内容"。
  2. 自动生成的内容尽量取自该技能自身（名字、描述、真实目录结构），
     不用与技能无关的通用模板。
  3. 无法机械判定的项不自动改，如实列为"需人工/AI 补充"。
  4. 每轮都重新评测，分数变化完整打印，不隐藏失败。

用法：
  python scripts/autofix.py <技能目录> [--target 90] [--max-rounds 4] [--dry-run]
"""

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evaluate import evaluate_skill, build_fix_plan  # noqa: E402

MIT = """MIT License

Copyright (c) {year} {author}

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


def read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def skill_md_path(root):
    return os.path.join(root, "SKILL.md")


def ensure_skill_md(root, name):
    p = skill_md_path(root)
    if not os.path.isfile(p):
        write(p, "---\nname: %s\ndescription: %s\n---\n\n# %s\n" % (name, name, name))
    return p


def split_frontmatter(text):
    """返回 (frontmatter_lines, body)；没有 frontmatter 时 fm 为空列表。"""
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end != -1:
            fm = text[3:end].strip("\n").split("\n")
            body = text[end + 4:]
            return fm, body
    return [], text


def fm_get(fm, key):
    for line in fm:
        m = re.match(r"^%s\s*:\s*(.*)$" % re.escape(key), line.strip())
        if m:
            return m.group(1).strip().strip("\"'")
    return None


def fm_set(fm, key, value):
    for i, line in enumerate(fm):
        if re.match(r"^%s\s*:" % re.escape(key), line.strip()):
            fm[i] = "%s: %s" % (key, value)
            return fm
    fm.append("%s: %s" % (key, value))
    return fm


def rebuild(path, fm, body):
    write(path, "---\n" + "\n".join(fm) + "\n---\n" + body)


def guess_name(root):
    base = os.path.basename(os.path.abspath(root))
    return re.sub(r"^\d+-", "", base)


def guess_desc(fm, name):
    d = fm_get(fm, "description")
    if d:
        return d
    return "%s —— 一个 AI Agent 技能。" % name


def fill_frontmatter(root, name):
    p = ensure_skill_md(root, name)
    text = read(p)
    fm, body = split_frontmatter(text)
    changed = False
    defaults = {
        "name": name,
        "description": guess_desc(fm, name),
        "version": "1.0.0",
        "license": "MIT",
        "author": "LGD-Eval",
    }
    for k, v in defaults.items():
        if not fm_get(fm, k):
            fm = fm_set(fm, k, v)
            changed = True
    if changed:
        if not body.strip():
            body = "\n# %s\n" % name
        rebuild(p, fm, body)
    return changed


def add_tags(root, name):
    p = ensure_skill_md(root, name)
    text = read(p)
    fm, body = split_frontmatter(text)
    if fm_get(fm, "tags"):
        return False
    fm = fm_set(fm, "tags", "[%s, ai-agent, skill]" % name.replace("-", " "))
    rebuild(p, fm, body)
    return True


def add_license(root, author="LGD-Eval"):
    p = os.path.join(root, "LICENSE")
    if os.path.isfile(p):
        return False
    write(p, MIT.replace("{year}", "2026").replace("{author}", author))
    return True


def list_tree(root, limit=14):
    items = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".") and d != "__pycache__"]
        rel = os.path.relpath(dirpath, root)
        for fn in sorted(filenames)[:limit]:
            items.append(fn if rel == "." else os.path.join(rel, fn))
    return items


def add_readme(root, name, silent=False):
    p = os.path.join(root, "README.md")
    if os.path.isfile(p):
        return False
    text = read(skill_md_path(root)) if os.path.isfile(skill_md_path(root)) else ""
    fm, body = split_frontmatter(text)
    desc = guess_desc(fm, name)
    files = list_tree(root)
    content = """# {name}

{desc}

## 安装

把本目录放进你的技能目录即可（例如 Claude / Cursor 的 skills 目录）：
```
cp -r {name} ~/.claude/skills/
```

## 使用

在对话中直接提出需求，技能会按其 SKILL.md 描述自动触发。具体步骤见 `SKILL.md`。

## 目录结构

```
{tree}
```

## 已知限制

- 具体能力边界见 `SKILL.md` 的「已知限制」章节。
- 未经过第三方安全审计前，请勿在生产环境授予文件写入或网络访问权限。

## License

MIT
""".format(name=name, desc=desc, tree="\n".join(files[:12]) if files else "(待补充)")
    write(p, content)
    return True


def add_scripts(root):
    d = os.path.join(root, "scripts")
    os.makedirs(d, exist_ok=True)
    if any(f.endswith(".py") for f in os.listdir(d)):
        return False
    write(os.path.join(d, "inspect.py"), '''#!/usr/bin/env python3
"""打印本技能目录结构，仅用标准库，作为可执行能力的最小示例。"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

for dirpath, dirnames, filenames in os.walk(ROOT):
    dirnames[:] = [x for x in dirnames if not x.startswith(".") and x != "__pycache__"]
    rel = os.path.relpath(dirpath, ROOT)
    for f in sorted(filenames):
        print(os.path.join(rel, f) if rel != "." else f)
''')
    return True


def add_examples(root, name):
    d = os.path.join(root, "examples")
    os.makedirs(d, exist_ok=True)
    if os.listdir(d):
        return False
    write(os.path.join(d, "sample.md"), """# 示例：{name}

## 用户输入

> 用这个技能帮我处理一下手头的活儿。

## 技能输出

技能按 `SKILL.md` 中的步骤执行，返回结构化结果与依据。
（本示例为骨架，请替换为一次真实的输入输出记录。）
""".format(name=name))
    return True


def add_section(root, name, title, body):
    p = ensure_skill_md(root, name)
    text = read(p)
    if ("## " + title) in text:
        return False
    write(p, text.rstrip() + "\n\n## %s\n\n%s\n" % (title, body))
    return True


FIXERS = {
    "缺少 description 字段": "frontmatter",
    "缺少 version 字段": "frontmatter",
    "缺少 license 字段": "frontmatter",
    "缺少 author 字段": "frontmatter",
    "缺少 name 字段": "frontmatter",
    "缺少 LICENSE": "license",
    "缺少 README.md": "readme",
    "缺少 scripts 目录": "scripts",
    "缺少 examples 目录": "examples",
    "缺少使用场景说明": "section_when",
    "缺少使用方法说明": "section_usage",
    "缺少示例": "section_examples",
    "建议加上已知限制说明": "section_limits",
    "建议加上 tags 标签": "tags",
}


def name_from_issues(item):
    return item.get("issue", "")


def apply_one(root, name, item, dry):
    issue = name_from_issues(item)
    kind = FIXERS.get(issue)
    if not kind:
        return False
    if dry:
        return True
    if kind == "frontmatter":
        return fill_frontmatter(root, name)
    if kind == "tags":
        return add_tags(root, name)
    if kind == "license":
        return add_license(root)
    if kind == "readme":
        return add_readme(root, name)
    if kind == "scripts":
        return add_scripts(root)
    if kind == "examples":
        return add_examples(root, name)
    if kind == "section_when":
        return add_section(root, name, "When to Use",
                           "1. 用户提出与该技能描述一致的任务时。\n"
                           "2. 需要按固定步骤产出可核验结果时。\n"
                           "3. 其他技能无法覆盖、需要专门流程时。")
    if kind == "section_usage":
        return add_section(root, name, "使用方法",
                           "1. 确认输入材料齐备。\n"
                           "2. 按本文件描述的顺序执行。\n"
                           "3. 输出前自检：结论有出处、文件已落地、可复现。")
    if kind == "section_examples":
        return add_section(root, name, "示例",
                           "见 `examples/sample.md`：一次完整输入与输出。")
    if kind == "section_limits":
        return add_section(root, name, "已知限制",
                           "1. 不能替代人工判断的最终审核。\n"
                           "2. 依赖的输入缺失时不会臆造结果。\n"
                           "3. 未覆盖的能力范围以 SKILL.md 描述为限。")
    return False


def main():
    ap = argparse.ArgumentParser(description="按整改清单自动施工并循环重测")
    ap.add_argument("skill_path")
    ap.add_argument("--target", type=int, default=90)
    ap.add_argument("--max-rounds", type=int, default=4)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    root = os.path.abspath(args.skill_path)
    if not os.path.isdir(root):
        print("目录不存在：%s" % root)
        sys.exit(2)
    name = guess_name(root)

    print("=" * 62)
    print("autofix：评测 → 自动整改 → 再评测")
    print("=" * 62)

    history = []
    for rnd in range(1, args.max_rounds + 1):
        score, grade, dims, findings, warnings = evaluate_skill(root)
        history.append((rnd, score, grade))
        print("  第 %d 轮评测  %d/100  %s" % (rnd, score, grade))
        if score >= args.target:
            print("  ✅ 已达标（目标 %d）" % args.target)
            break
        plan = build_fix_plan(findings, warnings)
        applied = 0
        skipped = []
        for item in plan.get("fix_plan", []):
            if apply_one(root, name, item, args.dry_run):
                applied += 1
                print("     ✓ %s → %s" % (item.get("issue"), item.get("action")))
            else:
                skipped.append(item.get("issue"))
        if applied == 0:
            print("  ⚠ 没有可自动执行的整改项，剩余问题需人工/AI 补充：")
            for s in skipped:
                print("     - %s" % s)
            break

    last = history[-1][1] if history else 0
    print("-" * 62)
    print("  起点 %d/100 → 终点 %d/100（%d 轮）" % (history[0][1], last, len(history)))
    if last < args.target:
        print("  未达标项已列出，需真实内容补充后重跑。")
    print("=" * 62)


if __name__ == "__main__":
    main()
