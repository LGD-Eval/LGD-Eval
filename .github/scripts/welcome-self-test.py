#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Welcome Bot self-test — 欢迎机器人自检（LGD-Eval, 仓库无关版）

Verifies, without any first-time-contributor event:
  1) mandatory routing file (README.md) exists in checkout
  2) welcome message template renders with the required bilingual blocks,
     and only links to routing docs that actually exist in THIS repo
     (避免跨仓库复用时引用不存在的文件产生死链)
  3) required route anchors appear in the message
Exit code: 0 on PASS, 1 on FAIL.
"""
import os
import sys


def _repo_root():
    """Locate the repo root by walking up from this script (cwd-independent)."""
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(5):
        if os.path.exists(os.path.join(d, "README.md")) or os.path.isdir(os.path.join(d, ".git")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return os.getcwd()


def build_welcome(login, base, root):
    """Build the welcome message.

    Routing links are only included for docs that exist in `root`,
    so the bot never posts dead links in repos that lack them.
    """
    lines = [
        "## Welcome, @%s! / 欢迎你！" % login,
        "",
        "Thanks for your first interaction with LGD-Eval. Here is how to proceed / 感谢你与 LGD-Eval 的首次互动，参与路径如下：",
        "",
        "- **Explore** / 了解我们: [README](%s/blob/main/README.md)" % base,
    ]
    # 可选路由文档：仅当仓库内确实存在时才写入欢迎消息（防死链）
    optional = {
        "CONTRIBUTORS.md": "**Contribute** / 参与（含零门槛路径，不会编程也能参与）",
        "AI-VOICE-AMBASSADORS.md": "**Onboard your AI** / 引导你的 AI 参与（登记即获 VC +1）",
    }
    for fname, label in optional.items():
        if os.path.exists(os.path.join(root, fname)):
            lines.append("- %s: [%s](%s/blob/main/%s)" % (label, fname, base, fname))
    lines.append("- **Good first issues** / 新手任务: filter by the `good first issue` label")
    lines.append("")
    lines.append("> AI-assisted welcome by LGD-Eval AI（AI-BOT-003, passport L3）· 由 LGD-Eval AI 自动欢迎 · 受 AI 护照制度治理")
    lines.append("> Maintainers aim to respond within 72h / 维护者将于 72 小时内响应。")
    return "\n".join(lines)


def main() -> int:
    failed = []
    repo = os.environ.get("GITHUB_REPOSITORY", "LGD-Eval/LGD-Eval")
    login = os.environ.get("TEST_LOGIN", "tester-ai")
    base = "https://github.com/%s" % repo

    _root = _repo_root()

    # 1) mandatory routing file present (every repo must have README.md)
    #    其余路由文档由 WELCOME_KEYFILES 环境变量按仓库声明，默认仅 README.md
    _key_env = os.environ.get("WELCOME_KEYFILES", "README.md")
    for f in [k.strip() for k in _key_env.split(",") if k.strip()]:
        if not os.path.exists(os.path.join(_root, f)):
            failed.append("missing %s" % f)

    # 2) message template renders & contains bilingual + routing anchors
    #    仅对仓库内真实存在的路由文档断言其锚点
    msg = build_welcome(login, base, _root)
    anchors = ["Welcome", "欢迎", "good first issue", "72h", "AI-BOT-003", "护照"]
    if os.path.exists(os.path.join(_root, "CONTRIBUTORS.md")):
        anchors.append("CONTRIBUTORS.md")
    if os.path.exists(os.path.join(_root, "AI-VOICE-AMBASSADORS.md")):
        anchors.append("AI-VOICE-AMBASSADORS.md")
    for anchor in anchors:
        if anchor not in msg:
            failed.append("anchor missing in message: %s" % anchor)

    # 3) login interpolation
    if "@%s" % login not in msg:
        failed.append("login interpolation failed")

    ok = not failed
    print("WELCOME SELF-TEST %s — repo=%s login=%s" % ("PASS" if ok else "FAIL", repo, login))
    if failed:
        print("\n".join("- " + f for f in failed))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
