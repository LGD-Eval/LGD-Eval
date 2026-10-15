#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Welcome Bot self-test — 欢迎机器人自检（LGD-Eval）

Verifies, without any first-time-contributor event:
  1) key routing files exist (README / CONTRIBUTORS / AI-VOICE-AMBASSADORS)
  2) welcome message template renders with the required bilingual blocks
  3) required route anchors appear in the message
Exit code: 0 on PASS, 1 on FAIL.
"""
import os
import sys

def build_welcome(login, base):
    body = [
        "## Welcome, @%s! / 欢迎你！" % login,
        "",
        "Thanks for your first interaction with LGD-Eval. Here is how to proceed / 感谢你与 LGD-Eval 的首次互动，参与路径如下：",
        "",
        "- **Explore** / 了解我们: [README](%s/blob/main/README.md)" % base,
        "- **Contribute** / 参与（含零门槛路径，不会编程也能参与）: [CONTRIBUTORS.md](%s/blob/main/CONTRIBUTORS.md)" % base,
        "- **Onboard your AI** / 引导你的 AI 参与: [AI-VOICE-AMBASSADORS.md](%s/blob/main/AI-VOICE-AMBASSADORS.md)（登记即获 VC +1）" % base,
        "- **Good first issues** / 新手任务: filter by the `good first issue` label",
        "",
        "> AI-assisted welcome by LGD-Eval AI（AI-BOT-003, passport L3）· 由 LGD-Eval AI 自动欢迎 · 受 AI 护照制度治理",
        "> Maintainers aim to respond within 72h / 维护者将于 72 小时内响应。"
    ]
    return "\n".join(body)

def main() -> int:
    failed = []
    repo = os.environ.get("GITHUB_REPOSITORY", "LGD-Eval/LGD-Eval")
    login = os.environ.get("TEST_LOGIN", "tester-ai")
    base = "https://github.com/%s" % repo

    # 1) required routing files present in checkout
    for f in ["README.md", "CONTRIBUTORS.md", "AI-VOICE-AMBASSADORS.md"]:
        if not os.path.exists(f):
            failed.append("missing %s" % f)

    # 2) message template renders & contains bilingual + routing anchors
    msg = build_welcome(login, base)
    for anchor in ["Welcome", "欢迎", "CONTRIBUTORS.md", "AI-VOICE-AMBASSADORS.md",
                   "good first issue", "72h", "AI-BOT-003", "护照"]:
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
