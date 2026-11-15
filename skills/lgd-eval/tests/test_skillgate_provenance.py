"""skillgate.py 的来源与强度一致性断言。

存在原因：2026-11-15 做跨仓比对时发现，LGD-Eval 里那份 skillgate.py 只有 72,112 B，
lgd-gate 里的正典是 120,641 B。差的不是注释，是规则：

    表                     正典    LGD-Eval 旧副本
    INVISIBLE_RANGES       14 段   无（隐形字符整个类不检）
    PROMPT_INJECTION       27 条   15 条
    CREDENTIAL_PATTERNS    22 条   11 条
    AUTH_PATTERNS          13 条   6 条
    REMOTE_EXEC_PATTERNS   12 条   无
    INSTALL_HOOKS           7 个   无

它自己的文件头还写着"公开仓同步对"，但早已不同步。用户从 LGD-Eval 装到的是弱一档的
扫描器——和 evaluate.py 那次分叉是同一类问题：修在库里，产品拿到的是旧库。

这组测试把"两边同源"钉成可执行断言，任何一侧再分叉，这里先红。
"""
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "skills" / "lgd-eval" / "scripts" / "skillgate.py"
VENDOR = ROOT / "vendor" / "scripts" / "skillgate.py"

# 与 lgd-gate 仓正典同源，改动必须三处一起同步并更新此值
PINNED_SHA256 = "b08433e79f339ea8969f7c28990b6ca178857c556e58d61471322db637bc4266"


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def test_vendor_matches_source():
    assert SRC.is_file() and VENDOR.is_file()
    assert _sha(VENDOR) == _sha(SRC), "vendor 与源码的 skillgate.py 不一致"


def test_matches_pinned_canonical():
    actual = _sha(SRC)
    assert actual == PINNED_SHA256, (
        "skillgate.py 与正典不一致。\n  期望 %s\n  实际 %s\n"
        "修复方式：先改 lgd-gate/skillgate.py，再整文件复制到本仓两处并更新此值。"
        % (PINNED_SHA256, actual)
    )


def test_carries_the_class_tables():
    """分叉时的具体症状：关键规则表整张缺失。"""
    body = SRC.read_text(encoding="utf-8")
    for needle in ("INVISIBLE_RANGES", "REMOTE_EXEC_PATTERNS",
                   "ACTIVE_RULE_TABLES", "RULE_TABLES_DECLARED_OFF",
                   "INSTALL_HOOKS", "AUTH_PATTERNS", "CREDENTIAL_PATTERNS"):
        assert needle in body, "正典里的 %s 不在这份副本里" % needle


JS_PINNED_SHA256 = "97bce99b6ba580aa10d213b3ed97453cd0f67c185a76710d8fbc067554d4c534"


def test_js_analyzer_matches_source():
    """JS 引擎同一个病：LGD-Eval 那份只有 4,062 B，正典 8,324 B。

    少的是 CRED_PATHS（读 .aws/.ssh 不报）、{...process.env} 展开、
    Object.keys/assign 变体，以及跨文件组合所需的 import 解析。
    实测 8 个 JS 形态：同步前 4 个漏检，同步后 8/8 与正典一致。
    """
    js_src = SRC.parent / "js_analyzer.py"
    js_ven = VENDOR.parent / "js_analyzer.py"
    assert js_src.is_file() and js_ven.is_file()
    assert _sha(js_ven) == _sha(js_src), "vendor 与源码的 js_analyzer.py 不一致"
    assert _sha(js_src) == JS_PINNED_SHA256, (
        "js_analyzer.py 与正典不一致。\n  期望 %s\n  实际 %s"
        % (JS_PINNED_SHA256, _sha(js_src))
    )
    body = js_src.read_text(encoding="utf-8")
    for needle in ("CRED_PATHS", "NET_SINKS", "IMPORT_RE", "TLS_OFF"):
        assert needle in body, "正典里的 %s 不在这份 JS 引擎里" % needle
