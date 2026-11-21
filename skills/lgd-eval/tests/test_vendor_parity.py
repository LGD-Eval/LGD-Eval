"""vendor/scripts 与 skills/lgd-eval/scripts 的逐字节一致性断言。

把 README 第 70 行的承诺（"与 GitHub 源码逐字节相同"）变成可执行断言：
一旦 npm 分发物（vendor/）与源码出现任何一字节差异，测试立刻失败。
这正是 Issue #10 的 P2（ast_analyzer.py 曾 vendor 6277B / 源码 6629B）。
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]          # 仓库根
SRC = ROOT / "skills" / "lgd-eval" / "scripts"
VENDOR = ROOT / "vendor" / "scripts"


def _sha(p: Path) -> str:
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return h.hexdigest()


def test_both_dirs_exist():
    assert SRC.is_dir(), f"源码脚本目录缺失: {SRC}"
    assert VENDOR.is_dir(), f"分发脚本目录缺失: {VENDOR}"


def test_file_sets_identical():
    src_files = {p.name for p in SRC.glob("*.py")}
    ven_files = {p.name for p in VENDOR.glob("*.py")}
    assert src_files == ven_files, (
        "两侧脚本文件集合不一致：仅源码有 " + str(sorted(src_files - ven_files)) +
        "，仅 vendor 有 " + str(sorted(ven_files - src_files))
    )


def test_no_byte_differences():
    different = []
    for p in sorted(VENDOR.glob("*.py")):
        q = SRC / p.name
        if not q.is_file():
            different.append((p.name, "源码无同名文件"))
            continue
        if _sha(p) != _sha(q):
            different.append((p.name, f"vendor={p.stat().st_size}B src={q.stat().st_size}B"))
    assert not different, "vendor 与源码存在逐字节差异: " + repr(different)


def test_package_json_ships_vendor():
    """npm 分发物必须覆盖 vendor/，否则"npx 与 clone 一致"这个承诺不成立。"""
    pkg = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    assert "vendor" in pkg.get("files", []), pkg.get("files")
