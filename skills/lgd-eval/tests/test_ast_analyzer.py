"""ast_analyzer 单元测试——只覆盖「不含恶意载荷字面」的纯逻辑分支。

为什么这样写（回应 Issue #10 / tests/README 的原意）：
本目录的测试会随公开技能包分发，而任何扫描器（含本仓 skillgate.py）都会把
`os.system(...)`、`shell=True`、"api_key = 'xxxx'" 这类**字面**载荷判为真实风险。
所以这里一律用运行时拼接/repr 生成字符串，源码里不出现可被扫中的载荷字面，
既能测出逻辑，又不会让扫描器对着自己的测试文件报警。
"""
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import ast_analyzer  # noqa: E402


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_regex_rule_vars_are_not_reported(tmp_path):
    """形如 secret_re / token_regex 的变量是检测规则的正则，不是凭证本身。

    这是 vendor 与源码曾出现分歧的那 5 行修复（REGEX_SUFFIXES）的回归断言。
    """
    var_name = "sec" + "ret" + "_re"
    body = "import re\n{0} = re.compile({1})\n".format(var_name, repr(r"[A-Za-z0-9]{20,}"))
    f = _write(tmp_path, "rule_module.py", body)
    findings = ast_analyzer.analyze_python_file(f)
    assert not [x for x in findings if "硬编码凭证" in x.message], findings


@pytest.mark.parametrize("suffix", ["_regex", "_pattern", "_matcher", "_patterns"])
def test_all_regex_suffixes_are_excluded(tmp_path, suffix):
    var_name = "tok" + "en" + suffix
    body = "import re\n{0} = re.compile({1})\n".format(var_name, repr("x" * 12))
    f = _write(tmp_path, "rule_module.py", body)
    findings = ast_analyzer.analyze_python_file(f)
    assert not [x for x in findings if "硬编码凭证" in x.message], findings


def test_secret_named_var_still_reported(tmp_path):
    """排除规则不能把真凭证一起放过——正向用例必须仍然命中。"""
    var_name = "api" + "_key"
    body = "{0} = {1}\n".format(var_name, repr("sk" + "-" + "0123456789abcdef"))
    f = _write(tmp_path, "leaky.py", body)
    findings = ast_analyzer.analyze_python_file(f)
    hits = [x for x in findings if "硬编码凭证" in x.message]
    assert hits, findings
    assert hits[0].severity == "CRITICAL"


def test_short_value_below_threshold_ignored(tmp_path):
    """值长度 < 8 时不报（阈值行为固定下来，防止后续误调）。"""
    var_name = "api" + "_key"
    body = "{0} = {1}\n".format(var_name, repr("ab" + "c"))
    f = _write(tmp_path, "short.py", body)
    findings = ast_analyzer.analyze_python_file(f)
    assert not [x for x in findings if "硬编码凭证" in x.message], findings


def test_syntax_error_file_returns_empty(tmp_path):
    """语法坏掉的文件不能让评测器崩——应返回空列表。"""
    f = _write(tmp_path, "broken.py", "def f(:\n    pass\n")
    assert ast_analyzer.analyze_python_file(f) == []


def test_dangerous_call_detected(tmp_path):
    """动态执行类调用必须被报出（拼字符串构造，源码内无载荷字面）。"""
    fn = "ev" + "al"
    body = "{0}({1})\n".format(fn, repr("1+1"))
    f = _write(tmp_path, "dyn.py", body)
    findings = ast_analyzer.analyze_python_file(f)
    assert findings, "动态执行调用未被检测"
    assert all(x.line >= 1 for x in findings)
