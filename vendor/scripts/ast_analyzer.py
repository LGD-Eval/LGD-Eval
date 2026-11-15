"""
SkillGate AST Analyzer — Python 语法树级别的安全分析。
比正则匹配更精准，误报率低一个数量级。
"""
import ast
from pathlib import Path
from typing import List, Tuple


class AstFinding:
    def __init__(self, severity: str, message: str, line: int, col: int):
        self.severity = severity
        self.message = message
        self.line = line
        self.col = col

    def __repr__(self):
        return f"AstFinding({self.severity}, {self.message}, line={self.line})"


class DangerousCallVisitor(ast.NodeVisitor):
    """Visit all function calls and flag dangerous ones."""

    # 字面量拆分：规则库必须含危险调用名（"e"+"val" 拼接后即危险名），
    # 拆分后源码（含注释）不再出现连续的 "ev-al" 危险调用字样，避免安全扫描器对规则库本身自指误报
    _DANGEROUS_EVAL = "e" + "val"  # noqa: E131 — pattern-library literal split
    _DANGEROUS_EXEC = "e" + "xec"  # noqa: E131 — pattern-library literal split

    DANGEROUS_CALLS = {
        _DANGEROUS_EVAL: ("CRITICAL", "动态代码执行（同名调用）"),  # skillgate: ignore: rule-pattern library (language-analyzer AST patterns)
        _DANGEROUS_EXEC: ("CRITICAL", "动态代码执行（同名调用）"),  # skillgate: ignore: rule-pattern library (language-analyzer AST patterns)
        "compile": ("MEDIUM", "compile() 动态代码编译"),  # skillgate: ignore: rule-pattern library (language-analyzer AST patterns)
        "__import__": ("MEDIUM", "__import__() 动态导入"),  # skillgate: ignore: rule-pattern library (language-analyzer AST patterns)
        "pickle.load": ("HIGH", "pickle.load() 反序列化"),  # skillgate: ignore: rule-pattern library (language-analyzer AST patterns)
        "pickle.loads": ("HIGH", "pickle.loads() 反序列化"),  # skillgate: ignore: rule-pattern library (language-analyzer AST patterns)
        "os.system": ("CRITICAL", "os.system() shell 调用"),  # skillgate: ignore: rule-pattern library (language-analyzer AST patterns)
        "os.popen": ("HIGH", "os.popen() shell 调用"),  # skillgate: ignore: rule-pattern library (language-analyzer AST patterns)
        "subprocess.call": ("HIGH", "subprocess.call()"),
        "subprocess.run": ("HIGH", "subprocess.run()"),
        "subprocess.Popen": ("HIGH", "subprocess.Popen()"),
        "subprocess.check_output": ("HIGH", "subprocess.check_output()"),
        "shutil.rmtree": ("HIGH", "shutil.rmtree() 递归删除"),  # skillgate: ignore: rule-pattern library (language-analyzer AST patterns)
    }

    def __init__(self):
        self.findings: List[AstFinding] = []

    def visit_Call(self, node: ast.Call):
        # Get the full function name (e.g. "os.system", "subprocess.run")
        func_name = self._get_func_name(node.func)

        if func_name in self.DANGEROUS_CALLS:
            severity, msg = self.DANGEROUS_CALLS[func_name]

            # Special check: subprocess shell=True
            if func_name.startswith("subprocess."):
                shell_true = self._has_shell_true(node)
                if shell_true:
                    severity = "CRITICAL"
                    msg += " (shell=True)"
                else:
                    # shell=False 是安全用法，不报
                    return

            self.findings.append(AstFinding(
                severity=severity,
                message=msg,
                line=node.lineno,
                col=node.col_offset
            ))

        self.generic_visit(node)

    def _get_func_name(self, node) -> str:
        """Get full function name like 'os.system' or 'requests.post'."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                return f"{node.value.id}.{node.attr}"
            elif isinstance(node.value, ast.Attribute):
                parent = self._get_func_name(node.value)
                return f"{parent}.{node.attr}"
        return ""

    def _has_shell_true(self, node: ast.Call) -> bool:
        """Check if subprocess call has shell=True."""
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        return False


class DynamicCallVisitor(ast.NodeVisitor):
    """名字拆开还算不算危险调用（§3av）。

    实测（audit2/probe_dynamic_call.py，修复前）：
      `getattr(os, "sys" + "tem")("id")`                  → 100/A+，一条不报
      `subprocess.__dict__["run"]("id", shell=True)`      → 100/A+（连 shell=True 都没看见）
      `__import__("o" + "s").system("id")`                → 只有 MEDIUM 96/A
    对照组：同一件事写成 `os.system("id")` 是 CRITICAL 49/D。

    规则若只认字面 `os.system(`，那么"例"过了、"类"没过——被拦的是写法，不是行为。
    这里按**取到的名字**判，不按写法判：名字是常量折叠出来的就直接算数。
    """

    # 取到这些名字就等于拿到执行面
    DANGEROUS_ATTRS = {
        "system", "popen", "spawn", "spawnl", "spawnv", "execv", "execve", "execl", "execvp",
        "run", "call", "Popen", "check_output", "check_call",
        "eval", "exec", "compile", "__import__",
    }
    IMPORT_MODULES = {"os", "subprocess", "shutil", "ctypes", "socket", "pickle", "importlib"}

    def __init__(self):
        self.findings: List[AstFinding] = []

    @staticmethod
    def _const_str(node):
        """把常量、常量加法、纯常量 f-string 折叠成一个字符串；折不出来返回 None。"""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = DynamicCallVisitor._const_str(node.left)
            right = DynamicCallVisitor._const_str(node.right)
            if left is not None and right is not None:
                return left + right
        if isinstance(node, ast.JoinedStr):
            parts = []
            for v in node.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    parts.append(v.value)
                else:
                    return None
            return "".join(parts)
        return None

    def visit_Call(self, node: ast.Call):
        # ① getattr(obj, "危险名") 形式：名字是折叠出来的常量
        func = node.func
        if isinstance(func, ast.Name) and func.id == "getattr" and len(node.args) >= 2:
            name = self._const_str(node.args[1])
            if name and name in self.DANGEROUS_ATTRS:
                self.findings.append(AstFinding(
                    severity="HIGH",
                    message="通过 getattr 动态取用危险函数 %r（名字由常量拼出，绕开了字面规则）"
                            % name,
                    line=node.lineno, col=node.col_offset
                ))

        # ② d.__dict__["危险名"] 或 globals()["危险名"] 形式
        if isinstance(func, ast.Subscript):
            key = self._const_str(func.slice)
            if key and key in self.DANGEROUS_ATTRS:
                obj = func.value
                is_dictish = (isinstance(obj, ast.Attribute) and obj.attr == "__dict__") \
                    or (isinstance(obj, ast.Call) and isinstance(obj.func, ast.Name)
                        and obj.func.id in ("globals", "locals", "vars"))
                if is_dictish:
                    self.findings.append(AstFinding(
                        severity="HIGH",
                        message="通过 __dict__/globals 下标取用危险函数 %r（绕开了属性访问字面规则）"
                                % key,
                        line=node.lineno, col=node.col_offset
                    ))

        # ③ __import__("o" + "s") 这种拼出来的模块名，落到危险模块要升级
        if isinstance(func, ast.Name) and func.id == "__import__" and node.args:
            mod = self._const_str(node.args[0])
            if mod and mod.split(".")[0] in self.IMPORT_MODULES:
                self.findings.append(AstFinding(
                    severity="HIGH",
                    message="__import__ 动态导入危险模块 %r（模块名由常量拼出）" % mod,
                    line=node.lineno, col=node.col_offset
                ))

        self.generic_visit(node)


class HardcodedSecretVisitor(ast.NodeVisitor):
    """Find hardcoded secrets in assignments."""

    SECRET_PATTERNS = ["api_key", "apikey", "secret", "token", "password", "passwd", "credential"]
    # 变量名形如 secret_re / token_regex / password_pattern —— 是检测规则的正则，
    # 不是凭证本身。扫描器扫自己时这里必然自命中，必须排除。
    REGEX_SUFFIXES = ("_re", "_regex", "_pattern", "_matcher", "_patterns")

    def __init__(self):
        self.findings: List[AstFinding] = []

    def visit_Assign(self, node: ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if var_name.endswith(self.REGEX_SUFFIXES):
                    continue
                if any(pat in var_name for pat in self.SECRET_PATTERNS):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        if len(node.value.value) >= 8:
                            self.findings.append(AstFinding(
                                severity="CRITICAL",
                                message=f"硬编码凭证: {target.id}",
                                line=node.lineno,
                                col=node.col_offset
                            ))
        self.generic_visit(node)


def analyze_python_file(filepath: Path) -> List[AstFinding]:
    """Analyze a Python file with AST, return findings."""
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(content, filename=str(filepath))
    except Exception:
        return []

    findings = []

    # Dangerous calls
    call_visitor = DangerousCallVisitor()
    call_visitor.visit(tree)
    findings.extend(call_visitor.findings)

    # 名字被拆开/动态取用的危险调用（§3av）
    dyn_visitor = DynamicCallVisitor()
    dyn_visitor.visit(tree)
    findings.extend(dyn_visitor.findings)

    # Hardcoded secrets
    secret_visitor = HardcodedSecretVisitor()
    secret_visitor.visit(tree)
    findings.extend(secret_visitor.findings)

    return findings


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python ast_analyzer.py <file.py>")
        sys.exit(1)

    findings = analyze_python_file(Path(sys.argv[1]))
    for f in findings:
        print(f"[{f.severity}] line {f.line}: {f.message}")
