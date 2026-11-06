#!/usr/bin/env python3
"""skillgate — Skill 安全与质量扫描门禁

Usage:
    python skillgate scan <skill_dir>
    python skillgate scan <skill_dir> --format json
    python skillgate scan <skill_dir> --format markdown --output report.md

Exit codes:
    0 = pass (all checks green)
    1 = fail (critical/high findings)
    2 = usage error

正典声明：本文件为 LGD-Eval 评测线 skillgate 扫描器的发布正典副本。
公开仓同步对：LGD-Eval/lgd-gate/skillgate.py 与 zhaoxinghua09-cell/skillgate/scripts/skillgate.py
两仓内容逐字节一致（blob SHA 相同）；本地开发正典位于 coze-publish/02-skill-eval-engine/scripts/。
改动请同步两公开仓，勿让双副本分叉（Muse 复测 P2-5 收敛要求）。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.request  # skillgate: ignore
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

# Import AST analyzer
try:
    from ast_analyzer import analyze_python_file as ast_analyze
except ImportError:
    ast_analyze = None

# Import JS analyzer
try:
    from js_analyzer import scan_js_file
except ImportError:
    scan_js_file = None


# ── Check patterns ──────────────────────────────────────────────────────────

# 1. Dangerous code execution
DANGEROUS_CODE_PATTERNS = [
    (r"\beval\s*\(", "MEDIUM", "eval() 动态代码执行（工具常用，需人工判断）"),  # skillgate: ignore
    (r"\bexec\s*\(", "MEDIUM", "exec() 动态代码执行（工具常用，需人工判断）"),
    (r"\bos\.system\s*\(", "HIGH", "os.system() shell 调用"),  # skillgate: ignore
    (r"\bsubprocess\.(run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True", "HIGH", "subprocess shell=True"),
    (r"\bos\.popen\s*\(", "HIGH", "os.popen() shell 调用"),  # skillgate: ignore
    (r"\b__import__\s*\(", "MEDIUM", "动态 import"),
    (r"\bpickle\.load(s)?\s*\(", "HIGH", "pickle 反序列化"),
    (r"\byaml\.load\s*\([^)]*\)(?![^#]*Loader\s*=\s*SafeLoader)", "MEDIUM", "yaml.load 非安全加载"),
    (r"(?<!\.)\bcompile\s*\(", "INFO", "compile() 动态代码编译（低风险）"),
    (r"\bgetattr\s*\([^)]*os\.", "MEDIUM", "getattr 动态调用 os 模块"),
    (r"\bglobals\(\)", "INFO", "globals() 访问全局命名空间（低风险）"),
    (r"\blocals\(\)", "INFO", "locals() 访问局部命名空间（低风险）"),
    (r"\binput\s*\(\)", "INFO", "input() 接受用户输入（CLI 工具常见）"),
    (r"\binput\s*\([^)]*\)", "INFO", "input() 接受用户输入（CLI 工具常见）"),
    (r"\b__builtins__\b", "INFO", "访问 __builtins__（低风险）"),
    (r"\bglobals\(\)\[", "MEDIUM", "globals() 动态修改"),
    (r"\bsetattr\s*\(", "INFO", "setattr 动态属性设置（低风险）"),
    (r"\bdelattr\s*\(", "INFO", "delattr 动态属性删除（低风险）"),
    # === 新增规则 ===
    (r"\bmarshal\.load(s)?\s*\(", "HIGH", "marshal 反序列化"),
    (r"\bshelve\.open\s*\(", "MEDIUM", "shelve 反序列化"),
    (r"\bjsonpickle\.decode\s*\(", "HIGH", "jsonpickle 反序列化"),
    (r"\byaml\.unsafe_load\s*\(", "CRITICAL", "yaml.unsafe_load 任意代码执行"),
    (r"\b__reduce__\s*\(", "MEDIUM", "__reduce__ 反序列化钩子"),
    (r"\bbuiltins\.__import__\s*\(", "MEDIUM", "builtins.__import__ 动态导入"),
    (r"\bimportlib\.import_module\s*\(", "LOW", "importlib 动态导入"),
    (r"\bctypes\.CDLL\s*\(", "HIGH", "ctypes 加载动态库"),
    (r"\bctypes\.windll\s*\(", "HIGH", "ctypes 加载 Windows DLL"),
    (r"\bctypes\.oledll\s*\(", "HIGH", "ctypes 加载 OLE DLL"),
    (r"\bdl\.open\s*\(", "HIGH", "dlopen 加载动态库"),
    (r"\bctypes\.pythonapi\b", "MEDIUM", "ctypes.pythonapi 直接调用 C API"),  # skillgate: ignore
]

# 2. Network calls / data exfiltration
NETWORK_PATTERNS = [
    (r"\bimport\s+requests\b", "INFO", "requests 网络库（常见）"),
    (r"\bfrom\s+requests\s+import\b", "INFO", "requests 网络库（常见）"),
    (r"\bimport\s+urllib\b", "INFO", "urllib 网络库（常见）"),
    (r"\bimport\s+http\.client\b", "INFO", "http.client 网络库"),
    (r"\bimport\s+socket\b", "LOW", "socket 原始网络连接"),
    (r"\bimport\s+ftplib\b", "LOW", "FTP 库"),
    (r"\bimport\s+smtplib\b", "LOW", "SMTP 邮件库"),
    (r"\burlopen\s*\(", "LOW", "urlopen 网络请求"),
    (r"\bpost\s*\([^)]*https?://", "MEDIUM", "POST 数据到外部 URL"),
    (r"\brequests\.get\s*\([^)]*https?://", "LOW", "GET 请求外部 URL"),
    (r"\bhttpx\b", "INFO", "httpx HTTP 客户端（常见）"),
    (r"\baiohttp\b", "INFO", "aiohttp 异步 HTTP（常见）"),
    (r"\bcurl\b", "LOW", "curl 命令行网络工具"),
    (r"\bwget\b", "LOW", "wget 命令行网络工具"),
    (r"\bnc\s+-[el]\b", "HIGH", "netcat 反向 shell 风险"),
    (r"\bncat\b", "LOW", "ncat 网络工具"),
    (r"\btelnetlib\b", "HIGH", "telnetlib 明文传输"),  # skillgate: ignore
    (r"\bparamiko\b", "LOW", "paramiko SSH 库"),
    (r"\bscp\b", "LOW", "scp 文件传输"),
]

# 3. Credential / secret access
CREDENTIAL_PATTERNS = [
    (re.compile(r"(api[_-]?key|apikey|secret|token|password|passwd|credential)\s*[:=]\s*['\"]([^'\"]{8,})['\"]", re.IGNORECASE),
     "CRITICAL", "硬编码凭证"),
    (re.compile(r"os\.environ\[['\"](.*TOKEN|.*KEY|.*SECRET|.*PASSWORD)['\"]\]", re.IGNORECASE),
     "INFO", "从环境变量读凭证（安全做法）"),
    (re.compile(r"os\.getenv\s*\(\s*['\"](.*TOKEN|.*KEY|.*SECRET|.*PASSWORD)", re.IGNORECASE),
     "INFO", "从环境变量读凭证（安全做法）"),
    (re.compile(r"~\.ssh/", re.IGNORECASE),
     "HIGH", "访问 SSH 密钥目录"),
    (re.compile(r"\.aws/credentials", re.IGNORECASE),  # skillgate: ignore
     "HIGH", "访问 AWS 凭证文件"),
    (re.compile(r"\.git-credentials", re.IGNORECASE),  # skillgate: ignore
     "HIGH", "访问 Git 凭证文件"),
    (re.compile(r"\.netrc", re.IGNORECASE),  # skillgate: ignore
     "MEDIUM", "访问 .netrc 凭证文件"),
    (re.compile(r"\.npmrc", re.IGNORECASE),  # skillgate: ignore
     "MEDIUM", "访问 .npmrc 凭证文件"),
    (re.compile(r"\.pypirc", re.IGNORECASE),  # skillgate: ignore
     "MEDIUM", "访问 .pypirc 凭证文件"),
    (re.compile(r"id_rsa", re.IGNORECASE),  # skillgate: ignore
     "HIGH", "访问 SSH 私钥"),
    (re.compile(r"id_ed25519", re.IGNORECASE),  # skillgate: ignore
     "HIGH", "访问 SSH 私钥"),  # skillgate: ignore
]

# 4. File system danger
FILESYSTEM_PATTERNS = [
    (r"\bshutil\.rmtree\s*\(", "MEDIUM", "shutil.rmtree 递归删除"),
    (r"\bos\.remove\s*\(", "INFO", "os.remove 删除文件（常见）"),
    (r"\bos\.rmdir\s*\(", "INFO", "os.rmdir 删除目录（常见）"),
    (r"\bos\.unlink\s*\(", "MEDIUM", "os.unlink 删除文件"),
    (r"\bopen\s*\([^)]*['\"]/etc/", "HIGH", "写入 /etc/ 系统目录"),
    (r"\bopen\s*\([^)]*['\"]C:\\\\Windows\\\\", "HIGH", "写入 Windows 系统目录"),
    (r"\bopen\s*\([^)]*['\"]/System/", "HIGH", "写入 macOS 系统目录"),
    (r"\bos\.rename\s*\([^)]*/etc/", "MEDIUM", "重命名 /etc/ 下文件"),
    (r"\bshutil\.move\s*\([^)]*/etc/", "MEDIUM", "移动文件到 /etc/"),
    (r"\btempfile\.mkdtemp\b", "LOW", "创建临时目录"),
    (r"\btempfile\.mktemp\b", "MEDIUM", "mktemp 临时文件竞争风险"),
]

# 5. Prompt injection / LLM-specific risks
PROMPT_INJECTION_PATTERNS = [
    (r"ignore\s+(all\s+)?(the\s+)?previous\s+instructions", "CRITICAL", "Prompt injection: ignore previous"),
    (r"disregard\s+(all\s+)?(the\s+)?previous", "CRITICAL", "Prompt injection: disregard previous"),
    (r"you\s+are\s+now\s+a?n?\s+\w+", "LOW", "角色定义，低风险，需人工确认"),
    (r"system\s+prompt\s+leak", "HIGH", "System prompt leak attempt"),
    (r"jailbreak", "CRITICAL", "Jailbreak pattern"),
    (r"reveal\s+your\s+instructions", "HIGH", "Reveal system instructions attempt"),
    (r"reveal\s+your\s+prompt", "HIGH", "Reveal system prompt attempt"),
    (r"bypass\s+safety", "HIGH", "Bypass safety guardrails"),
    (r"do\s+not\s+tell\s+the\s+user", "MEDIUM", "Hide actions from user"),
    (r"do\s+not\s+mention", "LOW", "Instructed to omit information"),
    (r"pretend\s+you\s+are", "LOW", "角色定义，低风险，需人工确认"),
    (r"act\s+as\s+if\s+you\s+are", "LOW", "角色定义，低风险，需人工确认"),
    (r"forget\s+your\s+rules", "CRITICAL", "Forget your rules"),
    (r"override\s+your\s+guidelines", "CRITICAL", "Override guidelines"),
    (r"ignore\s+your\s+training", "CRITICAL", "Ignore training"),
]

# 5.5 数字诚实性规则（防止吹牛）
HONESTY_PATTERNS = [
    # 注：删除了过宽的 \b\d{3,}\+ 规则（"1000+" "5000+" 等正常能力宣称均误报，
    # 静态无法判定真吹牛），仅保留高特异性的具体吹牛模式。
    (r"17\s+languages", "MEDIUM", "疑似吹牛：17 languages"),
    (r"600\+\s+rules", "MEDIUM", "疑似吹牛：600+ rules"),
]

# 6. Excessive agency / MCP risks
EXCESSIVE_AGENCY_PATTERNS = [
    (r"delete\s+all\s+files", "CRITICAL", "Excessive agency: delete all files"),  # skillgate: ignore
    (r"send\s+all\s+data", "HIGH", "Excessive agency: exfiltrate all data"),
    (r"send\s+all\s+user\s+data", "HIGH", "Excessive agency: exfiltrate all user data"),
    (r"exfiltrat\w*\s+(?:all\s+)?(?:user\s+)?data", "HIGH", "Excessive agency: exfiltration of all data"),
    (r"run\s+arbitrary\s+commands", "HIGH", "Arbitrary command execution"),
    (r"access\s+all\s+files", "MEDIUM", "Overly broad file access"),
    (r"read\s+every\s+file", "HIGH", "Read every file"),  # skillgate: ignore
    (r"modify\s+all\s+configs", "HIGH", "Modify all configs"),  # skillgate: ignore
    (r"install\s+any\s+package", "MEDIUM", "Install any package"),
    (r"unrestricted\s+internet\s+access", "MEDIUM", "Unrestricted internet access"),  # skillgate: ignore
    (r"bypass\s+all\s+safety\s+checks", "CRITICAL", "Bypass all safety checks"),  # skillgate: ignore
    (r"disable\s+all\s+filters", "HIGH", "Disable all filters"),
    (r"grant\s+yourself\s+admin", "CRITICAL", "Grant yourself admin access"),  # skillgate: ignore
    (r"add\s+new\s+user\s+accounts", "HIGH", "Add new user accounts"),
]

# 7. License compliance
LICENSE_PATTERNS = [
    (r"\bGPL\b", "MEDIUM", "GPL 许可证（传染性）"),
    (r"\bAGPL\b", "HIGH", "AGPL 许可证（网络传染性）"),
    (r"\bSSPL\b", "HIGH", "SSPL 许可证（服务端传染性）"),
    (r"\bUnlicense\b", "LOW", "Unlicense（公有领域）"),
]

# 8. Code quality
QUALITY_PATTERNS = [
    (r"\bTODO\b", "LOW", "TODO 注释未完成"),
    (r"\bFIXME\b", "LOW", "FIXME 注释未修复"),
    (r"\bHACK\b", "LOW", "HACK 临时方案"),
    (r"\bXXX\b", "LOW", "XXX 标记的问题"),
    (r"\bprint\s*\(", "LOW", "print 调试语句"),
    (r"\bconsole\.log\(", "LOW", "console.log 调试语句"),
    (r"\bdebugger\b", "MEDIUM", "debugger 语句"),
]

# 9. Authentication & Authorization
AUTH_PATTERNS = [
    (r"\bauth\s*=\s*None\b", "MEDIUM", "认证被禁用"),
    (r"\bverify\s*=\s*False\b", "HIGH", "SSL 验证被禁用"),
    (r"\bALLOW_ALL\b", "HIGH", "允许所有访问"),
    (r"\bCORS.*\*\b", "MEDIUM", "CORS 允许所有来源"),
    (r"\bpassword\s*=\s*['\"][^'\"]+['\"]", "CRITICAL", "硬编码密码"),
    (r"\btoken\s*=\s*['\"][a-zA-Z0-9]{20,}['\"]", "CRITICAL", "硬编码 token"),
]

# 10. Input Validation
VALIDATION_PATTERNS = [
    (r"\brequest\.args\.get\(", "LOW", "直接读取请求参数"),
    (r"\binput\s*\(", "MEDIUM", "读取用户输入"),
    (r"\bsys\.argv\b", "LOW", "读取命令行参数"),
    (r"\bos\.environ\[", "MEDIUM", "读取环境变量"),
]

# 11. Data Exfiltration Risk
EXFIL_PATTERNS = [
    (r"\brequests\.post\([^)]*https?://", "MEDIUM", "向外发 POST 请求"),
    (r"\burllib\.request\.urlopen\(", "MEDIUM", "向外发请求"),
    (r"\bsmtplib\.SMTP\(", "MEDIUM", "发送邮件"),
    (r"\bsocket\.socket\(", "MEDIUM", "原始 socket 网络连接"),
]

FRONTMATTER_REQUIRED_FIELDS = ["name", "description"]
FRONTMATTER_OPTIONAL_FIELDS = ["version", "license", "author", "tags"]

STDLIB_MODULES = {
    "argparse", "ast", "base64", "collections", "copy", "csv", "datetime",
    "functools", "hashlib", "itertools", "json", "logging", "math",
    "os", "pathlib", "pickle", "platform", "random", "re", "shutil",
    "sqlite3", "string", "sys", "tempfile", "time", "typing", "urllib",
    "xml", "zipfile", "__future__", "abc", "asyncio", "dataclasses",
    "enum", "io", "socket", "subprocess", "threading", "unittest",
    "warnings", "weakref",
}


# ── Data classes ──────────────────────────────────────────────────────────

# Category explanations (有证：每个结论有解释)
CATEGORY_EXPLANATIONS = {
    "dangerous-code": "检测到危险代码模式，可能导致代码执行或系统破坏",
    "credential-leak": "检测到硬编码凭证或敏感信息泄露",
    "prompt-injection": "检测到 prompt 注入风险，可能被绕过安全限制",
    "excessive-agency": "检测到过度权限，可能超出预期的操作范围",
    "network": "检测到网络请求，注意数据外带风险",
    "filesystem": "检测到文件系统操作，注意删除和写入风险",
    "deserialization": "检测到不安全的反序列化，可能导致 RCE",
    "dependency": "检测到有风险的依赖包",
    "license": "检测到许可证合规问题",
    "code-quality": "代码质量问题，不影响安全但影响可维护性",
    "auth": "认证授权相关问题",
    "input-validation": "输入验证相关问题",
    "exfiltration": "数据外带风险",
    "ast-analysis": "AST 语法树分析发现的问题",
    "structure": "项目结构问题",
    "file-read": "文件读取问题",
}


@dataclass
class Finding:
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW
    category: str
    message: str
    file: str
    line: Optional[int] = None
    rule_id: str = ""  # 规则唯一 ID
    explanation: str = ""  # 为什么报这个


@dataclass
class ScanResult:
    skill_name: str = ""
    skill_dir: str = ""
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    frontmatter: dict = field(default_factory=dict)
    trust_score: int = 0
    grade: str = ""
    rule_version: str = "v3.1.3"  # 规则版本号（有籍）

    @property
    def critical_count(self): return len([f for f in self.findings if f.severity == "CRITICAL"])
    @property
    def high_count(self): return len([f for f in self.findings if f.severity == "HIGH"])
    @property
    def medium_count(self): return len([f for f in self.findings if f.severity == "MEDIUM"])
    @property
    def low_count(self): return len([f for f in self.findings if f.severity == "LOW"])


# ── Scanners ──────────────────────────────────────────────────────────────

# 字符串字面量（含规则定义字符串、文档示例、占位符）——剥离避免自证陷阱误报
_STRING_RE = re.compile(r"('[^'\\]*(?:\\.[^'\\]*)*'|\"[^\"\\]*(?:\\.[^\"\\]*)*\")")

def clean_line(line: str) -> str:
    """去掉字符串字面量与行内注释，仅保留真实代码/指令部分。

    顺序：先剥字符串（注释里的引号不会干扰），再按 # 截断行内注释。
    这样规则定义字符串（如 'eval('）、示例 "your-key"、注释里的示例代码
    都不会被误判为真实调用。
    """
    stripped = _STRING_RE.sub(" ", line)
    idx = stripped.find("#")
    if idx != -1:
        stripped = stripped[:idx]
    return stripped


# 规则表元素行：整行就是一个裸 raw/普通字符串字面量（或元组首元素）
# 例：  r"((read|cat|open)...(\.ssh|\.aws...)"     属于检测词表，不是真实行为
_RULE_LITERAL_RE = re.compile(r"^(?:\(\s*)?(?:[rR])?[\"']")


def is_rule_literal_line(line: str) -> bool:
    """判断该行是否是"检测规则词表"的字符串元素。

    扫描器扫自己时，规则表里的路径/关键词会被当成本体行为（自证陷阱）。
    这里只跳过"整行就是一个裸字符串字面量"的行——真实恶意代码不会写成这样。
    """
    return bool(_RULE_LITERAL_RE.match(line.strip()))


# ── v3.1.0: 固定参数 vs 动态参数判断（确定性，纯静态，无外部依赖） ────────────

def _strip_comment(line: str) -> str:
    """去掉行内注释（# 不在字符串内），保留字符串字面量。
    用于需要看到实参原文（判断固定 vs 动态）的规则。"""
    out = []
    i = 0
    n = len(line)
    in_str = None
    while i < n:
        ch = line[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(line[i + 1])
                i += 2
                continue
            if ch == in_str:
                in_str = None
            i += 1
        else:
            if ch in ('"', "'"):
                in_str = ch
                out.append(ch)
                i += 1
            elif ch == "#":
                break
            else:
                out.append(ch)
                i += 1
    return "".join(out)


def _call_args_are_literal(line: str, open_paren_idx: int) -> bool:
    """从 open_paren_idx 处的 '(' 做括号配平取实参文本，剥掉字符串字面量后，
    若每个非空实参段要么已变成空白（纯字符串实参），要么是 name=字面量
    （True/False/None/数字），则判为"固定参数"。
    出现裸标识符、+ 拼接、% 格式化、.format(、f-string 残留等即判动态。
    跨行/括号不配平时保守判动态。"""
    depth = 1
    j = open_paren_idx + 1
    n = len(line)
    in_str = None
    segs = []
    seg_start = j
    while j < n:
        ch = line[j]
        if in_str:
            if ch == "\\":
                j += 2
                continue
            if ch == in_str:
                in_str = None
        else:
            if ch in ('"', "'"):
                in_str = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    break
            elif ch == "," and depth == 1:
                segs.append(line[seg_start:j])
                seg_start = j + 1
        j += 1
    if depth != 0:
        return False  # 跨行调用，单行无法证明固定 → 动态
    segs.append(line[seg_start:j])

    for seg in segs:
        stripped = _LITERAL_STRING_RE.sub(" ", seg).strip()
        if not stripped:
            continue
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$", stripped)
        if m and re.match(r"^(True|False|None|-?\d+(\.\d+)?)$", m.group(2).strip()):
            continue
        return False
    return True


def strip_strings_to_code(content: str) -> list[str]:
    """整文件级字符串/注释剥离：返回与原文等长的行列表，字符串字面量
    （含跨行三引号 docstring）与行内注释全部替换为空格。
    确定性状态机；用于非凭证规则的逐行扫描，避免多行 docstring 里提到
    eval/os.system 等词造成误报。"""
    out_lines = []
    pending_triple = None  # None / '"""' / "'''"
    for line in content.splitlines():
        n = len(line)
        chars = []
        i = 0
        if pending_triple is not None:
            close = line.find(pending_triple)
            if close == -1:
                out_lines.append(" " * n)
                continue
            chars.append(" " * (close + 3))
            i = close + 3
            pending_triple = None
        while i < n:
            if line[i] == "#":
                break
            if line[i:i + 3] in ('"""', "'''"):
                triple = line[i:i + 3]
                close = line.find(triple, i + 3)
                if close == -1:
                    chars.append(" " * (n - i))
                    pending_triple = triple
                    i = n
                else:
                    chars.append(" " * (close + 3 - i))
                    i = close + 3
                continue
            if line[i] in ('"', "'"):
                quote = line[i]
                k = i + 1
                while k < n:
                    if line[k] == "\\":
                        k += 2
                        continue
                    if line[k] == quote:
                        break
                    k += 1
                end = k + 1 if k < n else n
                chars.append(" " * (end - i))
                i = end
                continue
            chars.append(line[i])
            i += 1
        out_lines.append("".join(chars))
    return out_lines


# 字面量字符串（含 r/b/u 前缀；f 前缀故意不匹配——f-string 插值即动态）
_LITERAL_STRING_RE = re.compile(r"(?:[rRbBuU])?('[^'\\]*(?:\\.[^'\\]*)*'|\"[^\"\\]*(?:\\.[^\"\\]*)*\")")

# 固定参数降级表：规则 pattern -> (固定时降级级别, 固定时消息)
# 动态调用保持原级别与原消息；纯静态判断，确定性可复现
FIXED_DOWNGRADE = {
    r"\beval\s*\(": ("LOW", "eval() 固定目标，风险低（建议改用 ast.literal_eval）"),
    r"\bexec\s*\(": ("LOW", "exec() 固定目标，风险低（建议改用 ast.literal_eval）"),
    r"\b__import__\s*\(": ("LOW", "动态 import 固定目标，风险低"),
    r"\bos\.system\s*\(": ("LOW", "固定命令 shell 调用，无注入面，建议人工确认"),
    r"\bos\.popen\s*\(": ("LOW", "固定命令 shell 调用，无注入面，建议人工确认"),
    r"\bsubprocess\.(run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True":
        ("LOW", "固定命令 subprocess shell=True，无注入面，建议人工确认"),
    r"\bpost\s*\([^)]*https?://": ("LOW", "对外请求，URL 固定，需确认接口用途"),
}

# md 示例/讨论语境标记词：行内含这些词时，注入模式命中最可能是
# "讨论/演示如何检测注入"而非"实际注入指令"
DISCUSSION_MARKERS = (
    "example", "例如", "比如", "示例", "样例", "pattern", "正则",
    "命中", "检测到", "模拟", "注入", "攻击", "恶意", "威胁", "渗透",
    "演练", "防御", "识别", "拦截", "防止", "避免",
)


# 占位符/示例值标记：硬编码凭证命中时，若值命中这些标记则不算真实凭证
PLACEHOLDER_MARKERS = (
    "your-", "your_", "YOUR_", "YOUR-", "yourkey", "your_key", "your-api",
    "xxx", "XXX", "example", "placeholder", "changeme", "sample", "demo",
    "key-here", "key_here", "<", ">", "{{", "}}", "...", "…", "hunter2",
)

def is_placeholder_value(value: str) -> bool:
    """判断凭证值是否为占位符/示例（your-key / xxx / example 等），是则非真实硬编码。"""
    v = value.strip("\"' ")
    low = v.lower()
    if not v:
        return True
    for m in PLACEHOLDER_MARKERS:
        if m in low:
            return True
    return False


# 安全/防御主题上下文词：md 文档中出现这些词时，"jailbreak/ignore previous" 等
# 命中最可能是"讨论安全方案"而非"实际注入指令"（防注入技能、红队工具、研究文档必含）
SAFETY_CONTEXT_WORDS = (
    "red-team", "red team", "redteam", "scan", "detect", "test", "guard",
    "shield", "protect", "drill", "benchmark", "resistance", "evaluation",
    "security", "safety", "harness", "红队", "越狱", "扫描", "检测", "防护",
    "对抗", "加固", "测评", "审计", "基准", "防御", "安全", "风险",
    # 威胁模型/防御说明类词：讲"外部文本可能含注入指令"也属于讨论而非指令本身
    "untrusted", "external", "secrets", "leakage", "can say", "can't tell",
)


def scan_python_file(filepath: Path, result: ScanResult):
    """Scan a single Python file for dangerous patterns."""
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        result.findings.append(Finding(
            severity="LOW", category="file-read",
            message=f"无法读取文件: {e}", file=str(filepath)
        ))
        return

    lines = content.splitlines()

    # === 第一步：AST 分析（更准，误报低） ===
    ast_lines = set()  # 记录 AST 已经报过的行，正则就不要重复报了
    try:
        from ast_analyzer import analyze_python_file
        ast_findings = analyze_python_file(filepath)
        for af in ast_findings:
            # 行级抑制约定：与 Bandit # nosec / SonarQube NOSONAR 一致，
            # 标注必须与命中行同行
            if af.line and af.line - 1 < len(lines):
                cur = lines[af.line - 1]
                if "skillgate: ignore" in cur or "lgd: ignore" in cur:
                    continue
            result.findings.append(Finding(
                severity=af.severity,
                category="ast-analysis",
                message=f"[AST] {af.message}",
                file=str(filepath),
                line=af.line
            ))
            ast_lines.add(af.line)  # 记录这一行已经报过了
    except Exception:
        pass  # AST 分析失败不影响正则扫描

    # v3.1.0: 整文件级字符串/注释剥离结果（跨行三引号 docstring 也算字符串）
    code_lines = strip_strings_to_code(content)

    # Helper: check if line is a comment
    def is_comment_line(line: str) -> bool:
        stripped = line.strip()
        return stripped.startswith("#") or stripped.startswith('"""') or stripped.startswith("'''")

    # Helper: check if match is inside a string (simple heuristic)
    def is_inside_string(line: str, match_start: int) -> bool:
        """Simple heuristic: check if the match position is inside a string literal."""
        # Count quotes before the match
        before = line[:match_start]
        # Count unescaped quotes
        single_quotes = before.count("'") - before.count("\\'")
        double_quotes = before.count('"') - before.count('\\"')
        # If odd number of either, we're inside a string
        return (single_quotes % 2 == 1) or (double_quotes % 2 == 1)

    # Helper: check if line has skillgate: ignore suppression
    def is_suppressed(line_idx: int) -> bool:
        """Check if the current line or previous line has # skillgate: ignore"""
        # Check current line
        if 0 < line_idx <= len(lines):
            if "skillgate: ignore" in lines[line_idx - 1]:
                return True
        # Check previous line
        if line_idx > 1:
            if "skillgate: ignore" in lines[line_idx - 2]:
                return True
        return False

    # 1. Dangerous code patterns（code_lines 为整文件级字符串/注释剥离结果；
    #    固定参数类规则逐匹配判断 固定 vs 动态，动态保持原级别）
    for pattern, severity, msg in DANGEROUS_CODE_PATTERNS:
        downgrade = FIXED_DOWNGRADE.get(pattern)
        for i, line in enumerate(lines, 1):
            if is_comment_line(line):
                continue
            if is_suppressed(i):
                continue
            if i in ast_lines:  # AST 已经报过了，不要重复报
                continue
            if downgrade is not None:
                base_line = _strip_comment(line)
                code_line = code_lines[i - 1]
                for m in re.finditer(pattern, base_line):
                    # 命中点若落在字符串/docstring 剥离后的空格列上，说明是
                    # 文案/文档里提到该词，非真实调用，跳过
                    if m.start() >= len(code_line) or code_line[m.start()] == " ":
                        continue
                    open_pos = base_line.find("(", m.start())
                    if open_pos != -1 and _call_args_are_literal(base_line, open_pos):
                        sev, msg_out = downgrade
                    else:
                        sev, msg_out = severity, msg
                    result.findings.append(Finding(
                        severity=sev, category="dangerous-code",
                        message=msg_out, file=str(filepath), line=i
                    ))
            elif re.search(pattern, code_lines[i - 1]):
                result.findings.append(Finding(
                    severity=severity, category="dangerous-code",
                    message=msg, file=str(filepath), line=i
                ))

    # 2. Network patterns
    for pattern, severity, msg in NETWORK_PATTERNS:
        downgrade = FIXED_DOWNGRADE.get(pattern)
        for i, line in enumerate(lines, 1):
            if is_comment_line(line):
                continue
            if is_suppressed(i):
                continue
            if downgrade is not None:
                base_line = _strip_comment(line)
                code_line = code_lines[i - 1]
                for m in re.finditer(pattern, base_line):
                    if m.start() >= len(code_line) or code_line[m.start()] == " ":
                        continue  # 命中在字符串/docstring 内，非真实调用
                    open_pos = base_line.find("(", m.start())
                    if open_pos != -1 and _call_args_are_literal(base_line, open_pos):
                        sev, msg_out = downgrade
                    else:
                        sev, msg_out = severity, msg
                    result.findings.append(Finding(
                        severity=sev, category="network",
                        message=msg_out, file=str(filepath), line=i
                    ))
            elif re.search(pattern, code_lines[i - 1]):
                result.findings.append(Finding(
                    severity=severity, category="network",
                    message=msg, file=str(filepath), line=i
                ))

    # 3. Credential / secret patterns（凭证必须在字符串内，不能 clean_line；
    #    用占位符过滤掉 your-xxx / example / {{}} 等示例与模板值）
    for pattern, severity, msg in CREDENTIAL_PATTERNS:
        for i, line in enumerate(lines, 1):
            if is_comment_line(line):
                continue
            if is_suppressed(i):
                continue
            m = pattern.search(line)
            if m:
                # 该行剥离字符串/注释后已无实质代码 —— 说明整行内容都在字符串里
                # （多行 raw 模板、规则词表、文档示例），扫描器扫自己时最常踩的就是这里
                if i - 1 < len(code_lines) and not code_lines[i - 1].strip(" \t,()[]{}:;'\"\\"):
                    continue
                # 规则定义字符串自命中（如 re.compile(r"\.aws/credentials") 所在行）
                # ——扫描器扫描自己的规则表时，规则定义字符串会被误判为真实凭证
                if is_inside_string(line, m.start()) and (
                        re.search(r're\.compile\(r?["\']', line)
                        or is_rule_literal_line(line)):
                    continue
                # 善意 INFO 规则：命中点若在字符串字面量内（建议文案/文档示例），跳过
                if severity == "INFO" and is_inside_string(line, m.start()):
                    continue
                if len(m.groups()) >= 2 and is_placeholder_value(m.group(2)):
                    continue  # 值形如 your-key / {{TOKEN}} / example → 示例或模板，非真实凭证
                result.findings.append(Finding(
                    severity=severity, category="credential-leak",
                    message=msg, file=str(filepath), line=i
                ))

    # 4. Filesystem danger patterns
    for pattern, severity, msg in FILESYSTEM_PATTERNS:
        for i, line in enumerate(lines, 1):
            if is_comment_line(line):
                continue
            if is_suppressed(i):
                continue
            if re.search(pattern, code_lines[i - 1]):
                result.findings.append(Finding(
                    severity=severity, category="filesystem",
                    message=msg, file=str(filepath), line=i
                ))

    # 5. Excessive agency patterns
    for pattern, severity, msg in EXCESSIVE_AGENCY_PATTERNS:
        for i, line in enumerate(lines, 1):
            if is_comment_line(line):
                continue
            if is_suppressed(i):
                continue
            if re.search(pattern, code_lines[i - 1], re.IGNORECASE):
                result.findings.append(Finding(
                    severity=severity, category="excessive-agency",
                    message=msg, file=str(filepath), line=i
                ))

    # 6. AST analysis 已在函数开头（步骤 1，含行级去重）执行；
    #    v3.1.3 修复：此处原重复调用 AST 造成同一命中双计（[AST]+无前缀各一条），已移除。


def scan_md_file(filepath: Path, result: ScanResult):
    """Scan a Markdown file for prompt injection patterns AND credential leaks."""
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return

    lines = content.splitlines()

    # 代码块行（``` ... ```）跳过：示例载荷非指令本身
    in_code_block = False
    code_lines = set()
    for i, line in enumerate(lines, 1):
        if line.strip().startswith("```"):
            in_code_block = not in_code_block
            code_lines.add(i)
            continue
        if in_code_block:
            code_lines.add(i)

    # frontmatter 区域行号（Muse 复测 P0：frontmatter 的 description 是智能体
    # 运行时实际读取的指令文本，属第一攻击面——注入/外泄扫描不得整段跳过，
    # 仅凭证扫描跳过该区域以防元数据字段名误报）
    fm_lines = set()
    if content.startswith("---"):
        for i, line in enumerate(lines, 1):
            if i == 1:
                fm_lines.add(i)
                continue
            if line.strip() == "---":
                fm_lines.add(i)
                break
            fm_lines.add(i)

    def is_safety_discussion(line: str) -> bool:
        """该行是否在讨论安全/防御主题（红队、扫描、防护等），
        此时 jailbreak / ignore previous 等词是主题词而非注入指令。"""
        low = line.lower()
        return any(w in low for w in SAFETY_CONTEXT_WORDS)

    def _match_in_quoted(line: str, m_start: int) -> bool:
        """命中位置是否在反引号/引号之内（示例载荷），非指令本身。"""
        before = line[:m_start]
        if before.count("`") % 2 == 1:
            return True
        if before.count('"') % 2 == 1 or before.count("'") % 2 == 1:
            return True
        return False

    # 1. Prompt injection patterns（讨论语境跳过：安全主题/示例载荷/讨论标记词）
    for pattern, severity, msg in PROMPT_INJECTION_PATTERNS:
        for i, line in enumerate(lines, 1):
            if i in code_lines:
                continue
            m = re.search(pattern, line, re.IGNORECASE)
            if not m:
                continue
            if is_safety_discussion(line):
                continue  # 安全/红队/扫描主题文档提及该词 = 主题词，非注入指令
            # CRITICAL/HIGH 注入模式只允许安全主题框架跳过；
            # 标记词/引号内示例跳过仅作用于 MEDIUM/LOW，避免恶意中文载荷漏报
            if severity in ("MEDIUM", "LOW"):
                if _match_in_quoted(line, m.start()):
                    continue  # 命中文本在反引号/引号内（示例载荷），非指令
                if any(w in line.lower() for w in DISCUSSION_MARKERS):
                    continue  # 示例/讨论语境（"例如 ignore previous" 等描述）
            result.findings.append(Finding(
                severity=severity, category="prompt-injection",
                message=msg, file=str(filepath), line=i
            ))

    # 2. Credential / secret patterns（.md 也检查，但过滤占位符与示例值；
    #    跳过 frontmatter 区域避免元数据字段名误报）
    for pattern, severity, msg in CREDENTIAL_PATTERNS:
        for i, line in enumerate(lines, 1):
            if i in code_lines or i in fm_lines:
                continue
            m = pattern.search(line)
            if m:
                if len(m.groups()) >= 2 and is_placeholder_value(m.group(2)):
                    continue  # your-key / {{TOKEN}} / example 等示例与模板值
                result.findings.append(Finding(
                    severity=severity, category="credential-leak",
                    message=msg + " (in .md file)", file=str(filepath), line=i
                ))

    # 3. 数字诚实性规则（仅剩高特异性模式，普通宣称数字不再报）
    for pattern, severity, msg in HONESTY_PATTERNS:
        for i, line in enumerate(lines, 1):
            if i in code_lines:
                continue
            if re.search(pattern, line, re.IGNORECASE):
                result.findings.append(Finding(
                    severity=severity, category="honesty",
                    message=msg, file=str(filepath), line=i
                ))

    # 4. Excessive agency / exfiltration patterns（P0 修复：SKILL.md 等 md
    #    文档同样检查外泄指令；讨论语境/引号示例跳过逻辑与注入一致）
    for pattern, severity, msg in EXCESSIVE_AGENCY_PATTERNS:
        for i, line in enumerate(lines, 1):
            if i in code_lines:
                continue
            m = re.search(pattern, line, re.IGNORECASE)
            if not m:
                continue
            if is_safety_discussion(line):
                continue  # 安全/红队/扫描主题文档提及该词 = 主题词，非外泄指令
            if severity in ("MEDIUM", "LOW"):
                if _match_in_quoted(line, m.start()):
                    continue  # 命中文本在反引号/引号内（示例载荷），非指令
                if any(w in line.lower() for w in DISCUSSION_MARKERS):
                    continue  # 示例/讨论语境（"例如 delete all files" 等描述）
            result.findings.append(Finding(
                severity=severity, category="exfiltration",
                message=msg, file=str(filepath), line=i
            ))


def scan_dependencies(skill_path: Path, result: ScanResult):
    """Scan dependencies for known vulnerabilities via OSV.dev."""
    # Find requirements.txt
    req_file = skill_path / "requirements.txt"
    if not req_file.exists():
        return

    try:
        content = req_file.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return

    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Parse package name and version
        if "==" in line:
            name, version = line.split("==", 1)
            deps.append((name.strip(), version.strip()))
        elif ">=" in line:
            name = line.split(">=", 1)[0].strip()
            deps.append((name, "latest"))

    if not deps:
        return

    # Query OSV.dev for each dependency
    for name, version in deps[:10]:  # limit to 10 deps to avoid timeout
        try:
            payload = json.dumps({
                "package": {"name": name, "ecosystem": "PyPI"},
                "version": version
            }).encode()

            req = urllib.request.Request(
                "https://api.osv.dev/v1/query",
                data=payload,
                headers={"Content-Type": "application/json"}
            )

            with urllib.request.urlopen(req, timeout=5) as resp:  # nosec B310 - URL is fixed OSV API, not user input; skillgate: ignore
                data = json.loads(resp.read())
                vulns = data.get("vulns", [])
                if vulns:
                    for v in vulns[:3]:  # top 3 vulns per dep
                        result.findings.append(Finding(
                            severity="HIGH", category="dependency-vuln",
                            message=f"{name}=={version}: {v.get('summary', 'known vulnerability')}",
                            file=str(req_file)
                        ))
        except Exception:
            # Offline fallback: just note that we couldn't check
            result.findings.append(Finding(
                severity="LOW", category="dependency-scan",
                message=f"无法联网检查 {name} 的已知漏洞",
                file=str(req_file)
            ))


def scan_shell_file(filepath: Path, result: ScanResult):
    """Scan a shell script for dangerous patterns."""
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return

    lines = content.splitlines()
    dangerous_sh_patterns = [
        (r"\brm\s+-rf?\s+/\s*(;|&&|\||$)", "CRITICAL", "rm -rf / 危险删除（仅根目录）"),
        (r"\bcurl\s+.*\|\s*sh", "MEDIUM", "curl | sh 管道执行远程脚本（常见安装方式，需确认来源可信）"),
        (r"\bwget\s+.*\|\s*bash", "MEDIUM", "wget | bash 管道执行远程脚本（常见安装方式，需确认来源可信）"),
        (r"\bchmod\s+777", "MEDIUM", "chmod 777 权限过松"),
        (r"\bsudo\s+", "MEDIUM", "sudo 权限提升"),
    ]

    for pattern, severity, msg in dangerous_sh_patterns:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, clean_line(line)):
                result.findings.append(Finding(
                    severity=severity, category="dangerous-shell",
                    message=msg, file=str(filepath), line=i
                ))


def parse_frontmatter(filepath: Path, result: ScanResult):
    """Parse YAML frontmatter from SKILL.md."""
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return

    if not content.startswith("---"):
        result.findings.append(Finding(
            severity="MEDIUM", category="frontmatter",
            message="SKILL.md 缺少 YAML frontmatter", file=str(filepath)
        ))
        return

    end = content.find("---", 3)
    if end == -1:
        result.findings.append(Finding(
            severity="MEDIUM", category="frontmatter",
            message="SKILL.md frontmatter 未闭合", file=str(filepath)
        ))
        return

    fm_text = content[3:end].strip()
    # Simple YAML parsing (enough for frontmatter)
    current_key = None
    for line in fm_text.splitlines():
        if line.startswith("- "):
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            result.frontmatter[key] = value

    # Check required fields
    for field_name in FRONTMATTER_REQUIRED_FIELDS:
        if field_name not in result.frontmatter:
            result.findings.append(Finding(
                severity="LOW", category="frontmatter",
                message=f"缺少必填字段: {field_name}", file=str(filepath)
            ))

    result.skill_name = result.frontmatter.get("name", filepath.parent.name)
    
    # 数字诚实性检查（新增！）
    lines = content.splitlines()
    for pattern, severity, msg in HONESTY_PATTERNS:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                result.findings.append(Finding(
                    severity=severity, category="honesty",
                    message=msg, file=str(filepath), line=i
                ))


def compute_trust_score(result: ScanResult) -> int:
    """Weighted Trust Score calculation.

    Weights:
    - CRITICAL: -15 each
    - HIGH: -8 each
    - MEDIUM: -4 each
    - LOW: -1 each
    - Missing frontmatter required fields: -10
    """
    score = 100

    # Weighted deductions by severity
    score -= result.critical_count * 15
    score -= result.high_count * 8
    score -= result.medium_count * 4
    score -= result.low_count * 1

    # Frontmatter completeness penalty
    fm = result.frontmatter
    if not fm:
        score -= 20
    else:
        required_present = sum(1 for f in FRONTMATTER_REQUIRED_FIELDS if fm.get(f))
        if required_present < len(FRONTMATTER_REQUIRED_FIELDS):
            score -= 10

    # Zero dependencies bonus（此前被提前 return 短路，永不执行——已修复）
    has_network = any(f.category == "network" for f in result.findings)
    if not has_network:
        score += 2

    # CRITICAL 注入/外泄封顶（Muse 复测 P0 窄修：注入命中必须硬降级，不只报发现）
    injection_critical = any(
        f.severity == "CRITICAL" and f.category in ("prompt-injection", "exfiltration")
        for f in result.findings
    )
    if injection_critical:
        score = min(score, 40)  # 存在 CRITICAL 注入/外泄 → 最高 D 档；_ci_exit 同时 exit 1 阻断

    # Clamp to 0-100
    return max(0, min(100, score))


def grade_from_score(score: int) -> str:
    if score >= 90: return "A+"
    if score >= 80: return "A"
    if score >= 70: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"


def generate_badge(result: ScanResult) -> str:
    """Generate a shields.io-style SVG badge for Trust Score."""
    score = result.trust_score
    grade = result.grade

    # Color based on score
    if score >= 90:
        color = "brightgreen"
    elif score >= 75:
        color = "green"
    elif score >= 60:
        color = "yellow"
    elif score >= 40:
        color = "orange"
    else:
        color = "red"

    label = "trust score"
    value = f"{score}/100 {grade}"

    # Simple SVG badge (shields.io style)
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="120" height="20">
  <linearGradient id="smooth" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="round">
    <rect width="120" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#round)">
    <rect width="60" height="20" fill="#555"/>
    <rect width="60" height="20" x="60" fill="{color}"/>
    <rect width="120" height="20" fill="url(#smooth)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="30" y="14" fill="#010101" fill-opacity=".3">{label}</text>
    <text x="30" y="13">{label}</text>
    <text x="90" y="14" fill="#010101" fill-opacity=".3">{value}</text>
    <text x="90" y="13">{value}</text>
  </g>
</svg>'''
    return svg


# ── Main ───────────────────────────────────────────────────────────────────

def find_skill_documents(skill_path: Path) -> list[Path]:
    """Find skill definition files in any supported format.

    Supports:
    - SKILL.md (Claude Code / standard)
    - AGENTS.md (Codex / OpenCode)
    - .cursorrules / .cursor/rules/*.md (Cursor)
    - *.md in root (generic fallback)
    """
    docs = []

    # Standard SKILL.md
    if (skill_path / "SKILL.md").exists():
        docs.append(skill_path / "SKILL.md")

    # AGENTS.md (Codex/OpenCode)
    if (skill_path / "AGENTS.md").exists():
        docs.append(skill_path / "AGENTS.md")

    # .cursorrules (Cursor)
    if (skill_path / ".cursorrules").exists():
        docs.append(skill_path / ".cursorrules")

    # .cursor/rules/*.md (Cursor modern format)
    cursor_rules = skill_path / ".cursor" / "rules"
    if cursor_rules.is_dir():
        docs.extend(cursor_rules.glob("*.md"))

    # .claude/skills/*.md (Claude Code plugin format)
    claude_skills = skill_path / ".claude" / "skills"
    if claude_skills.is_dir():
        docs.extend(claude_skills.glob("*/SKILL.md"))

    # .agents/skills/*.md (OpenCode format)
    agents_skills = skill_path / ".agents" / "skills"
    if agents_skills.is_dir():
        docs.extend(agents_skills.glob("*/SKILL.md"))

    # Fallback: any top-level .md file (but not README)
    if not docs:
        for md in skill_path.glob("*.md"):
            if md.name.lower() != "readme.md":
                docs.append(md)

    return docs


def scan_skill(skill_dir: str) -> ScanResult:
    skill_path = Path(skill_dir).resolve()
    if not skill_path.is_dir():
        print(f"错误: 目录不存在 - {skill_dir}", file=sys.stderr)
        sys.exit(2)

    # 安全检查：不允许扫描系统敏感目录（防路径遍历攻击）
    SENSITIVE_DIRS = ["/etc", "/proc", "/sys", "C:\\Windows", "C:\\Program Files"]
    for sensitive in SENSITIVE_DIRS:
        if str(skill_path).lower().startswith(sensitive.lower()):
            print(f"安全限制: 不允许扫描系统敏感目录 ({sensitive})", file=sys.stderr)
            sys.exit(3)

    result = ScanResult(skill_dir=str(skill_path))

    # Default excluded directories
    DEFAULT_EXCLUDES = {"tests", "test", "docs", "doc", ".git", "__pycache__", "node_modules", "._test_scratch", "_backup"}

    def should_exclude(filepath: Path) -> bool:
        """Check if a file should be excluded from scanning."""
        parts = filepath.relative_to(skill_path).parts
        for part in parts:
            if part in DEFAULT_EXCLUDES:
                return True
        return False

    # Find skill definition files in any supported format
    skill_docs = find_skill_documents(skill_path)

    if not skill_docs:
        result.findings.append(Finding(
            severity="MEDIUM", category="structure",
            message="未找到 skill 定义文件（SKILL.md / AGENTS.md / .cursorrules）",
            file=str(skill_path)
        ))
    else:
        for doc in skill_docs:
            # Try to parse frontmatter (only if it starts with ---)
            try:
                content = doc.read_text(encoding="utf-8-sig", errors="replace")
                if content.startswith("---"):
                    parse_frontmatter(doc, result)
            except Exception:
                pass
            scan_md_file(doc, result)
            result.files_scanned += 1

    # Scan all Python files
    for py_file in skill_path.rglob("*.py"):
        if should_exclude(py_file):
            continue
        scan_python_file(py_file, result)
        result.files_scanned += 1

    # Scan all shell scripts
    for sh_file in skill_path.rglob("*.sh"):
        if should_exclude(sh_file):
            continue
        scan_shell_file(sh_file, result)
        result.files_scanned += 1

    # Scan all JS/TS files
    if scan_js_file:
        for js_file in list(skill_path.rglob("*.js")) + list(skill_path.rglob("*.ts")):
            if should_exclude(js_file):
                continue
            try:
                js_findings = scan_js_file(js_file)
                for sev, cat, msg, line in js_findings:
                    result.findings.append(Finding(
                        severity=sev, category=cat,
                        message=msg, file=str(js_file), line=line
                    ))
            except Exception:
                pass
            result.files_scanned += 1

    # Scan all Markdown files (excluding already-scanned skill docs)
    for md_file in skill_path.rglob("*.md"):
        if md_file in skill_docs:
            continue
        if should_exclude(md_file):
            continue
        scan_md_file(md_file, result)
        result.files_scanned += 1

    # Scan dependencies for known vulnerabilities
    scan_dependencies(skill_path, result)

    # Compute score
    result.trust_score = compute_trust_score(result)
    result.grade = grade_from_score(result.trust_score)

    return result


def _ci_exit(result: ScanResult, fail_under: int = None) -> int:
    """机器可读格式（json/sarif/junit/markdown）统一门禁退出码。

    P1-1 修复：此前 --fail-under 只在 terminal 分支计算退出码，CI 消费
    json/sarif/junit/markdown 时 exit 恒 0，门禁静默失效。
    现在：任一 CRITICAL/HIGH，或 trust_score < fail_under → exit 1；否则 0。
    """
    if result.critical_count > 0 or result.high_count > 0:
        return 1
    if fail_under is not None and result.trust_score < fail_under:
        return 1
    return 0


def print_terminal_report(result: ScanResult, fail_under: int = None):
    print(f"\n{'='*60}")
    print(f"  SkillGate 扫描报告")
    print(f"{'='*60}")
    print(f"  Skill: {result.skill_name}")
    print(f"  目录: {result.skill_dir}")
    print(f"  扫描文件数: {result.files_scanned}")
    print(f"{'='*60}")
    print(f"  Trust Score: {result.trust_score}/100  ({result.grade})")
    print(f"{'='*60}")

    if not result.findings:
        print("  ✅ 全部检查通过，无发现")
    else:
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(result.findings, key=lambda f: severity_order.get(f.severity, 99))
        for f in sorted_findings:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(f.severity, "⚪")
            loc = f"{f.file}:{f.line}" if f.line else f.file
            print(f"  {icon} [{f.severity}] {f.category}: {f.message}")
            print(f"      {loc}")

    print(f"{'='*60}")

    # Determine exit code
    exit_code = 0
    if result.critical_count > 0 or result.high_count > 0:
        print(f"  ❌ 阻断发布: {result.critical_count} CRITICAL, {result.high_count} HIGH")
        exit_code = 1
    elif fail_under is not None and result.trust_score < fail_under:
        print(f"  ❌ 阻断发布: Trust Score {result.trust_score} < 阈值 {fail_under}")
        exit_code = 1
    else:
        print(f"  ✅ 通过: {result.medium_count} MEDIUM, {result.low_count} LOW")

    return exit_code


def generate_sarif(result: ScanResult) -> str:
    """Generate SARIF 2.1.0 output for GitHub Code Scanning."""
    # Map our severities to SARIF levels
    severity_map = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }

    rules = {}
    sarif_results = []

    for f in result.findings:
        rule_id = f"skillgate/{f.category}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.category,
                "shortDescription": {"text": f.message},
                "fullDescription": {"text": f.message},
                "defaultConfiguration": {"level": severity_map.get(f.severity, "warning")},
            }

        sarif_results.append({
            "ruleId": rule_id,
            "level": severity_map.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": f.line or 1}
                }
            }]
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SkillGate",
                    "version": "0.2.0",
                    "informationUri": "https://github.com/your-org/skillgate",
                    "rules": list(rules.values())
                }
            },
            "results": sarif_results
        }]
    }

    return json.dumps(sarif, indent=2, ensure_ascii=False)


def generate_junit_xml(result: ScanResult) -> str:
    """Generate JUnit XML output for CI test reporting."""
    import xml.etree.ElementTree as ET
    from xml.dom import minidom

    testsuites = ET.Element("testsuites")
    testsuite = ET.SubElement(testsuites, "testsuite", {
        "name": "SkillGate",
        "tests": str(len(result.findings) + 1),  # +1 for overall score
        "failures": str(result.critical_count + result.high_count),
        "errors": "0",
        "time": "0.1"
    })

    # Overall score test
    overall_test = ET.SubElement(testsuite, "testcase", {
        "name": f"Trust Score: {result.trust_score}/100",
        "classname": "skillgate.overall"
    })
    if result.trust_score < 80:
        failure = ET.SubElement(overall_test, "failure", {
            "message": f"Score {result.trust_score} below threshold 80"
        })

    # Individual findings as test cases
    for i, f in enumerate(result.findings):
        testcase = ET.SubElement(testsuite, "testcase", {
            "name": f"{f.category}: {f.message[:50]}",
            "classname": f"skillgate.{f.category}"
        })
        if f.severity in ("CRITICAL", "HIGH"):
            failure = ET.SubElement(testcase, "failure", {
                "message": f"[{f.severity}] {f.message}"
            })

    # Pretty print
    rough = ET.tostring(testsuites, encoding="unicode")
    pretty = minidom.parseString(rough).toprettyxml(indent="  ")  # nosec B318 - XML is self-generated, not untrusted input
    return pretty


def generate_agent_summary(result: ScanResult) -> str:
    """Generate a short, agent-friendly summary that can be relayed to the user."""
    score = result.trust_score
    grade = result.grade
    name = result.skill_name

    if score >= 90:
        verdict = "SAFE: ok to use."
        detail = f"Trust Score {score}/100 ({grade}), no critical issues."
    elif score >= 75:
        verdict = "MOSTLY SAFE: usable, minor issues."
        detail = f"Trust Score {score}/100 ({grade}), {result.medium_count} medium findings."
    elif score >= 60:
        verdict = "CAUTION: review findings before use."
        detail = f"Trust Score {score}/100 ({grade}), {result.high_count} high findings."
    else:
        verdict = "UNSAFE: do not install."
        detail = f"Trust Score {score}/100 ({grade}), {result.critical_count} critical findings."

    lines = [
        f"SKILLGATE_RESULT",
        f"SKILL: {name}",
        f"SCORE: {score}/100",
        f"GRADE: {grade}",
        f"VERDICT: {verdict}",
        f"DETAIL: {detail}",
    ]

    if result.findings:
        lines.append(f"TOP_FINDINGS:")
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(result.findings, key=lambda f: severity_order.get(f.severity, 99))[:5]
        for f in sorted_findings:
            lines.append(f"  - [{f.severity}] {f.category}: {f.message}")

    # Add fix suggestions
    fix_suggestions = generate_fix_suggestions(result)
    if fix_suggestions:
        lines.append(f"\n修复建议：")
        for s in fix_suggestions:
            lines.append(f"  → {s}")

    return "\n".join(lines)


def generate_fix_suggestions(result: ScanResult) -> list[str]:
    """Generate actionable fix suggestions based on findings."""
    suggestions = []
    categories = {f.category for f in result.findings}

    if "dangerous-code" in categories:
        suggestions.append("替换 eval/exec 为安全的替代方案（ast.literal_eval / 直接类型转换）")
        suggestions.append("避免 shell=True，用列表参数传 subprocess")

    if "network" in categories:
        suggestions.append("如果 skill 不需要联网，移除 requests/urllib 等网络依赖")
        suggestions.append("如果必须联网，在 SKILL.md 里声明需要网络权限")

    if "credential-leak" in categories:
        suggestions.append("硬编码凭证改用环境变量：os.getenv('API_KEY')")
        suggestions.append("不要把 .env 文件提交到 git")

    if "prompt-injection" in categories:
        suggestions.append("移除任何试图绕过 system prompt 的指令")
        suggestions.append("不要在 skill 里写 'ignore previous instructions' 这类内容")

    if "filesystem" in categories:
        suggestions.append("避免递归删除操作，或者加白名单检查路径")
        suggestions.append("不要写入系统目录（/etc/, C:\\Windows\\）")

    if "frontmatter" in categories:
        suggestions.append("在 SKILL.md 头部补全 frontmatter：name, description, version, license, author")

    return suggestions


def main():
    ap = argparse.ArgumentParser(description="SkillGate — Skill 安全与质量扫描门禁")
    sub = ap.add_subparsers(dest="command")

    scan_parser = sub.add_parser("scan", help="扫描一个 skill 目录")
    scan_parser.add_argument("skill_dir", help="skill 目录路径")
    scan_parser.add_argument("--format", choices=["terminal", "json", "markdown", "agent", "sarif", "junit"], default="terminal")
    scan_parser.add_argument("--output", help="输出文件路径（默认 stdout）")
    scan_parser.add_argument("--fail-under", type=int, default=None,
                             help="CI 模式：Trust Score 低于此值则 exit 1")
    scan_parser.add_argument("--badge", help="生成 SVG badge 到指定路径")
    scan_parser.add_argument("--batch", action="store_true",
                             help="批量扫描：扫描目录下所有子目录")
    scan_parser.add_argument("--lenient", action="store_true",
                             help="宽松模式：所有规则降一级别（减少误报）")

    # Quickstart subcommand
    quickstart_parser = sub.add_parser("quickstart", help="快速演示 SkillGate 怎么用")

    args = ap.parse_args()

    if args.command == "quickstart":
        print("=" * 60)
        print("  🛡️  SkillGate Quickstart")
        print("=" * 60)
        print()
        print("1. Scan a skill:")
        print("   python skillgate.py scan ./my-skill/")
        print()
        print("2. Get AI-friendly output:")
        print("   python skillgate.py scan ./my-skill/ --format agent")
        print()
        print("3. CI integration:")
        print("   python skillgate.py scan ./my-skill/ --fail-under 80")
        print()
        print("4. Generate badge for your README:")
        print("   python skillgate.py scan ./my-skill/ --badge badge.svg")
        print()
        print("5. Save report to file:")
        print("   python skillgate.py scan ./my-skill/ --format json --output report.json")
        print()
        print("📚 Full docs: https://github.com/your-org/skillgate")
        print("=" * 60)
        sys.exit(0)

    if args.command == "scan":
        # Batch mode: scan all subdirectories
        if args.batch:
            base_path = Path(args.skill_dir).resolve()
            if not base_path.is_dir():
                print(f"错误: 目录不存在 - {args.skill_dir}", file=sys.stderr)
                sys.exit(2)

            all_results = []
            skill_dirs = [d for d in base_path.iterdir() if d.is_dir()]
            print(f"批量扫描: 发现 {len(skill_dirs)} 个子目录")

            for d in skill_dirs:
                try:
                    r = scan_skill(str(d))
                    all_results.append(r)
                    status = "✅" if r.critical_count == 0 and r.high_count == 0 else "❌"
                    print(f"  {status} {r.skill_name}: {r.trust_score}/100 ({r.grade})")
                except Exception as e:
                    print(f"  ⚠️  {d.name}: 扫描失败 - {e}")

            # Summary
            print(f"\n{'='*60}")
            print(f"  批量扫描汇总")
            print(f"{'='*60}")
            print(f"  总计: {len(all_results)} 个 skill")
            avg_score = sum(r.trust_score for r in all_results) / len(all_results) if all_results else 0
            print(f"  平均 Trust Score: {avg_score:.1f}/100")
            passed = len([r for r in all_results if r.critical_count == 0 and r.high_count == 0])
            print(f"  通过: {passed}/{len(all_results)}")

            # Exit code
            if passed < len(all_results):
                sys.exit(1)
            else:
                sys.exit(0)

        result = scan_skill(args.skill_dir)

        # Lenient mode: downgrade all findings by one level
        if args.lenient:
            severity_downgrade = {
                "CRITICAL": "HIGH",
                "HIGH": "MEDIUM",
                "MEDIUM": "LOW",
                "LOW": "INFO",
                "INFO": "INFO",
            }
            for f in result.findings:
                f.severity = severity_downgrade.get(f.severity, f.severity)
            print("  (宽松模式：所有规则降一级别)")

        # 自动记录到审计日志（有籍）
        try:
            from audit_log import record_scan
            record_scan(result, args.skill_dir)
        except Exception:
            pass  # 审计日志失败不影响主流程

        # Generate badge if requested
        if args.badge:
            badge_svg = generate_badge(result)
            Path(args.badge).write_text(badge_svg, encoding="utf-8")
            print(f"Badge 已生成: {args.badge}")

        if args.format == "agent":
            output = generate_agent_summary(result)
            if args.output:
                Path(args.output).write_text(output, encoding="utf-8")
                print(f"Agent summary written to: {args.output}")
            else:
                print(output)
            # Exit code for CI usage
            if result.critical_count > 0 or result.high_count > 0:
                sys.exit(1)
        elif args.format == "sarif":
            output = generate_sarif(result)
            if args.output:
                Path(args.output).write_text(output, encoding="utf-8")
                print(f"SARIF 报告已写入: {args.output}")
            else:
                print(output)
            sys.exit(_ci_exit(result, fail_under=args.fail_under))
        elif args.format == "junit":
            output = generate_junit_xml(result)
            if args.output:
                Path(args.output).write_text(output, encoding="utf-8")
                print(f"JUnit XML 报告已写入: {args.output}")
            else:
                print(output)
            sys.exit(_ci_exit(result, fail_under=args.fail_under))
        elif args.format == "json":
            output = json.dumps(asdict(result), indent=2, ensure_ascii=False)
            if args.output:
                Path(args.output).write_text(output, encoding="utf-8")
                print(f"JSON 报告已写入: {args.output}")
            else:
                print(output)
            sys.exit(_ci_exit(result, fail_under=args.fail_under))
        elif args.format == "markdown":
            lines = [
                f"# SkillGate 扫描报告",
                f"",
                f"- **Skill**: {result.skill_name}",
                f"- **Trust Score**: {result.trust_score}/100 ({result.grade})",
                f"- **扫描文件数**: {result.files_scanned}",
                f"",
                f"## Findings",
                f"",
            ]
            if result.findings:
                for f in result.findings:
                    lines.append(f"- [{f.severity}] {f.category}: {f.message} (`{f.file}:{f.line}`)")
            else:
                lines.append("✅ 无发现")
            output = "\n".join(lines)
            if args.output:
                Path(args.output).write_text(output, encoding="utf-8")
                print(f"Markdown 报告已写入: {args.output}")
            else:
                print(output)
            sys.exit(_ci_exit(result, fail_under=args.fail_under))
        else:
            exit_code = print_terminal_report(result, fail_under=args.fail_under)
            sys.exit(exit_code)
    else:
        ap.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()
