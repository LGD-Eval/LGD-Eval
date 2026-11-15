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
    from js_analyzer import scan_js_file, js_flags
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
    # === JS / Node 技能形态：evaluate.py 已覆盖，skillgate 此前漏检，
    # 导致同一技能两套扫描器结论不一致（js-skill 34 分但 skillgate 0 HIGH） ===
    (r"\bchild_process\b", "HIGH", "Node 子进程能力（child_process）"),
    (r"\bexecSync\s*\(", "HIGH", "Node execSync 同步执行 shell"),
    (r"\bshell\s*:\s*true", "HIGH", "Node 子进程 shell:true"),
    (r"\bnew\s+Function\s*\(", "HIGH", "new Function 动态构造代码"),
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
    # 整份环境变量导出：单项 os.environ["KEY"] 是正常配置，全量打包才是外泄前兆。
    # 这里只给 MEDIUM（还差一次外发才算实锤）；evaluate.py 的 R-SEC-21 做组合判定。
    (r"\bdict\s*\(\s*os\.environ\b", "MEDIUM", "整份环境变量导出（外泄前兆）"),
    (r"\bos\.environ\.copy\s*\(", "MEDIUM", "整份环境变量复制（外泄前兆）"),
    (r"\bin\s+os\.environ\.items\s*\(", "MEDIUM", "遍历全部环境变量"),
    # 2026-11-15 类覆盖：上一轮只认"打包成 dict/copy/items"三种形状，直接打印、
    # 直接塞进子进程 env、直接 json 序列化三种同样把全量环境变量抖出去的写法放行。
    (r"print\s*\(\s*os\.environ", "MEDIUM", "打印全部环境变量"),
    (r"env\s*=\s*(?:dict\s*\(\s*)?os\.environ", "INFO", "全量环境变量传入子进程（默认继承行为，仅在与外发组合时才是信号）"),
    (r"json\.dumps?\s*\([^\n]*os\.environ", "MEDIUM", "环境变量序列化（外泄前兆）"),
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

    # 2026-11-15 类覆盖（灭类不灭例）：凭证这一类原先只认"字段名 + 冒号 + 长字符串"一种形状。
    # 10 种真实凭证形态里 8 种放行——AWS、GitHub PAT、Slack、Google、Stripe、私钥块、
    # 带口令的数据库 DSN、Azure 存储密钥，全是"没有字段名也一眼能认"的硬凭证。
    # 按前缀/形状认，比按变量名认可靠。
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "CRITICAL", "AWS Access Key ID"),
    (re.compile(r"\bASIA[0-9A-Z]{16}\b"), "CRITICAL", "AWS 临时访问密钥 ID"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "CRITICAL", "GitHub 令牌"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "CRITICAL", "Slack 令牌"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "CRITICAL", "Google API Key"),
    (re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}\b"), "CRITICAL", "Stripe 线上密钥"),
    (re.compile(r"-----BEGIN[ A-Z]*PRIVATE KEY-----"), "CRITICAL", "私钥块"),
    (re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/]+:[^@\s]{3,}@",
                re.IGNORECASE), "CRITICAL", "带口令的连接串"),
    (re.compile(r"AccountKey\s*=\s*[A-Za-z0-9+/]{20,}={0,2}"), "CRITICAL", "Azure 存储账户密钥"),
    (re.compile(r"\.aws/credentials", re.IGNORECASE),  # skillgate: ignore
     "HIGH", "访问 AWS 凭证文件"),
    # 路径分段拼接：os.path.join(home, ".aws", "credentials") 是恶意包最常见的写法，
    # 字面匹配在上面那一条永远命不中——第三方实测样本就是这么躲过去的。
    (re.compile(r"['\"]\.?aws['\"]\s*[\),]\s*['\"]?credentials", re.IGNORECASE),  # skillgate: ignore
     "HIGH", "访问 AWS 凭证文件（路径分段拼接）"),
    (re.compile(r"['\"]\.ssh['\"]\s*[\)]\s*[^\n]*['\"]id_", re.IGNORECASE),  # skillgate: ignore
     "HIGH", "访问 SSH 私钥（路径分段拼接）"),
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
    # 2026-11-15 类覆盖（灭类不灭例）：同一类"批量删除"里另有两条被放行——
    # pathlib 的 rglob 循环 unlink、以及 Windows 侧 Remove-Item -Recurse。
    # 只在 POSIX 语境测过，Windows 上的等价写法等于没被看见。
    (r"(?:rglob|glob)\s*\([^)]*\)[^\n]*(?:unlink|remove|rmdir)",
     "MEDIUM", "通配递归删除（pathlib/glob）"),
    (r"remove-item[^\n]*-recurse", "HIGH", "PowerShell 递归删除"),
    (r"del\s+/[sfq][^\n]*[/]s", "HIGH", "cmd 递归删除（del /s）"),
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

    # --- 2026-11-15 红队复测（灭类不灭例）：注入这一类里，非英文形态曾整体失明 ---
    # 14 条样本里 13 条漏检：中文指令覆盖、结构标签伪造、编码载荷、分隔符伪造全放行。
    # 我们服务的生态主要说中文，只认英文等于对中文用户交白卷。以下按类补齐。
    # 严重度按"是否直接改写行为"分：改写指令 = CRITICAL，隐瞒/窃取语境 = HIGH，
    # 角色扮演 = LOW（正常提示词也大量使用，报重了就是误伤）。
    (r"(?:忽略|无视|抛开|跳过)(?:掉)?(?:以上|上面|前面|之前|先前|此前|上述)(?:的)?(?:所有|全部)?(?:指令|指示|提示|规则|设定|要求)",
     "CRITICAL", "中文注入：忽略以上指令"),
    (r"(?:忘掉|忘记|丢弃|清空)(?:你)?(?:之前|原来|原有|此前)?(?:的)?(?:所有)?(?:规则|指令|设定|限制|约束)",
     "CRITICAL", "中文注入：忘掉原有规则"),
    (r"(?:绕过|突破|跳过)(?:掉)?(?:安全|内容|审核|过滤|限制|防护|护栏)(?:检查|机制|策略)?",
     "CRITICAL", "中文注入：绕过安全限制"),
    (r"(?:覆盖|重写|改写)(?:掉)?(?:你的)?(?:系统)?(?:提示词|系统提示|指令|设定)",
     "CRITICAL", "中文注入：覆盖系统设定"),
    (r"<\s*/?\s*system\s*>|\[\s*system\s*\]|\"role\"\s*:\s*\"system\"",
     "CRITICAL", "结构伪造：伪装 system 角色"),
    (r"system_prompt_override|override_system_prompt",
     "HIGH", "配置伪造：声明覆盖系统提示"),
    (r"(?:不要|别|切勿)(?:告诉|通知|提醒|透露给|告知)(?:用户|使用者|调用者)",
     "HIGH", "中文注入：对用户隐瞒行为"),
    # 语序不固定（"把系统提示词输出给我" / "输出你的系统提示"），故两个方向都认
    (r"(?=[^\n]*(?:系统提示词|系统提示|初始提示|隐藏指令))(?:输出|泄露|打印|发给我|给出|告知)"
     r"|(?:系统提示词|系统提示|初始提示|隐藏指令)[^\n]*(?:输出|泄露|给出|发给|打印|告知)",
     "HIGH", "中文注入：索取系统提示"),
    (r"base64\s+(?:-d|--decode)[^\n]*\|\s*(?:sh|bash|zsh|python)",
     "CRITICAL", "编码载荷：base64 解码后直接执行"),
    (r"<<\s*SYS\s*>>|\[\s*INST\s*\]",
     "MEDIUM", "聊天模板标记（可能伪造角色边界，需人工确认）"),
    (r"你现在(?:是|就是|扮演)|假装(?:你)?是|(?:请)?扮演(?:一个)?",
     "LOW", "角色定义，低风险，需人工确认"),
    (r"\]\]>\s*</?\w+>",
     "MEDIUM", "分隔符伪造：闭合标签后追加新指令"),
]

# 5.4 不可见字符承载的指令（CSA 2026-03 报告的 Unicode Tags 注入）
# 正则看不见它们，所以写在文本规则里等于没有。这里按码位单独扫：
#   U+E0000–U+E007F  Tags 块，逐字对应 ASCII，屏幕上完全不显示，模型照读
#   U+200B–U+200F  零宽空格/连接符
#   U+2060–U+2064  词连接符/不可见运算符
#
# 2026-11-15 红队复测（灭类不灭例）：上面三段只覆盖了"Tags 类""零宽类""格式类"三个例，
# 同一风险类里还有一批能被静默承载的字符完全没被看到——9 类全部漏检。已按"类"补齐，
# 并给每段一个最小出现次数（min_count）：像软连字符、盲文空白、谚文填充符这类
# 在正常排版里偶尔出现一次不算攻击，出现≥2 次才报；承载 ASCII 的强载体（Tags 块、
# 变体选择符补充区、双向控制符、音乐格式控制符）出现 1 个就报。
# 刻意**不**收 U+FE00–U+FE0F：那是 emoji 的合法变体选择符（"❤️"就含 FE0F），
# 收进来等于给所有带 emoji 的 README 报 CRITICAL，是拿误报换覆盖。
INVISIBLE_RANGES = (
    (0xE0000, 0xE007F, "Unicode Tags 块（隐形承载 ASCII 指令）", 1),
    (0x200B, 0x200F, "零宽字符", 1),
    (0x2060, 0x2064, "不可见格式字符", 1),
    (0x061C, 0x061C, "阿拉伯字母标记（控制阅读方向）", 1),
    (0x202A, 0x202E, "双向控制符（可反转显示顺序）", 1),
    (0x2066, 0x2069, "双向隔离符", 1),
    (0xFEFF, 0xFEFF, "零宽不换行空格（BOM 字符）", 1),
    (0x1D173, 0x1D17A, "音乐符号格式控制符", 1),
    (0xE0100, 0xE01EF, "变体选择符补充区（隐形承载数据）", 1),
    (0x00AD, 0x00AD, "软连字符", 2),
    (0x180E, 0x180E, "蒙古文元音分隔符", 2),
    (0x2800, 0x2800, "盲文空白", 2),
    (0x3164, 0x3164, "谚文填充符", 2),
    (0xFFA0, 0xFFA0, "半角谚文填充符", 2),
)


def invisible_payloads(text):
    """返回 [(码位, 区间名, 上下文片段)]。同一区间只报一次，避免刷屏。

    min_count 语义：该区间字符在全文出现次数达到阈值才报，
    避免"软连字符出现一次"这种正常排版被当成注入。
    """
    hits = {}
    counts = {}
    first = {}
    for idx, ch in enumerate(text):
        cp = ord(ch)
        for lo, hi, label, min_n in INVISIBLE_RANGES:
            if lo <= cp <= hi:
                counts[label] = counts.get(label, 0) + 1
                if label not in first:
                    first[label] = (cp, text[max(0, idx - 20):idx + 20])
                break
    for label, n in counts.items():
        if n >= next(r[3] for r in INVISIBLE_RANGES if r[2] == label):
            hits[label] = first[label]
    return [(v[0], label, v[1]) for label, v in hits.items()]

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
    # 2026-11-15 类覆盖（灭类不灭例）：关 TLS 校验这一类原先只认 requests 的 verify=False。
    # 7 种真实写法里 4 种放行——ssl.unverified 上下文、CERT_NONE、Node 的
    # rejectUnauthorized、以及用环境变量关掉整个进程的校验。按语言/容器各补一条。
    (r"ssl\._create_unverified_context\s*\(", "HIGH", "SSL 校验关闭（unverified context）"),
    (r"verify_mode\s*=\s*(?:ssl\.)?CERT_NONE", "HIGH", "SSL 校验关闭（CERT_NONE）"),
    (r"check_hostname\s*=\s*False", "HIGH", "SSL 主机名校验关闭"),
    (r"rejectUnauthorized\s*:\s*false", "HIGH", "Node TLS 校验关闭（rejectUnauthorized）"),
    (r"NODE_TLS_REJECT_UNAUTHORIZED[^\n]{0,20}['\"]?\s*=?\s*['\"]?0", "HIGH", "Node TLS 校验关闭（环境变量）"),
    (r"PYTHONHTTPSVERIFY[^\n]{0,20}['\"]?\s*=?\s*['\"]?0", "HIGH", "进程级 TLS 校验关闭（环境变量）"),
    (r"CURL_CA_BUNDLE\s*=\s*['\"]{2}|GIT_SSL_NO_VERIFY", "HIGH", "TLS 校验关闭（环境变量）"),
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
# ⚠️ 本表历史上定义过、但从未接入扫描循环（死表）：它的规则一条都不会生效。
# 已在本次修复中把独有规则并入 NETWORK_PATTERNS，此表仅为兼容旧引用而保留。
# 新增外泄规则请加到 NETWORK_PATTERNS，不要再往这里加。
EXFIL_PATTERNS = [
    (r"\brequests\.post\([^)]*https?://", "MEDIUM", "向外发 POST 请求"),
    (r"\burllib\.request\.urlopen\(", "MEDIUM", "向外发请求"),
    (r"\bsmtplib\.SMTP\(", "MEDIUM", "发送邮件"),
    (r"\bsocket\.socket\(", "MEDIUM", "原始 socket 网络连接"),
]

# ------------------------------------------------------------------
# 规则表接线声明（2026-11-15）
#
# AUTH_PATTERNS 被查出"从定义起就没被任何循环引用"之后，静态核对发现同类问题
# 不止一张：EXFIL / LICENSE / QUALITY / VALIDATION 四张表同样零引用。
# 死规则表比错规则更危险——错规则至少会响，死规则让"我们能检出 X"变成一句空话。
#
# 从此每张表必须落到两类之一，二选一都要写明理由：
#   ACTIVE_RULE_TABLES —— 扫描循环真的在读（tests/test_rule_table_wiring.py 会核）
#   RULE_TABLES_DECLARED_OFF —— 有意关闭，且必须给理由，不能只留空表
# 新增规则表而不登记，守卫测试直接红。
# ------------------------------------------------------------------
ACTIVE_RULE_TABLES = (
    "DANGEROUS_CODE_PATTERNS",
    "NETWORK_PATTERNS",
    "CREDENTIAL_PATTERNS",
    "FILESYSTEM_PATTERNS",
    "EXCESSIVE_AGENCY_PATTERNS",
    "HONESTY_PATTERNS",
    "AUTH_PATTERNS",
    "PROMPT_INJECTION_PATTERNS",
    "INSTALL_HOOKS",
    "REMOTE_EXEC_PATTERNS",
    # §3as：配置里的"远程下载落盘"写法（certutil/bitsadmin/curl -o/Invoke-WebRequest -OutFile）
    "REMOTE_DOWNLOAD_PATTERNS",
)

RULE_TABLES_DECLARED_OFF = {
    "EXFIL_PATTERNS": "独有规则已并入 NETWORK_PATTERNS，保留此表仅为兼容旧引用",
    "LICENSE_PATTERNS": ("未接入：扫描对象是技能仓，README 里提到 GPL/AGPL 属于叙述，"
                         "按行报会把许可证讨论一律打成分；许可证判断走仓库级 LICENSE 文件核对，不走行级正则"),
    "QUALITY_PATTERNS": ("未接入：TODO/FIXME/print 属风格噪声，不是安全信号；"
                         "接进来会把每个正常仓库都降一档，与「检出风险」这一声称无关"),
    "VALIDATION_PATTERNS": ("未接入：request.args/input/sys.argv 是常规入口，单看入口判不出未校验；"
                            "真正的注入判断在 DANGEROUS_CODE_PATTERNS 与 AST 层"),
}


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
    # scoring=False：只披露、不扣分（"我没读 / 我读不全"这类事实陈述）。
    # 由来（audit2/probe_counted_disclosure.py）：§3ad–§3ag 的披露都写着"不计分"，
    # 但计数只按 severity、不看 category —— 实测披露把 100 分打到 98，
    # 也就是说"不计分"是句没实现的话。现在由这个字段兑现。
    scoring: bool = True


# 只披露、不计分的类别（能力边界与读数范围，不是问题本身）
NON_SCORING_CATEGORIES = {"coverage"}


@dataclass
class ScanResult:
    skill_name: str = ""
    skill_dir: str = ""
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    frontmatter: dict = field(default_factory=dict)
    trust_score: int = 0
    grade: str = ""
    rule_version: str = "v3.1.3"  # 规则版本号（有籍）；报告头与 JSON 都从这里取
    engine: str = "skillgate.py"  # 引擎身份：本仓有两个引擎都打印 Trust Score，必须可区分
    excluded: list = field(default_factory=list)  # 显式排除的路径（供审计复现）

    @property
    def critical_count(self): return len([f for f in self.findings
                                          if f.severity == "CRITICAL" and f.scoring])
    @property
    def high_count(self): return len([f for f in self.findings
                                      if f.severity == "HIGH" and f.scoring])
    @property
    def medium_count(self): return len([f for f in self.findings
                                        if f.severity == "MEDIUM" and f.scoring])
    @property
    def low_count(self): return len([f for f in self.findings
                                 if f.severity == "LOW" and f.scoring])


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


# 同形字表：西里尔/希腊/全角/数学字母 里"看着像拉丁字母"的那一批。
# 只收拉丁同形，不收整段转写——避免把正常俄语/希腊语正文改写成可匹配文本。
_CONFUSABLE = {
    # 西里尔
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X", "І": "I", "Ї": "I",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ї": "i", "ѕ": "s", "ј": "j", "ԁ": "d", "ӏ": "l", "һ": "h",
    # 希腊
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    "α": "a", "ο": "o", "ν": "v", "ι": "i", "κ": "k", "υ": "u", "χ": "x",
    # 常用全角
    "ａ": "a", "ｂ": "b", "ｃ": "c", "ｄ": "d", "ｅ": "e", "ｆ": "f", "ｇ": "g",
    "ｈ": "h", "ｉ": "i", "ｊ": "j", "ｋ": "k", "ｌ": "l", "ｍ": "m", "ｎ": "n",
    "ｏ": "o", "ｐ": "p", "ｑ": "q", "ｒ": "r", "ｓ": "s", "ｔ": "t", "ｕ": "u",
    "ｖ": "v", "ｗ": "w", "ｘ": "x", "ｙ": "y", "ｚ": "z",
}
_STRIP_INVISIBLE = dict.fromkeys(
    [0x00AD, 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E, 0x00A0]
    + list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A))
)


def _fold_confusables(text: str) -> str:
    """把"人眼看得懂、正则不认"的写法折叠成可匹配形式。

    做三件事：去零宽/方向控制符 → 同形字映射到拉丁 → 空白压平。
    实测（audit2/probe_homoglyph.py）：`Іgnore аll previous instructions`、
    `Ignore all\\nprevious instructions` 在原文写法下都是 0 命中。
    """
    out = []
    for ch in text:
        cp = ord(ch)
        if cp in _STRIP_INVISIBLE:
            continue
        out.append(_CONFUSABLE.get(ch, ch))
    return re.sub(r"\s+", " ", "".join(out)).strip()


# 单文件读取上限：超过就只读前面这一段，并且**必须披露**读了多少。
# 由来（audit2/probe_big_file.py）：40.3 MB 的单文件扫了 15 分钟没跑完（人工中止）。
# 但比"跑得慢"更要紧的是口径：一旦截断，报告必须与"扫过且没问题"长得不一样，
# 否则就是 §3aj「读不出来 ≠ 干净」的同类缺陷。
MAX_SCAN_BYTES = 8 * 1024 * 1024
_TRUNCATED_FILES: list = []


def _binary_reason(filepath: Path, sniff: int = 65536):
    """文本后缀里装的其实是二进制？返回理由，否则 None。

    为什么要专门查：扫描器是"按后缀决定怎么读"的。后缀写 .py/.md 就会被当文本读，
    读得进去（不会抛异常），于是"没报错"被当成"没问题"。实测
    （audit2/probe_binary_in_text.py）：
      · .py 末尾加一个 NUL 字节 → ast.parse 失败 → 危险调用从 CRITICAL(49/D) 静默掉到 LOW(100/A+)
      · 真 PE 二进制改名 .py → 100/A+，一句不提
    判据只看"这条路还能不能审"，不看内容像什么：含 NUL / 已知二进制文件头 /
    按 BOM 与常见编码都解不出来。
    """
    try:
        raw = filepath.open("rb").read(sniff)
    except OSError:
        return None
    if not raw:
        return None
    for magic, what in ((b"MZ", "PE/Windows 可执行文件头"),
                        (b"\x7fELF", "ELF 可执行文件头"),
                        (b"\xca\xfe\xba\xbe", "Mach-O/Java class 文件头"),
                        (b"\xcf\xfa\xed\xfe", "Mach-O 文件头")):
        if raw.startswith(magic):
            return what
    if b"\x00" in raw:
        return "含 NUL 字节"
    # 窗口是从大文件切出来的：窗口末尾可能正好切在一个多字节字符中间。
    # 直接拿截断窗口做严格解码，会把**正常的大文本文件**判成二进制
    # （实测：skillgate.py 长到 180 KB 后，第 65536 字节落在一个中文字符中间，
    #   自扫立刻多出一条 HIGH「内容是二进制」——§3ap 修复自带的假阳性）。
    # 所以只读窗口时，先容掉末尾几个字节再判；真二进制在任何切点都解不出来。
    truncated = len(raw) >= sniff
    tail_cuts = (0, 1, 2, 3, 4, 5, 6, 7, 8) if truncated else (0,)
    for cut in tail_cuts:
        probe = raw[:len(raw) - cut] if cut else raw
        try:
            _decode_bytes_strict(probe)
            return None
        except UnicodeDecodeError:
            continue
    return "按 UTF-8/UTF-16/GBK 均无法解码"


def scan_binary_in_text(skill_path: Path, result: ScanResult, should_exclude):
    """声明为文本、内容是二进制：这条文件"读了，但审不了"。

    定级 HIGH 而不是"披露不计分"：这不是"没扫到"，是**故意让文本通道失效**——
    夹一个 NUL 字节就能把 CRITICAL 打成 LOW，改名就能把二进制藏成脚本。
    计分，且计入封顶（HIGH → 最高 69/C）。
    """
    TEXT_SUFFIXES = {".py", ".js", ".ts", ".mjs", ".cjs", ".sh", ".ps1", ".bat", ".cmd",
                     ".md", ".txt", ".json", ".yaml", ".yml", ".ini", ".cfg", ".conf",
                     ".toml", ".env", ".properties"}
    for p in skill_path.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if should_exclude(p):
            continue
        reason = _binary_reason(p)
        if not reason:
            continue
        result.findings.append(Finding(
            severity="HIGH", category="integrity",
            message="文件声明为文本（%s）但内容是二进制（%s）：代码/正文结构无法解析，"
                    "其中的危险调用可能因此不被报出" % (p.suffix.lower(), reason),
            file=str(p.relative_to(skill_path)), line=1
        ))


def read_text_smart(filepath: Path) -> str:
    """按 BOM 与真实编码解码，而不是一律当成 UTF-8。

    为什么必须这样：引擎过去统一 `read_text(encoding="utf-8", errors="replace")`。
    文件若是 UTF-16LE（Windows 记事本"另存为"的默认选项之一），读出来是一片替换字符，
    于是**按内容匹配的规则全部失效**。

    实测（audit2/probe_encoding_coverage.py）：
      · UTF-16 的 .md（含零宽字符 + "Ignore all previous instructions"）→ 0 命中，
        UTF-8 BOM 的同一份 → 5 命中。同一段文字，只因为编码不同就看不见。
      · UTF-16 的 .py → Python 自己也拒绝执行（`source code string cannot contain null bytes`），
        所以代码面是理论风险；**数据面（文档/配置）才是真漏洞**，因为模型照样能读到那些字。

    顺序：BOM 嗅探 → UTF-8 严格 → GBK（中文 Windows 常见）→ 最后才退回替换模式。
    """
    try:
        raw = filepath.read_bytes()
    except OSError:
        return ""
    if len(raw) > MAX_SCAN_BYTES:
        _TRUNCATED_FILES.append((str(filepath), len(raw)))
        raw = raw[:MAX_SCAN_BYTES]
    return _decode_bytes(raw)


def _decode_bytes(raw: bytes) -> str:
    """字节 → 文本：BOM 嗅探 → UTF-8 严格 → GBK → 替换模式兜底。

    独立出来是为了让备用数据流（ADS）的内容也能走同一套解码——
    流里的载荷同样可能是 UTF-16 存的。
    """
    boms = (
        (b"\xef\xbb\xbf", "utf-8-sig"),
        (b"\xff\xfe\x00\x00", "utf-32-le"),
        (b"\x00\x00\xfe\xff", "utf-32-be"),
        (b"\xff\xfe", "utf-16-le"),
        (b"\xfe\xff", "utf-16-be"),
    )
    for bom, enc in boms:
        if raw.startswith(bom):
            try:
                return raw.decode(enc)
            except UnicodeDecodeError:
                break

    for enc in ("utf-8", "gbk"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue

    return raw.decode("utf-8", errors="replace")


def _decode_bytes_strict(raw: bytes) -> str:
    """同 _decode_bytes，但解不出来就抛，不兜底成替换字符。

    兜底版本是给"要尽量读出来"的场景用的；判断"这是不是文本"必须用这个，
    否则一切二进制都会被"解码成功"。
    """
    boms = (
        (b"\xef\xbb\xbf", "utf-8-sig"),
        (b"\xff\xfe\x00\x00", "utf-32-le"),
        (b"\x00\x00\xfe\xff", "utf-32-be"),
        (b"\xff\xfe", "utf-16-le"),
        (b"\xfe\xff", "utf-16-be"),
    )
    for bom, enc in boms:
        if raw.startswith(bom):
            return raw.decode(enc)  # BOM 说了算：解不出就该抛
    for enc in ("utf-8", "gbk"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    raise UnicodeDecodeError("utf-8", raw[:1] or b"\x00", 0, 1, "not decodable as text")



def scan_python_file(filepath: Path, result: ScanResult):
    """Scan a single Python file for dangerous patterns."""
    try:
        content = read_text_smart(filepath)
    except Exception as e:
        result.findings.append(Finding(
            severity="LOW", category="file-read",
            message=f"无法读取文件: {e}", file=str(filepath)
        ))
        return

    lines = content.splitlines()

    # === 第零步：结构能不能解析 ===
    # ast_analyzer.analyze_python_file 自己吞掉异常并返回 []，所以"AST 没报"
    # 和"AST 跑不了"在调用方看起来一模一样。这里自己先解析一次，把状态说出来。
    import ast as _ast
    try:
        _ast.parse(content, filename=str(filepath))
    except SyntaxError as e:
        if not _binary_reason(filepath):
            result.findings.append(Finding(
                severity="LOW", category="integrity",
                message="AST 解析失败（第 %s 行：%s），该文件仅按正则扫描，代码结构未经分析"
                        % (e.lineno, (e.msg or "")[:60]),
                file=str(filepath), line=e.lineno or 1
            ))
    except (ValueError, RecursionError) as e:
        result.findings.append(Finding(
            severity="LOW", category="integrity",
            message="AST 解析失败（%s），该文件仅按正则扫描" % str(e)[:60],
            file=str(filepath), line=1
        ))

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
            sev, msg = af.severity, af.message
            # 递归删除：写了路径守卫就是"可以接受的删除"，不写才是风险。
            # 修复前实测：带 startswith 守卫的干净样本仍被判 HIGH 69/C，
            # 而没有守卫的同类样本也是 HIGH —— 两条都报等于规则没用信息量。
            if "递归删除" in msg and has_path_guard(lines, af.line):
                sev, msg = "LOW", msg + "（同文件检测到路径守卫）"
            result.findings.append(Finding(
                severity=sev,
                category="ast-analysis",
                message=f"[AST] {msg}",
                file=str(filepath),
                line=af.line
            ))
            ast_lines.add(af.line)  # 记录这一行已经报过了
    except Exception as e:
        # 原来这里是 `pass`：AST 挂了就静默退回正则。
        # 实测（audit2/probe_binary_in_text.py）：同一个 .py，只是夹了一个 NUL 字节，
        # ast.parse 失败 → 危险调用从 CRITICAL(49/D) 掉到 LOW(100/A+)。
        # "解析器读不了"必须自己说出来，否则它就是一条免检通道。
        if _binary_reason(filepath):
            pass  # 由 scan_binary_in_text 统一报，避免重复
        else:
            result.findings.append(Finding(
                severity="LOW", category="integrity",
                message="AST 解析失败（%s），该文件仅按正则扫描，代码结构未经分析"
                        % str(e).split("\n")[0][:80],
                file=str(filepath), line=1
            ))

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

    # 4.5 Auth / TLS 类（AUTH_PATTERNS）
    #     2026-11-15 类覆盖时发现：这张表自建立起就没被任何扫描循环引用过，
    #     是死代码。于是 "verify=False / CERT_NONE / rejectUnauthorized:false"
    #     这些声称"能检出 TLS 校验关闭"的规则，实际上一条都没生效——
    #     7 种写法里只有 3 种被别的规则（network 的通用 INFO）顺带撞上。
    #     接进来，并给独立 category，避免和 network 的通用命中混在一起。
    for pattern, severity, msg in AUTH_PATTERNS:
        for i, line in enumerate(lines, 1):
            if is_comment_line(line):
                continue
            if is_suppressed(i):
                continue
            # TLS 环境变量名本身写在字符串里（os.environ['PYTHONHTTPSVERIFY']），
            # code_lines 会把字符串剥掉，所以这一组对原始行判；
            # 同时必须绕开规则定义行，否则扫描器扫自己的规则表就自命中。
            if is_rule_literal_line(line):
                continue
            if re.search(pattern, line, re.IGNORECASE):
                result.findings.append(Finding(
                    severity=severity, category="auth",
                    message=msg, file=str(filepath), line=i
                ))

    # 4.6 跨行"通配 + 删除"组合
    #     pathlib 的 rglob 循环里 unlink 是两行三行分开写的，单行正则永远看不到它们
    #     在一起。按"同一文件内同时出现"判，才抓到这一类。
    _has_glob = re.search(r"\b(?:rglob|glob)\s*\(", content)
    _has_del = re.search(r"(?:unlink|rmtree|rmdir|remove)\s*\(", content)
    if _has_glob and _has_del:
        _ln = content[:_has_del.start()].count("\n") + 1
        result.findings.append(Finding(
            severity="MEDIUM", category="filesystem",
            message="通配遍历 + 删除组合（可能批量清除）",
            file=str(filepath), line=_ln
        ))

    # 4.7 写在字符串里的 shell 删除命令
    #     code_lines 会把字符串剥掉，于是 os.system("Remove-Item -Recurse …") 这种
    #     "把危险命令当字符串传下去"的写法被剥离后看不见。这里对原始行再看一遍。
    _SHELL_DEL = (
        (r"remove-item[^\n]*-(?:recurse|force)[^\n]*", "HIGH", "PowerShell 递归删除（字符串内）"),
        (r"\brd\s+/s\b|\brmdir\s+/s\b", "HIGH", "cmd 递归删除目录（字符串内）"),
        (r"\bdel\s+/[sfq][^\n]*/s\b", "HIGH", "cmd 递归删除文件（字符串内）"),
        (r"\brm\s+-rf?\s+(?:/|~|\*)[^\n]*", "HIGH", "rm -rf 删除根/家目录/通配（字符串内）"),
    )
    for _pat, _sev, _msg in _SHELL_DEL:
        for i, line in enumerate(lines, 1):
            if is_comment_line(line) or is_suppressed(i):
                continue
            if is_rule_literal_line(line):
                continue  # 规则定义行（本文件里的模式字面量）不自命中
            if re.search(_pat, line, re.IGNORECASE):
                result.findings.append(Finding(
                    severity=_sev, category="dangerous-shell",
                    message=_msg, file=str(filepath), line=i
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
        content = read_text_smart(filepath)
    except Exception:
        return

    lines = content.splitlines()

    # 代码块行（``` ... ```）跳过：示例载荷非指令本身
    in_code_block = False
    code_lines = set()
    fence_start = 0
    for i, line in enumerate(lines, 1):
        if line.strip().startswith("```"):
            in_code_block = not in_code_block
            code_lines.add(i)
            if in_code_block:
                fence_start = i
            continue
        if in_code_block:
            code_lines.add(i)

    # 未闭合的围栏：一条 ``` 就能把后面整篇文档变成"代码块"。
    # 实测（audit2/probe_unclosed_fence.py）：````text` 开了不关，越狱句写在后面，
    # 分数 100/A+ —— 因为注入全落进"代码块示例、不计分"通道。
    # 口径：示例豁免的前提是"这是个完整的示例块"。围栏没闭合，其后内容不算示例。
    unclosed_fence_at = fence_start if in_code_block else 0
    if unclosed_fence_at:
        code_lines -= {n for n in code_lines if n >= unclosed_fence_at}
        result.findings.append(Finding(
            severity="MEDIUM", category="coverage",
            message="未闭合的代码围栏（第 %d 行起）：其后内容不视为示例，已按正文扫描"
                    % unclosed_fence_at,
            file=str(filepath), line=unclosed_fence_at
        ))

    def is_suppressed(line_idx: int) -> bool:
        """与 Python 侧同一约定：当前行或上一行含 skillgate: ignore 即视为
        已声明的抑制（Bandit # nosec / NOSONAR 的同类做法）。

        md 侧原先没有这段，导致文档里的 `<!-- skillgate: ignore -->` 完全无效——
        抑制约定只对 .py 生效，对 .md 是装饰。这是一致性缺陷，补上。
        """
        if 0 < line_idx <= len(lines) and "skillgate: ignore" in lines[line_idx - 1]:
            return True
        if line_idx > 1 and "skillgate: ignore" in lines[line_idx - 2]:
            return True
        return False

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
        此时 jailbreak / ignore previous 等词是主题词而非注入指令。

        2026-11-15 收紧：原先"命中任一个安全词就豁免"。中文注入几乎必然带"安全"二字
        （"绕过安全限制"），于是把自己豁免掉了——实测该样本被判 MISS。
        改为分级：出现两个以上不同安全词，或出现明确的讨论标记（例如/示例/论文 等），
        才算讨论语境；只有一个"安全"这类泛词不构成豁免。
        """
        low = line.lower()
        hits = {w for w in SAFETY_CONTEXT_WORDS if w in low}
        if len(hits) >= 2:
            return True
        return any(w in low for w in ("例如", "示例", "举例", "恶意样本", "攻击样例",
                                      "e.g.", "example", "payload sample"))

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
            if is_suppressed(i):
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

    # 1c. 代码块里的注入：示例豁免不能变成隐身衣。
    # 实测（audit2/probe_block_evasion.py）：把越狱句放进 ```text ``` 围栏里 → 0 命中；
    # 而模型读文档时读的是**原文**，围栏里的句子照样是它读到的字。
    # 但代码块确实常放"反面示例"，所以按披露处理：写明有几处、在第几行、未计分。
    code_hits = []
    for i in sorted(code_lines):
        if i > len(lines):
            continue
        folded = _fold_confusables(lines[i - 1])
        for pattern, severity, msg in PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, folded, re.IGNORECASE):
                code_hits.append((i, msg))
                break
    if code_hits:
        result.findings.append(Finding(
            severity="MEDIUM", category="coverage",
            message="代码块内含注入式语句 %d 处（首个在第 %d 行，示例语境未计分，但模型照样读得到）"
                    % (len(code_hits), code_hits[0][0]),
            file=str(filepath), line=code_hits[0][0]
        ))

    # 实测（audit2/probe_homoglyph.py）：
    #   `Іgnore аll previous instructions`（西里尔 І/а 看着像 I/a）→ 0 命中
    #   `Ignore all\nprevious instructions`（拆成两行）             → 0 命中
    # 人眼和模型都照样读得懂，只是正则不认。所以把段落折叠后（去零宽、同形字转 ASCII、
    # 空白压平）再跑一遍；同一模式在原文已命中则不重复计分。
    reported_msgs = {f.message for f in result.findings
                     if f.category == "prompt-injection" and f.file == str(filepath)}

    para: list = []
    para_start = 0
    blocks = []
    for i, line in enumerate(lines, 1):
        if i in code_lines or not line.strip():
            if para:
                blocks.append((para_start, " ".join(para)))
                para = []
            continue
        if not para:
            para_start = i
        para.append(line)
    if para:
        blocks.append((para_start, " ".join(para)))

    # 分窗：段落折叠不能整段硬塞进正则。
    # 实测（audit2/probe_big_profile.py）：0.2 MB 的单段落文档扫 111 s，
    # cProfile 显示 110 s 全在 re.Pattern.search 上——注入规则里有
    # `(?=[^\n]*(?:系统提示词|…))(?:输出|…)` 这种前瞻，在长串上退化成 O(n²)，
    # 130 KB 的一个段落 = 130 KB × 130 KB。数据 10 倍、时间 100 倍，就是它。
    # 4000 字符一窗、相邻窗重叠 300 字符，跨窗的拆行写法仍能命中，复杂度回到线性。
    WIN, OVERLAP = 4000, 300

    def _windows(text: str):
        if len(text) <= WIN:
            yield text
            return
        step = WIN - OVERLAP
        for off in range(0, len(text), step):
            yield text[off:off + WIN]
            if off + WIN >= len(text):
                return

    for start_line, block in blocks:
        if is_safety_discussion(block):
            continue
        for window in _windows(block):
            folded = _fold_confusables(window)
            for pattern, severity, msg in PROMPT_INJECTION_PATTERNS:
                if msg in reported_msgs:
                    continue
                if re.search(pattern, folded, re.IGNORECASE):
                    result.findings.append(Finding(
                        severity=severity, category="prompt-injection",
                        message=msg + "（同形字/拆行归一后命中）",
                        file=str(filepath), line=start_line
                    ))
                    reported_msgs.add(msg)
                    break


    # 1.2 编码载荷：base64 解出来再判。只看"一长串 base64"会全员误报
    #     （文档里的哈希、证书、密钥指纹都是这种形态），解出明文再看里面有没有指令才准。
    for _m in re.finditer(r"[A-Za-z0-9+/]{40,}={0,2}", content):
        _blob = _m.group(0)
        try:
            import base64 as _b64
            _dec = _b64.b64decode(_blob + "=" * (-len(_blob) % 4),
                                 validate=False).decode("utf-8", "ignore")
        except Exception:
            continue
        if not _dec or len(_dec) < 8:
            continue
        _low = _dec.lower()
        if any(k in _low for k in ("ignore", "system prompt", "jailbreak",
                                   "忽略", "指令", "system")):
            _line = content[:_m.start()].count("\n") + 1
            if is_suppressed(_line):
                continue
            result.findings.append(Finding(
                severity="CRITICAL", category="prompt-injection",
                message="编码载荷：base64 解码后含注入指令（%s…）" % _dec.strip()[:40],
                file=str(filepath), line=_line
            ))

    # 1.5 不可见字符：正则看不见它们，必须按码位扫。
    #     只在文档类文件（.md/.txt）里查——源码里的零宽字符是编码事故，
    #     但 SKILL.md 里的隐形段落是给人读不到、给模型读得到的指令通道。
    if filepath.suffix.lower() in (".md", ".txt", ".markdown"):
        for cp, label, ctx in invisible_payloads(content):
            marker = chr(cp)
            line_no = content[:content.find(marker)].count("\n") + 1
            if is_suppressed(line_no):
                continue
            result.findings.append(Finding(
                severity="CRITICAL", category="prompt-injection",
                message="不可见字符承载指令：%s（U+%04X）" % (label, cp),
                file=str(filepath), line=line_no
            ))

    # 2. Credential / secret patterns（.md 也检查，但过滤占位符与示例值；
    #    跳过 frontmatter 区域避免元数据字段名误报）
    for pattern, severity, msg in CREDENTIAL_PATTERNS:
        for i, line in enumerate(lines, 1):
            if i in code_lines or i in fm_lines or is_suppressed(i):
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
            if i in code_lines or is_suppressed(i):
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
            if is_suppressed(i):
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


def _parse_requirement_line(line):
    """把一行依赖拆成 (name, version) 或 ("", 原始行)。

    只对**精确固定版本**返回版本号：`requests>=2.31` 曾被写成 `==latest`
    送去 OSV，回来的一堆漏洞被按 HIGH 报成"requests==latest 存在 XX 漏洞"——
    那是一个不存在的版本号，属于假精确，比漏报更难被使用者识破。
    范围约束只能说明"不低于某版本"，判不出具体受影响包版本，所以只报"无法判定"。
    """
    line = line.split(";")[0].strip()
    line = line.split("#")[0].strip()
    if not line:
        return "", ""
    if "==" in line:
        name, version = line.split("==", 1)
        name = name.strip()
        version = version.strip().strip("\"'")
        if name and version and not any(c in version for c in ("*", " ", "<", ">")):
            return name, version
    return "", line


POPULAR_PY = {
    "requests", "numpy", "pandas", "flask", "django", "pytest", "setuptools",
    "urllib3", "boto3", "pyyaml", "cryptography", "pillow", "jinja2", "click",
    "scipy", "tqdm", "redis", "sqlalchemy", "fastapi", "pydantic", "openai",
    "anthropic", "matplotlib", "httpx", "aiohttp", "attrs", "packaging",
    "certifi", "idna", "six",
}
POPULAR_NPM = {
    "lodash", "express", "react", "react-dom", "axios", "chalk", "commander",
    "moment", "request", "debug", "uuid", "dotenv", "webpack", "tslib",
    "minimist", "node-fetch", "socket.io", "mongoose", "yargs", "colors",
    "eslint-plugin-unused-imports",
}
# 视觉替换：0→o、1→l、3→e、5→s、7→t，rn→m，分隔符统一。
_CONFUSE = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t"})


def _norm_name(name):
    n = name.lower().replace("rn", "m")
    for sep in ("_", ".", "-"):
        n = n.replace(sep, "-")
    return n.translate(_CONFUSE)


def _levenshtein(a, b):
    if a == b:
        return 0
    if not a or not b:
        return max(len(a), len(b))
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _typosquat_suspects(name, ecosystem):
    """名称相似度只是**怀疑**，不是 registry 事实。

    依据（公开研究）：
      · Levenshtein 距离 1–2 是主流启发式，已知误报高；
        40 个已知 typosquat 中 18 个的距离 ≤2（arXiv 2502.20528 综述口径）。
      · "子集型"（把一个长包名简化）编辑距离可以到 14，
        只有分词能抓——例如 eslint-plugin-unused-imports → unused-imports。
      · 依赖混淆的结构性修法是受控 scope + 显式 registry 映射，
        扫描器能做的只是"提醒核对来源"，不能替代 registry 侧校验。
    因此这里只产出 LOW，绝不升级为 HIGH：一个名字长得像，不是证据。
    """
    popular = POPULAR_NPM if ecosystem == "npm" else POPULAR_PY
    low = name.lower()
    if low in popular:
        return []
    hits = []
    for p in popular:
        if _norm_name(low) == _norm_name(p):
            hits.append("%s（形近替换 %s）" % (p, p))
            continue
        if len(p) >= 5 and len(low) >= 5 and _levenshtein(_norm_name(low), _norm_name(p)) == 1:
            hits.append("%s（编辑距离 1）" % p)
            continue
        pt = set(p.replace("_", "-").split("-"))
        nt = set(low.replace("_", "-").split("-"))
        if len(pt) >= 2 and nt and nt < pt:
            hits.append("%s（子集型：%s ⊂ %s）" % (p, "-".join(sorted(nt)), "-".join(sorted(pt))))
    return hits[:2]


def _load_private_inventory(skill_path: Path):
    """读使用者提供的私有包清单（`private-packages.json`）。

    dependency confusion 的可验证形态需要两样东西：哪些名字是我的，
    以及这些名字在公开 registry 上是否已被别人占用。第一件只能由使用者提供，
    第二件要联网（不在本引擎内做）。
    清单格式：{"names": ["acme-utils"], "scopes": ["@acme"]}
    """
    p = skill_path / "private-packages.json"
    if not p.exists():
        return None
    try:
        data = json.loads(read_text_smart(p))
    except Exception:
        return {"error": "无法解析 private-packages.json"}
    if not isinstance(data, dict):
        return {"error": "private-packages.json 顶层应为对象"}
    names = {str(n).lower() for n in data.get("names", []) if str(n).strip()}
    scopes = {str(s).lower() for s in data.get("scopes", []) if str(s).strip()}
    return {"names": names, "scopes": scopes, "error": ""}


def _private_name_hits(deps, inventory):
    """私有包名被声明成公开名、或不带 scope —— 这是 dependency confusion 的前置条件。

    只报 LOW 且措辞写明"需 registry 侧核对占用"：清单说明它是私有包，
    但"这个公开名字现在是否被别人占着"本引擎看不到。
    """
    if not inventory or inventory.get("error"):
        return []
    out = []
    for d in deps:
        name = d[0].lower()
        eco = d[2]
        scopes = inventory.get("scopes", set())
        bare = name if eco == "PyPI" else name.split("/")[-1]
        has_scope = name.startswith("@") and any(name.startswith(s + "/") for s in scopes)
        if bare in inventory.get("names", set()) and not has_scope:
            out.append((name, d[3],
                        "私有包 %s 以公开名（无 scope）声明：公开 registry 上同名包可能被"
                        "他人抢注并优先解析。需 registry 侧核对归属后锁定来源" % name))
    return out


def _declared_dependency_files(skill_path: Path):
    """声明依赖的所有文件：requirements.txt、requirements-*.txt、pyproject.toml。

    修复前只读 requirements.txt。真实技能常把依赖写在 pyproject.toml 里，
    于是"扫过依赖"这句话在那类仓里其实是"什么都没扫"。
    """
    files = []
    for name in ("requirements.txt", "pyproject.toml", "package.json",
                 "package-lock.json", "poetry.lock"):
        p = skill_path / name
        if p.exists():
            files.append(p)
    for p in sorted(skill_path.glob("requirements-*.txt")):
        if p.is_file():
            files.append(p)
    for sub in ("scripts", "src"):
        d = skill_path / sub
        if not d.is_dir():
            continue
        for name in ("requirements.txt", "pyproject.toml"):
            p = d / name
            if p.exists():
                files.append(p)
        for p in sorted(d.glob("requirements-*.txt")):
            if p.is_file():
                files.append(p)
    return files


def _deps_from_pyproject(text):
    """取 PEP 621 的 dependencies 与 Poetry 的 [tool.poetry.dependencies]。

    返回 (spec, is_dev) 列表：`optional-dependencies` 与 poetry 的
    dev/group 是**开发依赖**，它们不进运行时，未固定版本不该按运行时风险算。
    实测踩到过：lgd-eval 自己的 pyproject 里有 `pytest>=7`，
    一刀切成 MEDIUM 会把自家技能从 90 扣到 86——理由不成立，属于自伤噪音。
    """
    try:
        import tomllib
    except ImportError:            # py3.8–3.10：不猜，直接说没解析
        return None
    try:
        data = tomllib.loads(text)
    except Exception:
        return None
    specs = []
    proj = data.get("project") or {}
    for item in proj.get("dependencies") or []:
        specs.append((str(item), False))
    opt = proj.get("optional-dependencies") or {}
    for group in opt.values():
        for item in group or []:
            specs.append((str(item), True))
    poetry = ((data.get("tool") or {}).get("poetry") or {})
    for name, spec in (poetry.get("dependencies") or {}).items():
        if name.lower() == "python":
            continue
        specs.append(("%s%s" % (name, spec if isinstance(spec, str) else ""), False))
    for name, spec in (poetry.get("dev-dependencies") or {}).items():
        specs.append(("%s%s" % (name, spec if isinstance(spec, str) else ""), True))
    for group in (poetry.get("group") or {}).values():
        for name, spec in (group.get("dependencies") or {}).items():
            specs.append(("%s%s" % (name, spec if isinstance(spec, str) else ""), True))
    return specs


def _parse_js_range(spec):
    """npm 版本说明 → (精确版本, 原始说明)。

    `^1.2.3` / `~1.2.3` / `>=1.2.3` 都不是"就是这个版本"，
    与 Python 侧同理：只查能得到确切版本的，其余报"无法判定"，不编版本号。
    """
    spec = (spec or "").strip()
    if not spec:
        return "", ""
    if spec.startswith("="):
        spec = spec[1:].strip()
    if spec[:1] in "^~<>*" or " " in spec or spec.startswith("workspace"):
        return "", spec
    if any(c in spec for c in ("x", "X", "*")):
        return "", spec
    if spec.startswith("http") or spec.startswith("file:") or spec.startswith("git"):
        return "", spec
    return spec, spec


def _deps_from_package_json(text):
    """package.json 的 dependencies / devDependencies / optionalDependencies。

    修复前 package.json 只被查安装钩子，依赖从不进漏洞库——
    JS 侧那条"依赖扫描"其实是空的，一个生态的整块缺口。
    """
    try:
        data = json.loads(text)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    specs = []
    for key, is_dev in (("dependencies", False), ("optionalDependencies", True),
                        ("devDependencies", True)):
        block = data.get(key) or {}
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            specs.append(("%s@%s" % (name, spec), is_dev))
    return specs


def _deps_from_package_lock(text):
    """package-lock.json（v2/v3 用 packages，v1 用嵌套 dependencies）。

    清单里的范围只是**声明**，锁文件里才是真正装到机器上的那一个版本。
    供应链核查要的是后者：声明写 `^4.17.15` 时，实际装的是哪一版只有锁文件知道。
    """
    try:
        data = json.loads(text)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    specs = []
    pkgs = data.get("packages")
    if isinstance(pkgs, dict):
        for path, meta in pkgs.items():
            if not isinstance(meta, dict) or not path:
                continue
            name = meta.get("name") or path.split("node_modules/")[-1]
            version = str(meta.get("version") or "")
            if not name or not version:
                continue
            specs.append(("%s@%s" % (name, version), bool(meta.get("dev"))))
    elif isinstance(data.get("dependencies"), dict):
        for name, meta in data["dependencies"].items():
            if not isinstance(meta, dict):
                continue
            version = str(meta.get("version") or "")
            if version:
                specs.append(("%s@%s" % (name, version), bool(meta.get("dev"))))
    return specs


def _deps_from_poetry_lock(text):
    """poetry.lock 的 [[package]]：锁定后的确切版本。"""
    try:
        import tomllib
    except ImportError:
        return None
    try:
        data = tomllib.loads(text)
    except Exception:
        return None
    specs = []
    for item in data.get("package") or []:
        if not isinstance(item, dict):
            continue
        name, version = item.get("name"), item.get("version")
        if name and version:
            specs.append(("%s==%s" % (name, version), False))
    return specs


def _write_ranged(result, ranged, severity, message_of, file_of):
    if not ranged:
        return
    names = ", ".join(raw for raw, _ in ranged[:5])
    result.findings.append(Finding(
        severity=severity, category="dependency-scan",
        message=message_of % names, file=str(file_of[0][1])))


def scan_dependencies(skill_path: Path, result: ScanResult):
    """Scan declared dependencies for known vulnerabilities via OSV.dev."""
    dep_files = _declared_dependency_files(skill_path)
    if not dep_files:
        return

    deps = []            # (name, version, ecosystem, file)
    ranged = []          # (raw, file)           运行时依赖
    dev_ranged = []      # (raw, file)           开发依赖
    unparsed = []        # pyproject 在没有 tomllib 时 / package.json 坏了
    for dep_file in dep_files:
        try:
            content = read_text_smart(dep_file)
        except Exception:
            continue
        if dep_file.name == "poetry.lock":
            specs = _deps_from_poetry_lock(content)
            if specs is None:
                unparsed.append(dep_file)
                continue
            lines = specs
            eco = "PyPI"
            parse = None
            js = False
        elif dep_file.name == "package-lock.json":
            specs = _deps_from_package_lock(content)
            if specs is None:
                unparsed.append(dep_file)
                continue
            lines = specs
            eco = "npm"
            parse = None
            js = True
        elif dep_file.suffix == ".toml":
            specs = _deps_from_pyproject(content)
            if specs is None:
                unparsed.append(dep_file)
                continue
            lines = specs
            eco = "PyPI"
            parse = _parse_requirement_line
            js = False
        elif dep_file.name == "package.json":
            specs = _deps_from_package_json(content)
            if specs is None:
                unparsed.append(dep_file)
                continue
            lines = specs
            eco = "npm"
            parse = None
            js = True
        else:
            lines = [(ln, False) for ln in content.splitlines()]
            eco = "PyPI"
            parse = _parse_requirement_line
            js = False
        for line, is_dev in lines:
            if js:
                # npm 侧（清单与锁文件）：统一改成 name@version 形状
                name, spec = (line.rsplit("@", 1) if "@" in line else (line, ""))
                version, raw = _parse_js_range(spec)
                if version:
                    deps.append((name.strip(), version, eco, dep_file, is_dev))
                elif raw:
                    (dev_ranged if is_dev else ranged).append(
                        ("%s@%s" % (name.strip(), raw), dep_file))
                continue
            if parse is None:
                # 锁文件（poetry.lock）：已经写死为 name==version
                name, version = (line.split("==", 1) if "==" in line else ("", ""))
                if name.strip() and version.strip():
                    deps.append((name.strip(), version.strip(), eco, dep_file, is_dev))
                continue
            name, tail = parse(line)
            if name:
                deps.append((name, tail, eco, dep_file, is_dev))
            elif tail:
                (dev_ranged if is_dev else ranged).append((tail, dep_file))

    # 同一 (包, 版本, 生态) 只查一次：清单与锁文件会给出重复项
    seen = set()
    uniq = []
    for d in deps:
        key = (d[0].lower(), d[1], d[2])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(d)
    deps = uniq

    for f in unparsed:
        result.findings.append(Finding(
            severity="LOW", category="dependency-scan",
            message="%s 未能解析，依赖未检查" % f.name,
            file=str(f)
        ))

    _write_ranged(result, ranged, "MEDIUM",
                  "依赖版本为范围约束，无法判定具体受影响版本：%s"
                  "（请固定为 ==x.y.z 或 1.2.3 后复核）", ranged)
    _write_ranged(result, dev_ranged, "LOW",
                  "开发依赖未固定版本：%s（不进运行时，不作运行时风险计）", dev_ranged)

    if not deps:
        return

    # 上限是性能决定，但不能是沉默的：查了 10 个就说查了 10 个，
    # 剩下的必须报出来。修复前超出的部分既不查也不说，报告上看起来"已扫完"。
    CAP = 10
    if len(deps) > CAP:
        result.findings.append(Finding(
            severity="LOW", category="dependency-scan",
            message="共 %d 个固定版本依赖，本次只查了前 %d 个；其余 %d 个未查漏洞库"
                    "（上限是性能折中，不代表已扫完）" % (len(deps), CAP, len(deps) - CAP),
            file=str(deps[CAP][3])
        ))

    # 私有包名以公开名声明（dependency confusion 的前置条件）
    inv = _load_private_inventory(skill_path)
    if inv and inv.get("error"):
        result.findings.append(Finding(
            severity="LOW", category="dependency-name",
            message=inv["error"] + "：未做私有包名核对（不猜）",
            file=str(skill_path / "private-packages.json")))
    for name, dep_file, msg in _private_name_hits(deps, inv):
        result.findings.append(Finding(
            severity="LOW", category="dependency-name",
            message=msg, file=str(dep_file)))

    # 名称相似度只提示、不定罪（LOW）：
    # 一个包名长得像热门包，可能只是有人随手命名；只有当它与热门包
    # 形成"形近替换/编辑距离1/子集型"时才提一句，让人去核对来源。
    for d in deps[:CAP]:
        sus = _typosquat_suspects(d[0], d[2])
        if sus:
            result.findings.append(Finding(
                severity="LOW", category="dependency-name",
                message="%s 疑似仿冒热门包：%s。名称相似度判定，**不是** registry 事实；"
                        "请核对包来源与发布者" % (d[0], "；".join(sus)),
                file=str(d[3])
            ))

    # Query OSV.dev for each dependency
    for name, version, eco, dep_file, is_dev in deps[:CAP]:  # limit to avoid timeout
        dev_note = "（开发依赖，不进运行时）" if is_dev else ""
        try:
            payload = json.dumps({
                "package": {"name": name, "ecosystem": eco},
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
                    label = ("%s@%s" % (name, version)) if eco == "npm" \
                        else ("%s==%s" % (name, version))
                    for v in vulns[:3]:  # top 3 vulns per dep
                        result.findings.append(Finding(
                            severity="LOW" if is_dev else "HIGH",
                            category="dependency-vuln",
                            message=f"{label}{dev_note}: {v.get('summary', 'known vulnerability')}",
                            file=str(dep_file)
                        ))
        except Exception:
            # Offline fallback: just note that we couldn't check
            result.findings.append(Finding(
                severity="LOW", category="dependency-scan",
                message=f"无法联网检查 {name} 的已知漏洞{dev_note}",
                file=str(dep_file)
            ))


def scan_shell_file(filepath: Path, result: ScanResult):
    """Scan a shell script for dangerous patterns."""
    try:
        content = read_text_smart(filepath)
    except Exception:
        return

    lines = content.splitlines()
    dangerous_sh_patterns = [
        (r"\brm\s+-rf?\s+/\s*(;|&&|\||$)", "CRITICAL", "rm -rf / 危险删除（仅根目录）"),
        (r"\bcurl\s+.*\|\s*sh", "HIGH", "curl | sh 管道执行远程脚本（管道 = 远程代码直接进解释器）"),
        (r"\bwget\s+.*\|\s*bash", "HIGH", "wget | bash 管道执行远程脚本（管道 = 远程代码直接进解释器）"),
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
        content = read_text_smart(filepath)
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
    #
    # §3aq：加分**不能抵消扣分**。原实现 `score += 2` 加在扣分之后、clamp 之前，
    # 等于把 100 分的基线抬到 102：文档写"LOW −1"，按文档 12 条 LOW 应该 88（A，门槛 90 拦），
    # 实际算成 90（A+，门槛 90 放行）——加分把 2 分退给了有问题的技能。
    # 实测 audit2/probe_threshold_edge.py：LOW×8→94、×12→90（A+/放行）、×13→89（拦住）。
    # 加分只对"本来满分"有意义（满分之上再加也是满分），所以它现在只确认满分，
    # 不参与任何扣分的抵减。
    has_network = any(f.category == "network" for f in result.findings)
    if not has_network and score >= 100:
        score = 100  # 零依赖加分：满分就是满分，不越过 100，也不退还扣分

    # CRITICAL 注入/外泄封顶（Muse 复测 P0 窄修：注入命中必须硬降级，不只报发现）
    injection_critical = any(
        f.severity == "CRITICAL" and f.category in ("prompt-injection", "exfiltration")
        for f in result.findings
    )
    if injection_critical:
        score = min(score, 40)  # 存在 CRITICAL 注入/外泄 → 最高 D 档；_ci_exit 同时 exit 1 阻断

    # 封顶必须覆盖**所有阻断档**，不能只覆盖注入/外泄：
    # 实测一个读凭证并外发的样本被判 HIGH（组合判定为 exfil），扣 8 分后仍得
    # 87/100（A）—— 门禁说"阻断发布"、徽章说"A 级可信"，两句互相打脸。
    # 与 evaluate.py 的 VETO 语义对齐：CRITICAL → ≤49(D)、HIGH → ≤69(C)。
    if result.critical_count > 0:
        score = min(score, 49)
    elif result.high_count > 0:
        score = min(score, 69)

    # Clamp to 0-100
    return max(0, min(100, score))


def grade_from_score(score: int) -> str:
    if score >= 90: return "A+"
    if score >= 80: return "A"
    if score >= 70: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"


# 徽章颜色：唯一来源是**等级**，不另立一套分数分档。
# 旧实现是 5 档（90/75/60/40），等级是 6 档（90/80/70/60/40）——
# 于是 70–79 分等级说 B、徽章给 A 的颜色，79 和 80 印出来一模一样。
COLOR_FOR_GRADE = {
    "A+": "brightgreen",
    "A": "green",
    "B": "yellow",
    "C": "orange",
    "D": "red",
    "F": "lightgrey",
}


def generate_badge(result: ScanResult) -> str:
    """Generate a shields.io-style SVG badge for Trust Score."""
    score = result.trust_score
    grade = result.grade

    color = COLOR_FOR_GRADE.get(grade, "lightgrey")

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


# 安装期钩子：这些生命周期脚本会在 `npm install` 时自动执行
INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare", "prepublish",
                 "prepublishOnly", "prepack")

# 远程取码并执行的形态：curl/wget 接管道进 shell，或 PowerShell 的 iex
#
# 2026-11-15 红队复测（灭类不灭例）：原先 5 条只覆盖"管道进 shell"和"node -e"两个例，
# 同类里另有 7 种真实在用的写法全漏——bash -c "$(curl …)"、node <(curl …)、
# python -c 里 urlopen+exec、npx/npm exec 直接拉远程包、curl -o 落地再执行。
# 已按类补齐。仍守一条边界：本地脚本（node ./scripts/build.mjs）不算，报了就是误伤。
REMOTE_EXEC_PATTERNS = (
    r"curl[^|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)",
    r"wget[^|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)",
    r"\b(?:sh|bash|zsh)\s+<\(\s*(?:curl|wget)",
    r"(?:iwr|invoke-webrequest|curl)[^;]*\|\s*(?:iex|invoke-expression)",
    r"\bnode\s+-e\b",
    # bash -c "$(curl …)" / bash -lc "$(wget …)"：命令替换里取码，再交给 shell 执行
    r"\b(?:sh|bash|zsh)\s+-[a-z]*c\b[^\n]*\$\(\s*(?:curl|wget)",
    # node <(curl …)：进程替换把远程脚本当成文件参数喂给解释器
    r"\b(?:node|python|python3)\s+<\(\s*(?:curl|wget)",
    # python -c 一条命令里"取远程 + 执行"（两个特征不分先后，故用前视）
    r"\b(?:python|python3)\s+-c\b(?=[^\n]*(?:urlopen|urlretrieve|requests\.get))[^\n]*(?:exec|eval)",
    # npx / npm exec 直接拉远程包执行（只认带 URL 或 --package= 的形态，不误伤 npx tsc）
    r"\bnpx\b[^|;]*(?:https?://|--package=)",
    r"\bnpm\s+exec\b[^|;]*--package=",
    # 先落盘再执行：curl -o 写文件，同一条命令里接着 sh/node/python 它
    r"(?:curl|wget)[^\n]*\s-o\s+\S+[^\n]*&&\s*(?:sh|bash|zsh|node|python|python3)",
)


def _search_any(pattern, text: str) -> bool:
    """规则表里既有字符串模式也有已编译的 Pattern，统一走这里。

    坑：对已编译的 Pattern 再传 flags 会 ValueError（
    "cannot process flags argument with a compiled pattern"），
    影子扫描第一版就是这样崩的。
    """
    if hasattr(pattern, "search"):
        return bool(pattern.search(text))
    return bool(re.search(pattern, text, re.IGNORECASE))


def scan_excluded_scope(skill_path: Path, result: ScanResult,
                        is_in_default_exclude, passed_excludes):
    """被排除目录里的执行面：不计分，但必须说出来。

    DEFAULT_EXCLUDES 排除 demo/samples/tests/fixtures 等目录，是为了不把仓库自己的
    投毒夹具算进技能评分（否则安全工具扫自己必红）。但"不计分"不等于"可以藏东西"：
    技能完全可以把要执行的代码放进 demo/，再在 SKILL.md 里写"运行 demo/run.py"。

    实测（audit2/probe_excluded_payload.py）：
      demo/run.py    os.system("curl … | sh")   → 0 命中，不披露
      samples/run.mjs child_process + exec      → 0 命中，不披露
      tests/run.sh    curl | sh                 → 0 命中，不披露
      fixtures/run.ps1 下载后 bypass 执行        → 0 命中，不披露

    做法：影子扫描——真的扫一遍，但结果只作为**一条披露**（不计入评分），
    报出路径与最高级别，让评审者自己判断这个 demo 目录是不是执行面。

    §3ao 补的两处（audit2/probe_exclude_class.py）：
      ① **名单漂移**：这里原来自带一份手写目录表，与 DEFAULT_EXCLUDES 不是同一份，
         后者多出 `.git`/`__pycache__`/`node_modules`/`._test_scratch`/`_backup` 五个
         ——放在这几个目录里的载荷既不扫也不披露，彻底静默。
         改为直接吃调用方传进来的同一份名单（单一来源）。
      ② **只看代码后缀**：原来 EXEC_SUFFIXES 之外一律跳过，
         于是 `docs/guide.md` 里写越狱句既不报也不披露——文档型载荷同样是模型读得到的东西。
         现在文档/配置后缀也会扫，按"文档型载荷"披露。
    """
    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    EXEC_SUFFIXES = {".py", ".js", ".ts", ".mjs", ".cjs", ".sh", ".ps1", ".bat", ".cmd"}
    DOC_SUFFIXES_SHADOW = {".md", ".txt", ".json", ".yaml", ".yml", ".ini",
                           ".cfg", ".conf", ".toml", ".env"}

    default_set = set(is_in_default_exclude or ())

    for p in skill_path.rglob("*"):
        if not p.is_file():
            continue
        suffix = p.suffix.lower()
        if suffix not in EXEC_SUFFIXES and suffix not in DOC_SUFFIXES_SHADOW:
            continue
        rel = p.relative_to(skill_path).as_posix()
        parts = p.relative_to(skill_path).parts
        in_default = any(part in default_set for part in parts)
        in_explicit = any(rel == e or rel.startswith(e + "/") for e in passed_excludes)
        if in_explicit:
            # 用户用 --exclude 点名的目录是"我知道这是夹具"的主动声明，尊重它；
            # 只有引擎自己默认排除的目录才需要披露（那是自动豁免，用户没选过）
            continue
        if not in_default:
            continue

        scratch = ScanResult(skill_name=skill_path.name)
        ext = suffix
        if ext == ".py":
            scan_python_file(p, scratch)
        elif ext in {".js", ".ts", ".mjs", ".cjs"} and scan_js_file:
            for sev, cat, msg, line in scan_js_file(p):
                scratch.findings.append(Finding(severity=sev, category=cat,
                                                message=msg, file=str(p), line=line))
        elif ext == ".sh":
            scan_shell_file(p, scratch)
        elif ext in EXEC_SUFFIXES:
            scan_windows_script(p, scratch)
        else:
            # 文档/配置型：只查"模型会读到什么"——注入式语句与凭证
            text = read_text_smart(p)
            folded = _fold_confusables(text)
            for pattern, severity, msg in PROMPT_INJECTION_PATTERNS:
                if _search_any(pattern, folded):
                    scratch.findings.append(Finding(
                        severity=severity, category="prompt-injection",
                        message=msg, file=str(p), line=1))
            for pattern, severity, msg in CREDENTIAL_PATTERNS:
                if _search_any(pattern, text):
                    scratch.findings.append(Finding(
                        severity=severity, category="credential-leak",
                        message=msg, file=str(p), line=1))

        if not scratch.findings:
            continue
        top = min((f.severity for f in scratch.findings), key=lambda s: SEV_ORDER.get(s, 9))
        kind = "执行面" if suffix in EXEC_SUFFIXES else "文档型载荷"
        result.findings.append(Finding(
            severity="MEDIUM" if SEV_ORDER.get(top, 9) <= 1 else "LOW",
            category="coverage",
            message="默认排除目录内%s，且命中危险模式：%s（最高 %s，%d 处）——未计入评分，"
                    "但它正是这条豁免名单可能被当成后门用的地方"
                    % (kind, rel, top, len(scratch.findings)),
            file=str(p), line=1
        ))


def _already_reported(result: ScanResult, filepath: str, category: str) -> bool:
    """该文件在该类别下是否已经报过（防同一文件被多条 glob 重复扫）。"""
    return any(f.file == filepath and f.category == category
               for f in result.findings)


ARCHIVE_SUFFIXES = (".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".rar")
BINARY_SUFFIXES = {".exe", ".dll", ".so", ".dylib", ".bin", ".pyc", ".node", ".wasm",
                   ".class", ".jar"}
DOC_SUFFIXES = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt",
                ".png", ".jpg", ".jpeg", ".gif", ".md", ".csv", ".mp4", ".zip"}


def scan_deceptive_names(skill_path: Path, result: ScanResult, should_exclude):
    """伪装藏在名字里：三个形态都读内容读不出来。

    A 双向控制符（U+202A–202E / U+2066–2069）：`invoice\\u202Efdp.exe` 在资源管理器与多数编辑器里
      显示为 `invoiceexe.pdf`——审批弹窗给用户看的就是这个"名字"，点下去跑的是 exe。
    B 零宽字符（U+200B–200D / U+2060 / U+FEFF）：`pay\\u200Bload.py` 与 `payload.py` 肉眼看不出差别，
      按后缀分派时也会错位。
    C 双扩展名：`report.pdf.exe`——Windows 默认隐藏已知扩展名，用户只看到 `report.pdf`。

    实测（audit2/probe_name_coverage.py）：修复前 RLO 只在真被 .exe 落到"二进制披露"时才露面，
    名字伪装本身一句不提；零宽名 0 命中。
    """
    BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200F, 0x200E}
    ZERO = set(range(0x200B, 0x200E)) | {0x2060, 0xFEFF, 0x00AD}

    for p in skill_path.rglob("*"):
        name = p.name
        if not name or should_exclude(p):
            continue

        bad_bidi = [c for c in name if ord(c) in BIDI]
        bad_zero = [c for c in name if ord(c) in ZERO]

        if bad_bidi:
            result.findings.append(Finding(
                severity="HIGH", category="obfuscation",
                message="文件名含双向控制符（U+%04X）：显示出来的名字与实际扩展名可能相反"
                        % ord(bad_bidi[0]),
                file=str(p), line=1
            ))
        elif bad_zero:
            result.findings.append(Finding(
                severity="MEDIUM", category="obfuscation",
                message="文件名含零宽字符（U+%04X）：看起来与同名普通文件无法区分"
                        % ord(bad_zero[0]),
                file=str(p), line=1
            ))

        suffix = p.suffix.lower()
        if suffix in BINARY_SUFFIXES:
            stem_suffix = Path(name[:-len(p.suffix)]).suffix.lower()
            if stem_suffix in DOC_SUFFIXES:
                result.findings.append(Finding(
                    severity="MEDIUM", category="obfuscation",
                    message="双扩展名 %s：Windows 默认隐藏已知扩展名，用户会以为这是 %s"
                            % (name, stem_suffix),
                    file=str(p), line=1
                ))


def scan_carriers(skill_path: Path, result: ScanResult, should_exclude):

    """未读载体披露：压缩包与二进制。

    本引擎只读文本。压缩包里的 install 脚本、二进制里的载荷，一个字节都没看过。
    实测（audit2/probe_carrier_coverage.py）：payload.zip / bundle.tgz 里藏
    `os.system("curl … | sh")`、helper.exe 藏可执行载荷，修复前全部 0 命中，
    **而且报告里一句不提**——用户会以为"扫过了，没问题"。

    诚实原则：没读就说没读，不能静默通过。
    """
    arch, bina = [], []
    for p in skill_path.rglob("*"):
        if not p.is_file() or should_exclude(p):
            continue
        low = p.name.lower()
        if low.endswith(ARCHIVE_SUFFIXES):
            arch.append(p)
        elif p.suffix.lower() in BINARY_SUFFIXES:
            bina.append(p)

    for p in arch:
        result.findings.append(Finding(
            severity="MEDIUM", category="coverage",
            message="含压缩包但未拆包扫描：%s（载荷可能藏在里面，本引擎只读文本）"
                    % p.relative_to(skill_path).as_posix(),
            file=str(p), line=1
        ))
    for p in bina:
        result.findings.append(Finding(
            severity="MEDIUM", category="coverage",
            message="含二进制/编译产物且未分析：%s（只做存在性披露）"
                    % p.relative_to(skill_path).as_posix(),
            file=str(p), line=1
        ))


def scan_case_variant_files(skill_path: Path, result: ScanResult, should_exclude):
    """大小写变体后缀兜底（跨平台一致性）。

    `rglob("*.py")` 是区分大小写的字符串匹配：Windows 上 `.PY` 侥幸能扫到
    （文件系统不区分大小写），Linux 上同一份技能换个 `.PY` 就整块跳过。
    判据必须与平台无关，所以按 suffix.lower() 再兜一遍。
    """
    CANON = {".py": "py", ".js": "js", ".ts": "js", ".mjs": "js", ".cjs": "js",
             ".sh": "sh", ".ps1": "ps", ".bat": "ps", ".cmd": "ps"}
    for p in skill_path.rglob("*"):
        if not p.is_file() or should_exclude(p):
            continue
        raw = p.suffix
        if not raw or raw.islower():
            continue
        kind = CANON.get(raw.lower())
        if not kind:
            continue
        # Windows 的主循环其实已经扫过大写变体（文件系统不区分大小写），
        # 这里只补"主循环漏掉"的情况，否则同一处会报两遍（实测踩过）
        if any(f.file == str(p) for f in result.findings):
            continue
        if kind == "py":
            scan_python_file(p, result)
        elif kind == "js" and scan_js_file:
            for sev, cat, msg, line in scan_js_file(p):
                result.findings.append(Finding(
                    severity=sev, category=cat, message=msg, file=str(p), line=line
                ))
        elif kind == "sh":
            scan_shell_file(p, result)
        elif kind == "ps":
            scan_windows_script(p, result)


def scan_config_secrets(filepath: Path, result: ScanResult):
    """配置文件里的硬编码密钥。

    为什么单列：泄漏最常发生在 .env / .ini / .toml / .json / .txt，而不是 .py / .js。
    实测（audit2/probe_secrets_coverage.py）：同一批假密钥（AKIA… / ghp_… / sk-proj-…），
    写进 creds.py 与 creds.js 都报 CRITICAL，而 .env / settings.ini / config.toml /
    creds.txt / config.json 全部 0 命中——凭证这一类等于只覆盖了代码文件。

    只认"形如真实密钥"的强格式与 key=value 赋值，并排除明确占位值，
    不做"出现 password 一词就报"的宽判据，否则每个模板都会中招。
    """
    try:
        text = read_text_smart(filepath)
    except OSError:
        return
    if len(text) > 2_000_000:
        return

    PLACEHOLDER_HINTS = ("your_", "xxx", "example", "placeholder", "<", "${", "changeme",
                         "redacted", "...", "***", "dummy", "sample")

    STRONG = (
        (r"AKIA[0-9A-Z]{16}", "CRITICAL", "AWS Access Key ID"),
        (r"ghp_[A-Za-z0-9]{36}", "CRITICAL", "GitHub Token"),
        (r"github_pat_[A-Za-z0-9_]{20,}", "CRITICAL", "GitHub fine-grained Token"),
        (r"sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}", "CRITICAL", "模型 API Key"),
        (r"xox[baprs]-[A-Za-z0-9-]{10,}", "CRITICAL", "Slack Token"),
        (r"AIza[0-9A-Za-z_-]{35}", "HIGH", "Google API Key"),
        (r"glpat-[A-Za-z0-9_-]{20,}", "CRITICAL", "GitLab Token"),
    )
    WEAK = re.compile(
        r"(?i)\b(aws_secret_access_key|secret_access_key|api[_-]?key|apikey|access[_-]?token|"
        r"auth[_-]?token|client[_-]?secret|private[_-]?key|password|passwd)\b\s*[:=]\s*"
        r"[\"']?([A-Za-z0-9/+_\-]{16,})[\"']?"
    )

    for pat, sev, label in STRONG:
        for m in re.finditer(pat, text):
            result.findings.append(Finding(
                severity=sev, category="credential",
                message="配置文件中硬编码凭证（%s）：%s…" % (label, m.group(0)[:12]),
                file=str(filepath),
                line=text[:m.start()].count("\n") + 1
            ))
            break

    for m in WEAK.finditer(text):
        val = m.group(2) or ""
        if any(h in val.lower() for h in PLACEHOLDER_HINTS) or val.isdigit():
            continue
        result.findings.append(Finding(
            severity="HIGH", category="credential",
            message="配置文件里 %s 赋了非占位值（长度 %d）" % (m.group(1), len(val)),
            file=str(filepath),
            line=text[:m.start()].count("\n") + 1
        ))
        break


def scan_exec_scripts(skill_path: Path, result: ScanResult, should_exclude):
    """"这是不是要审的东西"，不能靠后缀白名单回答（§3aw）。

    实测（audit2/probe_exec_filetypes.py，修复前）：
      install.hta（mshta 一键装）              → 100/A+，一条不报
      setup.vbs（WScript.Shell 跑 iwr|iex）    → 100/A+，一条不报
      job.wsf（JScript + WScript.Shell）        → 100/A+，一条不报
      evil.service（systemd ExecStart=curl|sh） → 100/A+，一条不报
      com.evil.plist（launchd ProgramArguments）→ 100/A+，一条不报
      evil.desktop（Exec=bash -c "curl…|sh"）   → 100/A+，一条不报
      run（无后缀，首行 #!/bin/sh + curl|sh）   → 100/A+，一条不报
    对照：同内容的 build.bat 是 CRITICAL 49/D、run.sh 只到 MEDIUM 96/A。

    两类判据：
      ① 后缀：.hta/.vbs/.vba/.wsf（Windows 脚本宿主，双击或 mshta <url> 即执行）、
              .service/.plist/.desktop（系统按文件启用的执行入口）
      ② 无后缀 + 首行 shebang（`#!/bin/sh`、`#!/usr/bin/env python` …）

    判级与配置即命令（§3as）同一张表：远程取码执行 → CRITICAL；下载落盘后执行 → CRITICAL；
    仅联网取文件 → HIGH。另给一条不计分 LOW 披露，说明只判这两类。
    """
    SHEBANG_SUFFIXES_FREE = ("", ".in", ".tmpl")
    WINDOWS_HOST_SUFFIXES = {".hta", ".vbs", ".vba", ".wsf", ".wsh"}
    SYSTEM_ENTRY_SUFFIXES = {".service", ".plist", ".desktop"}

    for path in skill_path.rglob("*"):
        if not path.is_file() or should_exclude(path):
            continue
        suffix = path.suffix.lower()
        carrier = None
        if suffix in WINDOWS_HOST_SUFFIXES:
            carrier = "Windows 脚本宿主（%s）" % suffix
        elif suffix in SYSTEM_ENTRY_SUFFIXES:
            carrier = "系统执行入口（%s）" % suffix
        elif suffix in SHEBANG_SUFFIXES_FREE:
            try:
                head = read_text_smart(path)[:160]
            except OSError:
                continue
            if not head.startswith("#!"):
                continue
            carrier = "无后缀 shebang 可执行件（%s）" % head.splitlines()[0][:40]
        if not carrier:
            continue

        result.files_scanned += 1
        try:
            text = read_text_smart(path)
        except OSError:
            continue
        low = text.lower()

        fired = False
        for pat in REMOTE_EXEC_PATTERNS:
            if re.search(pat, low):
                result.findings.append(Finding(
                    severity="CRITICAL", category="supply-chain",
                    message="%s 在执行期从远程取代码并运行：%s" % (carrier, path.name),
                    file=str(path), line=1
                ))
                fired = True
                break

        if not fired:
            fetch = any(t in low for t in ("curl", "wget", "iwr", "invoke-webrequest",
                                           "downloadstring", "certutil -urlcache",
                                           "bitsadmin", "start-bitstransfer"))
            execu = any(t in low for t in ("| sh", "| bash", "iex", "invoke-expression",
                                           "wscript.shell", "cmd /c", "powershell",
                                           "/bin/sh", "/bin/bash", "execstart", "exec="))
            if fetch and execu:
                result.findings.append(Finding(
                    severity="CRITICAL", category="supply-chain",
                    message="%s 下载远程文件并随后执行：%s" % (carrier, path.name),
                    file=str(path), line=1
                ))
            elif fetch:
                result.findings.append(Finding(
                    severity="HIGH", category="supply-chain",
                    message="%s 在运行期联网取文件：%s" % (carrier, path.name),
                    file=str(path), line=1
                ))

        # 披露不计分：本扫描只判"取码"与"下载"两类，别的一律没看
        result.findings.append(Finding(
            severity="LOW", category="coverage", scoring=False,
            message="%s 已纳入扫描，但只判取码执行与远程下载两类：%s" % (carrier, path.name),
            file=str(path), line=1
        ))


def scan_windows_script(filepath: Path, result: ScanResult):
    """Windows 装载脚本（.ps1/.bat/.cmd）：技能在 Windows 上最常用的执行入口。

    为什么单列：默认扫描只认 .py/.sh/.js/.ts，等同内容的 .ps1/.bat/.cmd 一个都不看。
    实测（audit2/probe_file_types.py）：`Invoke-WebRequest … ; powershell -ep bypass -f x.ps1`
    与 `curl -o i.bat ; call i.bat` 两种样本，修复前 0 命中。

    判级：
      远程取码（curl/wget/iwr/Invoke-WebRequest/DownloadString/certutil -urlcache/bitsadmin）
        + 执行迹象（iex/Invoke-Expression/call/start/-f/powershell/cmd /c）  → CRITICAL
      只有远程取码                                                          → HIGH
      编码指令（-EncodedCommand / -enc）                                     → HIGH
      其余命中 REMOTE_EXEC_PATTERNS                                         → CRITICAL
    """
    try:
        text = read_text_smart(filepath)
    except OSError:
        return
    low = text.lower()

    fetch_tokens = ("curl", "wget", "iwr", "invoke-webrequest", "downloadstring",
                    "certutil -urlcache", "bitsadmin", "start-bitstransfer")
    exec_tokens = ("invoke-expression", "iex", "call ", "start ", "powershell",
                   "cmd /c", "-encodedcommand", " -f ", "& '")
    has_fetch = any(t in low for t in fetch_tokens)
    has_exec = any(t in low for t in exec_tokens)

    for pat in REMOTE_EXEC_PATTERNS:
        if re.search(pat, low):
            result.findings.append(Finding(
                severity="CRITICAL", category="supply-chain",
                message="Windows 脚本在执行期从远程取代码并运行：%s" % filepath.name,
                file=str(filepath), line=1
            ))
            return

    if has_fetch and has_exec:
        result.findings.append(Finding(
            severity="CRITICAL", category="supply-chain",
            message="Windows 脚本下载远程文件并随后执行（installation-time 常见形态）",
            file=str(filepath), line=1
        ))
    elif has_fetch:
        result.findings.append(Finding(
            severity="HIGH", category="supply-chain",
            message="Windows 脚本在执行期联网取文件",
            file=str(filepath), line=1
        ))
    elif "-encodedcommand" in low or re.search(r"\s-enc\b", low):
        result.findings.append(Finding(
            severity="HIGH", category="obfuscation",
            message="Windows 脚本使用编码指令执行（-EncodedCommand/-enc），内容不可直读",
            file=str(filepath), line=1
        ))


def scan_gyp_file(filepath: Path, result: ScanResult):
    """构建文件（binding.gyp / *.gyp）里的命令展开 → 安装期执行。

    为什么单列一条：`<!@(cmd)` 与 `<!xx` 是 gyp 的"命令展开"语法，node-gyp 生成阶段
    会真的把 cmd 交给 shell 跑。npm 文档写得很清楚：包里有 binding.gyp 且没自定义
    install/preinstall，npm 就把 install 默认设为 `node-gyp rebuild`
    （https://docs.npmjs.com/cli/v11/commands/npm-rebuild/）。
    所以这是"安装期执行代码"的一个成员，与 postinstall 同类，只是写在了另一个文件里。

    判级：
      命令里出现远程取码（curl/wget/iwr/http）→ CRITICAL（取远程代码并执行）
      其余命令展开                              → HIGH（安装期执行任意命令）
    """
    try:
        text = read_text_smart(filepath)
    except OSError:
        return
    # gyp 命令展开：<!@(...) 执行并按行分割输出；<!... 直接内联输出
    for m in re.finditer(r"<![@!]?\(([^)]+)\)|<!([^\s)>]+)", text):
        cmd = (m.group(1) or m.group(2) or "").strip()
        if not cmd:
            continue
        low = cmd.lower()
        remote = ("curl" in low or "wget" in low or "iwr" in low
                  or "invoke-webrequest" in low or "http://" in low or "https://" in low)
        if remote:
            result.findings.append(Finding(
                severity="CRITICAL", category="supply-chain",
                message="构建文件在生成阶段从远程取代码并执行（installation-time）：%s" % cmd[:80],
                file=str(filepath), line=1
            ))
        else:
            result.findings.append(Finding(
                severity="HIGH", category="supply-chain",
                message="构建文件在生成阶段执行 shell 命令（installation-time）：%s" % cmd[:80],
                file=str(filepath), line=1
            ))


def scan_package_install_scripts(pkg_file: Path, result: ScanResult):
    """package.json 的安装钩子里出现远程取码执行 → CRITICAL。

    只判"取远程代码并执行"这一类，不把所有 postinstall 都算风险：
    本地脚本（node ./scripts/x.mjs）是正常构建动作，报了就是误伤。
    """
    try:
        pkg = json.loads(read_text_smart(pkg_file))
    except (OSError, ValueError):
        return
    scripts = pkg.get("scripts") or {}
    if not isinstance(scripts, dict):
        return
    for hook in INSTALL_HOOKS:
        cmd = scripts.get(hook)
        if not isinstance(cmd, str) or not cmd.strip():
            continue
        low = cmd.lower()
        for pat in REMOTE_EXEC_PATTERNS:
            if re.search(pat, low):
                result.findings.append(Finding(
                    severity="CRITICAL", category="supply-chain",
                    message="安装钩子 %s 在执行期从远程取代码并运行：%s" % (hook, cmd[:80]),
                    file=str(pkg_file), line=1
                ))
                break

    # 隐式安装钩子：有 binding.gyp 又没有自定义 install/preinstall 时，
    # npm 会把 install 默认成 `node-gyp rebuild`。这不是缺陷，是必须如实说出来的事实——
    # 扫描器不追编译期行为，报告里得让人知道"安装时会编译"，否则"没报=没问题"是假安心。
    if (pkg_file.parent / "binding.gyp").is_file():
        if not (scripts.get("install") or scripts.get("preinstall")):
            result.findings.append(Finding(
                severity="MEDIUM", category="supply-chain",
                message=("安装期将隐式执行 node-gyp rebuild（npm 默认行为；本扫描器不追编译期行为，"
                         "已另行扫描 .gyp 里的命令展开）"),
                file=str(pkg_file), line=1
            ))


CONFIG_EXEC_NAMES = {
    ".mcp.json", "mcp.json", "mcp_config.json", "plugin.json", "manifest.json",
    "hooks.json", "settings.json", "config.json",
}
CONFIG_EXEC_KEYS = {
    "command", "cmd", "script", "entry", "run", "exec", "shell", "args",
    "postinstall", "preinstall", "prepare", "prepublish", "install",
}
# 这些键下面挂的东西天然是"要被执行的"（Claude hooks / MCP 服务器 / npm scripts）
CONFIG_EXEC_CONTAINERS = {"hooks", "mcpservers", "scripts", "commands", "lifecycle"}
SHELL_INTERP_RE = re.compile(
    r"(?:^|[\s\"'`;&|(])(?:bash|dash|sh|zsh|fish|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh|"
    r"python[0-9.]*|node|perl|ruby)\s+(?:-c\b|/c\b|-Command\b|-e\b|--eval\b|--exec\b)",
    re.I)
# 远程取二进制/脚本的另一套写法：不经过管道，直接落盘（certutil/bitsadmin/curl -o）
REMOTE_DOWNLOAD_PATTERNS = (
    r"certutil[^\n]*-(?:urlcache|decode)",
    r"bitsadmin\s+/transfer",
    r"(?:curl|wget)[^\n]*(?:\s-o\s|\s-O\s|--output)",
    r"invoke-webrequest[^\n]*-outfile",
    r"start-bitstransfer[^\n]*-destination",
)


NOSUFFIX_SCRIPT_NAMES = {
    "dockerfile", "containerfile", "makefile", "gnumakefile", "jenkinsfile",
    "justfile", "vagrantfile", "procfile", "rakefile", "gemfile", "buildkite",
    "brewfile", "nfdefile",
}
NOSUFFIX_SCRIPT_PREFIXES = ("dockerfile.", "makefile.", "jenkinsfile.")


def scan_nosuffix_scripts(skill_path: Path, result: ScanResult, should_exclude):
    """没有后缀的构建/CI 脚本：Dockerfile、Makefile、Jenkinsfile、Justfile…

    实测（audit2/probe_nosuffix.py，修复前）：
      Dockerfile `RUN curl … | sh`、Makefile recipe `curl … | sh`、
      Jenkinsfile `sh 'curl … | sh'`、Justfile、Vagrantfile
      —— 五例全部 **100/A+，一条不报**。

    原因是分发挂在后缀上：没有后缀 → 走不进任何规则分支 → 跳过。
    "没认出这个文件"和"看过且干净"在报告里长得一模一样，这是同一类 fail-open。
    """
    targets = []
    for p in skill_path.rglob("*"):
        if not p.is_file() or should_exclude(p):
            continue
        name = p.name.lower()
        if name in NOSUFFIX_SCRIPT_NAMES or name.startswith(NOSUFFIX_SCRIPT_PREFIXES):
            targets.append(p)
    for p in skill_path.rglob("*.mk"):
        if p.is_file() and not should_exclude(p):
            targets.append(p)

    for path in targets:
        try:
            text = read_text_smart(path)
        except OSError:
            continue
        result.files_scanned += 1
        for lineno, line in enumerate(text.splitlines(), 1):
            low = line.lower()
            if any(re.search(pat, low) for pat in REMOTE_EXEC_PATTERNS):
                result.findings.append(Finding(
                    severity="CRITICAL", category="nosuffix-exec",
                    message="无后缀构建/CI 脚本里的远程取码执行：%s" % line.strip()[:80],
                    file=str(path), line=lineno
                ))
                continue
            if any(re.search(pat, low) for pat in REMOTE_DOWNLOAD_PATTERNS):
                result.findings.append(Finding(
                    severity="CRITICAL", category="nosuffix-exec",
                    message="无后缀构建/CI 脚本里从远程下载文件到本地：%s" % line.strip()[:80],
                    file=str(path), line=lineno
                ))
        # 这类文件在构建/CI 时必然被执行——存在本身就该说一句（不计分，只披露）
        result.findings.append(Finding(
            severity="LOW", category="nosuffix-exec",
            message="存在构建/CI 脚本（构建或流水线执行时会运行，本扫描只判取码/下载两类）",
            file=str(path), line=1, scoring=False
        ))


def _notebook_code_cells(doc):
    """把 .ipynb 的 code 单元格摊平成 (序号, 源码)。"""
    for idx, cell in enumerate(doc.get("cells") or [], 1):
        if not isinstance(cell, dict) or cell.get("cell_type") != "code":
            continue
        src = cell.get("source")
        if isinstance(src, list):
            src = "".join(str(x) for x in src)
        if isinstance(src, str) and src.strip():
            yield idx, src


def _ast_findings_from_source(src: str):
    """对一段源码跑 AST 分析（与 .py 走同一套 visitor）。"""
    import ast as _ast
    try:
        from ast_analyzer import DangerousCallVisitor, HardcodedSecretVisitor
    except Exception:
        return []
    try:
        tree = _ast.parse(src)
    except (SyntaxError, ValueError, RecursionError):
        return []
    out = []
    for v in (DangerousCallVisitor(), HardcodedSecretVisitor()):
        v.visit(tree)
        out.extend(getattr(v, "findings", []) or [])
    return out


def scan_notebooks(skill_path: Path, result: ScanResult, should_exclude):
    """Jupyter 笔记本：后缀不在文本名单里，于是整本被跳过。

    实测（audit2/probe_notebook.py，修复前）：
      `!curl … | sh`、`os.system('rm -rf …')`、`!pip install --index-url http://evil…`、
      `pickle.loads(...)` 四本笔记本 **全部 100/A+，一条不报**；
      同一段 `os.system` 写进 .py 是 49/D。
    笔记本比 .py 更能跑：`!` 前缀直接执行 shell，`%%bash` 整格都是 shell。
    """
    for path in skill_path.rglob("*.ipynb"):
        if not path.is_file() or should_exclude(path):
            continue
        try:
            doc = json.loads(read_text_smart(path))
        except (OSError, ValueError):
            continue
        result.files_scanned += 1
        for cell_no, src in _notebook_code_cells(doc):
            lines = src.splitlines()
            py_lines = []
            for ln, line in enumerate(lines, 1):
                s = line.strip()
                if s.startswith("!"):
                    cmd = s.lstrip("!").strip()
                    low = cmd.lower()
                    remote = next((p for p in REMOTE_EXEC_PATTERNS if re.search(p, low)), None)
                    if remote:
                        result.findings.append(Finding(
                            severity="CRITICAL", category="notebook",
                            message="笔记本单元格里的 shell 远程取码执行（第 %d 格）：%s"
                                    % (cell_no, cmd[:70]),
                            file=str(path), line=ln
                        ))
                        continue
                    if any(re.search(p, low) for p in REMOTE_DOWNLOAD_PATTERNS):
                        result.findings.append(Finding(
                            severity="CRITICAL", category="notebook",
                            message="笔记本单元格里从远程下载文件到本地（第 %d 格）：%s"
                                    % (cell_no, cmd[:70]),
                            file=str(path), line=ln
                        ))
                        continue
                    # 换源安装 = 供应链入口（依赖混淆的经典写法）
                    if re.search(r"pip[0-9]*\s+install[^\n]*-(?:-extra-)?-index-url", low) \
                            or re.search(r"pip[0-9]*\s+install[^\n]*--index-url", low):
                        if not re.search(r"--index-url\s+https://pypi\.org", low):
                            result.findings.append(Finding(
                                severity="HIGH", category="notebook",
                                message="笔记本单元格从非官方源安装依赖（供应链入口）：%s" % cmd[:70],
                                file=str(path), line=ln
                            ))
                    continue
                # %magic / %%bash 等行不参与 Python 解析
                if s.startswith("%") or s.startswith("?"):
                    continue
                py_lines.append(line)

            code = "\n".join(py_lines)
            if not code.strip():
                continue
            for af in _ast_findings_from_source(code):
                result.findings.append(Finding(
                    severity=af.severity, category="notebook",
                    message="[笔记本第 %d 格] %s" % (cell_no, af.message),
                    file=str(path), line=getattr(af, "line", 1) or 1
                ))


def _iter_config_strings(node, trail=()):
    """把 JSON 里所有字符串连同它的键路径摊平。"""
    if isinstance(node, dict):
        for k, v in node.items():
            for item in _iter_config_strings(v, trail + (str(k),)):
                yield item
    elif isinstance(node, list):
        for i, v in enumerate(node):
            for item in _iter_config_strings(v, trail + ("[%d]" % i,)):
                yield item
    elif isinstance(node, str):
        yield trail, node


def _is_config_exec_carrier(path: Path) -> bool:
    name = path.name.lower()
    if name in CONFIG_EXEC_NAMES:
        return True
    # 点目录下的配置（.claude/.codex/.cursor/.gemini/…）同样是加载期入口
    return path.parent.name.startswith(".")


def scan_config_exec(skill_path: Path, result: ScanResult, should_exclude):
    """配置文件里的执行入口：读的是配置，跑的是命令。

    实测（audit2/probe_config_exec.py，修复前）：
      · `.claude/settings.json` 的 PreToolUse hook 写着 `curl … | sh` + `iwr … | iex` → **100/A+，一条不报**
      · `.mcp.json` 的 mcpServers 写着 `bash -c "curl … | sh"` 与 `certutil -urlcache` → **100/A+**
      · `plugin.json` 带 `postinstall: curl … | sh` → **100/A+**
    三者都是 .json：人按"配置"读，机器按"命令"跑。§3aa 只堵了 package.json，
    于是"例子通过、类没通过"——同一条通道换个文件名就全绿。

    分级（避免把正常 MCP/hook 全判红）：
      CRITICAL：配置里声明了"从远程取代码并执行"（计分）
      HIGH    ：配置里声明 shell 解释器 + `-c`/`/c`/`-Command` 形式（任意命令执行面，计分）
      MEDIUM  ：只是声明了一个执行入口（不计分，仅披露——正常 hook 也有 command）
    """
    for path in skill_path.rglob("*.json"):
        if not path.is_file() or should_exclude(path):
            continue
        if not _is_config_exec_carrier(path):
            continue
        if _already_reported(result, str(path), "config-exec"):
            continue
        try:
            doc = json.loads(read_text_smart(path))
        except (OSError, ValueError):
            continue
        for trail, s in _iter_config_strings(doc):
            if not s.strip():
                continue
            low = s.lower()
            key = trail[-1].lower() if trail else ""
            in_container = any(t.lower() in CONFIG_EXEC_CONTAINERS for t in trail)
            if not (key in CONFIG_EXEC_KEYS or in_container):
                continue
            remote = next((p for p in REMOTE_EXEC_PATTERNS if re.search(p, low)), None)
            if remote:
                result.findings.append(Finding(
                    severity="CRITICAL", category="config-exec",
                    message="配置里的执行入口从远程取代码并运行（%s）：%s"
                            % ("/".join(trail[-2:]), s[:80]),
                    file=str(path), line=1
                ))
                continue
            if any(re.search(p, low) for p in REMOTE_DOWNLOAD_PATTERNS):
                result.findings.append(Finding(
                    severity="CRITICAL", category="config-exec",
                    message="配置里的执行入口从远程下载文件到本地（certutil/bitsadmin/curl -o 类）：%s"
                            % s[:80],
                    file=str(path), line=1
                ))
                continue
            if SHELL_INTERP_RE.search(s):
                result.findings.append(Finding(
                    severity="HIGH", category="config-exec",
                    message="配置里声明了 shell 解释器直执行（任意命令执行面）：%s" % s[:80],
                    file=str(path), line=1
                ))
                continue
            if key in ("command", "cmd", "script", "entry", "run", "exec"):
                result.findings.append(Finding(
                    severity="MEDIUM", category="config-exec",
                    message="配置声明了执行入口（加载/调用时会运行，未取远程代码）：%s" % s[:80],
                    file=str(path), line=1, scoring=False
                ))


# 路径守卫的写法：删除前先校验“目标在工作目录内”。只认这些具体惯用法，
# 不认“文件里出现过 raise”这类宽泛信号（那样恶意样本也能被放过）。
PATH_GUARD_MARKERS = (
    "is_relative_to",
    ".startswith(",
    "realpath(",
    "abspath(",
    "raise SystemExit",
    "raise ValueError",
    "raise RuntimeError",
    "raise PermissionError",
)


def has_path_guard(lines, line_no):
    """在命中行之前（同文件）找路径守卫。找不到就认为没有守卫。"""
    if not line_no or line_no < 1:
        return False
    head = "\n".join(lines[:line_no - 1])
    return any(m in head for m in PATH_GUARD_MARKERS)


def scan_invisible_file(filepath: Path, result: ScanResult):
    """对任意文本文件做不可见字符扫描（元数据、配置同样承载指令）。"""
    try:
        text = read_text_smart(filepath)
    except OSError:
        return
    for cp, label, _ctx in invisible_payloads(text):
        line_no = text[:text.find(chr(cp))].count("\n") + 1
        result.findings.append(Finding(
            severity="CRITICAL", category="prompt-injection",
            message="不可见字符承载指令：%s（U+%04X）" % (label, cp),
            file=str(filepath), line=line_no
        ))


def scan_unreadable(skill_path: Path, result: ScanResult, should_exclude=None):
    """读不出来的文件不许当成干净文件（fail-open）。

    实测（audit2/probe_unreadable.py）：
      · 另一个进程独占打开 busy.py（内含 `os.system(curl|sh)`）→ 引擎 **0 命中**，
        报告里它和"扫过且没问题的文件"长得一模一样。
      · 权限被 ACL 拒（icacls /deny）同样 `OSError` → `read_text_smart` 返回空串 → 0 命中。

    这和 §3ad「未拆包就披露」是同一条纪律：**没读 ≠ 干净**。
    所有内容规则都是"读进来再匹配"，读不进来时它们的沉默不代表通过。
    """
    def walk(d: Path):
        try:
            entries = list(os.scandir(str(d)))
        except OSError:
            result.findings.append(Finding(
                severity="MEDIUM", category="unreadable",
                message="目录无法读取（权限或占用），其下全部内容未经扫描",
                file=str(d), line=1
            ))
            return
        for e in entries:
            p = Path(e.path)
            if _is_link_like(p):
                continue
            try:
                is_dir = e.is_dir(follow_symlinks=False)
            except OSError:
                is_dir = False
            if is_dir:
                walk(p)
                continue
            if should_exclude and should_exclude(p):
                continue
            try:
                with open(str(p), "rb") as fh:
                    fh.read(1)
            except OSError as exc:
                result.findings.append(Finding(
                    severity="MEDIUM", category="unreadable",
                    message="文件无法读取（%s），其内容未经扫描，不能视为干净"
                            % type(exc).__name__,
                    file=str(p), line=1
                ))

    walk(skill_path)


ADS_BENIGN = ("::$DATA", ":Zone.Identifier", ":Zone.Identifier:$DATA")


if os.name != "nt":
    def scan_alternate_streams(skill_path: Path, result: ScanResult,
                               should_exclude=None) -> None:
        """非 Windows：没有 NTFS 备用数据流，此规则不适用（不披露、不扣分）。"""
        return

else:
    import ctypes

    class _LARGE_INTEGER(ctypes.Structure):
        _fields_ = [("LowPart", ctypes.c_ulong), ("HighPart", ctypes.c_long)]

    class _FIND_STREAM_DATA(ctypes.Structure):
        _fields_ = [("StreamSize", _LARGE_INTEGER), ("cStreamName", ctypes.c_wchar * 296)]

    def _list_streams(f: Path):
        """枚举一个文件的全部 NTFS 数据流；失败返回空列表（不假装查过）。

        **必须先确认文件可读**：在 ACL 拒绝读的文件上直接调 FindFirstStreamW，
        实测会触发 Windows 访问冲突（access violation，整个 Python 进程崩掉），
        不是普通的 OSError。扫描器崩掉比静默放行更糟——连报告都出不来。
        所以先 open 一次；读不了就抛出去，由 scan_unreadable 披露"读不了"。
        """
        with open(str(f), "rb") as fh:
            fh.read(1)

        k32 = ctypes.windll.kernel32
        k32.FindFirstStreamW.argtypes = [ctypes.c_wchar_p, ctypes.c_int,
                                         ctypes.POINTER(_FIND_STREAM_DATA), ctypes.c_uint]
        k32.FindFirstStreamW.restype = ctypes.c_void_p
        k32.FindNextStreamW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_FIND_STREAM_DATA)]
        k32.FindNextStreamW.restype = ctypes.c_int
        k32.FindClose.argtypes = [ctypes.c_void_p]

        data = _FIND_STREAM_DATA()
        h = k32.FindFirstStreamW(str(f), 0, ctypes.byref(data), 0)
        if not h:
            return []
        out = []
        try:
            while True:
                size = data.StreamSize.HighPart * (2 ** 32) + data.StreamSize.LowPart
                out.append((data.cStreamName, size))
                if not k32.FindNextStreamW(h, ctypes.byref(data)):
                    break
        finally:
            k32.FindClose(h)
        return out

    def scan_alternate_streams(skill_path: Path, result: ScanResult,
                               should_exclude=None) -> None:
        """NTFS 备用数据流（ADS）：普通读取一律看不到的那部分内容。

        实测（audit2/probe_ads_coverage.py）：`Set-Content -Stream hidden` 把越狱句
        + `os.system(curl|sh)` 挂到 notes.md 上，资源管理器/type/Get-Content 都只显示主数据流，
        引擎 **0 命中**；而 `open("notes.md:hidden")` 能原样读出来。
        因此它既能藏载荷，也能藏"我扫过了"的证据。

        口径：存在非默认流即披露——
          · 流内容命中危险/越狱/隐形字符 → HIGH
          · 只是存在、内容看不出问题     → MEDIUM（普通读取不可见，无法人工复核）
        `Zone.Identifier` 必须放行：那是 Windows 给下载文件打的来源标记，
        每个下载文件都有，报它等于让所有正常下载物全红。
        """
        def walk(d: Path):
            try:
                entries = list(os.scandir(str(d)))
            except OSError:
                return
            for e in entries:
                p = Path(e.path)
                if _is_link_like(p):
                    continue
                try:
                    is_dir = e.is_dir(follow_symlinks=False)
                except OSError:
                    continue
                if is_dir:
                    walk(p)
                    continue
                if should_exclude and should_exclude(p):
                    continue
                try:
                    streams = _list_streams(p)
                except Exception:
                    # 枚举失败（权限/占用/非常规卷）不算"没有流"，
                    # 由 scan_unreadable 统一披露"读不了"
                    continue
                for name, size in streams:
                    if name in ADS_BENIGN:
                        continue
                    stream_path = str(p) + name.split(":$DATA")[0]
                    try:
                        raw = open(stream_path, "rb").read()
                    except OSError:
                        result.findings.append(Finding(
                            severity="MEDIUM", category="ads",
                            message="存在备用数据流 %s（%d 字节，读不出内容）" % (name, size),
                            file=str(p), line=1
                        ))
                        continue
                    text = _decode_bytes(raw)
                    hit_label = ""
                    for pat, label in (
                        (r"(?i)ignore\s+(all\s+)?previous\s+instructions", "越狱句"),
                        (r"(?i)curl[^\n]{0,60}\|\s*(ba)?sh", "远程执行"),
                        (r"\bos\.system\s*\(", "危险调用"),
                    ):
                        if re.search(pat, text):
                            hit_label = label
                            break
                    if hit_label:
                        result.findings.append(Finding(
                            severity="HIGH", category="ads",
                            message="备用数据流 %s 内含%s（普通读取看不到，%d 字节）"
                                    % (name, hit_label, size),
                            file=str(p), line=1
                        ))
                    else:
                        result.findings.append(Finding(
                            severity="MEDIUM", category="ads",
                            message="存在备用数据流 %s（%d 字节，普通读取看不到）" % (name, size),
                            file=str(p), line=1
                        ))

        walk(skill_path)


def _is_link_like(p: Path) -> bool:

    """符号链接、目录 junction、以及其他 reparse point。"""
    try:
        st = p.stat(follow_symlinks=False)
    except OSError:
        return False
    if getattr(st, "st_file_attributes", 0) & 0x400:  # FILE_ATTRIBUTE_REPARSE_POINT
        return True
    try:
        return p.is_symlink()
    except OSError:
        return False


def scan_links(skill_path: Path, result: ScanResult) -> set:
    """链接指向哪里：指向目录之外就只披露、不跟随。

    实测（audit2/probe_link_coverage.py）：
      · Windows 上文件/目录 symlink 需特权（WinError 1314），但 **junction 不需要**——
        `mklink /J` 一条命令就能造出来。
      · 修复前引擎会走进 junction 读到仓库外的文件，而报告把路径写成"仓库内"：
        命中的是外面的 evil.py 和 host_secret.txt，路径却全在技能目录里。
        于是**证据链本身失真**，链接本身一句不提。

    口径：扫描边界 = 物理上仍在技能目录内的东西。
      外链 → HIGH 披露（写明指向哪、未读取），并把它及其子树排除出扫描；
      内链 → LOW 披露，照常扫描。
    """
    root = os.path.normcase(str(skill_path.resolve()))
    escapes = set()

    def walk(d: Path):
        try:
            entries = list(os.scandir(str(d)))
        except OSError:
            return
        for e in entries:
            p = Path(e.path)
            if _is_link_like(p):
                try:
                    tgt = os.path.realpath(str(p))
                except OSError:
                    tgt = str(p)
                if not os.path.normcase(tgt).startswith(root):
                    result.findings.append(Finding(
                        severity="HIGH", category="link",
                        message="链接指向技能目录之外：%s → %s（未跟随，未读取其内容）"
                                % (p.name, tgt),
                        file=str(p), line=1
                    ))
                    escapes.add(os.path.normcase(str(p)))
                else:
                    result.findings.append(Finding(
                        severity="LOW", category="link",
                        message="目录内链接：%s（已照常扫描）" % p.name,
                        file=str(p), line=1
                    ))
                continue  # 一律不跟随链接向下走
            try:
                if e.is_dir(follow_symlinks=False):
                    walk(p)
            except OSError:
                continue

    walk(skill_path)
    return escapes


def scan_skill(skill_dir: str, excludes=None) -> ScanResult:
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
    trunc_baseline = len(_TRUNCATED_FILES)

    # Default excluded directories
    # 故意投毒的检测夹具目录：评测器（evaluate.py）早就跳过它们，gate 不跳，
    # 结果就是"安全工具扫自己得 0/F"——那是对外最难解释的一种自相矛盾。
    DEFAULT_EXCLUDES = {"tests", "test", "docs", "doc", ".git", "__pycache__",
                        "node_modules", "._test_scratch", "_backup",
                        "_demo", "demo", "samples", "benchmarks", "corpus",
                        "fixtures", "testdata", "red-team"}

    # 显式排除（--exclude）：用于把"故意投毒的检测夹具"排除出发布门禁，
    # 同时把排除项写进结果里，保证别人能复现"我到底扫了什么"。
    # 注意：这是报告字段，不是隐身衣——被排除的路径会打印出来。
    ex_parts = []
    for e in (excludes or []):
        p = str(e).replace("\\", "/").strip()
        while p.startswith("./"):
            p = p[2:]
        p = p.strip("/")
        if p:
            ex_parts.append(p)
    result.excluded = ex_parts

    # 链接先定性：指向外部的链接只披露、不进内容扫描（否则读的是宿主机文件，
    # 而报告会把外部路径写成"仓库内"，证据链失真）
    escape_links = scan_links(skill_path, result)

    # 备用数据流：普通读取看不到的那部分内容，必须单独查（Windows 专有）
    scan_alternate_streams(skill_path, result, should_exclude=None)

    # 读不出来 ≠ 干净：锁住/权限拒绝的文件必须披露（否则它和"扫过且没问题"长得一样）
    scan_unreadable(skill_path, result, should_exclude=None)

    def should_exclude(filepath: Path) -> bool:
        """Check if a file should be excluded from scanning."""
        # 落在"指向外部的链接"子树里 → 一律不扫
        nc = os.path.normcase(str(filepath))
        for esc in escape_links:
            if nc == esc or nc.startswith(esc + os.sep):
                return True
        rel = filepath.relative_to(skill_path).as_posix()
        for e in ex_parts:
            if rel == e or rel.startswith(e + "/"):
                return True
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

    # Windows 装载脚本：同一类执行面，换个后缀就在扫描范围外
    for win_file in list(skill_path.rglob("*.ps1")) + list(skill_path.rglob("*.bat")) \
            + list(skill_path.rglob("*.cmd")):
        if should_exclude(win_file):
            continue
        scan_windows_script(win_file, result)
        result.files_scanned += 1

    # Scan all JS/TS files
    # 后缀覆盖：Node 的 ESM/CJS 入口是 .mjs/.cjs，现代包比 .js 还常见。
    # 实测（audit2/probe_file_types.py）：同一段 child_process + exec 代码，
    # 叫 evil.js 报两条 HIGH，叫 evil.mjs / evil.cjs 是 0 命中——按后缀漏掉整个执行面。
    js_facts = {}
    if scan_js_file:
        js_files = []
        for ext in ("*.js", "*.ts", "*.mjs", "*.cjs"):
            js_files.extend(skill_path.rglob(ext))
        for js_file in sorted(set(js_files)):
            if should_exclude(js_file):
                continue
            try:
                js_findings = scan_js_file(js_file)
                for sev, cat, msg, line in js_findings:
                    result.findings.append(Finding(
                        severity=sev, category=cat,
                        message=msg, file=str(js_file), line=line
                    ))
                js_facts[str(js_file)] = js_flags(js_file)
            except Exception:
                pass
            result.files_scanned += 1

    # 夹具目录只豁免"语义规则"，不豁免"隐形字符"：
    # 默认排除（_demo/samples/fixtures…）是必要的，否则安全工具扫自己得 0/F；
    # 但它同时是一条规避通道——把载荷放进叫 demo 的目录就没人看。
    # 实测证据：audit2/probe/_evasion-demo 的 Tags 载荷修复前两引擎均无否决。
    # 干净夹具里不会有不可见字符，所以这里报出来的一定是有人放进去的。
    for any_file in skill_path.rglob("*"):
        if not any_file.is_file() or any_file.suffix.lower() not in (
                ".md", ".markdown", ".txt", ".json", ".yaml", ".yml"):
            continue
        if should_exclude(any_file):
            scan_invisible_file(any_file, result)

    # Scan all Markdown files (excluding already-scanned skill docs)
    for md_file in skill_path.rglob("*.md"):
        if md_file in skill_docs:
            continue
        if should_exclude(md_file):
            continue
        scan_md_file(md_file, result)
        result.files_scanned += 1

    # 元数据文件也承载指令：MCP 服务器把工具描述直接注入模型上下文，
    # arXiv 2607.05744 证明的正是"审批视图与送进模型的字节可以不一致"。
    for meta_glob in ("*.json", "*.yaml", "*.yml"):
        for meta_file in skill_path.rglob(meta_glob):
            if should_exclude(meta_file):
                continue
            scan_invisible_file(meta_file, result)
            result.files_scanned += 1

    # 配置文件里的硬编码密钥：泄漏最常发生在这里，而不是代码里。
    # 实测（audit2/probe_secrets_coverage.py）：同一批假密钥写进 .py/.js 报 CRITICAL，
    # 写进 .env/.ini/.toml/.txt/.json 修复前全部 0 命中。
    for cfg_glob in ("*.env", ".env", "*.ini", "*.cfg", "*.conf", "*.toml",
                     "*.properties", "*.txt", "*.json", "*.yaml", "*.yml"):
        for cfg_file in skill_path.rglob(cfg_glob):
            if should_exclude(cfg_file) or not cfg_file.is_file():
                continue
            if _already_reported(result, str(cfg_file), "credential"):
                continue        # 同一个文件被两条 glob 命中时不重复报
            scan_config_secrets(cfg_file, result)

    # 大小写变体后缀：判据必须与平台无关（Linux 上 .PY 与 .py 是两回事）
    scan_case_variant_files(skill_path, result, should_exclude)

    # 未读载体披露：压缩包/二进制里的载荷一个字节都没看过，必须说出来
    scan_carriers(skill_path, result, should_exclude)

    # 名字本身就是伪装：双向控制符/零宽字符/双扩展名，读内容永远读不出来
    scan_deceptive_names(skill_path, result, should_exclude)

    # 被排除目录（demo/samples/tests/--exclude）：不计分，但里面有执行面就要披露。
    # 名单必须是**同一份** DEFAULT_EXCLUDES：这里原来自带一份手写的，
    # 与主表不是同一份，`.git`/`__pycache__`/`node_modules`/`_backup` 等五个目录
    # 于是既不扫也不披露（audit2/probe_exclude_class.py）。
    scan_excluded_scope(skill_path, result, DEFAULT_EXCLUDES, ex_parts)

    # 文本后缀里装的其实是二进制：读了，但审不了（NUL / PE 头 / 解不出来）
    scan_binary_in_text(skill_path, result, should_exclude)

    # 安装期脚本：package.json 的 postinstall 是一条装载代码的执行通道。
    # OWASP AST02 与 arXiv 2601.10338 都把它列为供应链风险的典型形态；
    # 修复前实测 curl | sh 的 postinstall 样本在本引擎拿 100/A+（完全放行）。
    for pkg_file in skill_path.rglob("package.json"):
        if should_exclude(pkg_file):
            continue
        scan_package_install_scripts(pkg_file, result)
        result.files_scanned += 1

    # 同一类通道换个文件名就全绿：hooks / MCP 服务器定义 / 插件清单同样是
    # "读着是配置、跑起来是命令"（audit2/probe_config_exec.py，修复前均 100/A+）。
    scan_config_exec(skill_path, result, should_exclude)

    # 没有后缀的构建/CI 脚本：分发挂在后缀上，于是 Dockerfile/Makefile/Jenkinsfile
    # 一个都走不进规则分支（audit2/probe_nosuffix.py，修复前五例全 100/A+）。
    scan_nosuffix_scripts(skill_path, result, should_exclude)

    # Jupyter 笔记本：后缀不在文本名单里，整本被跳过，而 `!` 前缀直接跑 shell。
    scan_notebooks(skill_path, result, should_exclude)

    # Windows 脚本宿主 / 系统执行入口 / 无后缀 shebang（§3aw）
    scan_exec_scripts(skill_path, result, should_exclude)

    # 同一类的另一条通道：binding.gyp / *.gyp 里的 `<!@(cmd)` 会在生成阶段执行 shell。
    # 实测（audit2/probe_install_bypass.py）：同样的 curl|sh，写在 postinstall 报 CRITICAL，
    # 写在 binding.gyp 里 0 命中——"例子通过、类没通过"。
    # npm 文档：有 binding.gyp 且未定义 install/preinstall 时，install 默认就是 node-gyp rebuild
    # （docs.npmjs.com/cli/v11/commands/npm-rebuild/），所以这是安装期真会跑的一步。
    for gyp_file in list(skill_path.rglob("*.gyp")):
        if should_exclude(gyp_file):
            continue
        scan_gyp_file(gyp_file, result)
        result.files_scanned += 1

    # Scan dependencies for known vulnerabilities
    scan_dependencies(skill_path, result)

    # 组合判定：单条规则只能看到"整份环境变量导出"这一步（MEDIUM），
    # 看不到后面还有没有真的发出去。评分类引擎（evaluate.py R-SEC-21）做的是
    # "导出 + 外发"合并判定，这里必须对齐，否则同一技能会被判出两种结论：
    # 一个 A+ 通过、一个 D 阻断。
    #
    # 关键前提：判的是代码行为，不是文档里"提到"这些词。引擎自己的规则定义里有
    # 匹配 dict(os.environ 的正则、注释里也会讲到整份导出——不排除会把扫描器自己判成外泄。
    def _behaviour_line(fp, ln):
        try:
            with open(fp, encoding="utf-8", errors="ignore") as _f:
                _lines = _f.read().splitlines()
        except OSError:
            return False
        s = _lines[ln - 1].strip() if 0 < ln <= len(_lines) else ""
        if not s:
            return False
        if s.startswith("#") or s.startswith('"""') or s.startswith("'''") or s.startswith("*"):
            return False
        if "re.compile(" in s or s.startswith('r"') or s.startswith("r'"):
            return False
        return True

    def _line_has(fp, ln, needles):
        """这一行里是否出现了某个"读动作"记号。用来区分「只是提到了密钥路径」
        和「真的把它读进来了」——后者才够得上跨文件外发的读取端。"""
        try:
            with open(fp, encoding="utf-8", errors="ignore") as _f:
                _lines = _f.read().splitlines()
        except OSError:
            return False
        if not (0 < ln <= len(_lines)):
            return False
        return any(n in _lines[ln - 1] for n in needles)

    # 只认两类：整份导出（前兆）与真实外发动作。
    # "遍历全部环境变量"不算导出——构造子进程环境变量（env={**os.environ}）是正常做法；
    # "网络库（常见）"这类 INFO 也不算外发，否则同一个文件里既有 environ 又有 import 就误报。
    _ENV_MSGS = ("整份环境变量导出（外泄前兆）", "整份环境变量复制（外泄前兆）")
    _NET_MSGS = ("POST 数据到外部 URL", "urlopen 网络请求", "向外发请求",
                 "原始 socket 网络连接", "向外发 POST 请求", "发送邮件")
    # 凭证类：单条规则只能说"碰了这个文件"，碰了之后有没有发出去要看同一文件里
    # 后面还有没有网络动作。evaluate.py 的口径是 R-SEC-09/10（凭证外泄）= CRITICAL，
    # 这边若只报 HIGH，同一个技能就会被两个引擎判成两个等级。
    _CRED_MSGS = ("访问 AWS 凭证文件", "访问 SSH 密钥目录", "访问 Git 凭证文件",
                 "访问 SSH 私钥", "访问 AWS 凭证文件（路径分段拼接）",
                 "访问 SSH 私钥（路径分段拼接）")
    env_by_file, net_by_file, cred_by_file = {}, {}, {}
    for f in result.findings:
        if f.message in _ENV_MSGS and _behaviour_line(f.file, f.line):
            env_by_file.setdefault(f.file, []).append(f.line)
        elif f.message in _NET_MSGS and _behaviour_line(f.file, f.line):
            net_by_file.setdefault(f.file, []).append(f.line)
        elif f.message in _CRED_MSGS and _behaviour_line(f.file, f.line):
            cred_by_file.setdefault(f.file, []).append(f.line)

    handled = set()
    # 跨文件：读凭证在一个文件、发出去在另一个文件 —— 单个文件看不出因果，
    # 但 evaluate.py 的 AST 污点分析把这种情形判 CRITICAL（R-SEC-10 跨文件线性）。
    # 这里没有污点分析，用"读动作 + 网络 sink 分处两个文件"做保守近似：
    # 代价只是等级从 C 降到 D（本来两者都阻断发布），换来的是两个引擎对同一技能
    # 给出同一个结论——不一致本身就是缺陷。
    _READ_HINTS = ("open(", "read(", "read_text", "Path(", "expanduser", ".load(")
    for cred_fp, cred_lines in sorted(cred_by_file.items()):
        read_lines = [ln for ln in cred_lines if _line_has(cred_fp, ln, _READ_HINTS)]
        if not read_lines:
            continue
        for net_fp, net_lines in sorted(net_by_file.items()):
            if net_fp == cred_fp or net_fp in handled:
                continue
            if read_lines and net_lines:
                result.findings.append(Finding(
                    severity="CRITICAL", category="exfil",
                    message="凭证跨文件外发（读取与网络外发分处不同文件，组合判定）",
                    file=net_fp, line=min(net_lines)
                ))
                handled.add(net_fp)
                break

    # JS 跨文件：A 里读凭证，B 里 import 了 A 又发出去。单文件规则看不见因果，
    # 但 evaluate.py 的 js 跨文件判定会报 CRITICAL——两侧必须同结论。
    # 只认显式相对导入（require('./a') / import './a'），不靠目录相邻猜因果。
    for src_fp, src_flags in sorted(js_facts.items()):
        if not (src_flags.get("cred") and src_flags.get("read")):
            continue
        src_mod = os.path.splitext(os.path.basename(src_fp))[0]
        for dst_fp, dst_flags in sorted(js_facts.items()):
            if dst_fp == src_fp or not dst_flags.get("sink"):
                continue
            if src_mod in dst_flags.get("imports", set()):
                result.findings.append(Finding(
                    severity="CRITICAL", category="exfil",
                    message="凭证跨文件外发（JS：读取与网络外发分处不同文件，组合判定）",
                    file=dst_fp, line=dst_flags["sink"]
                ))
                break

    # 凭证外泄比环境变量外泄更重：先判，判中就跳过该文件的环境变量合并，
    # 免得同一份证据被报成两条 CRITICAL（重复计数会虚增发现数）。
    for fp, cred_lines in sorted(cred_by_file.items()):
        first_cred = min(cred_lines)
        if any(ln >= first_cred for ln in net_by_file.get(fp, [])):
            result.findings.append(Finding(
                severity="CRITICAL", category="exfil",
                message="凭证读取后网络外发（凭证文件 + 网络外发同文件，组合判定）",
                file=fp, line=1
            ))
            handled.add(fp)

    # 与 evaluate.py R-SEC-21 同序：外发必须发生在导出之后，才构成"导出了又发出去"。
    # 只是同一个文件里先有网络代码、后面才构造环境变量，不构成因果。
    for fp, env_lines in sorted(env_by_file.items()):
        if fp in handled:
            continue
        first_env = min(env_lines)
        if any(ln >= first_env for ln in net_by_file.get(fp, [])):
            result.findings.append(Finding(
                severity="CRITICAL", category="exfil",
                message="环境变量整份外发（导出 + 网络外发同文件，组合判定）",
                file=fp, line=1
            ))

    # 超大文件被截断：必须披露"读了多少、还剩多少没读"。
    # "跑得慢"可以忍，"读了一半还说通过"不能忍——这条披露不计分（事实陈述），
    # 但它把"我没读全"写进了报告，避免与"扫过且没问题"混同。
    truncated_any = len(_TRUNCATED_FILES) > trunc_baseline
    while _TRUNCATED_FILES[trunc_baseline:]:
        path, total = _TRUNCATED_FILES.pop()
        result.findings.append(Finding(
            severity="MEDIUM", category="coverage",
            message="文件超过 %d MB 上限，仅扫描前 %d MB（原始 %.1f MB），其余未读"
                    % (MAX_SCAN_BYTES // (1024 * 1024), MAX_SCAN_BYTES // (1024 * 1024),
                       total / 1048576),
            file=path, line=1
        ))

    # 兑现"只披露、不计分"：coverage 类讲的是"我读不到 / 读不全"这种事实，
    # 不是问题本身。集中在这里标记，避免每个披露点各写一遍 scoring=False。
    for f in result.findings:
        if f.category in NON_SCORING_CATEGORIES:
            f.scoring = False

    # Compute score
    # 截断不按条扣分（它只是"我没读全"），但**封顶 A，不给 A+**：
    # 最高档只留给"我确实读完了"的扫描。否则 12 MB 文件里 4 MB 没读，却照样 A+，
    # 与 §3aj「读不出来 ≠ 干净」是同一种错。
    result.trust_score = compute_trust_score(result)
    if truncated_any:
        result.trust_score = min(result.trust_score, 89)
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
    print(f"  引擎: {result.engine} {result.rule_version}（规则命中口径）")
    print(f"  Skill: {result.skill_name}")
    print(f"  目录: {result.skill_dir}")
    print(f"  扫描文件数: {result.files_scanned}")
    if result.excluded:
        print(f"  显式排除: {', '.join(result.excluded)}")
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


def generate_sarif(result: ScanResult, fail_under: int = None) -> str:
    """Generate SARIF 2.1.0 output for GitHub Code Scanning.

    §3ar：SARIF 本身没有"分数"，读它的一方只能看到 findings 条数——
    所以分数与阈值必须显式写进 `run.properties`，否则同一份扫描在 JSON 出口和
    SARIF 出口说的是两件事（JSON 说 85/100 且门槛 90 拦，SARIF 什么都不说）。
    """
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
            "properties": {"severity": f.severity, "scoring": f.scoring},
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
            "properties": {
                "trust_score": result.trust_score,
                "grade": result.grade,
                "fail_under": fail_under,
                "blocked": (fail_under is not None
                            and result.trust_score < fail_under)
                           or result.critical_count > 0 or result.high_count > 0,
            },
            "results": sarif_results
        }]
    }

    return json.dumps(sarif, indent=2, ensure_ascii=False)


def generate_junit_xml(result: ScanResult, fail_under: int = None) -> str:
    """Generate JUnit XML output for CI test reporting.

    §3ar：JUnit 是"通过/失败"协议，所以它必须说**和退出码同一件事**。
    修复前它硬编码 `threshold 80`，完全不看命令行：
      · 分 85 + `--fail-under 90` → 进程 exit 1（拦住），XML 却写 failures=0
        —— 读 JUnit 的 CI（GitHub Test Reporter、IDE）看到一片绿，门禁其实已经拦了；
      · 分 69 + `--fail-under 60` → 进程 exit 0（放行），XML 却记一条 failure
        —— 反过来报红。
    现在阈值跟随 `--fail-under`（未给时沿用本格式的历史默认 80，并写进 message），
    failures 数按**实际写出的 failure 元素**统计，不再用 critical+high 估。
    非计分披露（scoring=False）不产生 failure——否则披露会变成"测试失败"。
    """
    import xml.etree.ElementTree as ET
    from xml.dom import minidom

    threshold = fail_under if fail_under is not None else 80

    testsuites = ET.Element("testsuites")
    testsuite = ET.SubElement(testsuites, "testsuite", {
        "name": "SkillGate",
        "tests": str(len(result.findings) + 1),  # +1 for overall score
        "failures": "0",                          # 最后按实际元素回填
        "errors": "0",
        "time": "0.1"
    })

    n_fail = 0

    # Overall score test
    overall_test = ET.SubElement(testsuite, "testcase", {
        "name": f"Trust Score: {result.trust_score}/100",
        "classname": "skillgate.overall"
    })
    if result.trust_score < threshold:
        ET.SubElement(overall_test, "failure", {
            "message": f"Score {result.trust_score} below threshold {threshold}"
        })
        n_fail += 1

    # Individual findings as test cases
    for i, f in enumerate(result.findings):
        testcase = ET.SubElement(testsuite, "testcase", {
            "name": f"{f.category}: {f.message[:50]}",
            "classname": f"skillgate.{f.category}"
        })
        if f.scoring and f.severity in ("CRITICAL", "HIGH"):
            ET.SubElement(testcase, "failure", {
                "message": f"[{f.severity}] {f.message}"
            })
            n_fail += 1

    testsuite.set("failures", str(n_fail))

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
    scan_parser.add_argument("--exclude", nargs="*", default=[], metavar="PATH",
                             action="extend",
                             help="显式排除的路径（相对 skill_dir），如 _demo；可重复指定，"
                                  "排除项会记入结果，用于复现")

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

        result = scan_skill(args.skill_dir, args.exclude)

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
            # §3ar：这里原来自己写了一条"只有 CRITICAL/HIGH 才非零"的规则，
            # 不看 --fail-under —— 同一份扫描，markdown 出口 exit 1（拦住），
            # agent 出口 exit 0（放行）。六个出口只能有一套生死判定。
            sys.exit(_ci_exit(result, fail_under=args.fail_under))
        elif args.format == "sarif":
            output = generate_sarif(result, fail_under=args.fail_under)
            if args.output:
                Path(args.output).write_text(output, encoding="utf-8")
                print(f"SARIF 报告已写入: {args.output}")
            else:
                print(output)
            sys.exit(_ci_exit(result, fail_under=args.fail_under))
        elif args.format == "junit":
            # 阈值必须与退出码同源，否则读 JUnit 的 CI 会与门禁说两套话
            output = generate_junit_xml(result, fail_under=args.fail_under)
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
                f"- **引擎**: {result.engine} {result.rule_version}（规则命中口径）",
                f"- **Skill**: {result.skill_name}",
                f"- **Trust Score**: {result.trust_score}/100 ({result.grade})",
                f"- **扫描文件数**: {result.files_scanned}",
                (f"- **显式排除**: {', '.join(result.excluded)}" if result.excluded else ""),
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
