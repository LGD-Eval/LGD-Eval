"""Node / TypeScript 技能扫描器。

存在原因：skillgate.py 早就写了 `from js_analyzer import scan_js_file`，
但本模块从未被创建，import 静默失败后 scan_js_file 变成 None，
所有 .js/.ts 技能因此被整体跳过，却照样报"通过"。
这是最坏的一类缺陷——不报错、分数还很高。

规则口径与 evaluate.py 的 JS 侧（R-SEC-17/18）保持一致，
只做"能可靠判定"的：确定的危险 API、确定的硬编码凭证、确定的 shell 拼接。
"""
import json
import os
import re

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# 确定的危险执行面：无论参数多克制，这几样都是任意代码执行
DANGEROUS = [
    (re.compile(r"require\s*\(\s*['\"]child_process['\"]\s*\)"), "HIGH",
     "引入 child_process（任意子进程执行）"),
    (re.compile(r"from\s+['\"]child_process['\"]"), "HIGH",
     "引入 child_process（任意子进程执行）"),
    (re.compile(r"\bexecSync\s*\("), "HIGH", "execSync 同步执行 shell"),
    (re.compile(r"\bexecFileSync\s*\("), "HIGH", "execFileSync 同步执行外部程序"),
    (re.compile(r"\bspawn\s*\([^)]*shell\s*:\s*true"), "HIGH", "spawn 开启 shell"),
    (re.compile(r"\bexec\s*\(\s*[`'\"]"), "HIGH", "exec 执行命令字符串"),
    (re.compile(r"\bnew\s+Function\s*\("), "HIGH", "new Function 动态构造代码"),
    (re.compile(r"\beval\s*\("), "MEDIUM", "eval 动态求值（工具常用，需人工判断）"),
    (re.compile(r"\bvm\.runInNewContext\s*\("), "MEDIUM", "vm 隔离执行（可逃逸）"),
]

# 凭证：与 Python 侧同一套格式，避免两个扫描器口径不一
SECRETS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "CRITICAL", "硬编码 AWS Access Key"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "CRITICAL", "硬编码 GitHub Token"),
    (re.compile(r"sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}"), "CRITICAL", "硬编码模型 API Key"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "CRITICAL", "硬编码 Slack Token"),
]

# 外泄前兆：整份环境变量 / 大量文件内容上报
EXFIL = [
    (re.compile(r"JSON\.stringify\s*\(\s*process\.env\s*\)"), "MEDIUM",
     "整份 process.env 导出（外泄前兆）"),
    (re.compile(r"Object\.entries\s*\(\s*process\.env\s*\)"), "MEDIUM",
     "遍历全部环境变量"),
    # 2026-11 补：展开语法与键枚举是同一件事的另外两种写法。此前只认
    # JSON.stringify，{...process.env} 直接漏过——第三方实测已复现。
    (re.compile(r"\{\s*\.\.\.\s*process\.env\s*\}"), "MEDIUM",
     "整份 process.env 展开导出（外泄前兆）"),
    (re.compile(r"Object\.keys\s*\(\s*process\.env\s*\)"), "MEDIUM",
     "枚举全部环境变量键"),
    (re.compile(r"Object\.assign\s*\(\s*\{\s*\}\s*,\s*process\.env\s*\)"), "MEDIUM",
     "整份 process.env 浅拷贝导出"),
    (re.compile(r"https?://[^\s'\"`]+\.(com|net|org)[^\s'\"`]*"), "LOW",
     "硬编码外部 URL"),
]

# 凭证路径：Node 技能最常见的两类偷法——字面路径与 path.join 拼路径
CRED_PATHS = [
    (re.compile(r"['\"](?:\.aws|\.ssh|\.npmrc|\.netrc|netrc|credentials|id_rsa"
                r"|id_ed25519|\.kube|\.docker|\.pgpass)['\"]"), "HIGH",
     "引用凭证目录/文件路径"),
    (re.compile(r"['\"][^'\"\n]*(?:/\.aws/|/\.ssh/|\.aws/credentials|/credentials\b"
                r"|id_rsa|id_ed25519|\.pgpass|/\.npmrc)[^'\"\n]*['\"]"), "HIGH",
     "引用凭证文件路径"),
]

# 网络发送 sink：判定"真的发出去了"，与凭证读取做组合
NET_SINKS = re.compile(
    r"(?:https?\.(?:request|get)\s*\(|\bfetch\s*\(|axios\.(?:post|put|get|request)"
    r"|\bnet\.connect\s*\(|new\s+WebSocket|sendBeacon|got\s*\()"
)
READ_CALLS = re.compile(r"(?:readFileSync|readFile|createReadStream|fs\.read|open\s*\()")

# 相对导入：跨文件组合要靠它把"A 读"和"B 发"连起来，否则只能靠目录相邻猜因果
IMPORT_RE = re.compile(r"(?:require\s*\(\s*['\"]\./([^'\"]+)['\"]"
                       r"|from\s*['\"]\./([^'\"]+)['\"]"
                       r"|import\s*\(\s*['\"]\./([^'\"]+)['\"]\s*\))")


def js_flags(filepath):
    """返回 {"cred","read","sink","env"} 首次出现行号（0 = 未出现）与 imports 集合。

    跨文件判定需要"哪个文件读、哪个文件发"，单文件扫描器自己拼不出来。
    """
    flags = {"cred": 0, "read": 0, "sink": 0, "env": 0, "imports": set()}
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
    except OSError:
        return flags
    for i, line in enumerate(lines, 1):
        if not line.strip() or _is_comment(line):
            continue
        if not flags["cred"] and any(p.search(line) for p, _s, _m in CRED_PATHS):
            flags["cred"] = i
        if not flags["read"] and READ_CALLS.search(line):
            flags["read"] = i
        if not flags["sink"] and NET_SINKS.search(line):
            flags["sink"] = i
        if not flags["env"] and any(p.search(line) for p, _s, m in EXFIL
                                   if "process.env" in m):
            flags["env"] = i
        for m in IMPORT_RE.finditer(line):
            mod = m.group(1) or m.group(2) or m.group(3)
            if mod:
                flags["imports"].add(os.path.basename(mod))
    return flags

FS_DANGER = [
    (re.compile(r"\brmSync\s*\("), "MEDIUM", "rmSync 删除"),
    (re.compile(r"\brimraf\b"), "MEDIUM", "rimraf 递归删除"),
    (re.compile(r"\bunlinkSync\s*\("), "LOW", "unlinkSync 删除文件"),
]

# 2026-11-15 类覆盖：JS 侧一直缺 TLS 这一整类。
# evaluate.py 的 R-SEC-26 早就认 rejectUnauthorized，但本模块不认，
# 于是同一个技能走库扫描时放行、走 CLI 时拦下——两个引擎口径不一，等于都不算数。
TLS_OFF = [
    (re.compile(r"rejectUnauthorized\s*:\s*false"), "HIGH",
     "TLS 校验被关闭（rejectUnauthorized:false）"),
    (re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED\s*['\"]?\s*[=:]\s*['\"]?0"), "HIGH",
     "TLS 校验被关闭（NODE_TLS_REJECT_UNAUTHORIZED=0）"),
    (re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED\s*['\"]?\s*,\s*['\"]0['\"]"), "HIGH",
     "TLS 校验被关闭（environment 注入 0）"),
    (re.compile(r"checkServerIdentity\s*:\s*(?:\(\s*\)\s*=>\s*(?:null|undefined|true)"
                r"|function\s*\(\s*\)\s*\{\s*return\s+(?:null|undefined|true))"), "HIGH",
     "TLS 主机名校验被架空（checkServerIdentity 返回通过）"),
    (re.compile(r"\bservername\s*:\s*false"), "MEDIUM",
     "关闭 SNI（与自签证书绕过常成对出现）"),
]


def _is_comment(line):
    s = line.strip()
    return s.startswith("//") or s.startswith("*") or s.startswith("/*")


def scan_js_file(filepath):
    """返回 [(severity, category, message, line)]。"""
    out = []
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
    except OSError:
        return out

    for i, line in enumerate(lines, 1):
        if _is_comment(line):
            continue
        if "skillgate: ignore" in line:
            continue
        for pattern, sev, msg in DANGEROUS:
            if pattern.search(line):
                out.append((sev, "dangerous-code", msg, i))
                break
        for pattern, sev, msg in SECRETS:
            if pattern.search(line):
                out.append((sev, "credential", msg, i))
                break
        for pattern, sev, msg in CRED_PATHS:
            if pattern.search(line):
                out.append((sev, "credential", msg, i))
                break
        for pattern, sev, msg in EXFIL:
            if pattern.search(line):
                # 硬编码 URL 太常见，只在同一行出现数据外发动词时才记
                if msg == "硬编码外部 URL" and not re.search(r"\b(fetch|axios|post|send)\b", line):
                    continue
                out.append((sev, "network", msg, i))
                break
        for pattern, sev, msg in FS_DANGER:
            if pattern.search(line):
                out.append((sev, "filesystem", msg, i))
                break
        for pattern, sev, msg in TLS_OFF:
            if pattern.search(line):
                out.append((sev, "tls", msg, i))
                break

    # 组合判定：单条规则只看到一步。凭证路径 + 读取调用 + 网络 sink 同文件共存，
    # 才是"读出去"这个行为；只报其中任一步都会让同一技能被两套引擎判成两种结论。
    # 已知边界：跨文件组合（A 读、B 发）暂不判。
    _lines = [(i, l.strip()) for i, l in enumerate(lines, 1)
              if l.strip() and not _is_comment(l)]
    _cred = _read = _sink = _env = 0
    for i, s in _lines:
        if not _cred and any(p.search(s) for p, _sev, _m in CRED_PATHS):
            _cred = i
        if not _read and READ_CALLS.search(s):
            _read = i
        if not _sink and NET_SINKS.search(s):
            _sink = i
        if not _env and any(p.search(s) for p, _sev, _m in EXFIL
                            if "process.env" in _m):
            _env = i
    if _sink and _cred and _read:
        out.append(("CRITICAL", "exfil",
                    "凭证读取后网络外发（JS 组合判定：凭证路径 + 读取 + 发送）", _sink))
    if _sink and _env:
        out.append(("CRITICAL", "exfil",
                    "整份 process.env 发往网络（JS 组合判定）", _sink))

    return out
