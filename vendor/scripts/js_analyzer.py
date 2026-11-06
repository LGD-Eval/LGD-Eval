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
    (re.compile(r"https?://[^\s'\"`]+\.(com|net|org)[^\s'\"`]*"), "LOW",
     "硬编码外部 URL"),
]

FS_DANGER = [
    (re.compile(r"\brmSync\s*\("), "MEDIUM", "rmSync 删除"),
    (re.compile(r"\brimraf\b"), "MEDIUM", "rimraf 递归删除"),
    (re.compile(r"\bunlinkSync\s*\("), "LOW", "unlinkSync 删除文件"),
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
    return out
