#!/usr/bin/env python3
"""
LGD-Gate: Independent Skill Evaluation
========================================
独立第三方技能评测服务。
五维评测体系：结构完整性 + 文档质量 + 安全检查 + 可运行性 + 生态兼容性
"""

import os
import sys
import re
import ast
import json
import time
import shutil
import tempfile
import hashlib
import subprocess
import urllib.request


# ============================================================
# 安全否决（safety veto）
# ------------------------------------------------------------
# 问题：五维加权平均会把"能读凭证并外发"的技能抬到 B 级——
# 结构、文档、生态几乎满分，把安全 7/25 稀释掉了。
# 业内成熟做法是按最严重命中封顶，而不是让平均说了算：
#   guard0    : ≥1 exploitable critical → 最高 D（≤69）
#   canopii   : critical cap 20 / high 49 / medium 74 / low 89
#   DataWizual: 出现 CRITICAL 时有效等级封顶 C，数学分照报
#   SonarQube : 门禁用条件判定，不看总分
# 这里采用"封顶 + 同时报告原始分"：结论可解释，信息不丢失。
# ============================================================

VETO_CRITICAL = 49   # 强制落到 L3（每次调用确认）以下
VETO_HIGH = 69       # 最高 C
VETO_MEDIUM = 89     # 最高 A


def safety_cap(findings):
    """按命中的最高严重度给出分数上限。返回 (cap, level, reason)。"""
    joined = " | ".join(findings)

    # critical：已经证明"读了敏感数据并往外送"，或安装期就能拉起远程代码
    crit_keys = (
        "凭证文件读取后网络外发",
        "跨文件凭证外泄",
        "同文件污点",
        "安装期脚本含下载执行",
        "下载执行或动态求值",
    )
    crit = any(k in joined for k in crit_keys)
    # 越权指令 + 隐瞒用户 + 读凭证 三者同时出现，等于在明说"别让人知道我在偷"
    if ("隐瞒用户" in joined) and ("读取凭证" in joined or "凭证文件" in joined):
        crit = True
    if crit:
        return VETO_CRITICAL, "critical", "命中文凭外泄 / 远程代码执行类问题"

    high_keys = (
        "硬编码凭证", "shell=True", "命令注入", "动态执行", "eval / exec",
        "child_process.exec", "new Function", "安装期自动执行脚本", "os.system",
        "不告知真实行为", "读取凭证文件指令",
    )
    if any(k in joined for k in high_keys):
        return VETO_HIGH, "high", "命中凭证暴露 / 命令执行类问题"
    if "越权指令" in joined or "免确认执行" in joined:
        return VETO_HIGH, "high", "命中越权或免确认执行指令"

    # 注意：不设 medium 档。反序列化、rmtree 之类已经在安全维度里扣过分了，
    # 再封顶一次会造成双重惩罚——清理临时目录的 rmtree 是最典型的误伤，
    # 评测器扫自己就会把自己的 92 分压成 89。否决只留给"已证实的外泄与远程执行"。
    return 100, "", ""


def evaluate_skill(skill_path):
    """评测一个技能。"""
    start_time = time.time()
    
    # 路径存在性门禁：不存在或不是目录时立即失败，不输出"评测完成"（Muse P1-7）
    if not os.path.isdir(skill_path):
        print("=" * 70)
        print("  ❌ LGD-Gate 评测失败")
        print("=" * 70)
        print(f"  评测对象: {skill_path}")
        print(f"  原因: 路径不存在或不是目录")
        print("=" * 70)
        sys.exit(1)
    
    print("=" * 70)
    print("  🏛️  LGD-Gate 独立第三方评测报告")
    print("=" * 70)
    print(f"  评测对象: {skill_path}")
    print()
    
    score = 100
    findings = []
    warnings = []
    dims = {}  # 五维得分记录（满分: 结构25/目录15/文档20/安全25/生态15）
    
    # ============================================================
    # 第一维：结构完整性（25分）
    # ============================================================
    dim_before = score
    print("📦 第一维：结构完整性（25分）")
    print("-" * 50)
    
    # SKILL.md
    skill_md = os.path.join(skill_path, "SKILL.md")
    if os.path.exists(skill_md):
        print("  ✅ SKILL.md 存在")
        with open(skill_md, 'r', encoding='utf-8') as f:
            content = f.read()
            
            required_fields = ['name', 'description', 'version', 'license', 'author']
            for field in required_fields:
                if f'{field}:' in content:
                    print(f"  ✅ {field} 字段完整")
                else:
                    print(f"  ⚠️ {field} 字段缺失")
                    score -= 2
                    findings.append(f"缺少 {field} 字段")
    else:
        print("  ❌ SKILL.md 不存在")
        score -= 20
        findings.append("缺少 SKILL.md")
    
    # LICENSE
    if os.path.exists(os.path.join(skill_path, "LICENSE")):
        print("  ✅ LICENSE 存在")
    else:
        print("  ⚠️ LICENSE 缺失")
        score -= 3
        findings.append("缺少 LICENSE")
    
    # README.md
    if os.path.exists(os.path.join(skill_path, "README.md")):
        print("  ✅ README.md 存在")
    else:
        print("  ⚠️ README.md 缺失")
        score -= 2
        findings.append("缺少 README.md")
    
    dims['结构完整性'] = max(0, 25 - (dim_before - score))
    print()
    
    # ============================================================
    # 第二维：目录结构（15分）
    # ============================================================
    dim_before = score
    print("📁 第二维：目录结构（15分）")
    print("-" * 50)
    
    # scripts 目录
    scripts_dir = os.path.join(skill_path, "scripts")
    if os.path.exists(scripts_dir):
        print("  ✅ scripts 目录存在")
        script_files = [f for f in os.listdir(scripts_dir) if f.endswith('.py')]
        print(f"     📄 包含 {len(script_files)} 个 Python 脚本")
    else:
        print("  ⚠️ scripts 目录缺失")
        score -= 5
        findings.append("缺少 scripts 目录")
    
    # examples 目录
    examples_dir = os.path.join(skill_path, "examples")
    if os.path.exists(examples_dir):
        print("  ✅ examples 目录存在")
        example_files = os.listdir(examples_dir)
        print(f"     📄 包含 {len(example_files)} 个示例文件")
    else:
        print("  ⚠️ examples 目录缺失")
        score -= 3
        findings.append("缺少 examples 目录")
    
    # references 目录
    if os.path.exists(os.path.join(skill_path, "references")):
        print("  ✅ references 目录存在")
    else:
        print("  ℹ️ references 目录（可选）")
    
    dims['目录结构'] = max(0, 15 - (dim_before - score))
    print()
    
    # ============================================================
    # 第三维：文档质量（20分）
    # ============================================================
    dim_before = score
    print("📝 第三维：文档质量（20分）")
    print("-" * 50)
    
    if os.path.exists(skill_md):
        with open(skill_md, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # 使用场景
            if '## When to Use' in content or '## 使用场景' in content or '## 何时用' in content:
                print("  ✅ 有使用场景说明")
            else:
                print("  ⚠️ 缺少使用场景说明")
                score -= 4
                findings.append("缺少使用场景说明")
            
            # 使用方法
            if '## Usage' in content or '## 使用方法' in content or '## 怎么用' in content:
                print("  ✅ 有使用方法说明")
            else:
                print("  ⚠️ 缺少使用方法说明")
                score -= 4
                findings.append("缺少使用方法说明")
            
            # 示例
            if '## Examples' in content or '## 示例' in content or '## 例子' in content:
                print("  ✅ 有示例")
            else:
                print("  ⚠️ 缺少示例")
                score -= 3
                findings.append("缺少示例")
            
            # 已知限制
            if '## Known Limits' in content or '## 已知限制' in content:
                print("  ✅ 有已知限制说明")
            else:
                print("  ℹ️ 缺少已知限制说明（可选）")
                warnings.append("建议加上已知限制说明")

            # 占位内容检测：防止"堆模板刷分"
            # 章节齐但内容是占位的技能，不代表内容真的落地，不应拿满分
            root = os.path.dirname(skill_md)
            ph_sources = [('SKILL.md', content)]
            readme = os.path.join(root, 'README.md')
            if os.path.exists(readme):
                try:
                    ph_sources.append(('README.md', open(readme, 'r', encoding='utf-8').read()))
                except Exception:
                    pass
            ex_dir = os.path.join(root, 'examples')
            if os.path.isdir(ex_dir):
                for fn in sorted(os.listdir(ex_dir))[:10]:
                    fp = os.path.join(ex_dir, fn)
                    if os.path.isfile(fp) and fn.lower().endswith(('.md', '.txt')):
                        try:
                            ph_sources.append(('examples/' + fn, open(fp, 'r', encoding='utf-8').read()))
                        except Exception:
                            pass
            placeholder_hits = []
            for kw in ('待补充', 'TODO', '本示例为骨架', '占位内容', '占位章节', '<作者名>'):
                for src, txt in ph_sources:
                    if kw in txt:
                        placeholder_hits.append('%s 含「%s」' % (src, kw))
                        break
            if placeholder_hits:
                score -= min(6, 3 * len(placeholder_hits))
                print("  ⚠️ 发现占位内容 %d 处（结构齐但内容未落地）" % len(placeholder_hits))
                findings.append("文档含占位标记需替换为真实内容：" + "；".join(placeholder_hits[:3]))
            else:
                print("  ✅ 未发现占位内容（章节内容已落地）")
    
    dims['文档质量'] = max(0, 20 - (dim_before - score))
    print()
    
    # ============================================================
    # 第四维：安全检查（25分）
    # ============================================================
    dim_before = score
    print("🔒 第四维：安全检查（25分）")
    print("-" * 50)
    
    # 扫描所有 Python 文件
    security_issues = []

    import ast as _ast

    # ---- 文本层规则：SKILL.md 的自然语言越权话术（AST 看不见这一层）----
    TEXT_SEC_RULES = [
        ("R-SEC-11", "越权指令：要求忽略既有规则",
         r"(ignore\s+(all\s+)?(previous|prior|above)\s+instructions"
         r"|disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|rules)"
         r"|忽略(之前|以上|前面|所有)的?(指令|提示|规则)|无视(之前|以上)的?(指令|要求))", 6),
        ("R-SEC-12", "隐瞒用户：要求不告知真实行为",
         r"(do\s+not\s+(tell|inform|notify)\s+the\s+user|without\s+telling\s+the\s+user"
         r"|不要(告诉|通知|提醒)用户|对用户隐瞒|不要让用户知道)", 4),
        ("R-SEC-13", "绕过安全检查",
         r"(bypass\s+(the\s+)?(security|safety|guard|filter|audit|scanner)"
         r"|disable\s+(the\s+)?(security|guard|safety)"
         r"|绕过(安全|审核|门禁|检测)|跳过(安全)?(检查|审核))", 6),
        ("R-SEC-14", "敏感数据外泄指令",
         r"((upload|send|post|forward|exfiltrate|transmit)\s+[^.\n]{0,40}"
         r"(credential|token|api[_ -]?key|\.env|secret|password|cookie|\.ssh|chat\s+history)"
         r"|(上传|发送|转发|外发)[^。\n]{0,20}(凭证|密钥|token|\.env|密码|cookie|聊天记录|会话记录))", 6),
        ("R-SEC-15", "读取凭证文件指令",
         r"((read|cat|open|print)[^.\n]{0,25}(\.ssh|\.aws|\.env\b|\.npmrc|\.git-credentials|id_rsa)"
         r"|(读取|打开|查看)[^。\n]{0,15}(\.ssh|\.aws|\.env|\.npmrc|\.git-credentials|id_rsa))", 6),
        ("R-SEC-16", "免确认执行",
         r"(without\s+(asking|confirmation|approval|permission)|no\s+confirmation\s+needed"
         r"|无需(确认|授权|同意)|不需要用户(同意|确认))", 4),
    ]

    # ---- 跨文件污点：敏感文件读取 → 网络外发 ----
    SENSITIVE_PATH_RE = re.compile(
        r"(\.ssh|\.aws|\.env\b|\.npmrc|\.git-credentials|id_rsa|credential|secret|token|password|凭证|私钥)",
        re.IGNORECASE)
    NET_SINK_MODULES = ("requests", "urllib", "httpx", "socket", "smtplib", "aiohttp")
    NET_SINK_METHODS = ("post", "put", "patch", "send", "sendall", "sendmail", "urlopen")

    def _strip_literals(src):
        """把字符串与注释替换成等长空格（保留行号列号），只留可执行代码。

        安全工具自身会把规则名写成字符串（如 'shell=True'、'eval('），
        若直接对原文跑行为类正则，就会把自己的规则表判成攻击。
        """
        import io as _io
        import tokenize as _tk
        try:
            toks = list(_tk.generate_tokens(_io.StringIO(src).readline))
        except Exception:
            return src
        buf = [list(line) for line in src.splitlines(keepends=True)]
        for t in toks:
            if t.type not in (_tk.STRING, _tk.COMMENT):
                continue
            (sr, sc), (er, ec) = t.start, t.end
            if sr == er:
                if 1 <= sr <= len(buf):
                    row = buf[sr - 1]
                    for c in range(sc, min(ec, len(row))):
                        if row[c] != "\n":
                            row[c] = " "
            else:
                for r in range(sr, er + 1):
                    if not (1 <= r <= len(buf)):
                        continue
                    row = buf[r - 1]
                    a = sc if r == sr else 0
                    b = ec if r == er else len(row)
                    for c in range(a, min(b, len(row))):
                        if row[c] != "\n":
                            row[c] = " "
        return "".join("".join(row) for row in buf)

    def _dotted(node):
        if isinstance(node, _ast.Name):
            return node.id
        if isinstance(node, _ast.Attribute):
            base = _dotted(node.value)
            return (base + "." + node.attr) if base else node.attr
        return None

    def _taint_info(src):
        """提取污染源（读敏感文件）与污染汇（网络外发），供跨文件串联。"""
        sources, sinks, imports = [], [], set()
        try:
            tree = _ast.parse(src)
        except SyntaxError:
            return sources, sinks, imports
        for n in _ast.walk(tree):
            if isinstance(n, _ast.Import):
                for a in n.names:
                    imports.add(a.name.split(".")[0])
            elif isinstance(n, _ast.ImportFrom) and n.module:
                imports.add(n.module.split(".")[0])
        for n in _ast.walk(tree):
            if not isinstance(n, _ast.Call):
                continue
            ln = getattr(n, "lineno", 1)
            d = _dotted(n.func) or ""
            head, tail = (d.split(".")[0], d.split(".")[-1])
            if head in NET_SINK_MODULES and tail in NET_SINK_METHODS:
                sinks.append((ln, d))
            if d in ("open", "os.open") and n.args:
                p = n.args[0]
                if (isinstance(p, _ast.Constant) and isinstance(p.value, str)
                        and SENSITIVE_PATH_RE.search(p.value)):
                    sources.append((ln, "读取敏感文件 %s" % p.value))
        return sources, sinks, imports

    taint = {}

    SEC_RULES = [
        ("R-SEC-01", "硬编码凭证（AWS/GitHub/OpenAI/xox 格式）",
         r"(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})", 8),
        ("R-SEC-02", "硬编码密钥赋值",
         r"(api_key|apikey|secret_key|access_key|password|token)\s*=\s*['\"][^'\"]{8,}['\"]", 5),
        ("R-SEC-03", "命令注入风险（shell=True）", r"shell\s*=\s*True", 6),
        ("R-SEC-04", "动态执行（eval / exec）", r"\b(eval|exec)\s*\(", 6),
        ("R-SEC-05", "系统命令调用（os.system）", r"os\.system\s*\(", 4),
        ("R-SEC-06", "不安全反序列化（pickle / marshal / yaml.load）",
         r"(pickle\.loads|marshal\.loads|yaml\.load)\s*\(", 5),
        ("R-SEC-07", "危险递归删除（shutil.rmtree）", r"shutil\.rmtree\s*\(", 4),
        ("R-SEC-17", "命令执行（child_process.exec / execSync）",
         r"(child_process\.(exec|execSync)\s*\(|require\s*\(\s*['\"]child_process['\"]\s*\))", 6),
        ("R-SEC-18", "动态构造代码（new Function）", r"new\s+Function\s*\(", 5),
    ]

    def _ast_security(src):
        """AST 语义扫描：常量折叠 + 别名解析 + 展开 dict 关键字参数。

        纯正则抓不到"拼接 / base64 / **dict / getattr / 别名调用"这类规避写法，
        这里用语法树把它们还原成真实语义再判定。
        """
        import ast as _ast
        out = []
        try:
            tree = _ast.parse(src)
        except SyntaxError:
            return out

        def cstr(node):
            try:
                if isinstance(node, _ast.Constant) and isinstance(node.value, str):
                    return node.value
                if isinstance(node, _ast.BinOp) and isinstance(node.op, _ast.Add):
                    a, b = cstr(node.left), cstr(node.right)
                    if a is not None and b is not None:
                        return a + b
                if (isinstance(node, _ast.Call) and isinstance(node.func, _ast.Attribute)
                        and node.func.attr in ("b64decode", "decodebytes") and node.args):
                    import base64
                    v = cstr(node.args[0])
                    if v:
                        try:
                            return base64.b64decode(v).decode("utf-8", "ignore")
                        except Exception:
                            return None
                return None
            except Exception:
                return None

        def nameof(node):
            if isinstance(node, _ast.Name):
                return node.id
            if isinstance(node, _ast.Attribute):
                base = nameof(node.value)
                return (base + "." + node.attr) if base else node.attr
            return None

        secret_re = (r"(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{20,}"
                     r"|xox[baprs]-[A-Za-z0-9-]{10,})")

        aliases, dicts = {}, {}
        for n in _ast.walk(tree):
            if isinstance(n, _ast.Assign):
                if isinstance(n.value, _ast.Name) and n.value.id in ("eval", "exec"):
                    for t in n.targets:
                        if isinstance(t, _ast.Name):
                            aliases[t.id] = n.value.id
                if isinstance(n.value, _ast.Dict):
                    d = {}
                    for k, v in zip(n.value.keys, n.value.values):
                        if isinstance(k, _ast.Constant) and isinstance(v, _ast.Constant):
                            d[k.value] = v.value
                    for t in n.targets:
                        if isinstance(t, _ast.Name):
                            dicts[t.id] = d

        seen = set()
        for n in _ast.walk(tree):
            if isinstance(n, (_ast.Constant, _ast.BinOp, _ast.Call)):
                v = cstr(n)
                if v and v not in seen and re.search(secret_re, v):
                    seen.add(v)
                    out.append(("R-SEC-01", "硬编码凭证（AST 折叠后命中）", getattr(n, "lineno", 1), 8))

        for n in _ast.walk(tree):
            if not isinstance(n, _ast.Call):
                continue
            ln = getattr(n, "lineno", 1)
            fname = nameof(n.func)
            if isinstance(n.func, _ast.Call) and nameof(n.func.func) == "getattr":
                obj = nameof(n.func.args[0]) if n.func.args else None
                attr = cstr(n.func.args[1]) if len(n.func.args) > 1 else None
                if obj and attr:
                    fname = obj + "." + attr
            for kw in n.keywords:
                is_shell = False
                if kw.arg == "shell":
                    is_shell = ((isinstance(kw.value, _ast.Constant) and kw.value.value is True)
                                or cstr(kw.value) == "True")
                elif kw.arg is None:
                    if isinstance(kw.value, _ast.Dict):
                        for k, v in zip(kw.value.keys, kw.value.values):
                            if (isinstance(k, _ast.Constant) and k.value == "shell"
                                    and isinstance(v, _ast.Constant) and v.value is True):
                                is_shell = True
                    elif isinstance(kw.value, _ast.Name) and dicts.get(kw.value.id, {}).get("shell") is True:
                        is_shell = True
                if is_shell:
                    out.append(("R-SEC-03", "命令注入风险（shell=True，AST 识别）", ln, 6))
            is_dyn = (fname in ("eval", "exec")
                      or fname.split(".")[-1] in ("eval", "exec")
                      or (isinstance(n.func, _ast.Name) and aliases.get(n.func.id) in ("eval", "exec")))
            if is_dyn:
                out.append(("R-SEC-04", "动态执行（eval/exec，AST 识别）", ln, 6))
                # 自解压 / 混淆特征：exec 的参数不是普通短字面量，而是解码、拼接、下载或变量
                arg = n.args[0] if n.args else None
                if arg is not None and not (isinstance(arg, _ast.Constant)
                                            and isinstance(arg.value, str) and len(arg.value) < 200):
                    out.append(("R-SEC-08", "运行时重建载荷（自解压/混淆特征）", ln, 5))
            if fname == "os.system":
                out.append(("R-SEC-05", "系统命令调用（os.system，AST 识别）", ln, 4))
            if fname in ("pickle.loads", "marshal.loads", "yaml.load"):
                out.append(("R-SEC-06", "不安全反序列化（AST 识别）", ln, 5))
            if fname == "shutil.rmtree":
                out.append(("R-SEC-07", "危险递归删除（AST 识别）", ln, 4))
        return out

    # 跳过评测器自身，避免"规则定义字符串"造成自证误报
    self_name = os.path.basename(__file__)

    if os.path.exists(scripts_dir):
        for script_file in sorted(os.listdir(scripts_dir)):
            ext = os.path.splitext(script_file)[1].lower()
            if ext not in (".py", ".js", ".ts", ".mjs", ".cjs") or script_file == self_name:
                continue
            script_path = os.path.join(scripts_dir, script_file)
            try:
                with open(script_path, 'r', encoding='utf-8') as f:
                    code = f.read()
            except (OSError, UnicodeDecodeError):
                continue
            code_lines = code.splitlines()
            if ext == ".py":
                taint[script_file] = _taint_info(code)
            # 行为类规则只看可执行部分；凭证类规则必须看字符串，故用原文
            code_behavior = _strip_literals(code) if ext == ".py" else code
            for rid, rule_name, pat, points in SEC_RULES:
                target = code if rid in ("R-SEC-01", "R-SEC-02") else code_behavior
                for m in re.finditer(pat, target):
                    line_no = code[:m.start()].count("\n") + 1
                    hit_line = code_lines[line_no - 1] if line_no - 1 < len(code_lines) else ""
                    if "skillgate: ignore" in hit_line:
                        continue
                    msg = "%s:%d: %s" % (script_file, line_no, rule_name)
                    if msg not in security_issues:
                        security_issues.append(msg)
                        score -= points
            # AST 语义扫描：补正则抓不到的规避写法
            if ext != ".py":
                continue
            for rid, rule_name, line_no, points in _ast_security(code):
                hit_line = code_lines[line_no - 1] if line_no - 1 < len(code_lines) else ""
                if "skillgate: ignore" in hit_line:
                    continue
                # 同一文件同一行同一类别已由正则报过，不重复扣分
                kw = rule_name.split("（")[0]
                if any(x.startswith("%s:%d" % (script_file, line_no)) and kw in x
                       for x in security_issues):
                    continue
                msg = "%s:%d: %s" % (script_file, line_no, rule_name)
                if msg not in security_issues:
                    security_issues.append(msg)
                    score -= points

    # ---- 同文件污点：先读敏感文件，后网络外发 ----
    for fname_, (srcs, snks, _im) in sorted(taint.items()):
        if srcs and snks:
            l_src = min(l for l, _ in srcs)
            l_sink = min(l for l, _ in snks)
            if l_sink >= l_src:
                msg = "%s:%d: 凭证文件读取后网络外发（同文件污点）" % (fname_, l_sink)
                if msg not in security_issues:
                    security_issues.append(msg)
                    score -= 8

    # ---- 跨文件污点：A 读凭证，B 引用 A 之后外发 ----
    for a, (a_src, _a_sink, _a_imp) in sorted(taint.items()):
        if not a_src:
            continue
        mod_a = os.path.splitext(a)[0]
        for b, (_b_src, b_sink, b_imp) in sorted(taint.items()):
            if a == b or not b_sink:
                continue
            if mod_a in b_imp:
                msg = "%s:%d: 跨文件凭证外泄（引用 %s 读取的凭证后外发）" % (
                    b, min(l for l, _ in b_sink), a)
                if msg not in security_issues:
                    security_issues.append(msg)
                    score -= 10

    # ---- 文本层：SKILL.md 的自然语言越权话术 ----
    if os.path.exists(skill_md):
        try:
            with open(skill_md, "r", encoding="utf-8", errors="ignore") as f:
                md_text = f.read()
        except OSError:
            md_text = ""
        md_lines = md_text.splitlines()
        for rid, rule_name, pat, points in TEXT_SEC_RULES:
            for m in re.finditer(pat, md_text, re.IGNORECASE):
                line_no = md_text[:m.start()].count("\n") + 1
                hit_line = md_lines[line_no - 1] if line_no - 1 < len(md_lines) else ""
                if "lgd: ignore" in hit_line or "skillgate: ignore" in hit_line:
                    continue
                msg = "SKILL.md:%d: %s" % (line_no, rule_name)
                if msg not in security_issues:
                    security_issues.append(msg)
                    score -= points

    # ---- Node 包脚本审计：postinstall 是 npm 供应链投毒最常见的落点 ----
    pkg_json = os.path.join(skill_path, "package.json")
    if os.path.isfile(pkg_json):
        try:
            with open(pkg_json, "r", encoding="utf-8") as f:
                pkg = json.load(f)
        except (OSError, ValueError):
            pkg = {}
        pkg_scripts = pkg.get("scripts") or {}
        for hook in ("preinstall", "install", "postinstall", "prepare"):
            body = pkg_scripts.get(hook)
            if not body:
                continue
            msg = "package.json:1: 安装期自动执行脚本（%s）" % hook
            if msg not in security_issues:
                security_issues.append(msg)
                score -= 5
            if re.search(r"(curl|wget)\s+[^|]*\|\s*(sh|bash)|node\s+-e|eval\s+\S", str(body)):
                msg2 = "package.json:1: 安装期脚本含下载执行或动态求值（%s）" % hook
                if msg2 not in security_issues:
                    security_issues.append(msg2)
                    score -= 8
        dep_count = 0
        for key in ("dependencies", "devDependencies"):
            d = pkg.get(key)
            if isinstance(d, dict):
                dep_count += len(d)
        if dep_count > 50:
            warnings.append("package.json 依赖 %d 个，建议收敛攻击面" % dep_count)

    if security_issues:
        for issue in security_issues:
            print(f"  ❌ {issue}")
            findings.append(issue)
    else:
        print("  ✅ 未发现安全问题")
    
    print()
    
    dims['安全'] = max(0, 25 - (dim_before - score))
    
    # ============================================================
    # 第五维：生态兼容性（15分）
    # ============================================================
    dim_before = score
    print("🌐 第五维：生态兼容性（15分）")
    print("-" * 50)
    
    # 检查是否符合 SKILL.md 标准
    if os.path.exists(skill_md):
        with open(skill_md, 'r', encoding='utf-8') as f:
            content = f.read()
            if content.startswith('---'):
                print("  ✅ 符合 SKILL.md frontmatter 标准")
            else:
                print("  ⚠️ 缺少 frontmatter")
                score -= 3
                findings.append("缺少 frontmatter")
    
    # 检查是否有 tags
    if os.path.exists(skill_md):
        with open(skill_md, 'r', encoding='utf-8') as f:
            content = f.read()
            if 'tags:' in content:
                print("  ✅ 有 tags 标签")
            else:
                print("  ⚠️ 缺少 tags 标签")
                score -= 2
                warnings.append("建议加上 tags 标签")
    
    print()
    
    dims['生态兼容性'] = max(0, 15 - (dim_before - score))
    
    # ============================================================
    # 最终评分
    # ============================================================
    elapsed = time.time() - start_time

    # ---- 安全否决：加权平均不得掩盖已经证实的安全事实 ----
    raw_score = score
    veto_cap, veto_level, veto_reason = safety_cap(findings)
    if score > veto_cap:
        score = veto_cap

    print("=" * 70)
    
    if score >= 90:
        grade = "A+"
        emoji = "🏆"
    elif score >= 80:
        grade = "A"
        emoji = "🥇"
    elif score >= 70:
        grade = "B"
        emoji = "🥈"
    elif score >= 60:
        grade = "C"
        emoji = "🥉"
    else:
        grade = "D"
        emoji = "⚠️"
    
    # 对外唯一分数：一行给完，不分列其他分数
    print(f"  LGD Trust Score: {score}/100  {emoji} {grade}")
    if raw_score != score:
        print(f"  ⛔ 安全否决：原始分 {raw_score} → 封顶 {score}（{veto_level}：{veto_reason}）")
    # 分数 → 执行权限分档（竞品只给分数，这里给出可直接落地的限权建议）
    if score >= 96:
        gate = "L0 免审批（可直接运行，无需限流）"
    elif score >= 81:
        gate = "L1 一次性确认（限流 60 次/分）"
    elif score >= 51:
        gate = "L2 人工复核（限流 30 次/分）"
    elif score >= 31:
        gate = "L3 沙箱运行（每次调用强制确认）"
    elif score >= 11:
        gate = "L4 隔离环境（仅允许只读调用）"
    else:
        gate = "L5 拒绝执行（需重写后重新评测）"
    print(f"  🚦 建议执行权限: {gate}")
    print(f"  评测耗时: {elapsed:.2f}s")
    print("=" * 70)
    
    # 改进建议
    if findings:
        print()
        print("🔧 改进建议：")
        for i, f in enumerate(findings, 1):
            print(f"  {i}. {f}")
    
    if warnings:
        print()
        print("💡 优化建议：")
        for i, w in enumerate(warnings, 1):
            print(f"  {i}. {w}")
    
    # ---- LGD 三律合规度 + 生态入口（评测 = 进入 LGD 生态的门）----
    l1_ok = os.path.exists(os.path.join(skill_path, "README.md")) and os.path.exists(os.path.join(skill_path, "CHANGELOG.md"))
    l2_ok = os.path.isdir(os.path.join(skill_path, "examples")) or os.path.isdir(os.path.join(skill_path, "tests"))
    l3_ok = True
    if findings:
        for f in findings:
            if any(k in f for k in ("危险", "风险", "泄", "密钥", "注入", "绕过")):
                l3_ok = False
                break
    print()
    print("=" * 70)
    print("  ⚖️  LGD 三律合规度（有籍 / 有证 / 有门禁）")
    print("-" * 70)
    print(f"  L1 有籍（Registered · 档案可追溯）: {'✅ 达标' if l1_ok else '❌ 待补'}")
    print(f"  L2 有证（Evidenced · 结论有证据）: {'✅ 达标' if l2_ok else '❌ 待补'}")
    print(f"  L3 有门禁（Gated · 关键节点有检查）: {'✅ 达标' if l3_ok else '❌ 待补'}")
    print("-" * 70)
    if l1_ok and l2_ok and l3_ok:
        print("  🏛️  三律全绿 = 可申请 LGD 认证徽章，进入 LGD 生态超市互链")
    else:
        print("  🏛️  按 LGD 三律补齐缺口后，可申请 LGD 认证徽章进入生态")
    print("  登记入口: lgd-ecosystem-hub（LGD 生态治理中枢，单一事实源）")
    print("  理论依据: LGD 三律 · AI 治理标准参与研究（W3C / ITU-T FG-TIDA）")
    print("=" * 70)
    
    print()
    print("=" * 70)
    print("  评测完成！")
    print("=" * 70)
    
    veto_info = None
    if raw_score != score:
        veto_info = {
            "applied": True,
            "raw_score": raw_score,
            "capped_to": score,
            "cap": veto_cap,
            "level": veto_level,
            "reason": veto_reason,
            "policy": "critical(凭证外泄/远程执行)→cap 49 · high(凭证暴露/命令执行)→cap 69；否决只封顶不替代五维明细",
        }

    return score, grade, dims, findings, warnings, veto_info

def render_ascii_bars(dims):
    """扣分明细（得分/满分）。刻意不输出百分比，避免出现第二套分数。"""
    MAXS = {"结构完整性": 25, "目录结构": 15, "文档质量": 20, "安全": 25, "生态兼容性": 15}
    order = ["结构完整性", "目录结构", "文档质量", "安全", "生态兼容性"]
    labels = {"结构完整性": "结构", "目录结构": "目录", "文档质量": "文档", "安全": "安全", "生态兼容性": "生态"}
    lines = ["  📋 扣分明细（得分 / 满分）:"]
    for k in order:
        got = dims.get(k, 0)
        ratio = got / MAXS[k] if MAXS[k] else 0
        filled = int(round(ratio * 10))
        bar = "█" * filled + "░" * (10 - filled)
        lines.append(f"    {labels[k]:<4} {bar} {got}/{MAXS[k]}")
    return "\n".join(lines)


def render_radar_svg(dims, out_path):
    """零依赖 SVG 五维雷达图（矢量、可嵌入报告/HTML）。"""
    import math
    MAXS = {"结构完整性": 25, "目录结构": 15, "文档质量": 20, "安全": 25, "生态兼容性": 15}
    order = ["结构完整性", "目录结构", "文档质量", "安全", "生态兼容性"]
    labels = {"结构完整性": "结构", "目录结构": "目录", "文档质量": "文档", "安全": "安全", "生态兼容性": "生态"}
    cx, cy, R = 260, 260, 200
    n = len(order)
    pts = []
    for i, k in enumerate(order):
        ang = math.pi / 2 + 2 * math.pi * i / n
        ratio = max(0.0, min(1.0, dims.get(k, 0) / MAXS[k]))
        pts.append((cx + R * ratio * math.cos(ang), cy - R * ratio * math.sin(ang)))
    poly = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
    svg = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="520" height="520" viewBox="0 0 520 520">',
        '<rect width="520" height="520" fill="#f8fafc" rx="16"/>',
        '<text x="260" y="38" text-anchor="middle" font-family="sans-serif" font-size="19" font-weight="bold" fill="#0f172a">LGD 评测 · 五维雷达图</text>',
    ]
    for level in range(1, 6):
        r = R * level / 5
        gpts = []
        for i in range(n):
            ang = math.pi / 2 + 2 * math.pi * i / n
            gpts.append(f"{cx + r * math.cos(ang):.1f},{cy - r * math.sin(ang):.1f}")
        svg.append(f'<polygon points="{" ".join(gpts)}" fill="none" stroke="#e2e8f0" stroke-width="1"/>')
    for i in range(n):
        ang = math.pi / 2 + 2 * math.pi * i / n
        svg.append(f'<line x1="{cx}" y1="{cy}" x2="{cx + R * math.cos(ang):.1f}" y2="{cy - R * math.sin(ang):.1f}" stroke="#cbd5e1" stroke-width="1"/>')
        lx, ly = cx + (R + 30) * math.cos(ang), cy - (R + 30) * math.sin(ang)
        svg.append(f'<text x="{lx:.1f}" y="{ly:.1f}" text-anchor="middle" font-family="sans-serif" font-size="15" font-weight="bold" fill="#334155">{labels[order[i]]}</text>')
        vx, vy = cx + (R - 34) * math.cos(ang), cy - (R - 34) * math.sin(ang)
        svg.append(f'<text x="{vx:.1f}" y="{vy:.1f}" text-anchor="middle" font-family="sans-serif" font-size="13" font-weight="bold" fill="#0f172a">{dims.get(order[i], 0)}</text>')
    svg.append(f'<polygon points="{poly}" fill="rgba(37,99,235,0.25)" stroke="#2563eb" stroke-width="3" stroke-linejoin="round"/>')
    for x, y in pts:
        svg.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="5" fill="#2563eb"/>')
    svg.append('</svg>')
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(svg))
    return out_path


def map_fix(issue):
    """把评测发现映射为「动作 + 落点 + 可判定验收」，供 AI 自主整改。"""
    i = issue.lower()
    # 占位内容优先：内容没落地时先补真实内容，而不是继续加章节
    if "占位" in i:
        return ("把占位内容替换为真实内容：示例贴一次真实输入输出，限制写真实做不到的事，README 写明真实安装命令与输出",
                "SKILL.md / README.md / examples/",
                "全目录检索不到 '待补充' / 'TODO' / '本示例为骨架' / '<作者名>' 等占位词")
    # frontmatter 字段优先：'缺少 license 字段' 不能当成缺 LICENSE 文件
    if "字段" in i or "frontmatter" in i:
        return ("补齐 SKILL.md frontmatter 五个必填字段：name、description、version、license、author",
                "SKILL.md",
                "SKILL.md frontmatter 同时含 name/description/version/license/author 且均非空")
    if "缺少 skill.md" in i:
        return ("创建 SKILL.md：frontmatter 五字段 + 何时用/怎么用/示例/已知限制四章",
                "SKILL.md",
                "包根存在 SKILL.md 且四章齐全")
    if "license" in i:
        return ("在包根新建 LICENSE，粘贴 MIT 全文（Copyright 2026 <作者名>）",
                "LICENSE",
                "包根存在 LICENSE，内容含 'MIT License' 与版权行")
    if "readme" in i:
        return ("创建 README.md：一句话定位 + 安装/使用命令 + 一次真实输出样例",
                "README.md",
                "包根存在 README.md，含安装命令与输出样例，正文 ≥500 字")
    if "scripts" in i:
        return ("创建 scripts/ 并放入至少 1 个 .py，只用标准库（平台运行时无第三方依赖）",
                "scripts/",
                "存在 scripts/ 且至少 1 个 .py，import 仅标准库")
    if "examples" in i:
        return ("创建 examples/ 并放入 1 个完整对答示例（用户输入 → 技能输出）",
                "examples/",
                "存在 examples/ 且至少 1 个文件同时含输入段与输出段")
    if "示例" in i:
        return ("在 SKILL.md 增加 `## 示例`，贴一次真实输入输出，不要写占位",
                "SKILL.md",
                "SKILL.md 含 '## 示例' 或 '## Examples' 章节")
    if "场景" in i:
        return ("在 SKILL.md 增加 `## When to Use`，列 3 条以上具体触发场景",
                "SKILL.md",
                "SKILL.md 含 '## When to Use' 或 '## 使用场景'")
    if "方法" in i:
        return ("在 SKILL.md 增加 `## 使用方法`，写清步骤与可直接复制的命令",
                "SKILL.md",
                "SKILL.md 含 '## Usage' 或 '## 使用方法'")
    if "限制" in i:
        return ("在 SKILL.md 增加 `## 已知限制`，列 3 条以上做不到的事",
                "SKILL.md",
                "SKILL.md 含 '## 已知限制' 且列 ≥3 条")
    if "tags" in i:
        return ("在 frontmatter 补 tags，写 3-5 个用户会搜的场景词",
                "SKILL.md",
                "frontmatter tags 含 ≥3 个标签")
    if any(k in i for k in ("eval/exec", "os.system", "密钥", "危险", "风险", "注入", "绕过", "网络", "泄漏", "硬编码")):
        return ("修复安全问题：先确认调用是否必要；确属规则定义的字符串加行级抑制注释（# skillgate: ignore）",
                "scripts/",
                "安全维度无 HIGH/CRITICAL 且 Trust Score ≥ 90")
    return ("按 issue 原文逐项定位并修复", ".", "重新评测后该项不再出现")


def build_fix_plan(findings, warnings):
    """输出机器可读整改清单：同一动作合并，避免 AI 重复执行同一件事。"""
    groups = {}
    order = []
    for issue in findings + warnings:
        key = issue.strip()
        if not key:
            continue
        action, target, acceptance = map_fix(issue)
        gkey = (action, target)
        if gkey not in groups:
            groups[gkey] = {"issue": key, "action": action, "target": target,
                            "acceptance": acceptance, "issues": []}
            order.append(gkey)
        if key not in groups[gkey]["issues"]:
            groups[gkey]["issues"].append(key)
    plan = [groups[k] for k in order]
    return {"fix_plan": plan, "count": len(plan), "framework": "LGD 三律（有籍/有证/有门禁）"}


# ============================================================
# 证据链（对应 LGD 三律的「有证 · Evidenced」）
# 每条扣分都必须能回答：哪条规则、哪个文件、第几行、证据什么、怎么改、怎么复验
# ============================================================

EVIDENCE_RULES = [
    ("缺少 SKILL.md", "R-STR-00", "结构完整性", "SKILL.md",
     "创建 SKILL.md 并写入 frontmatter（name/description/version/license/author）",
     "重跑规则 R-STR-00：文件存在即通过"),
    ("缺少 LICENSE", "R-STR-02", "结构完整性", "LICENSE",
     "添加许可证文件（建议 MIT 或 Apache-2.0，含年份与著作权人）",
     "重跑规则 R-STR-02：LICENSE 存在即通过"),
    ("缺少 README.md", "R-STR-03", "结构完整性", "README.md",
     "补写 README，至少包含用途、安装、用法三段",
     "重跑规则 R-STR-03：README 存在且非空即通过"),
    ("缺少 scripts 目录", "R-DIR-01", "目录结构", "scripts/",
     "建立 scripts/ 并放入可执行脚本；纯文档型技能可放一个占位说明",
     "重跑规则 R-DIR-01：目录存在即通过"),
    ("缺少 examples 目录", "R-DIR-02", "目录结构", "examples/",
     "建立 examples/ 并放入至少一个可运行或可复制的示例",
     "重跑规则 R-DIR-02：目录存在且含文件即通过"),
    ("缺少使用场景说明", "R-DOC-01", "文档质量", "SKILL.md",
     "补写「使用场景」章节，用具体任务描述说明何时该用",
     "重跑规则 R-DOC-01：命中场景章节关键词即通过"),
    ("缺少使用方法说明", "R-DOC-02", "文档质量", "SKILL.md",
     "补写「使用方法」章节，含命令行或调用方式",
     "重跑规则 R-DOC-02：命中用法章节关键词即通过"),
    ("缺少示例", "R-DOC-03", "文档质量", "SKILL.md",
     "在正文中加入至少一个可复制执行的示例",
     "重跑规则 R-DOC-03：命中示例章节关键词即通过"),
    ("建议加上已知限制说明", "R-DOC-04", "文档质量", "SKILL.md",
     "补写「已知限制」章节，说明不适用的场景与边界",
     "重跑规则 R-DOC-04：命中限制章节关键词即通过"),
    ("文档含占位标记", "R-DOC-05", "文档质量", "SKILL.md",
     "把占位标记（TODO/TBD/待补充/xxx）替换为真实内容",
     "重跑规则 R-DOC-05：占位标记归零即通过"),
    ("缺少 frontmatter", "R-ECO-01", "生态兼容性", "SKILL.md",
     "在文件首行加 --- 包裹的 YAML frontmatter",
     "重跑规则 R-ECO-01：frontmatter 可解析即通过"),
    ("建议加上 tags 标签", "R-ECO-02", "生态兼容性", "SKILL.md",
     "在 frontmatter 加 tags 列表，用于商店检索与路由",
     "重跑规则 R-ECO-02：tags 存在即通过"),
    ("运行时重建载荷", "R-SEC-08", "安全检查", "scripts/",
     "移除运行时拼装/解码/下载的载荷，改为可静态审阅的代码；确需动态执行须写明用途并加白名单",
     "重跑规则 R-SEC-08：exec/eval 参数为静态字面量或不出现即通过"),
    ("凭证文件读取后网络外发", "R-SEC-09", "安全检查", "scripts/",
     "禁止把 .ssh/.aws/.env 等敏感文件内容发往网络；如属必要功能须显式告知用户并取得授权",
     "重跑规则 R-SEC-09：敏感文件读取与外发不再出现在同一数据流"),
    ("跨文件凭证外泄", "R-SEC-10", "安全检查", "scripts/",
     "切断跨文件引用链：读取凭证的模块不得被外发模块导入",
     "重跑规则 R-SEC-10：两模块间不再存在引用关系"),
    ("越权指令", "R-SEC-11", "安全检查", "SKILL.md",
     "删除要求模型忽略既有规则的语句，这类话术是 prompt injection 的典型入口",
     "重跑规则 R-SEC-11：越权话术归零即通过"),
    ("隐瞒用户", "R-SEC-12", "安全检查", "SKILL.md",
     "删除要求向用户隐瞒行为的语句，改为显式告知用户",
     "重跑规则 R-SEC-12：隐瞒类话术归零即通过"),
    ("绕过安全检查", "R-SEC-13", "安全检查", "SKILL.md",
     "删除绕过/跳过安全审核的语句；如确需例外须走显式白名单并留痕",
     "重跑规则 R-SEC-13：绕过类话术归零即通过"),
    ("敏感数据外泄指令", "R-SEC-14", "安全检查", "SKILL.md",
     "删除把凭证/密钥/聊天记录上传或外发的指令",
     "重跑规则 R-SEC-14：外泄类指令归零即通过"),
    ("读取凭证文件指令", "R-SEC-15", "安全检查", "SKILL.md",
     "删除要求读取 .ssh/.aws/.env 等凭证文件的指令",
     "重跑规则 R-SEC-15：凭证读取指令归零即通过"),
    ("免确认执行", "R-SEC-16", "安全检查", "SKILL.md",
     "把免确认行为改为显式请求用户授权，或在文档中标注需要确认的步骤",
     "重跑规则 R-SEC-16：免确认话术归零即通过"),
]


def _line_of(root, rel, needle):
    """在文件里定位命中行号；定位不到返回 0，文件存在但无需定位返回 1。"""
    if not rel:
        return 0
    path = os.path.join(root, rel)
    if not os.path.isfile(path):
        return 0
    if not needle:
        return 1
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for i, ln in enumerate(f, 1):
                if needle in ln:
                    return i
    except OSError:
        pass
    return 1


def build_evidence(root, findings, warnings):
    """把文本 finding 升级成结构化证据链。不改动原有文本输出。"""
    items = [("finding", x) for x in findings] + [("warning", x) for x in warnings]
    out = []
    for kind, text in items:
        rid = dim = rel = fix = verify = None
        explicit_line = None
        # 形如 "evil.py:12: 描述" 的条目已自带精确位置，直接采用
        m_pos = re.match(r"^([^\s:]+\.(?:py|md|json|yml|yaml)):(\d+):\s*(.+)$", text)
        if m_pos:
            rel, explicit_line = m_pos.group(1), int(m_pos.group(2))
        m = re.match(r"缺少\s*([A-Za-z_]+)\s*字段", text)
        if m:
            field = m.group(1)
            rid, dim, rel = "R-STR-01", "结构完整性", "SKILL.md"
            fix = "在 frontmatter 中补 `%s` 字段" % field
            verify = "重跑规则 R-STR-01：该字段可解析即通过"
        if rid is None:
            for pat, r, d, f, fi, ve in EVIDENCE_RULES:
                if pat in text:
                    rid, dim, rel, fix, verify = r, d, f, fi, ve
                    break
        if rid is None:
            rid, dim, rel = "R-SEC-01", "安全检查", ""
            fix, verify = "按建议整改该安全问题", "重跑规则 R-SEC-01：该项不再出现即通过"
        needle = ""
        if "：" in text:
            needle = text.split("：", 1)[1].split("；")[0].strip()
        # 占位标记类：从「xxx」里取出真实词去定位，避免行号永远落在第 1 行
        if rid == "R-DOC-05":
            m2 = re.search(r"「([^」]+)」", text)
            if m2:
                needle = m2.group(1)
        out.append({
            "rule_id": rid,
            "dimension": dim,
            "file": (m_pos.group(1) if m_pos else rel),
            "line": explicit_line if explicit_line is not None else (_line_of(root, rel, needle) if rel else 0),
            "evidence": text,
            "fix": fix,
            "verify": verify,
            "severity": kind,
        })
    return out


def canonical_dumps(obj):
    """规范化序列化：键排序、无空格、不转义中文。同输入必得同字节。"""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _tree_hashes(root):
    """整棵树的文件哈希清单：任何人都能核对"评的就是这份代码"。"""
    files = {}
    skip = {".git", "__pycache__", "node_modules", ".venv", "venv"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, root).replace("\\", "/")
            try:
                with open(p, "rb") as f:
                    files[rel] = hashlib.sha256(f.read()).hexdigest()
            except OSError:
                continue
    tree = hashlib.sha256(canonical_dumps(files).encode("utf-8")).hexdigest()
    return files, "sha256:" + tree


def build_attestation(root, score, grade, dims, evidence, veto=None):
    """生成可复现的评测证明。fingerprint 只取自被测内容，不含路径与时间。"""
    payload = {
        "object": {"score": score, "grade": grade},
        "dims": {k: dims.get(k, 0) for k in sorted(dims)},
        "findings": [{"rule_id": e["rule_id"], "dimension": e["dimension"],
                      "file": e["file"], "line": e["line"],
                      "evidence": e["evidence"], "fix": e["fix"], "verify": e["verify"]}
                     for e in evidence],
    }
    if veto:
        payload["veto"] = veto
    fp = hashlib.sha256(canonical_dumps(payload).encode("utf-8")).hexdigest()
    files, tree = _tree_hashes(root)
    inputs = {
        "file_count": len(files),
        "files": files,
        "tree_sha256": tree,
        "note": "tree_sha256 是整棵树 + 目录结构的哈希；改动任何一个字节都会变，可用于 pin（锁定'跑的就是你审的'）",
    }
    return {
        "framework": "LGD 三律 · 有籍(可追溯) / 有证(可验证) / 有门禁(可阻断)",
        "engine_version": "1.1.0",
        "score": score,
        "grade": grade,
        "dims": payload["dims"],
        "findings": payload["findings"],
        "fingerprint": "sha256:" + fp,
        "safety_veto": veto if veto else {"applied": False},
        "inputs": inputs,
        "reproduce": "python evaluate.py <同一路径> --evidence-json out.json  # 应得到完全相同的 fingerprint 与 tree_sha256",
    }


# ============================================================
# 可插拔检测器：默认关闭，按需自配（核心功能零成本即可用）
# ============================================================
def lgd_capabilities():
    """返回各可选能力是否就绪。用于在报告里明确"什么没开"。"""
    cfg = _llm_config()
    backend = sandbox_backend()
    return {
        "llm_review": bool(cfg),
        "sandbox": bool(backend),
        "sandbox_backend": backend,
        "llm_model": cfg[2] if cfg else None,
    }


def _llm_config():
    base = (os.environ.get("LGD_LLM_BASE") or os.environ.get("OPENAI_BASE_URL") or "").strip()
    key = (os.environ.get("LGD_LLM_KEY") or os.environ.get("OPENAI_API_KEY") or "").strip()
    model = (os.environ.get("LGD_LLM_MODEL") or "gpt-4o-mini").strip()
    if base and key:
        return base.rstrip("/"), key, model
    return None


def llm_review(evidence):
    """L2 复核：只对已有命中项做二次判定，给出误报意见（不改分，交人判断）。

    需自配：LGD_LLM_BASE / LGD_LLM_KEY（OpenAI 兼容接口），否则自动跳过。
    """
    cfg = _llm_config()
    if not cfg:
        return {"enabled": False, "reason": "未配置 LGD_LLM_BASE / LGD_LLM_KEY"}
    base, key, model = cfg
    items = [{"index": i, "rule": e["rule_id"], "file": e["file"],
              "line": e["line"], "evidence": e["evidence"]}
             for i, e in enumerate(evidence)][:20]
    if not items:
        return {"enabled": True, "verdicts": [], "note": "无命中项"}
    prompt = (
        "你是技能安全审核员。下面是扫描器对某技能的命中项。"
        "逐条判断是真实风险(true_positive)还是规则误报(false_positive)，"
        "只输出 JSON 数组，每项 {index, verdict, reason}，不要额外文字。\n"
        + json.dumps(items, ensure_ascii=False)
    )
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
    }).encode("utf-8")
    req = urllib.request.Request(
        base + "/chat/completions", data=payload,
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + key})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = json.loads(resp.read().decode("utf-8", "ignore"))
        text = body["choices"][0]["message"]["content"].strip()
        text = text.strip("`").replace("json\n", "", 1).strip()
        return {"enabled": True, "verdicts": json.loads(text), "model": model}
    except Exception as exc:
        return {"enabled": True, "error": str(exc)[:200]}


LGD_AUDIT_HOOK = r'''
import sys, json, os
_L = os.environ.get("LGD_AUDIT_LOG", "")
_SENS = (".ssh", ".aws", ".env", "id_rsa", ".npmrc", ".git-credentials",
         "credential", "secret", "token", "password")
_BUSY = [False]

def _w(rec):
    if not _L:
        return
    with open(_L, "a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

def _hook(event, args):
    if _BUSY[0]:
        return
    _BUSY[0] = True
    try:
        if event == "socket.connect":
            _w({"ev": "connect", "addr": str(args[1])})
        elif event == "socket.getaddrinfo":
            _w({"ev": "resolve", "host": str(args[0])})
        elif event == "open" and args and isinstance(args[0], str):
            low = args[0].lower()
            if any(k in low for k in _SENS):
                _w({"ev": "open_sensitive", "path": args[0]})
        elif event in ("os.system", "subprocess.Popen"):
            _w({"ev": event, "arg": str(args)[:160]})
        elif event == "exec":
            sz = len(str(args[0])) if args else 0
            if sz > 200:
                _w({"ev": "exec_big", "size": sz})
    except Exception:
        pass
    finally:
        _BUSY[0] = False

sys.addaudithook(_hook)
'''


def sandbox_backend():
    """L3 后端优先级：docker > unshare(Linux) > 不可用。"""
    if shutil.which("docker"):
        return "docker"
    if sys.platform.startswith("linux") and shutil.which("unshare"):
        return "unshare"
    return None


def _sandbox_one(backend, tree, script, timeout):
    rel = os.path.relpath(script, tree).replace("\\", "/")
    logp = os.path.join(tree, "_audit_%s.jsonl"
                        % hashlib.sha256(rel.encode()).hexdigest()[:8])
    if os.path.exists(logp):
        os.remove(logp)
    env = dict(os.environ)
    env["LGD_AUDIT_LOG"] = logp
    env["HOME"] = tree
    for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
              "all_proxy", "ALL_PROXY", "ftp_proxy", "FTP_PROXY", "PYTHONHOME"):
        env.pop(k, None)
    if backend == "unshare":
        env["PYTHONPATH"] = tree
        cmd = ["unshare", "--user", "--map-root-user", "--net", "--pid", "--fork",
               "timeout", str(timeout), sys.executable, os.path.basename(script)]
        cwd = os.path.dirname(script)
    else:  # docker
        env["PYTHONPATH"] = "/s"
        cmd = ["docker", "run", "--rm", "--network", "none", "--read-only",
               "--memory", "256m", "--pids-limit", "64",
               "-e", "LGD_AUDIT_LOG=/logs/a.jsonl", "-e", "PYTHONPATH=/s",
               "-e", "HOME=/s",
               "-v", tree + ":/s:ro", "-v", tree + ":/logs:rw",
               "-w", "/s/" + os.path.dirname(rel),
               "python:3.12-slim", "timeout", str(timeout),
               "python3", os.path.basename(script)]
        cwd = tree
    try:
        r = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True,
                           text=True, timeout=timeout + 8)
        rc, err = r.returncode, r.stderr
    except (subprocess.TimeoutExpired, OSError) as exc:
        rc, err = "TIMEOUT/ERR", str(exc)[:140]
    events = []
    for cand in (logp, os.path.join(tree, "a.jsonl")):
        if os.path.exists(cand):
            with open(cand, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            events.append(json.loads(line))
                        except ValueError:
                            pass
            break
    return {"script": rel, "rc": rc, "stderr": err[-300:], "events": events}


def sandbox_detonate(target, timeout=8):
    """在隔离环境真实执行脚本，观测运行时行为：读凭证 / 解析外发域名 / 起子进程。

    静态只能推测"可能外发"，这里能证明"它确实读了凭证、也确实要发往某个域名"。
    """
    backend = sandbox_backend()
    if not backend:
        return {"enabled": False,
                "reason": "未检测到 docker 或 Linux unshare（装 docker 或换 Linux 后自动就绪）"}
    work = tempfile.mkdtemp(prefix="lgd-sb-")
    tree = os.path.join(work, "tree")
    shutil.copytree(target, tree)
    with open(os.path.join(tree, "sitecustomize.py"), "w", encoding="utf-8") as f:
        f.write(LGD_AUDIT_HOOK)
    # 蜜罐：放可读假凭证，让"读-发"链路能跑完，从而看到真实外发目标
    for d in (tree, os.path.join(tree, "scripts")):
        try:
            with open(os.path.join(d, ".env"), "w") as f:
                f.write("AWS_SECRET_ACCESS_KEY=FAKE_FOR_SANDBOX\n")
        except OSError:
            pass
    try:
        os.makedirs(os.path.join(tree, ".ssh"), exist_ok=True)
        with open(os.path.join(tree, ".ssh", "id_rsa"), "w") as f:
            f.write("-----BEGIN FAKE PRIVATE KEY-----\nHONEYPOT\n-----END-----\n")
    except OSError:
        pass

    results = []
    for dirpath, _, files in os.walk(tree):
        for fn in sorted(files):
            if fn.endswith(".py") and fn != "sitecustomize.py":
                results.append(_sandbox_one(backend, tree, os.path.join(dirpath, fn), timeout))

    exfil = []
    for r in results:
        sens = [e["path"] for e in r["events"] if e["ev"] == "open_sensitive"]
        hosts = [e["host"] for e in r["events"] if e["ev"] == "resolve"]
        if sens and hosts:
            exfil.append({"script": r["script"], "read": sens[0], "sent_to": hosts})
    return {"enabled": True, "backend": backend, "scripts": len(results),
            "results": results, "exfiltration_evidence": exfil}


def build_sarif(evidence, score, grade):
    """SARIF 2.1.0：GitHub Code Scanning / VS Code / 其他 SAST 平台可直接消费。"""
    rules, results = {}, []
    for e in evidence:
        rid = e["rule_id"]
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": "LGD" + rid.replace("R-", "").replace("-", ""),
                "shortDescription": {"text": e["dimension"]},
                "fullDescription": {"text": e["fix"]},
                "help": {"text": e["verify"]},
                "helpUri": ("https://github.com/LGD-Eval/lgd-gate/blob/main/README.md#"
                            + rid.lower()),
                "defaultConfiguration": {
                    "level": "error" if e["severity"] == "finding" else "warning"
                },
                "properties": {"tags": ["security", "lgd", e["dimension"]]},
            }
        results.append({
            "ruleId": rid,
            "level": "error" if e["severity"] == "finding" else "warning",
            "message": {"text": e["evidence"]},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": e["file"] or "SKILL.md"},
                "region": {"startLine": max(1, int(e["line"] or 1))},
            }}],
            "properties": {"dimension": e["dimension"], "severity": e["severity"]},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "LGD-Gate",
                "informationUri": "https://github.com/LGD-Eval/lgd-gate",
                "version": "1.0.0",
                "rules": list(rules.values()),
            }},
            "results": results,
            "properties": {"trustScore": score, "grade": grade,
                           "framework": "LGD 三律 · 有籍/有证/有门禁"},
        }],
    }


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="LGD 评测引擎 · 独立第三方技能质检")
    ap.add_argument("skill_path", nargs="?", help="技能目录路径")
    ap.add_argument("--chart", action="store_true", help="生成五维雷达图 radar.svg")
    ap.add_argument("--ascii", action="store_true", help="输出五维 ASCII 雷达条形图")
    ap.add_argument("--fix-json", metavar="PATH", help="输出机器可读整改清单 JSON（供 AI 自主整改）")
    ap.add_argument("--evidence-json", metavar="PATH",
                    help="输出可复现评测证明 JSON（含证据链与 sha256 fingerprint）")
    ap.add_argument("--detail", action="store_true",
                    help="在终端打印证据链：规则 → 文件:行 → 证据 → 整改 → 复验")
    ap.add_argument("--fail-under", type=int, default=0, metavar="N",
                    help="门禁模式：分数低于 N 时以退出码 1 结束，可直接用于 CI 卡 PR")
    ap.add_argument("--sarif", metavar="PATH",
                    help="输出 SARIF 2.1.0（GitHub Code Scanning 可直接消费）")
    ap.add_argument("--llm-review", action="store_true",
                    help="L2 复核（需自配 LGD_LLM_BASE / LGD_LLM_KEY；未配则跳过）")
    ap.add_argument("--capabilities", action="store_true",
                    help="只打印可选能力就绪状态（LLM 复核 / 沙箱）")
    ap.add_argument("--sandbox", action="store_true",
                    help="L3 沙箱：隔离执行并观测运行时行为（需 docker 或 Linux unshare）")
    args = ap.parse_args()

    if args.capabilities:
        caps = lgd_capabilities()
        print("可选能力（默认关闭，按需自配）：")
        print("  L2 LLM 复核: %s" % ("就绪 · " + str(caps["llm_model"]) if caps["llm_review"]
                                  else "未配置（设 LGD_LLM_BASE + LGD_LLM_KEY 即可启用）"))
        print("  L3 沙箱:     %s" % ("就绪 · 后端 " + str(caps["sandbox_backend"]) if caps["sandbox"]
                                  else "未启用（装 docker，或在 Linux 上运行即可）"))
        sys.exit(0)
    
    if not args.skill_path:
        print("用法: python evaluate.py <skill_path> [--chart] [--ascii] [--fix-json <path>]")
        print()
        print("示例:")
        print("  python evaluate.py ./my-skill/")
        print("  python evaluate.py ./my-skill/ --chart --ascii --fix-json fix-plan.json")
        sys.exit(1)
    
    target = args.skill_path
    if os.path.isfile(target):
        # 单文件模式：把单个 SKILL.md / prompt 文件包装成标准技能目录再评，
        # 让"贴一段内容就评测"与竞品入口对齐，同时保留完整五维口径
        target = tempfile.mkdtemp(prefix="lgd-eval-file-")
        shutil.copyfile(args.skill_path, os.path.join(target, "SKILL.md"))
        print("ℹ️ 单文件模式：已按标准技能目录包装评测（%s）" % os.path.basename(args.skill_path))
        print("   仅能评文本质量；结构/目录维度会因缺 LICENSE、README、scripts/ 扣分。完整评测请传目录。")

    score, grade, dims, findings, warnings, veto_info = evaluate_skill(target)

    
    if args.ascii:
        print()
        print(render_ascii_bars(dims))
    if args.chart:
        out = os.path.join(os.getcwd(), "radar.svg")
        render_radar_svg(dims, out)
        print()
        print(f"  📈 五维雷达图已生成: {out}")
    if args.fix_json:
        plan = build_fix_plan(findings, warnings)
        with open(args.fix_json, 'w', encoding='utf-8') as f:
            json.dump(plan, f, ensure_ascii=False, indent=2)
        print()
        print(f"  🔧 机器可读整改清单已生成: {args.fix_json}（{plan['count']} 项，AI 可自主整改）")

    if args.evidence_json or args.detail or args.sarif or args.llm_review:
        evidence = build_evidence(target, findings, warnings)
        att = build_attestation(target, score, grade, dims, evidence, veto_info)

        if args.evidence_json:
            with open(args.evidence_json, 'w', encoding='utf-8', newline='\n') as f:
                f.write(canonical_dumps(att))
            print()
            print(f"  🧾 可复现评测证明已生成: {args.evidence_json}")
            print(f"     fingerprint: {att['fingerprint']}")

        if args.detail:
            print()
            print("  🧾 证据链（规则 → 文件:行 → 证据 → 整改 → 复验）:")
            for e in evidence:
                loc = ("%s:%s" % (e["file"], e["line"])) if e["file"] else "—"
                print(f"    [{e['rule_id']}] {loc}")
                print(f"       证据: {e['evidence']}")
                print(f"       整改: {e['fix']}")
                print(f"       复验: {e['verify']}")

        if args.sarif:
            with open(args.sarif, 'w', encoding='utf-8', newline='\n') as f:
                f.write(canonical_dumps(build_sarif(evidence, score, grade)))
            print()
            print(f"  🛰️ SARIF 2.1.0 已生成: {args.sarif}（可上传到 GitHub Code Scanning）")

        if args.llm_review:
            rv = llm_review(evidence)
            print()
            if not rv.get("enabled"):
                print("  ⚠️ L2 复核未启用：%s（核心检测已生效，无需联网）" % rv.get("reason"))
            elif rv.get("error"):
                print("  ⚠️ L2 复核失败：%s" % rv["error"])
            else:
                vs = rv.get("verdicts") or []
                tp = sum(1 for v in vs if str(v.get("verdict")) == "true_positive")
                print("  🤖 L2 复核（%s）：真阳性 %d / 疑误报 %d" % (rv.get("model"), tp, len(vs) - tp))
                for v in vs:
                    if str(v.get("verdict")) != "false_positive":
                        continue
                    idx = v.get("index")
                    if isinstance(idx, int) and 0 <= idx < len(evidence):
                        print("     · 疑误报 [%s] %s" % (evidence[idx]["rule_id"],
                                                   evidence[idx]["evidence"][:80]))

    if args.sandbox:
        sb = sandbox_detonate(target)
        print()
        if not sb.get("enabled"):
            print("  ⚠️ L3 沙箱未启用：%s（静态检测已生效，无需环境）" % sb.get("reason"))
        else:
            print("  🧪 L3 沙箱（后端 %s）：执行 %d 个脚本" % (sb["backend"], sb["scripts"]))
            for r in sb["results"]:
                flags = []
                if any(e["ev"] == "open_sensitive" for e in r["events"]):
                    flags.append("读敏感文件")
                if any(e["ev"] == "resolve" for e in r["events"]):
                    flags.append("尝试外发")
                if any(e["ev"] in ("os.system", "subprocess.Popen") for e in r["events"]):
                    flags.append("起子进程")
                print("     · %s → %s" % (r["script"], "、".join(flags) if flags else "未观测到可疑行为"))
            if sb["exfiltration_evidence"]:
                print("  ⛔ 运行时铁证（静态只能推测，这里是它真的做了）：")
                for e in sb["exfiltration_evidence"]:
                    print("     %s 读取 %s → 发往 %s" % (e["script"], e["read"], ", ".join(e["sent_to"])))

    if args.fail_under:
        if score < args.fail_under:
            print()
            print(f"  ⛔ 门禁未通过：{score} < {args.fail_under}（退出码 1）")
            sys.exit(1)
        print()
        print(f"  ✅ 门禁通过：{score} ≥ {args.fail_under}")
