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
    
    def _strip_string_literals(code):
        # 剥离字符串字面量，避免规则定义字符串（如 'eval(' / 'os.system('）被误判为真实调用
        return re.sub(r"('[^'\\]*(?:\\.[^'\\]*)*'|\"[^\"\\]*(?:\\.[^\"\\]*)*\")", '', code)
    
    if os.path.exists(scripts_dir):
        for script_file in os.listdir(scripts_dir):
            if script_file.endswith('.py'):
                script_path = os.path.join(scripts_dir, script_file)
                with open(script_path, 'r', encoding='utf-8') as f:
                    code = f.read()
                    stripped = _strip_string_literals(code)
                    
                    # 检查硬编码密钥（真实赋值语句才命中）
                    if re.search(r'api_key\s*=\s*["\']', stripped, re.IGNORECASE):
                        security_issues.append(f"{script_file}: 硬编码 API key")
                        score -= 5
                    
                    # 检查 eval/exec（排除字符串字面量中的规则定义）
                    if 'eval(' in stripped or 'exec(' in stripped:  # skillgate: ignore
                        security_issues.append(f"{script_file}: 使用 eval/exec")
                        score -= 3
                    
                    # 检查 os.system（排除字符串字面量中的规则定义）
                    if 'os.system(' in stripped:  # skillgate: ignore
                        security_issues.append(f"{script_file}: 使用 os.system")
                        score -= 2
    
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
    
    return score, grade, dims, findings, warnings

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
            "file": rel,
            "line": _line_of(root, rel, needle) if rel else 0,
            "evidence": text,
            "fix": fix,
            "verify": verify,
            "severity": kind,
        })
    return out


def canonical_dumps(obj):
    """规范化序列化：键排序、无空格、不转义中文。同输入必得同字节。"""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def build_attestation(root, score, grade, dims, evidence):
    """生成可复现的评测证明。fingerprint 只取自被测内容，不含路径与时间。"""
    payload = {
        "object": {"score": score, "grade": grade},
        "dims": {k: dims.get(k, 0) for k in sorted(dims)},
        "findings": [{"rule_id": e["rule_id"], "dimension": e["dimension"],
                      "file": e["file"], "line": e["line"],
                      "evidence": e["evidence"], "fix": e["fix"], "verify": e["verify"]}
                     for e in evidence],
    }
    fp = hashlib.sha256(canonical_dumps(payload).encode("utf-8")).hexdigest()
    return {
        "framework": "LGD 三律 · 有籍(可追溯) / 有证(可验证) / 有门禁(可阻断)",
        "score": score,
        "grade": grade,
        "dims": payload["dims"],
        "findings": payload["findings"],
        "fingerprint": "sha256:" + fp,
        "reproduce": "python evaluate.py <同一路径> --evidence-json out.json  # 应得到完全相同的 fingerprint",
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
    args = ap.parse_args()
    
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

    score, grade, dims, findings, warnings = evaluate_skill(target)

    
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

    if args.evidence_json or args.detail:
        evidence = build_evidence(target, findings, warnings)
        att = build_attestation(target, score, grade, dims, evidence)

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

    if args.fail_under:
        if score < args.fail_under:
            print()
            print(f"  ⛔ 门禁未通过：{score} < {args.fail_under}（退出码 1）")
            sys.exit(1)
        print()
        print(f"  ✅ 门禁通过：{score} ≥ {args.fail_under}")
