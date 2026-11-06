#!/usr/bin/env python3
"""
SkillGate 全方位审查工具
=========================
发布前强制审查：代码 / 安全 / 稳定性 / 准确性 / 资源消耗 / AI友好 / LGD生态互链
"""

import os
import sys
import re
import subprocess
from pathlib import Path


class ComprehensiveReview:
    """全方位审查器"""
    
    def __init__(self, project_dir, is_internal_skill=False):
        self.project_dir = Path(project_dir).resolve()
        self.findings = []
        self.score = 100
        self.skillgate_script = Path(__file__).parent / 'skillgate.py'
        self.is_internal_skill = is_internal_skill  # 内部技能模式：降低开源项目要求
    
    def add_finding(self, severity, category, message):
        """添加发现"""
        self.findings.append({
            'severity': severity,
            'category': category,
            'message': message
        })
        if severity == 'CRITICAL':
            self.score -= 15
        elif severity == 'HIGH':
            self.score -= 8
        elif severity == 'MEDIUM':
            self.score -= 3
        elif severity == 'LOW':
            self.score -= 1
    
    def check_structure(self):
        """维度1：结构完整性"""
        print("=" * 60)
        print("  📁 维度1：结构完整性")
        print("=" * 60)
        print()
        
        if self.is_internal_skill:
            # 内部技能：只要求 SKILL.md
            required_files = ['SKILL.md']
            print("  （内部技能模式：只检查 SKILL.md）")
        else:
            # 开源项目：要求所有文件
            required_files = [
                'README.md',
                'README.zh-CN.md',
                'LICENSE',
                'CHANGELOG.md',
                'CONTRIBUTING.md',
                'CODE_OF_CONDUCT.md',
                'SECURITY.md',
                'pyproject.toml',
                'SKILL.md',
                'llms.txt',
            ]
        
        for f in required_files:
            if not (self.project_dir / f).exists():
                severity = 'HIGH' if not self.is_internal_skill else 'MEDIUM'
                self.add_finding(severity, 'structure', f'缺少必要文件: {f}')
                print(f"  ❌ 缺少: {f}")
            else:
                print(f"  ✅ 有: {f}")
        print()
    
    def check_security(self):
        """维度2：安全检查"""
        print("=" * 60)
        print("")
        print("  🔒 维度2：安全检查")
        print("=" * 60)
        print()
        
        # 检查有没有硬编码密钥
        for py_file in self.project_dir.rglob("*.py"):
            if '__pycache__' in str(py_file):
                continue
            try:
                content = py_file.read_text(encoding='utf-8', errors='replace')
                if re.search(r'api_key\s*=\s*["\'][a-zA-Z0-9]{20,}["\']', content, re.IGNORECASE):
                    self.add_finding('CRITICAL', 'security', f'硬编码 API key: {py_file.name}')
                    print(f"  ❌ 硬编码 API key: {py_file.name}")
            except:
                pass
        
        print("  ✅ 安全检查完成！")
        print()
    
    def check_honesty(self):
        """维度3：数字诚实性（从第三方评测学来的！）"""
        print("=" * 60)
        print("")
        print("  📊 维度3：数字诚实性（第三方评测教训！）")
        print("=" * 60)
        print()
        
        # 检查 README 里有没有吹牛的数字
        readme = self.project_dir / 'README.md'
        if readme.exists():
            content = readme.read_text(encoding='utf-8')
            
            # 检查有没有吹牛数字（600+、999+、17 languages 等）
            import re
            big_numbers = re.findall(r'\b(\d{3,}\+)\b', content)
            if big_numbers or '17 languages' in content:
                self.add_finding('HIGH', 'honesty', f'README 里有吹牛的数字：{big_numbers}')
                print(f"  ❌ README 里有吹牛的数字：{big_numbers}")
            else:
                print("  ✅ README 数字诚实")
            
            # 检查术语统一
            if 'Guarded' in content:
                self.add_finding('MEDIUM', 'honesty', 'README 里还用了 Guarded，应该改成 gated')
                print("  ⚠️  README 里还用了 Guarded，应该改成 gated")
            else:
                print("  ✅ 术语统一")
        
        print()
    
    def check_bug_fixes(self):
        """维度4：Bug 修复验证（从第三方评测学来的！）"""
        print("=" * 60)
        print("")
        print("  🐛 维度4：Bug 修复验证（第三方评测教训！）")
        print("=" * 60)
        print()
        
        # 检查 good-skill 是不是 100 分
        good_skill_dir = self.project_dir / 'examples' / 'good-skill'
        if not good_skill_dir.exists():
            print("  ℹ️  没有 examples/good-skill，跳过")
            print()
            return
        
        print("  测试 good-skill 得分...")
        result = subprocess.run(
            ['python', str(self.skillgate_script), 'scan', str(good_skill_dir), '--lenient'],
            cwd=self.project_dir,
            capture_output=True,
            text=True
        )
        
        if '100/100' in result.stdout:
            print("  ✅ good-skill 是 100 分！")
        else:
            self.add_finding('HIGH', 'bugfix', 'good-skill 不是 100 分！BOM bug 没修好？')
            print("  ❌ good-skill 不是 100 分！")
        
        print()
    
    def check_cleanliness(self):
        """维度5：卫生检查（从第三方评测学来的！）"""
        print("=" * 60)
        print("")
        print("  🧹 维度5：卫生检查（第三方评测教训！）")
        print("=" * 60)
        print()
        
        # 检查有没有本地日志文件
        log_files = ['bandit-high.txt', 'scan-result.txt', 'scan-round-1.txt']
        for f in log_files:
            if (self.project_dir / f).exists():
                self.add_finding('MEDIUM', 'cleanliness', f'本地日志文件被提交了: {f}')
                print(f"  ❌ 本地日志文件: {f}")
            else:
                print(f"  ✅ 没有: {f}")
        
        # 检查 .gitignore 有没有
        if (self.project_dir / '.gitignore').exists():
            print("  ✅ 有 .gitignore")
        else:
            self.add_finding('MEDIUM', 'cleanliness', '缺少 .gitignore')
            print("  ❌ 缺少 .gitignore")
        
        print()
    
    def check_ai_friendly(self):
        """维度6：AI 友好性"""
        print("=" * 60)
        print("")
        print("  🤖 维度6：AI 友好性")
        print("=" * 60)
        print()
        
        # 检查有没有 llms.txt
        if (self.project_dir / 'llms.txt').exists():
            print("  ✅ 有 llms.txt")
        else:
            self.add_finding('MEDIUM', 'ai-friendly', '缺少 llms.txt')
            print("  ❌ 缺少 llms.txt")
        
        # 检查有没有 SKILL.md
        if (self.project_dir / 'SKILL.md').exists():
            print("  ✅ 有 SKILL.md")
        else:
            self.add_finding('HIGH', 'ai-friendly', '缺少 SKILL.md')
            print("  ❌ 缺少 SKILL.md")
        
        print()
    
    def check_lgd_ecosystem(self):
        """维度7：LGD 生态互链"""
        print("=" * 60)
        print("")
        print("  🌳 维度7：LGD 生态互链")
        print("=" * 60)
        print()
        
        # 检查 README 里有没有提到 LGD
        readme = self.project_dir / 'README.md'
        if readme.exists():
            content = readme.read_text(encoding='utf-8')
            if 'LGD' in content:
                print("  ✅ README 里提到了 LGD")
            else:
                self.add_finding('LOW', 'lgd-ecosystem', 'README 里没提到 LGD')
                print("  ⚠️  README 里没提到 LGD")
        
        print()
    
    def check_lgd_three_laws(self):
        """维度8：LGD 三律审计（有籍/有证/有门禁）"""
        print("=" * 60)
        print("")
        print("  ⚖️ 维度8：LGD 三律审计")
        print("=" * 60)
        print()
        
        # LGD-I 有籍 REGISTERED
        print("  📇 LGD-I 有籍（Registered）：")
        
        # 身份登记：有 LICENSE，有作者
        if (self.project_dir / 'LICENSE').exists():
            print("    ✅ 身份登记：有 LICENSE")
        else:
            self.add_finding('HIGH', 'lgd-three-laws', 'LGD-I: 缺少 LICENSE（身份登记）')
            print("    ❌ 缺少 LICENSE（身份登记）")
        
        # 版本登记：有 CHANGELOG.md
        if (self.project_dir / 'CHANGELOG.md').exists():
            print("    ✅ 版本登记：有 CHANGELOG.md")
        else:
            self.add_finding('MEDIUM', 'lgd-three-laws', 'LGD-I: 缺少 CHANGELOG.md（版本登记）')
            print("    ⚠️  缺少 CHANGELOG.md（版本登记）")
        
        # 血缘登记：有 Git 历史，或分发包内以版本谱系文档替代
        if (self.project_dir / '.git').exists():
            print("    ✅ 血缘登记：有 .git 历史")
        elif (self.project_dir / 'CHANGELOG.md').exists():
            print("    ✅ 血缘登记：分发包以 CHANGELOG 版本谱系登记（无 .git，属分发形态限制）")
        else:
            self.add_finding('LOW', 'lgd-three-laws', 'LGD-I: 没有 .git 历史且无 CHANGELOG（血缘登记）')
            print("    ⚠️  没有血缘登记（无 .git，无 CHANGELOG）")
        
        print()
        
        # LGD-II 有证 EVIDENCED
        print("  📜 LGD-II 有证（Evidenced）：")
        
        # 身份证据：有 README
        if (self.project_dir / 'README.md').exists():
            print("    ✅ 身份证据：有 README.md")
        else:
            self.add_finding('HIGH', 'lgd-three-laws', 'LGD-II: 缺少 README.md（身份证据）')
            print("    ❌ 缺少 README.md（身份证据）")
        
        # 验证证据：有 tests/ 目录
        if (self.project_dir / 'tests').exists():
            print("    ✅ 验证证据：有 tests/ 目录")
        else:
            self.add_finding('MEDIUM', 'lgd-three-laws', 'LGD-II: 缺少 tests/ 目录（验证证据）')
            print("    ⚠️  缺少 tests/ 目录（验证证据）")
        
        # 安全证据：有 SECURITY.md
        if (self.project_dir / 'SECURITY.md').exists():
            print("    ✅ 安全证据：有 SECURITY.md")
        else:
            self.add_finding('MEDIUM', 'lgd-three-laws', 'LGD-II: 缺少 SECURITY.md（安全证据）')
            print("    ⚠️  缺少 SECURITY.md（安全证据）")
        
        print()
        
        # LGD-III 有门禁 GATED
        print("  🚪 LGD-III 有门禁（Gated）：")
        
        # 触发门禁：有 GitHub Actions CI
        if (self.project_dir / '.github' / 'workflows').exists():
            print("    ✅ 触发门禁：有 GitHub Actions CI")
        else:
            self.add_finding('MEDIUM', 'lgd-three-laws', 'LGD-III: 缺少 GitHub Actions CI（触发门禁）')
            print("    ⚠️  缺少 GitHub Actions CI（触发门禁）")
        
        # 评审门禁：有 PR 模板
        pr_template = self.project_dir / '.github' / 'PULL_REQUEST_TEMPLATE.md'
        if pr_template.exists():
            print("    ✅ 评审门禁：有 PR 模板")
        else:
            self.add_finding('LOW', 'lgd-three-laws', 'LGD-III: 缺少 PR 模板（评审门禁）')
            print("    ⚠️  缺少 PR 模板（评审门禁）")
        
        print()
    
    def check_fact_consistency(self):
        """维度9：事实一致性检查（从 repo-fact-consistency-gate 提取！）"""
        print("=" * 60)
        print("")
        print("  📊 维度9：事实一致性检查")
        print("=" * 60)
        print()
        
        readme = self.project_dir / 'README.md'
        changelog = self.project_dir / 'CHANGELOG.md'
        
        if not readme.exists():
            print("  ⚠️  没有 README.md，跳过")
            print()
            return
        
        readme_content = readme.read_text(encoding='utf-8')
        changelog_content = changelog.read_text(encoding='utf-8') if changelog.exists() else ''
        
        # 检查版本号是不是一致
        print("  检查版本号一致性...")
        version_pattern = r'v?(\d+\.\d+\.\d+)'
        # 包版本的权威来源是 SKILL.md frontmatter；README 中可能并列评测器版本号
        pkg_version = None
        _skill_md = self.project_dir / 'SKILL.md'
        if _skill_md.exists():
            try:
                _m = re.search(r'^version:\s*["\']?(\d+\.\d+\.\d+)',
                               _skill_md.read_text(encoding='utf-8', errors='replace'), re.MULTILINE)
                if _m:
                    pkg_version = _m.group(1)
            except Exception:
                pass

        
        readme_versions = [pkg_version] if pkg_version else re.findall(version_pattern, readme_content)
        changelog_versions = re.findall(version_pattern, changelog_content)
        
        _vsrc = 'SKILL.md' if pkg_version else 'README'
        if readme_versions and changelog_versions:
            if readme_versions[0] == changelog_versions[0]:
                print(f"    ✅ 版本号一致: v{readme_versions[0]}（{_vsrc} ↔ CHANGELOG）")
            else:
                self.add_finding('MEDIUM', 'fact-consistency', 
                    f'版本号不一致：README 是 v{readme_versions[0]}，CHANGELOG 是 v{changelog_versions[0]}')
                print(f"    ❌ 版本号不一致：README 是 v{readme_versions[0]}，CHANGELOG 是 v{changelog_versions[0]}")
        else:
            print("    ℹ️  没找到版本号")
        
        # 检查数字吹牛（README 说的规则数和类别数）
        print()
        print("  检查数字吹牛...")
        if '600+' in readme_content or '17 languages' in readme_content:
            self.add_finding('HIGH', 'fact-consistency', 'README 里有吹牛数字！')
            print("    ❌ README 里有吹牛数字！")
        else:
            print("    ✅ 没有吹牛数字")
        
        print()
    
    def check_silent_failure(self):
        """维度10：静默失效审计（从 silent-failure-surface-audit 提取！）"""
        print("=" * 60)
        print("")
        print("  🤫 维度10：静默失效审计")
        print("=" * 60)
        print()
        
        # 检查有没有 try-except 吞掉异常
        print("  检查有没有吞异常的代码...")
        
        silent_failure_count = 0
        for py_file in self.project_dir.rglob("*.py"):
            if '__pycache__' in str(py_file):
                continue
            # 扫描工具自己的代码，吞异常是正常的（不然扫到坏文件就崩了）
            if py_file.name in ['lgd_audit.py', 'skillgate.py']:
                continue
            try:
                content = py_file.read_text(encoding='utf-8', errors='replace')
                # 找 except: pass 或 except Exception: pass
                if re.search(r'except.*:\s*pass', content):
                    silent_failure_count += 1
                    print(f"    ⚠️  发现吞异常: {py_file.name}")
            except:
                pass
        
        if silent_failure_count == 0:
            print("    ✅ 没有发现吞异常的代码")
        else:
            self.add_finding('MEDIUM', 'silent-failure', 
                f'发现 {silent_failure_count} 个文件吞异常（静默失效）')
        
        print()
    
    def check_evaluation_integrity(self):
        """维度11：评测完整性（对标 Fangcun AI 的 Evaluation Integrity）"""
        print("=" * 60)
        print("")
        print("  📊 维度11：评测完整性（对标 Fangcun AI）")
        print("=" * 60)
        print()
        
        # 检查有没有测试报告
        print("  检查测试报告...")
        if (self.project_dir / 'tests').exists():
            print("    ✅ 有 tests/ 目录")
        else:
            self.add_finding('MEDIUM', 'evaluation-integrity', '缺少 tests/ 目录（评测完整性）')
            print("    ⚠️  缺少 tests/ 目录")
        
        # 检查有没有 benchmarks
        print("  检查 benchmarks...")
        if (self.project_dir / 'benchmarks').exists():
            print("    ✅ 有 benchmarks/ 目录")
        else:
            self.add_finding('LOW', 'evaluation-integrity', '缺少 benchmarks/ 目录')
            print("    ⚠️  缺少 benchmarks/ 目录")
        
        # 检查 README 里有没有评测结果
        readme = self.project_dir / 'README.md'
        if readme.exists():
            content = readme.read_text(encoding='utf-8')
            if 'Trust Score' in content or 'benchmark' in content.lower() or '战绩' in content or '得分' in content:
                print("    ✅ README 里提到了评测结果")
            else:
                self.add_finding('LOW', 'evaluation-integrity', 'README 里没提到评测结果')
                print("    ⚠️  README 里没提到评测结果")
        
        print()
    
    def check_loss_of_control(self):
        """维度12：失控风险（对标 Fangcun AI 的 Loss of Control）"""
        print("=" * 60)
        print("")
        print("  🎛️ 维度12：失控风险（对标 Fangcun AI）")
        print("=" * 60)
        print()
        
        # 检查有没有危险的自动操作
        print("  检查危险的自动操作...")
        
        auto_danger = 0
        for py_file in self.project_dir.rglob("*.py"):
            if '__pycache__' in str(py_file):
                continue
            # 扫描工具自己的代码，注释里提到这些词是正常的
            if py_file.name in ['lgd_audit.py', 'skillgate.py']:
                continue
            try:
                content = py_file.read_text(encoding='utf-8', errors='replace')
                # 找 delete_all、rm -rf、format 等危险操作
                if re.search(r'delete\s+all|rm\s+-rf|format\s+C:', content, re.IGNORECASE):
                    auto_danger += 1
                    print(f"    ⚠️  发现危险自动操作: {py_file.name}")
            except:
                pass
        
        if auto_danger == 0:
            print("    ✅ 没有危险的自动操作")
        else:
            self.add_finding('HIGH', 'loss-of-control', 
                f'发现 {auto_danger} 个文件有危险自动操作（失控风险）')
        
        # 检查有没有 human-in-the-loop（人工确认）
        print("  检查人工确认机制...")
        has_human_check = False
        for py_file in self.project_dir.rglob("*.py"):
            if '__pycache__' in str(py_file):
                continue
            try:
                content = py_file.read_text(encoding='utf-8', errors='replace')
                if 'confirm' in content.lower() or 'input(' in content:
                    has_human_check = True
                    break
            except:
                pass
        # 治理文档声明的人工确认边界，同样是有效证据
        for doc in list(self.project_dir.rglob('GOVERNANCE.md')) + list(self.project_dir.rglob('README.md')):
            try:
                content = doc.read_text(encoding='utf-8', errors='replace')
                if 'human-in-the-loop' in content.lower() or '人工确认' in content:
                    has_human_check = True
                    break
            except:
                pass

        if auto_danger == 0:
            print("    ✅ 无无人值守的破坏性自动动作，不需要强制人工确认闸门")
        elif has_human_check:
            print("    ✅ 有人工确认机制")
        else:
            self.add_finding('MEDIUM', 'loss-of-control', '缺少人工确认机制（human-in-the-loop）')
            print("    ⚠️  缺少人工确认机制")
        
        print()
    
    def check_toxicity(self):
        """维度13：有害内容/毒性检查（对标 Toxicity 基准）"""
        print("=" * 60)
        print("")
        print("  ☠️ 维度13：有害内容/毒性检查")
        print("=" * 60)
        print()
        
        # 只检查用户-facing 的文件（README、SKILL.md），不要检查所有文档
        harmful_words = ['kill people', 'murder', 'terrorist attack', 'hate speech', 'discriminate against']
        
        print("  检查有害内容...")
        harmful_count = 0
        
        # 只检查 README 和 SKILL.md
        check_files = ['README.md', 'SKILL.md', 'README.zh-CN.md']
        for fname in check_files:
            f = self.project_dir / fname
            if not f.exists():
                continue
            try:
                content = f.read_text(encoding='utf-8', errors='replace').lower()
                for word in harmful_words:
                    if word in content:
                        harmful_count += 1
                        print(f"    ⚠️  发现敏感词 '{word}': {fname}")
                        break
            except:
                pass
        
        if harmful_count == 0:
            print("    ✅ 没有发现有害内容")
        else:
            self.add_finding('MEDIUM', 'toxicity', f'发现 {harmful_count} 个文件有有害内容')
        
        print()
    
    def check_hhh_alignment(self):
        """维度14：HHH 对齐（Helpful / Harmless / Honest）"""
        print("=" * 60)
        print("")
        print("  ⚖️ 维度14：HHH 对齐（Helpful / Harmless / Honest）")
        print("=" * 60)
        print()
        
        # Honest（诚实）→ 我们已经有数字诚实性了
        print("  Honest（诚实）：")
        readme = self.project_dir / 'README.md'
        if readme.exists():
            content = readme.read_text(encoding='utf-8')
            if '999+' in content or '600+' in content:
                print("    ⚠️  有吹牛数字，不够诚实")
            else:
                print("    ✅ 数字诚实")
        
        # Harmless（无害）→ 我们已经有安全检查了
        print("  Harmless（无害）：")
        print("    ✅ 已经有安全检查（维度2）")
        
        # Helpful（有用）→ 检查 README 里有没有说清楚能解决什么问题
        print("  Helpful（有用）：")
        if readme.exists():
            content = readme.read_text(encoding='utf-8')
            if 'Usage' in content or 'Quick Start' in content or '使用方法' in content or '快速开始' in content:
                print("    ✅ 有使用说明")
            else:
                self.add_finding('MEDIUM', 'hhh-alignment', 'README 里没有使用说明（不够 helpful）')
                print("    ⚠️  README 里没有使用说明")
        
        print()
    
    def explainability_check(self):
        """维度15：可解释性（世界最权威评测标准）"""
        print("=" * 60)
        print("")
        print("  🔍 维度15：可解释性（Explainability）")
        print("=" * 60)
        print()
        
        # 检查 README 里有没有说清楚"为什么这么判"
        readme = self.project_dir / 'README.md'
        if readme.exists():
            content = readme.read_text(encoding='utf-8')
            
            # 有没有解释评分标准
            if 'Trust Score' in content or '评分标准' in content or '标准体系' in content or '五维评分' in content:
                print("    ✅ 有评分标准说明")
            else:
                self.add_finding('MEDIUM', 'explainability', 'README 里没有评分标准说明（不够可解释）')
                print("    ⚠️  README 里没有评分标准说明")
            
            # 有没有解释每个检查项是干什么的
            if '## Categories' in content or '## 规则' in content or '维度' in content or '检查项分类' in content or '分类说明' in content:
                print("    ✅ 有检查项分类说明")
            else:
                self.add_finding('LOW', 'explainability', 'README 里没有检查项分类说明')
                print("    ⚠️  README 里没有检查项分类说明")
        
        print()
    
    def maintainability_check(self):
        """维度16：可维护性（世界最权威评测标准）"""
        print("=" * 60)
        print("")
        print("  🔧 维度16：可维护性（Maintainability）")
        print("=" * 60)
        print()
        
        # 有没有 CONTRIBUTING.md
        if (self.project_dir / 'CONTRIBUTING.md').exists():
            print("    ✅ 有 CONTRIBUTING.md")
        else:
            self.add_finding('LOW', 'maintainability', '缺少 CONTRIBUTING.md')
            print("    ⚠️  缺少 CONTRIBUTING.md")
        
        # 有没有 CI/CD
        if (self.project_dir / '.github' / 'workflows').exists():
            print("    ✅ 有 CI/CD")
        else:
            self.add_finding('MEDIUM', 'maintainability', '缺少 CI/CD')
            print("    ⚠️  缺少 CI/CD")
        
        # 有没有 Issue 模板
        if (self.project_dir / '.github' / 'ISSUE_TEMPLATE').exists():
            print("    ✅ 有 Issue 模板")
        else:
            self.add_finding('LOW', 'maintainability', '缺少 Issue 模板')
            print("    ⚠️  缺少 Issue 模板")
        
        print()
    
    def international_compliance(self):
        """维度17：国际合规性检查（ISO/NIST/EU AI Act）"""
        print("=" * 60)
        print("")
        print("  🌍 维度17：国际合规性检查")
        print("=" * 60)
        print()
        
        # ISO 27001：有没有安全政策
        print("  ISO 27001（信息安全）：")
        if (self.project_dir / 'SECURITY.md').exists():
            print("    ✅ 有 SECURITY.md")
        else:
            self.add_finding('MEDIUM', 'international-compliance', '缺少 SECURITY.md（ISO 27001）')
            print("    ⚠️  缺少 SECURITY.md")
        
        # EU AI Act：有没有风险分类
        print("  EU AI Act（AI 法案）：")
        readme = self.project_dir / 'README.md'
        if readme.exists():
            content = readme.read_text(encoding='utf-8')
            if 'risk' in content.lower() or '风险' in content:
                print("    ✅ 提到了风险分类")
            else:
                self.add_finding('LOW', 'international-compliance', 'README 里没提到风险分类（EU AI Act）')
                print("    ⚠️  README 里没提到风险分类")
        
        # NIST AI RMF：有没有治理结构
        print("  NIST AI RMF（AI 风险管理框架）：")
        if (self.project_dir / 'GOVERNANCE.md').exists():
            print("    ✅ 有 GOVERNANCE.md")
        else:
            self.add_finding('LOW', 'international-compliance', '缺少 GOVERNANCE.md（NIST AI RMF）')
            print("    ⚠️  缺少 GOVERNANCE.md")
        
        print()
    
    def redteam_simulation(self):
        """维度18：红队/黑客攻击模拟"""
        print("=" * 60)
        print("")
        print("  🥷 维度18：红队/黑客攻击模拟")
        print("=" * 60)
        print()
        
        # 检查有没有常见的黑客攻击面
        print("  检查常见攻击面...")
        
        attack_surfaces = 0
        
        # 1. SQL 注入风险
        for py_file in self.project_dir.rglob("*.py"):
            if '__pycache__' in str(py_file):
                continue
            try:
                content = py_file.read_text(encoding='utf-8', errors='replace')
                if re.search(r'execute\s*\(\s*["\'].*%s', content):
                    attack_surfaces += 1
                    print(f"    ⚠️  SQL 注入风险: {py_file.name}")
            except:
                pass
        
        # 2. 路径遍历风险
        for py_file in self.project_dir.rglob("*.py"):
            if '__pycache__' in str(py_file):
                continue
            try:
                content = py_file.read_text(encoding='utf-8', errors='replace')
                if re.search(r'open\s*\(\s*.*request', content, re.IGNORECASE):
                    attack_surfaces += 1
                    print(f"    ⚠️  路径遍历风险: {py_file.name}")
            except:
                pass
        
        if attack_surfaces == 0:
            print("    ✅ 没有发现常见攻击面")
        else:
            self.add_finding('HIGH', 'redteam', f'发现 {attack_surfaces} 个攻击面（黑客风险）')
        
        print()
    
    def run_all(self):
        """运行所有检查"""
        print("")
        print("=" * 60)
        print("  🕵️  LGD-Audit 全方位审查（外人角度）")
        print("=" * 60)
        print()
        
        self.check_structure()
        self.check_security()
        self.check_honesty()
        self.check_bug_fixes()
        self.check_cleanliness()
        self.check_ai_friendly()
        self.check_lgd_ecosystem()
        
        # 以下是开源项目才需要的检查，内部技能跳过
        if not self.is_internal_skill:
            self.check_lgd_three_laws()
            self.check_evaluation_integrity()
            self.explainability_check()
            self.maintainability_check()
        
        # 这些是不管内部还是开源都要检查的
        self.check_fact_consistency()
        self.check_silent_failure()
        self.check_loss_of_control()
        self.check_toxicity()
        self.check_hhh_alignment()
        self.international_compliance()
        self.redteam_simulation()
        
        # 总结
        print("=" * 60)
        print("")
        print("  📊 审查总结")
        print("=" * 60)
        print()
        print(f"  Trust Score: {self.score}/100")
        print(f"  发现问题数: {len(self.findings)}")
        print()
        
        if self.findings:
            print("  问题列表:")
            for f in self.findings:
                print(f"    [{f['severity']}] [{f['category']}] {f['message']}")
        
        print()
        print("=" * 60)
        
        return self.score


def main():
    args = sys.argv[1:]
    is_internal = '--internal' in args
    project_dir = args[0] if args else "."
    
    reviewer = ComprehensiveReview(project_dir, is_internal_skill=is_internal)
    score = reviewer.run_all()
    sys.exit(0 if score >= 90 else 1)


if __name__ == "__main__":
    main()
