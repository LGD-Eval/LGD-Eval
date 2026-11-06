---
name: lgd-eval-engine
description: 独立第三方技能评测引擎：安全扫描 + 18 维审计 + 五维评分，输出可复现的 Trust Score 与改进清单。当用户说"这个技能安全吗""会不会乱动我的文件""给我打个分""这个值多少分""帮我评测这个技能""上架前体检一下""这两个哪个更该先修"时使用。触发词：技能评测、安全扫描、打个分、评分、体检、审计、Trust Score、上架前检查。
version: 1.0.0
license: MIT
author: LGD-Eval
tags:
  - evaluation
  - security
  - audit
  - trust
  - lgd
---

# LGD 评测引擎 · 独立第三方技能评测

## When to Use

- 你想独立评测一个 AI Agent 技能的安全性和质量
- 你想在发布技能前做一次上架体检
- 你想给一个技能打 Trust Score
- 你想做第三方安全审计

## 引擎组成（scripts/）

| 脚本 | 功能 |
|---|---|
| `skillgate.py` | 安全与质量扫描门禁：危险代码/硬编码密钥/网络泄漏/结构检查，Exit Code 门禁（0=通过，1=失败） |
| `lgd_audit.py` | 18 维度全方位审查：结构、数值诚实、红队模拟、LGD 三律、生态互链、HHH 对齐等 |
| `evaluate.py` | 五维评分：结构完整性(25) + 目录结构(15) + 文档质量(20) + 安全检查(25) + 生态兼容(15)，输出 Trust Score |

## 使用方法

### 方式一：五维评分（推荐入口）

```bash
python scripts/evaluate.py <技能目录>
```

输出：Trust Score（0-100）、等级（A+ / A / B / C / D）、发现项、改进建议。

### 方式一·B：CI 门禁（卡 PR）

```bash
python scripts/evaluate.py <技能目录> --fail-under 90 --fix-json fix-plan.json
```

分数低于阈值直接以退出码 1 结束，可直接写进 GitHub Actions 卡住不合格的 PR；
`--fix-json` 同时产出「缺口 + 整改动作 + 可判定验收」清单，交给 AI 或人逐项改，改完再跑一次即闭环。

### 方式一·C：自动施工（AI 自主改善闭环）

```bash
python scripts/autofix.py <技能目录> --target 90
```

自动读整改清单并执行**结构性修复**（补 frontmatter 五字段、LICENSE、README、scripts/、examples/、四类章节），每轮改完重新评测，直到达标，最多 4 轮。

边界（这是它可信的原因）：

- **只补结构合规，不编造内容。** 自动生成的示例与 README 带占位标记，评测器会识别为「内容未落地」并扣分，所以最多拿到 A+（97），拿不到满分。
- **满分留给真实内容。** 需要把示例换成一次真实输入输出、限制写成真实做不到的事，才可能到 100。
- 无法机械判定的项自动跳过并列出，不假装已修复。

### 方式二：18 维度全方位审计

```bash
python scripts/lgd_audit.py <技能目录>
python scripts/lgd_audit.py <技能目录> --internal   # 内部技能模式
```

### 方式三：安全扫描门禁

```bash
python scripts/skillgate.py scan <技能目录>
python scripts/skillgate.py scan <技能目录> --format markdown --output report.md
```

## 示例

- **示例评测报告**：`examples/example-report.md` —— 对一个「会议纪要」技能跑出的完整报告（安全门禁 91/A+、五维 96/A+、缺口与整改建议、可复现声明）。
- **五维雷达样式**：`examples/radar-example.svg` —— 报告中五维条/雷达的视觉参考。

示例报告可直接作为对外展示模板：同一输入 → 同一输出，行号与文件路径均可对照源码核查。

## 交付标准

- 输出结构化评测报告：总分、等级、各维度明细、发现项清单、改进建议
- 每个发现项标注严重级别（CRITICAL/HIGH/MEDIUM/LOW）与扣分影响
- 明确给出"是否可以上架/发布"的门禁结论

## 安全维度定位（重要边界）

本引擎的「安全 25 分」是**发布前快筛**，用于在打包、上架之前兜住明显问题，不是专业安全审计：

- 覆盖：危险代码模式、硬编码密钥、可疑网络外发、文件系统越权、结构风险。
- 不覆盖：深度语义攻击链、供应链投毒、混淆载荷还原、运行时行为。
- 需要深度审计时叠加专用引擎：SkillScanner（49 条规则 / 11 类威胁 / APPROVE-CAUTION-REJECT 三档裁决）、AgentShield（`npx @elliotllliu/agentshield scan --json --fail-under`）、SafeSkill（Yara/AST/LLM 组合）。
- 不要把本引擎的 100 分读成「绝对安全」：它只代表「在这套快筛规则下未命中」。

## 公开评分卡

```bash
python scripts/scorecard.py <技能目录...> --out score --index scores.md
```

为每个技能包生成独立 Markdown 评分卡（总分 / 五维明细 / 发现的问题 / 整改清单 / 三律 / 复跑命令），并生成索引页。每页都是可被搜索引擎与 AI 直接抓取的独立 URL，解决「评测结果只活在一次对话里、外人看不到」的问题。

## Known Limits

- 静态分析，不实际运行被评测技能
- 主要检查常见模式，不保证 100% 覆盖
- 独立第三方评测，结论仅供参考
- 若用户提供的是单个文件而非目录，需要先整理成标准技能目录结构再评测
