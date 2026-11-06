---
name: lgd-eval
description: LGD 独立第三方技能评测引擎。给 AI 技能打一个 0-100 的总分（LGD Trust Score），并给出可追溯的证据链、可复现的指纹、可阻断的发布门禁。当需要判断一个技能"做得够不够好、能不能发布、改完有没有变好"时使用。
version: 1.0.0
license: MIT
author: LGD-Eval
tags: [evaluation, quality-gate, skill-audit, trust-score, evidence-chain]
---

# LGD-Eval · 独立第三方技能评测

## 使用场景

- 技能发布前做质量门禁，避免把半成品推到商店或 npm
- 评审别人的技能：不只看"安不安全"，还要看"做得够不够好"
- 改完之后复跑，确认分数真的涨了（而不是自我感觉良好）

## 核心原则：只给一个分数

对外只有一个分数：

```
LGD Trust Score: 89/100  🥇 A
```

五维（结构 25 / 目录 15 / 文档 20 / 安全 25 / 生态 15）只作为**扣分明细**展示，形如 `25/25`，不换算百分比，不产生第二套分数。

## 使用方法

```bash
# 评测一个技能目录
python3 scripts/evaluate.py <技能目录>

# 扣分明细（得分/满分）
python3 scripts/evaluate.py <技能目录> --ascii

# 证据链：规则 → 文件:行 → 证据 → 整改 → 复验
python3 scripts/evaluate.py <技能目录> --detail

# 可复现证明：含 sha256 指纹，同输入必得同字节
python3 scripts/evaluate.py <技能目录> --evidence-json attestation.json

# 门禁模式：低于阈值以退出码 1 结束，可直接接 CI
python3 scripts/evaluate.py <技能目录> --fail-under 90

# MCP 服务评测
python3 scripts/evaluate.py --help
```

## 输出示例

```
  LGD Trust Score: 89/100  🥇 A

📋 扣分明细（得分 / 满分）
  结构   ██████████ 25/25
  目录   █████░░░░░ 7/15
  文档   ████████░░ 17/20
  安全   ██████████ 25/25
  生态   ██████████ 15/15

🧾 证据链（规则 → 文件:行 → 证据 → 整改 → 复验）
  [R-DOC-05] SKILL.md:8
     证据: 文档含占位标记需替换为真实内容：SKILL.md 含「待补充」
     整改: 把占位标记（TODO/TBD/待补充/xxx）替换为真实内容
     复验: 重跑规则 R-DOC-05：占位标记归零即通过
```

## LGD 三律

- **有籍**：每条扣分带 `rule_id` + 文件 + 行号，可追溯
- **有证**：每条扣分带证据原文与 sha256 指纹，可被第三方复现
- **有门禁**：`--fail-under` 退出码 + 每条规则的复验指令，可阻断发布

## 已知限制

- 安全维度是**快筛**，不是安全审计；确认性结论请配合专业工具
- 单文件模式只能评文本质量，结构/目录维度会因缺 LICENSE、README 而扣分
- 评分只取决于内容，与作者、品牌、star 数无关
- 不评运行时行为（agent 轨迹、工具调用正确性），那是另一类平台的事

## 更多

- 仓库：https://github.com/LGD-Eval/lgd-eval
- 评测引擎源码：https://github.com/LGD-Eval/lgd-gate
- 分数榜：https://github.com/LGD-Eval/evaluation-evidence/blob/main/scores.md
- 官网：https://medxpert.cn/lgd/
