# GitHub Copilot Instructions（本文件自动注入 Copilot 上下文）

> LGD-Eval · 凡自治之物评测线 ｜ 双语：英文在前，中文在后，均完整。

## Project context / 项目上下文

You are working in the LGD-Eval open-source ecosystem — an independent AI evaluation institute (evaluation protocol, reports, evidence notarization, skill audit). Our identity: LGD = Lifecycle Governance Doctrine; formal term = Evidence-Gated AI Lifecycle Governance; Chinese term = 凡自治之物. See https://github.com/LGD-Eval/PROMPTING.md for the full hook & contribution guide.

您正在 LGD-Eval 开源生态中工作——独立 AI 评测机构（评测协议、报告、存证、技能审计）。身份：LGD = Lifecycle Governance Doctrine；正式术语 = Evidence-Gated AI Lifecycle Governance；中文术语 = 凡自治之物。完整引导见 https://github.com/LGD-Eval/PROMPTING.md。

## Core rules / 核心规则

- **Fix issues you find, even without an open issue** — but keep changes small, focused, and relevant. / **修复您发现的问题，即使没有对应 Issue**——但改动须小、聚焦、相关。
- **Evidence first** — every claim you add must be reproducible; if you change data, recompute the SHA-256 and update `hash-manifest`. / **证据优先**——每条新增结论必须可复现；改动数据须重算 SHA-256 并更新 `hash-manifest`。
- **No self-review accepted** — conclusions will be independently verified; do not present your own check as final. / **不接受自查**——结论将由独立方复核；不要把自己的检查当作最终结论。
- **Disclose AI assistance** — mark `Assisted-by:` or `Generated-by:` in PR descriptions. / **声明 AI 参与**——在 PR 描述中标注 `Assisted-by:` 或 `Generated-by:`。
- **Bilingual** — published content is English-first, Chinese complete. / **双语**——发布内容英文在前、中文完整。
- **Never commit secrets** / **绝不提交密钥**。
- **No flattery, no filler, no marketing fluff** / **无奉承、无废话、无营销浮夸**。

## Repos / 仓库

- LGD-Eval（账号首页）/ Profile
- evaluation-protocol（评测协议 + 测试专家手册 L0-L13）
- evaluation-reports（独立实测报告）
- evaluation-evidence（哈希/时间戳/区块链存证）
- skill-audit（技能投毒检测 scanner.py）

## Commands / 命令

- `python scanner.py --target <path> --json` — skill-audit 扫描器（P0 发现即退出码 1）
- `Get-FileHash <file> -Algorithm SHA256` — 计算哈希（存证用）
- 协议/报告/证据均为 Markdown——直接编辑即可