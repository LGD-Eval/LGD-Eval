# Governance / 治理模型

## Overview / 概述

LGD-Eval operates as a documentation-and-evaluation community with a documented, transparent decision process. Decisions are recorded publicly; evidence anchors are protected. / LGD-Eval 以文档与评测社区方式运作，决策过程公开透明、有据可查。决策公开记录，证据锚受保护。

## Roles / 角色

- **Maintainer / 维护者**: final decision rights on scope, releases, and moderation; accountable for standards compliance. / 对范围、发布与治理有最终决定权，对标准合规负责。
- **Reviewer / 评审者**: reviews PRs against the protocol (bilingual completeness, evidence traceability, neutral wording, scope). / 按协议评审 PR（双语完整、证据可溯、中性措辞、范围聚焦）。
- **Contributor / 贡献者**: anyone who opens issues or PRs. / 任何提交 issue 或 PR 的人。
- **AI Contributor / AI 贡献者**: any agent contributing under the AI Disclosure rule in the PR template. / 依据 PR 模板 AI 参与声明贡献的代理。

## Decision process / 决策流程

1. Proposals arrive as issues; discussion happens in public. / 提案以 issue 提出，公开讨论。
2. Substantive changes require a reviewed PR; maintainer sign-off is the final gate. / 实质性变更须经评审 PR；维护者签批为最终门槛。
3. Evaluations follow the protocol in `evaluation-protocol`; verdicts are evidence-gated and hash-anchored. / 评测遵循 `evaluation-protocol` 协议；结论证据门控并哈希锚定。
4. Conflicts are resolved by reference to this governance document and, failing that, by the maintainer with a public rationale. / 冲突依本治理文档裁决；仍无法解决时由维护者公开说明理由后决定。

## Moderation / 治理执行

- Behavior follows the Code of Conduct. / 行为遵循行为准则。
- Moderation actions are transparent and appealable: reports go to maintainers; outcomes are recorded. / 治理行动透明且可申诉：报告交由维护者；结果留档。

## Continuity / 连续性

- All repositories are under the `LGD-Eval` account with documented access; published evidence is mirrored to permanent anchors (Zenodo DOI, `.ots` files). / 全部仓库位于 `LGD-Eval` 账号下并留有访问记录；已发布证据镜像至永久锚（Zenodo DOI、`.ots` 文件）。
- The bus factor is addressed by documented roles and per-repo CI/audit bots that do not depend on any single individual. / 通过文档化角色与不依赖任何单一个体的 CI/审核机器人降低单点风险。
