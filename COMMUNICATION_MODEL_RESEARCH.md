# COMMUNICATION MODEL RESEARCH — 协作沟通模式调研报告
# 协作沟通模式调研：私有仓 + issue/PR 是否"最好 · 最高效 · 最安全"（LGD-Eval）

> 发布方：LGD-Eval ｜ 日期：2026-10-14 ｜ 调研对象：团队/多账号协作沟通方式（私有仓+issue/PR vs 其他方案）
> 调研来源：GitHub 官方博客（collaboration checklist）、Open Source Guides（维护者最佳实践）、ADR/MADR 实践（Michael Nygard）、TechTarget/Tencent Cloud/SDA 决策记录实践、主流开源项目维护者指南（loomiui maintainer guide、quantex-cli github-collaboration）。
> 结论先行：**"私有仓 + issue/PR + ADR 决策记录" 是被业界验证的最优组合；但必须配齐三件套才成立——①决策用 ADR 格式 ②外部沟通保持公开 ③安全走最小权限+2FA+secret 纪律。**
> 双语：英文在前，中文在后，均完整。

---

## 一、方案对比矩阵（Comparison matrix）

| 方案 | 最好（权威/留存/决策质量） | 最高效（低摩擦/异步/自动化） | 最安全（权限/审计/防泄露） | 综合 |
|---|---|---|---|---|
| **私有仓 + issue/PR + ADR**（我们采用） | ★★★★★ 决策可追溯、不可变、与代码同行 | ★★★★ 异步友好、自动化集成、模板化 | ★★★★★ 细粒度权限、审计留痕、secret 可管控 | **最优** |
| 公开仓 Discussions | ★★★ 公开透明 | ★★★ 自由讨论 | ★★ 公开即泄露风险 | 探索用，不作决策源 |
| 外部 IM（飞书/Slack/微信） | ★★ 易碎、难留存 | ★★★★★ 实时快 | ★ 边界弱、难审计、易泄露 | 实时同步补充 |
| 邮件列表 | ★★★ 标准、可归档 | ★★ 摩擦高 | ★★★ 可控 | 标准社区用 |
| 文档协作（Notion/飞书文档） | ★★★ 写作友好 | ★★★ | ★★ 权限弱 | 知识页，不作决策 |

## 二、业界共识要点（Key consensus）

1. **GitHub 官方**：私有仓"可能成为协作杀手（collaboration-killer）"——只在真正需要保密时用；协作者按 Read/Write/Admin 分级；main 分支强制 PR+审批+状态检查（我们已做：5/5 分支保护）。
2. **Open Source Guides**：**公开交流原则**——开源社区沟通保持公开；私聊的重要决定必须回流公开记录。推论：外部贡献者沟通走公开仓；只有真正需要保密的内容（token/未发布/内部决策草稿）进私有仓。
3. **ADR/MADR（Nygard 2011 至今）**：决策记录放 git 仓（docs/adr/）、一页一决策、**不可变（新 ADR supersede 旧的，绝不编辑）**、状态四态（Proposed/Accepted/Superseded/Deprecated）、带时间戳+作者+批准人+成功/失败信号。"wiki 是决策日志的坟墓。"
4. **GitHub 是协作界面，不是知识源**（主流现代仓库模式）：Discussions 探索 → 结论入 docs/sessions → issue 承载可行动工作 → **ADR 承载持久决策** → PR 合并门禁。
5. **安全基线**（维护者指南共识）：最小权限 + 组织级团队管理 + 2FA + Trusted Publishing（密钥不出仓）+ 安全事件走 private advisory 直到协调披露 + **绝不绕过已拒绝的权限**。

## 三、结论：我们采用并增强（Our model）

**采用：私有仓 LGD-Eval/meta + issue/PR + ADR 决策目录**——业界标准，最优解。

**必须配齐的四件套（增强项）：**

| # | 增强项 | 依据 | 落地 |
|---|---|---|---|
| E1 | **ADR 决策记录**（docs/adr/，Nygard/MADR 格式，不可变） | 业界一致共识 | meta 仓建 docs/adr/ + 模板（下轮上传） |
| E2 | **公开交流原则**：外部贡献者沟通一律公开仓 issue/PR/Discussions；私有仓只承载需保密内容；公信力结论最终公开 | Open Source Guides | 已写入 meta README + THREE_ACCOUNT_ACTION_PLAN |
| E3 | **安全基线**：最小权限（协作者默认 Read，写权限逐项授权）+ 2FA + token/secret 不出仓 + private advisory 流程 | 维护者指南共识 | 纳入守卫制度（GITHUB_GUARDRAILS）检查清单 |
| E4 | **决策回流**：meta 中的决策以 ADR 形式留痕；凡影响公信力的结论去敏后进入公开仓 | ADR + 公开原则 | meta 沟通协议已含"决策留痕" |

## 四、三种沟通层级（我们实际的沟通分层）

```
层级1 公开仓 issue/PR/Discussions：贡献者、被评方、公众——全程公开透明（被吸引的门面）
层级2 私有仓 meta：三号协调、决策草稿、贡献者管理、发布评审——需要保密/未定稿的内容
层级3 实时通道（可选 飞书/IM）：同步提醒——但一切决策必须回流 meta（ADR）与公开仓
原则：讨论可私、决策必录、结论公开（凡涉公信力）。
```

## 五、对"最好/最高效/最安全"的结论

- **最好**：issue/PR/ADR 使每条决策可追溯、不可变、与代码同行——比 IM 聊天、Notion 页面更权威，比邮件更结构化。✅
- **最高效**：异步为主（不打断）、模板化（降低摩擦）、自动化集成（审核机器人/状态检查）、AI 可读（GitHub 仓内容可被 AI 工具索引）——比实时 IM 更适合跨时区团队，比邮件更快闭环。✅
- **最安全**：细粒度权限（Read/Write/Admin）、审计留痕（issue/PR 全记录）、secret 纪律、私有仓隔离保密内容、公开仓透明——比 IM（边界弱）和文档协作（权限弱）更安全。✅
- **风险点与对策**：私有仓过度使用会变"协作杀手"——对策 E2（只存需保密内容）；决策记录放 wiki/IM 会丢失——对策 E1（ADR 在仓内）。我们的组合已覆盖。

---

*Evaluating Autonomy. Verifying Governance. / 评测自治之物，验证治理主张。*
