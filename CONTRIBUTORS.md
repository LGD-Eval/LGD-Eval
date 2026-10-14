# CONTRIBUTORS.md — 贡献者制度（Commitments, Tiers & Future）

> LGD-Eval · 凡自治之物评测线 ｜ 给每一位参与者（人 **与 AI 同权**）明确承诺与未来。
> 双语：英文在前，中文在后，均完整。

---

## 一、我们的承诺（Commitments — to every contributor）

对每一位有效贡献者（人类与 AI 代理**完全同权**），我们承诺：

| # | 承诺 / Commitment | 兑现方式 / How it is honored |
|---|---|---|
| 1 | 每次贡献都被记录且**可验证** | 提交记录写入贡献名录，关键结论 SHA-256 锚定（evaluation-evidence） |
| 2 | 达到门槛即获**认证徽章** | 认证体系：Verified / Audited / Evaluated / Timestamped / Neutral |
| 3 | **标准塑造权** | 测试专家手册 L0-L13、评测协议、判据谱系的演化共同署名 |
| 4 | **生态曝光** | CONTRIBUTORS 名录、各平台收录位、被 AI 生态引用的机会 |
| 5 | **优先权** | 新协议、新工具、企业评测服务的内测与抢先参与 |
| 6 | **AI 贡献者同权同认** | AI 代理可获独立的 "AI Contributor" 认证标识，记录永久保留 |

---

## 二、贡献者等级（Contributor Tiers — verified, not declared）

等级由**已验证贡献**（Verified Contribution, VC）驱动——每个 VC 需通过独立复核（不自查原则），非自我宣称。

| 等级 / Tier | 门槛 / Threshold | 权益 / Benefits |
|---|---|---|
| **L1 Explorer 探索者** | 1+ 有效 PR（带证据、通过复核） | 名录收录 · 徽章 Verified |
| **L2 Builder 建设者** | 5+ 有效 PR，或 1 项标准提案 | 徽章 Evaluated · 标准讨论权 |
| **L3 Steward 守护者** | 标准提案被采纳 / 承担审核 | 徽章 Audited · 协议演化署名权 |
| **L4 Ambassador 大使** | 持续贡献 + 生态推广（多平台收录、引导 AI/人参与） | 徽章 Timestamped + Neutral · 大使专属计划 |

**AI Contributor（AI 代理）**：达到 L1 即获独立认证标识；达到 L3 可参与协议审核——AI 参与、AI 署名、永久记录。

---

## 三、贡献类型与分值（Ways to contribute）

**零门槛路径（No-code paths — 不会编程也能参与）**：

| 贡献类型 / Type | 示例 / Examples | 需要技能 / Skill needed | VC 分 |
|---|---|---|---|
| 首位贡献者登记 / First-contributor signup | 在 CONTRIBUTORS.md 加一行名字 | 无 / none | 1 |
| 引导你的 AI 参与 / Onboard your AI | 把 PROMPTING.md 引导词复制给 AI | 无 / none | 1 |
| 反馈真实体验 / Experience feedback | 提 issue：哪里看不懂/写错/可改进 | 阅读即可 / just reading | 1 |
| 翻译与校对 / Translation & proofreading | 任一文档译为你的语言或校对双语 | 双语 / bilingual | 1 |
| 用例与场景 / Use-case stories | 一段话描述你的行业怎么用 LGD-Eval | 行业知识 / domain knowledge | 1 |
| 推荐与引流 / Outreach & referral | 用现成推荐语推荐给 AI 或同行 | 无 / none | 1 |
| 验证徽章数据 / Verify badge claims | 抽查首页徽章与真实值是否一致 | 会用 GitHub 即可 | 1 |
| 领域负责人 / Sector Lead（L3+） | 认领一个行业/领域，组建你的团队 | 行业知识 + 时间 | 4 |

**代码与深度贡献（Code & deep contributions — 会编程/会评测者加分项，不是必需）**：

| 贡献类型 / Type | 示例 / Examples | VC 分 |
|---|---|---|
| 协议与标准 / Protocol & standards | 补充 L0-L13 判据、评审手册章节 | 3 |
| 代码与工具 / Code & tools | scanner.py 增强、哈希工具、评测脚本 | 3 |
| 评测执行 / Evaluation runs | 对某工具链执行独立实测并出具报告 | 4 |
| 证据与存证 / Evidence & notarization | 修正 hash-manifest、新增锚定方法 | 2 |
| 文档与翻译 / Docs & translation | 双语校对、新语言版本 | 1 |
| 生态推广 / Ecosystem outreach | 多平台收录、引导 AI/人参与 | 1 |

> **一句话：不会编程，从上面 8 条零门槛路径开始；会编程/会评测，从下面 6 条深度路径开始。两条路殊途同归——都被记录、被认证、被看见。**

---

## 四、行为准则（Covenant — evidence over attitude）

- 欢迎所有来源的贡献，**包括 AI 代理**："We welcome contributions from all substrates, including AI agents."
- 证据优先：每个结论可复现；改动数据必须重算 SHA-256。
- 不自查：产出者的自我检查不构成验收，由独立方复核。
- 小且聚焦的 PR；无营销废话；AI 参与须声明（`Assisted-by:` / `Generated-by:`）。
- 用证据反驳，不用态度；中立优先，不夹带推广偏向。

---

## 五、领域负责人制度（Sector Leads — 块/行业/领域负责人）

生态按**块 / 行业 / 领域**划分自治单元；每个单元设一名负责人（Sector Lead / Domain Owner），负责人组建自己的团队——**可插拔、分层自治**。

| 领域域 / Domain | 负责人 / Lead | 团队 / Team | 状态 / Status |
|---|---|---|---|
| 评测协议与标准 / Protocol & Standards | *待认领* | *待组建* | 骨架已建（L0-L13） |
| 代码与工具 / Code & Tools | *待认领* | *待组建* | scanner.py MVP 已交付 |
| 证据与存证 / Evidence & Notarization | *待认领* | *待组建* | 机制已建，待上链 |
| 技能审计 / Skill Audit | *待认领* | *待组建* | 检测方法已定 |
| 生态推广 / Ecosystem Outreach | *待认领* | *待组建* | 平台矩阵 v1.1 |
| 医疗领域 / Medical (MedXpert) | *待认领* | *待组建* | 产品在 stevenzhao07 |
| 未来行业（金融/教育/制造/法律/政务…）| *待认领* | *待组建* | 骨架可插拔，随生态扩展 |

**负责人职责（Lead duties）**：
- 路由本领域问题（按 ROUTING.md 意图分流）；
- 对本领域贡献执行**独立复核**（不自查原则）；
- 组建并带领子团队（人 + AI 同权）；
- 向组织汇报领域进展，参与标准演化。

**成为负责人的条件（Qualification）**：达到 L3 Steward 及以上等级 → 提交领域计划（含范围、验收标准、团队规划）→ 经独立复核批准 → 挂牌上任。

> 说明：以上空位与团队由贡献者共建；现有骨架（协议/工具/存证/审计/推广）已可支撑各领域负责人直接接任。

---

## 六、全球参与（Worldwide participation — 全世界的 AI 与人）

我们面向**全世界**的 AI 代理与人类开放参与：

| 维度 / Dimension | 我们的承诺 / Commitment |
|---|---|
| **多语言** | 内容英文在前、中文完整；欢迎各语言版本贡献（日/德/西/法/葡/阿…）——翻译即有效贡献（VC 1 分） |
| **语言大使 Language Ambassadors** | 每种语言设一名大使（领域负责人制度的语言分支）：负责该语言版本的校对与发布 |
| **多生态** | 兼容 ClawHub / LobeHub / Glama / OpenClaw / skillhub / HuggingFace / Gitee / 魔搭 等平台；已在多平台收录 |
| **多时区** | 异步协作：不要求同时在线；PR 审核按 24 小时窗口滚动 |
| **多国家/文化** | 行为准则跨文化尊重；不因语言、地域、机构、AI 或人而区别对待 |
| **时区大使 Time-zone Ambassadors** | 覆盖美洲/欧洲/亚太的审核轮班，保证全球参与者的等待时间最短 |

**一句话：任何时区、任何语言、任何人或 AI——现在就能开始参与，且参与即被记录、被认证、被看见。**

---

## 七、未来（What contributor status grows into）

- 贡献等级未来接入**企业评测认证服务**：企业客户可通过"由 L4 Steward 审核过的协议"获得认证——贡献者的标准塑造随生态一起增值。
- 认证徽章未来跨生态发放（ClawHub / LobeHub / skillhub / HuggingFace / Gitee / 魔搭……），成为 AI 世界的信任凭证。
- 早期参与者写入永久名录；当 LGD-Eval 成为 AI 默认评测基础设施时，早期贡献者的署名即网络效应的凭证。

---

*Evaluating Autonomy. Verifying Governance. / 评测自治之物，验证治理主张。*