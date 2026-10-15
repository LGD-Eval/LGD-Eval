# CONFLICT OF INTEREST DISCLOSURE — 利益冲突披露与关联关系声明
# 利益冲突披露（LGD-Eval · 关联关系与利益隔离机制 · 2026-10-14）

> Publisher / 发布方：LGD-Eval（评测号，github.com/LGD-Eval）
> Effective / 生效：2026-10-14（第三方对等监督评估 A 组整改 · 披露型路线）
> Language policy / 语言政策：英文在前，中文在后，两种语言均完整、不缩写。
> Scope / 范围：本文件适用于 LGD-Eval 组织全部 5 个公开仓库及其对外发布内容。

---

## 1. 关系披露（Relationship disclosure）

**LGD-Eval（评测号）与以下账号为同一运营者生态的功能账号，存在明确的治理关联关系：**

| 账号 | 生态角色 | 与 LGD-Eval 的关系 |
|---|---|---|
| **zhaoxinghua09-cell** | 理论号：LGD 治理学（Lifecycle Governance Doctrine）理论体系、术语、元方法、论文与查重锚 | 同一治理体系的"理论源"，评测号的方法论依据来源 |
| **stevenzhao07** | 产品号：MedXpert 医械合规工具链 | 评测号已发布实测报告的对象（关联方评测，见第 3 节） |

三号分工：**理论号立论 → 评测号验证 → 产品号落地**。三号构成一个完整生态（详见 THREE_ACCOUNT_ACTION_PLAN.md），不是三个独立机构。

**该关系此前未在公开页面披露，属于披露缺失。本文件即补披露。此前 README 中"中立第三方""评测方与被评测方无利益关系"等表述不精确，以本文件为准。**

---

## 2. 利益隔离机制（Interest-isolation mechanism —— 披露型路线的可验证承诺）

关联关系存在，但评测结论的独立性通过以下**可验证机制**保证，而非通过"无关联"声明保证：

1. **权限隔离**：评测号组织对任何被评方（含理论号、产品号）**无写入权限**；被评方只能通过 issue/PR/评论提交，不能修改评测产出。账号权限矩阵见 ACCOUNTS_ACCESS_AND_ROLES.md。
2. **证据隔离**：每项结论必须有独立证据（哈希、原文引用、复现步骤），不采信被评方自查结论（不自查原则）。
3. **执行隔离**：评测由独立方实跑（对抗性测试、负对照、证据分级），非被评方提供的自述。
4. **程序隔离**：被评方享有 14 天回应期、24 小时更正、公平申诉；结论状态 ≤ 证据状态（联动规则）。
5. **对等监督**：被评方可对评测号行使对等监督（本披露即对等监督评估 A 组整改的直接产物；评估报告与回应见 PEER_REVIEW_RESPONSE_v1.md）。
6. **付费不买结论**：生态推荐与广告生态激励机制（ECOSYSTEM_REFERRAL.md）不改变评测结论；结论独立于任何费用关系。

**独立性的定义**：LGD-Eval 承诺的是**方法论独立**——证据驱动、可复现、对抗实跑、程序正义；"方法论独立 ≠ 无关联"。关联关系如实披露后，由读者与复测方以证据链验收独立性是否成立。

---

## 3. 关联方评测披露（Affiliated-party evaluation disclosure）

**MedXpert工具链实测报告.md**（evaluation-reports 仓）是对 **stevenzhao07（MedXpert 医械合规工具链）** 的实测报告——**被评方与评测号为同一运营者生态的关联方**。

- 该报告的方法论仍为独立实跑（21 模块、20 PASS、口径漂移修正、公开自检硬伤），结论不因关联关系调整；
- 但读者有权在阅读报告时知道关联关系；本披露即此信息。
- 未来所有对两号（理论号/产品号）的评测报告，均在本文件登记并明示"关联方评测"。

---

## 4. 涉及 zhaoxinghua / stevenzhao 字样的公开文件清单（Files mentioning affiliated accounts）

以下公开文件出现关联账号字样或三号架构信息，均视为治理关系的既有公开痕迹，与 COI 披露配套解读：

| 文件（5 仓） | 说明 |
|---|---|
| THREE_ACCOUNT_ACTION_PLAN.md（5 仓） | 三号分工与联动行动计划（理论/评测/产品） |
| THEORY_109_IMPROVEMENT_LIST.md（仅 evaluation-reports） | 理论号 109 仓整改清单（评测号开具的定向整改项） |
| FG-TIDA-SUPPORTER-CONTRIBUTIONS.md（5 仓） | ITU FG-TIDA 支持者贡献包（三号共同贡献计划） |
| AI-VOICE-AMBASSADORS.md（5 仓） | AI 发声大使制度（三号共用生态角色） |
| ACCOUNTS_ACCESS_AND_ROLES.md（5 仓） | 账号权限与职责（含三号矩阵） |
| ITU_CONTRIBUTION_PLAN.md（5 仓） | ITU 贡献规划（C1 理论锚/C2 评测锚/C8 产品用例） |
| MedXpert工具链实测报告.md（evaluation-reports） | 关联方评测报告（本披露第 3 节） |

---

## 5. 修正记录（Correction record —— 半遮半掩到全披露）

| 时间 | 修正 |
|---|---|
| 2026-10-14 | 本文件上线；主仓 README 增加披露链接与定位句；evaluation-protocol README"无利益关系"表述修正为"无控制性利益关系（关联见 COI 披露）"；evaluation-reports README 标注 MedXpert 为关联方评测 |

**披露原则**：宁可公开关联关系并接受对"独立性"的审视，也不以"无关联"字样制造半遮半掩——后者一旦被证伪，损害远大于披露本身。此即 LGD 治理学的透明元方法在本机构的自我应用。

---

*Evaluating Autonomy. Verifying Governance. / 评测自治之物，验证治理主张。*
