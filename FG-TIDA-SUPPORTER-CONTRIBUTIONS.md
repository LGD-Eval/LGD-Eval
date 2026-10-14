# FG-TIDA SUPPORTER CONTRIBUTIONS — 支持者贡献方案
# FG-TIDA 支持者贡献方案（LGD-Eval · 支持者定位，提供贡献点）

> 发布方：LGD-Eval ｜ 生效：2026-10-14 ｜ 依据：FG-TIDA ToR 全文（itu.int/en/ITU-T/focusgroups/tida/Pages/ToR.aspx）
> **定位声明：我们以「支持者（supporter）」身份参与 FG-TIDA——不主导、不重复、不越界；按 ToR 提供我们最有权威支撑的贡献点，供焦点组共识采纳。**
> 双语：英文在前，中文在后，均完整。

---

## 一、支持者定位（Supporter positioning）

| 维度 | 我们的立场 |
|---|---|
| 角色 Role | 支持者（supporter / contributor），非议程主导者 |
| 原则 | 遵守 ITU A.7：不与既有研究组/焦点组工作重复；贡献与否由焦点组共识决定 |
| 边界 | 不碰 FG-TIDA out-of-scope：Agentic AI protocols / AI governance / 国家数字身份内容 |
| 姿态 | 我们提供"可用即权威"的贡献点；采纳权在焦点组，不承诺采纳 |
| 名义 | 一个 LGD 生态（理论号+评测号+产品号），一个贡献包一个署名身份，避免角色冲突 |

> **关键词纪律**：贡献措辞使用 FG-TIDA 语言（trust management / lifecycle assurance / continuous assessment / accountability / behavioural signals），**不以 "AI governance" 为主题词**（ToR 明确 out of scope）。

---

## 二、贡献点清单（Contribution points — 按权威支撑强度排序）

### P0 核心贡献点（我们最权威、最原创）

| # | 贡献点 | 对应 ToR 项 | 我们的权威支撑 |
|---|---|---|---|
| C1 | **信任生命周期框架**（Trust lifecycle framework）：建立→持续评估→降级→撤销，每阶段给出证据标准 | Annex A.2.2 | LGD 全程治理论（Registry·Evidence·Gates）原创理论；P0/P3 论文（DOI 10.5281/zenodo.22456647）、.ots、查重报告 |
| C2 | **评估准则与基准**（Assessment criteria & benchmarks）：可信度/互操作性/问责/人类监督的评估方法，含证据分级与偏倚控制 | ToR 3.4 / 4.5 | 评测号全套：权威准则（五级解读 Verified→Preliminary）、测试专家手册 L0-L13、多判官+人工锚定、AB/BA 偏倚控制、GRADE 证据分级、OWASP/NIST/ISO 标准映射 |
| C3 | **行为信任信号与静默失败**（Behavioural trust signals & silent failures）：行为基线、异常检测、证据数据模型 | Annex A.2.8 | 静默失败目录（Silent Failure Catalog）+ 评测证据链（hash/.ots/manifest）——"没报错但错了"的检测域 |
| C4 | **术语与定义包**（Terminology）：注册/证据/门禁 → registration/evidence/gates 的互操作术语 | ToR 3.1 | lgd-glossary（中英双语定义、版本化修订历史） |

### P1 强贡献点

| # | 贡献点 | 对应 ToR 项 | 我们的权威支撑 |
|---|---|---|---|
| C5 | **开源代理安全差距分析**（Security gap analysis of open-source agents） | Annex A.1.8 | 理论号 109 仓全量评测（进行中）+ skill-audit 扫描器 + 主动评测制度（PROACTIVE_EVALUATION）——对开源 AI 工具链的实证差距分析正是此项 |
| C6 | **人类监督集成框架**（Human oversight integration）：干预触发/升级标准/审计轨迹/责任分配 | Annex A.2.4 | "签发权在人"原则（准则 P7）、双人独立+第三裁决、程序正义（14 天回应/24h 更正/申诉并陈） |
| C7 | **机器可读信任元数据**（Machine-readable trust metadata）实践 | ToR 4.4 | schema.jsonld / .zenodo.json / CITATION.cff（已落地，Schema.org 兼容） |

### P2 用例贡献

| # | 贡献点 | 对应 ToR 项 | 我们的权威支撑 |
|---|---|---|---|
| C8 | **行业 use case：医械合规工具链实测** | ToR 4.1 / A.3.1 | MedXpert 工具链实测报告 + TEST_REPORT_FULL（真实部署证据） |

---

## 三、账号分工矩阵（三号区分、不冲突）

| 账号 | 角色 | 贡献内容 | 署名身份 | 互不冲突规则 |
|---|---|---|---|---|
| **zhaoxinghua09-cell（理论号）** | 理论之源 | C1 生命周期框架（理论版）、C4 术语 | 理论作者（引用 DOI） | 理论只以 lgd-theory SSOT 为源；评测号不重复发布理论 |
| **LGD-Eval（评测号）** | 独立评测执行 | C2 评估准则/基准、C3 静默失败/证据、C5 差距分析、C6 人类监督、C7 元数据 | 独立评测机构 | 评测号引用理论号 DOI，不自创理论版本；不写被评方 |
| **stevenzhao07（产品号）** | 工具链实现 | C8 use case（MedXpert 实测） | 工具链实现者 | 只作为被测/用例提供方；不参与标准文本起草 |

**冲突避免四则**：
1. 一个贡献包只署一个身份（不联名竞标同一工作项）。
2. 同一内容不以两个账号重复提交。
3. 理论版本一律引用 lgd-theory（DOI），任何转述以 SSOT 为准。
4. 对外统一呈现"一个 LGD 生态、三个角色"；与 ITU 沟通以单一协调邮箱/账号为主。

---

## 四、支持者行动清单（Supporter action list）

| 时间 | 动作 | 状态 |
|---|---|---|
| 立即 | 注册免费 ITU 账号（itu.int）并订阅 FG-TIDA 邮件列表（fgtida@lists.itu.int） | 🔶 待用户/主人执行（需个人邮箱） |
| 立即 | 联络焦点组秘书处 tsbfgtida@itu.int：表明支持者身份+贡献意向（附 C1/C2 摘要） | 🔶 待用户/主人执行 |
| 2026-10 | 起草 C1（信任生命周期框架）与 C2（评估准则基准）贡献稿（ITU 输入文档模板） | 🔶 本机构准备 |
| 2026-11-30/12-01 | FG-TIDA 首次面对面会议（巴黎 UNESCO 总部）——现场或在线注册参与 | 🔶 待登记 |
| 2027-01 | 第二次会议（日内瓦）：提交修订贡献稿 | 🔶 规划 |
| 持续 | C5 差距分析随 109 仓评测完成提交；C8 use case 随 AI for Good 窗口提交 | 🔶 规划 |

> 贡献输入文档模板见 FG-TIDA 官网 Templates（Input documents / Technical Report / Technical Specification）；工作语言为英文。

---

## 五、支持者公信力承诺（Supporter credibility）

1. **原创性**：每个贡献点挂首创证据（DOI/.ots/查重报告），不虚称首创。
2. **可验证**：贡献内容附公开仓链接与实测证据，ITU 可独立复核。
3. **中立**：非商业、无立场、无地域偏见；只提供最好的一版。
4. **透明**：贡献采纳与否公开记录；不承诺、不夸大。

---

*Evaluating Autonomy. Verifying Governance. / 评测自治之物，验证治理主张。*
