# AUTHORITY & INTERPRETATION GUIDELINES — 权威评测与解读准则
# 权威评测与解读准则（LGD-Eval · 让结论占得住）

> 发布方：LGD-Eval ｜ 生效：2026-10-14 ｜ 依据：全面调研（Judging the Judges 2026 / BiasScope / SOS-Bench ICLR2025 / Prior Prejudice ACL2026 / QUADAS-3 / GRADE / OWASP LLMSVS v2.0 / NIST AI RMF / ISO 42001 / MITRE ATLAS）＋ 本机构理论（LGD 全程治理论，DOI 10.5281/zenodo.22456647）
> 目标：**最权威、最公平、最公信**。本准则定义评测的方法学底线、证据分级、解读等级与报告规范——"给的解读一定要占得住"。
> 双语：英文在前，中文在后，均完整。

---

## 〇、方法论内核：LGD 三律贯穿一切（The LGD core — our theory as methodology）

> **理论不只在"评什么"里，也在"怎么评"里。** LGD 全程治理论（Evidence-Gated AI Lifecycle Governance · 凡自治之物 · 有籍·有证·有门禁）是评测机构的方法论内核：评测对象按其"自治之物"身份受三律审计；评测过程自身同样受三律约束。

### 0.1 评测对象按三律审计（Audit the object by the three laws）

每一项被评测的自治之物（AI 工具链、技能、代理、系统），都按其完整生命周期接受三律域审计：

| LGD 三律 | 评测域（Audit domain） | 典型检查项 |
|---|---|---|
| **有籍 Registry**（出生即登记） | 身份与归属 | 是否声明身份/创造者/治理归属；manifest 是否齐全；版本是否可追溯；许可是否明确 |
| **有证 Evidence**（关键行为留证据） | 证据链 | 日志/风险登记/变更记录是否完整；结论是否可复现（脚本+哈希）；存证是否锚定 |
| **有门禁 Gates**（演化前过门禁） | 演化与签发 | 变更是否过"触发→评估→放行→复盘"；签发权是否在人；门禁记录是否公开 |

> 三律域即权威报告第四节"偏倚域评估"的上层骨架：域级判断先按三律分域，再在域内做偏倚控制与证据分级。**LGD 三律 = 评测维度；GRADE/QUADAS = 证据质量工具；OWASP/NIST/ISO = 标准锚点**——三者不冲突，层层嵌套。

### 0.2 评测过程自身守三律（The process obeys the same laws）

| LGD 三律 | 评测机构的对应纪律 |
|---|---|
| 有籍 | 每份评测有**方案登记**（pre-registration：对象/范围/指标/判官/阈值先公开后执行）；判官卡备案 |
| 有证 | 全部证据链留痕（复现脚本/截图/日志/哈希/manifest/时间戳）；证据分级可复核 |
| 有门禁 | 报告发布前过**发布门禁**（双人独立 → 争议裁决 → 偏倚审计 → 发布人签发）；**签发权在人**——最终签发永远是自然人，不是 AI |

### 0.3 理论引用规范（Theoretical anchors）

- 判定标准以 lgd-theory 为准（概念 DOI 10.5281/zenodo.22456647；术语见 lgd-glossary）。
- 报告引用的每条理论条款须给出版本与链接；理论版本变化时报告须注明"依据版本"。
- 三号闭环：理论（标准之源）→ 产品（被测对象）→ 评测（独立执行）——评测机构不修改理论，只引用与检验。

### 0.4 理论矩阵：我们全部理论进入评测方法（Theory Matrix — every doctrine enters the method）

> 不止 LGD：凡自治生态**总结归纳的全部理论**都作为方法论组成。每份评测报告须在方法学节列出"本报告引用的理论矩阵"。

| 理论 / 方法论 | 来源（Theoretical source） | 在评测中的用法（How it enters evaluation） |
|---|---|---|
| **LGD 三律**（有籍·有证·有门禁） | lgd-theory（DOI 10.5281/zenodo.22456647） | 评测对象三域审计 + 评测过程纪律（见 0.1/0.2） |
| **Evidence-Gated AI Lifecycle Governance**（证据门禁治理） | lgd-theory（论文正式名） | 报告发布前过"证据充分性门禁"：证据不足不得发布 |
| **治理可判定性学说**（P0） | lgd-theory/papers/P0-governance-determinability-doctrine-v1.2 | 判官与评测的**可判定性边界**：什么可判、什么不可判，写进范围声明 |
| **批判原则：原则不能拯救 AI 治理**（P2） | lgd-theory/papers/P2（SSRN 提交） | 评测只认证据不认声明："宣称即通过"不被采信 |
| **治理不可能地图**（P5） | lgd-theory/papers/P5-governance-impossibility-map-v0.3 | 评测的**不可判定域自觉**：边界处只给"待定"，不猜测 |
| **ACD 回测**（P3） | lgd-theory/papers/P3-acd-backtest | 评测方法论自身要回测：判官一致性、偏倚审计定期重验 |
| **测试专家手册 L0-L13** | evaluation-protocol（本机构） | 执行层：分级评测判据、流程与门禁的具体化 |
| **静默失败目录 Silent Failure Catalog** | 理论号 Verification 线 | 专测"没报错但错了"的静默失败——AI 工具链最危险的一类，必须单列评测域 |
| **查重协议（多轮多维度）** | 评测线查重方法论 | 术语/命名/结论的原创性与冲突检验（防概念混淆） |
| **不自查原则** | 三号治理（ACCOUNTS_ACCESS_AND_ROLES） | 评测者自我检查不构成验收；一切结论独立复核 |
| **三权闭环 + 利益隔离** | ACCOUNTS_ACCESS_AND_ROLES | 机构独立性：只读被评方、不持利益、付费不买结论 |
| **九声矩阵 / 发声理论** | 理论号 voice-kb（发声大使×理论栈绑定矩阵 v2.1） | 解读与发布的语言纪律：发声即负责，解读等级与措辞绑定 |
| **R-STYLE 命名体例** | 理论号《命名体例规范》v1.0 | 报告术语/命名/概念层与仓名层的一致性 |
| **UIBC 一致性/越权用例** | 理论号 uibc-core（Apache-2.0） | 对抗性评测用例来源：一致性自检 + 越权测试两条线 |

### 0.5 理论边界自觉（Theoretical humility — P5 applied）

1. **不可判定域**："完全安全/绝对可靠"不可判定——我们只给"证据不足以判定"（P5 治理不可能地图的直接应用）。
2. **范围诚实**：每份报告必须有"本评测的边界"节：没测什么、为什么、什么条件下结论可能改变。
3. **理论演化**：报告标注所依据理论版本；理论更新后，旧版本结论自动降级至"有限/待定"并提示复核。
4. **方法论回测**：每季度对评测方法论自身做一次 ACD 式回测（判官卡重验、偏倚审计复跑），结果公开。

---

## 一、权威性七支柱（Seven pillars of authority）

| # | 支柱 Pillar | 要求 Requirement |
|---|---|---|
| P1 | 方法先行 Method pre-registration | 评测前公开评测方案（对象、范围、指标、判官、阈值）——先登记后执行，杜绝"先有结论再找证据" |
| P2 | 多判官 + 人工锚定 Multi-judge & human anchor | 结论不得依赖单一 LLM 判官；关键结论必须人工复核锚定 |
| P3 | 偏倚控制 Bias control | 位置交换（AB+BA）、风格归一、长度控制、盲化——每条结论附偏倚审计结果 |
| P4 | 证据分级 Evidence grading | 按 GRADE 式确定性分级（高/中/低/极低 + 降级条件），不得越级断言 |
| P5 | 报告可复现 Reproducible reporting | 每项发现附复现脚本、截图、日志、哈希（LLMSVS 标准：自动化工具结果不足以为充分证据） |
| P6 | 解读守则 Interpretation code | 结论措辞与证据等级严格绑定（句式模板），"确证/强/中等/弱/待定"五级分明 |
| P7 | 程序正义 Procedural fairness | 双人独立评审 + 争议第三裁决；被评方 14 天回应期；24h 事实更正；申诉不删报告只并陈 |

---

## 二、LLM-as-a-Judge 使用准则（实测依据，非教条）

> 依据：Judging the Judges（风格偏倚 0.10-0.76 为主，远超位置偏倚 ≤0.04）；Reliability without Validity（裸 agreement 高估判别力 33-41pp，κ 通缩）；SOS-Bench（风格压倒实质，judge 偏好与实质指标不相关）；Prior Prejudice（模型把自身信念当质量，提示词无法修复、明确指令反而恶化 35-43%）。

### 判官配置（JudgeStrategySelector 适配版）

| 场景 | 判官配置 | 说明 |
|---|---|---|
| 对抗/高风险评测 | 强模型（Claude/GPT-4o/Llama 级）+ **CoT Forcing（S5）** | 最佳 LLMBar 表现；对抗数据禁用位置单交换 |
| 常规/成本敏感 | 中端模型 + **Combined Budget（S8）** | 性价比最优（约 $0.001/评） |
| 未知模型 | CoT Forcing 兜底 | 最安全的默认 |

### 强制偏倚控制（Mandatory）

1. **位置交换**：AB + BA 双序配对，报告位置翻转率（position flip rate）。
2. **风格归一**：同一实质内容的 markdown 版与纯文本版各评一次——风格偏倚是主导偏倚。
3. **长度控制**：truncation pairs 区分"冗余填充"与"真正完整"；报告冗长偏倚方向。
4. **κ 而非裸 agreement**：一律报 chance-corrected（Cohen's κ / Krippendorff α），不得用 raw agreement 冒充可靠性。
5. **判官卡（Judge card）**：每份报告公开判官模型、版本、温度、去偏策略、偏倚审计结果——判官本身可被检验。
6. **先验偏倚防线**：判官不得接触"结论导向"提示；与结论利益无关；关键结论人工复核（Prior Prejudice 证明提示无法修复，只能换判官/加人工）。

### 禁止事项（Prohibited）

- ❌ 单一 LLM 判官产出"确证"级结论。
- ❌ 报告裸 agreement 而不报 κ/一致性。
- ❌ 用"独立判定"指令代替实际偏倚控制（实证：无效甚至有害）。
- ❌ 把 LLM 偏好（风格/冗长）当作品质结论。

---

## 三、证据分级与解读等级（GRADE 适配 Evidence→Interpretation）

### 解读等级（Interpretation levels — 结论措辞的法定上限）

| 等级 | 定义 | 所需证据 | 允许措辞示例 |
|---|---|---|---|
| **V · Verified 确证** | 多源独立复现 + 人工锚定 + 全证据链 | ≥2 独立执行者复现一致；判官卡通过；无未解偏倚域 | "我们确证 / We verify that…" |
| **S · Strong 强** | 受控复现，1 执行者 + 人工复核 | 复现脚本可跑；κ ≥ 0.6；偏倚域明确披露 | "我们强证据认为 / We find strong evidence that…" |
| **M · Moderate 中等** | 可复现但样本/条件受限 | 复现可行；κ 0.4-0.6；适用性受限 | "我们观察到 / We observe that…" |
| **L · Limited 有限** | 证据存在但不完整 | 部分复现；判官偏倚未完全控制 | "初步迹象表明 / Preliminary evidence suggests…" |
| **P · Preliminary 待定** | 不足以断言 | 无法复现/证据冲突 | "证据不足以判定 / Insufficient evidence to conclude…" |

### 降级条件（Downgrade triggers，满足任一即降一级）

1. **偏倚风险**：任一偏倚域 High/Unclear（QUADAS 式域级判断）。
2. **不精确**：样本过小或置信区间过宽。
3. **不一致**：不同判官/复现之间结果冲突。
4. **间接性**：测试环境与宣称场景不符（适用性关切）。
5. **发表/选择偏倚**：仅选取有利证据。

> **铁律**：解读等级只降不升；未知按未知处理，不按零值处理；"未发现 X"≠"X 不存在"，必须写"证据不足以判定 X"。

---

## 四、权威报告结构（Report anatomy — 对齐 LLMSVS/QUADAS）

每份评测报告必须包含（编号固定）：

```
1 执行摘要（Executive summary，含解读等级总览）
2 范围与排除声明（Scope & exclusions——评了什么、没评什么、为什么）
3 方法学（Method——方案登记号、判官卡、偏倚控制清单）
4 偏倚域评估（Domain-level RoB：域级判断，禁止复合分）
5 发现清单（Findings——每项附解读等级 + 证据）
6 证据附录（Evidence——复现脚本/截图/日志/哈希/manifest）
7 标准映射表（Standards mapping——发现 ↔ OWASP/NIST/ISO/MITRE/EU AI Act 条款）
8 回应与更正记录（Responses & corrections——被评方 14 天回应、24h 事实更正）
```

- **禁止复合分**：不同偏倚不可数值等价（QUADAS 原则）——不出"总分 85"式结论，只出域级判断 + 解读等级。
- **证据充分性**：自动化输出不足以定论；必须附可复现工作底稿（LLMSVS v2.0 原则）。
- **范围诚实**：明确排除项；不把"未测的"写成"通过的"。

---

## 五、标准映射（Standards anchors — 让结论可辩护）

发现须可映射到公认标准，权威性来自可交叉验证：

| 标准 | 对应发现域 |
|---|---|
| OWASP LLM Top 10（LLM01-LLM10） | 提示注入/输出处理/供应链/过度代理等 |
| OWASP Agentic AI Top 10（AAT-1-10）/ Agentic Security（ASI） | 代理威胁 |
| OWASP LLMSVS v2.0（V1-V8，L1-L3） | 安全验证要求 |
| NIST AI RMF（MAP/GOVERN/MEASURE/MANAGE） | 风险治理 |
| ISO/IEC 42001（A.4-A.9）/ ISO 23894 | AI 管理体系 |
| MITRE ATLAS（AML.T…） | 对抗战术 |
| EU AI Act | 合规衔接 |

**映射规则**：每项发现标至少 1 个标准条款；映射不当视为发现缺陷而非免责。

---

## 六、程序正义（Procedural fairness）

- **双人独立**：每项发现 ≥2 名独立评估者；争议由第三裁决（QUADAS/Cochrane 实践）。
- **盲化**：关键判断对"被评方身份/付费状态"盲化（检测偏倚控制）。
- **被评方权利**：14 天回应期（并陈不改结论）；事实错误 24h 核验更正（更正留痕）。
- **利益隔离**：评测者不得持有被评方利益；付费只买优先级不买结论。
- **自审禁止**：我们不自查自己的结论；一切结论由独立方复核（不自查原则）。

---

## 七、落地位置（Where it lives）

- 本准则：5 仓根目录（本文件）
- 评测方法：测试专家手册 L0-L13（evaluation-protocol）
- 主动评测：PROACTIVE_EVALUATION.md（选择标准 + 六步流程）
- 报告发布：evaluation-reports（结构按第四节模板）
- 存证：evaluation-evidence（hash-manifest + 时间戳）

---

*Evaluating Autonomy. Verifying Governance. / 评测自治之物，验证治理主张。*
