# FG-TIDA PEOPLE & COMPANIES DEEP DIVE — 人物与公司深度调研
# FG-TIDA 人物与公司深度调研：背景 · 公司 · 方向 · 契合点 · 接触建议（LGD-Eval）

> 发布方：LGD-Eval ｜ 日期：2026-10-14 ｜ 来源：ITU 官方（SG17 纪要/ToR/官方简历）、AI for Good、Cognizant 官方发布（2026-05/07）、Thales 产品线、Cyber Defense Matrix/SANS、Knostic 公开资料、IEEE 活动记录、WTSA-24
> 结论先行：**Amir Banifatemi 与 Sounil Yu 是最可能乐于接受的两人，且理由比第一轮更强**——Cognizant 已公开主打 "Provable Trust（可证明的信任）"，与我们的证据理念完全同频；Sounil 的 Knostic 正做 agentic AI 安全评估与开源工具，与我们的弹药全部重合。
> 双语：英文在前，中文在后，均完整。

---

## 一、Debora Comparin — Co-Chair（Thales, France）

**个人背景**：SG17（安全）WP1 主席联络人、FG-TIDA ToR 起草人；Thales 网络安全与数字身份（CDI）部门。是 FG-TIDA 成立的推动者之一（新闻稿中引用其观点："在这一切成为现实之前，我们需要共同国际基础，确立这些代理是谁、何时可被信任、人类如何保持控制"）。

**公司方向（Thales CDI / Thales Group）**：全球身份与认证基础设施巨头。业务线：
- **认证**：FIDO2 生物识别令牌（SafeNet eToken Fusion Bio）、PKI 智能卡（IDPrime 系列）、SafeNet Trusted Access、SafeNet FIDO Key Manager；
- **政府级生物识别**：CABIS（法庭级 AFIS——指纹/掌纹/人脸/虹膜多模态，NIST 验证，服务国家安全身份、边境、执法、民事登记）；
- **数字身份与移动 ID**：Gemalto 并入后的移动身份/电子证件能力。
- 即：**身份原语与认证基础设施的供应方**（身份注册、凭据、生物识别是其主业）。

**立场/关注点**：信任管理与数字身份基础设施的标准化；程序严谨（她是 ToR 起草人，最懂条款边界）；重视"身份是什么→何时可信→人类如何保持控制"的链路。

**与我们贡献的契合点**：C1（信任生命周期 A.2.2）正中她起草的条款；我们的 **Registry（有籍）原语与她的身份基础设施天然互补**——她做身份原语，我们做"注册之后的行为证据与门禁"。她的措辞："when they can be trusted / how people remain in control"——**C1 的 Evidence 与 Gates 正是答案**。

**接触建议**：正式、条款化语言；切入点是"补充 A.2.2 的可操作生命周期模型，与既有身份基础设施（FIDO/PKI）衔接而非替代"；走秘书处正式提交。

## 二、Amir Banifatemi — Co-Chair（Cognizant, UK）🔴 首选

**个人背景**：Cognizant Chief Responsible AI Officer（全球负责人）；**AI for Good 运动联合创始人**（与 ITU 共建，AI for Good Global Summit 共同发起）；XPRIZE 前首席创新官；OECD/GPAI/IEEE 活跃；博士（System Design & Cognitive Sciences）+ MBA + 电子工程；30 年创新与投资。邮箱公开：amir@bayspring.com（GIO 资料）。

**公司方向（Cognizant）**——**关键：与我们的理念完全同频**：
- 2026-05-07 发布 **Secure AI Services**，核心主张 **"从 assumed trust 转向 provable trust"**：基于证据、可追溯、持续保证（build-time ADLC + run-time Neuro Cybersecurity + Responsible AI 信任层）；
- 2026-07-01 发布 **Neuro AI Trust**：AI 治理控制平台，Guardian Agents 实时监控行为，内部已部署于 35 万员工 agentified 网络（Amir 亲自背书）；
- 对齐 ISO/IEC 42001、NIST AI RMF、EU AI Act；强调"连续保证、审计就绪证据、行为护栏"。

**立场/关注点**：负责任 AI 落地化；**证据化信任（provable trust）**；AI 生命周期治理；跨部门标准（OECD/GPAI/IEEE/ITU）。

**与我们贡献的契合点（极高）**：
- C2（评估准则/证据分级/程序正义）＝ **直接支持他的 "provable trust" 主张**——他卖的是"可证明的信任"，我们提供"怎么证明"的方法论与开源实践；
- 我们的证据链（.ots 时间戳、哈希清单、复现协议）＝他需要的"审计就绪证据"的现成示范；
- 我们的"评测→改进→复评"闭环 ＝他的"continuous assurance"的开源镜像。

**接触建议**：以"支持者贡献证据方法论"切入；语言用 provable trust / evidence-based / continuous assurance（他的词汇）；先公开渠道（FG-TIDA GitHub 评估类议题）再正式提交 C2。**他是"最容易听进去"的人——我们说的正是他在对外卖的主张。**

## 三、Sounil Yu — Vice-Chair（Knostic, USA）🔴 高优先

**个人背景**：Cyber Defense Matrix 作者、DIE Triad 创造者；FAIR Institute 董事；GMU Scalia 国家安研院高级研究员；卡内基梅隆客座讲师；美银前首席安全科学家（2012-2019）；JupiterOne 前 CISO；YL Ventures CISO-in-Residence；20+ 专利；SANS 终身成就奖、网络安全名人堂；SANS 常驻讲师（Shadow AI、AI 供应链安全、知识分割议题）。

**公司方向（Knostic，Sounil 联合创办/首席 AI 安全官）**：agentic AI 安全平台：
- **Kirin**：保护 AI agents/编码助手（Cursor、Claude Code、Copilot）/MCP 服务器——最少权限策略、运行时异常检测、prompt-injection 阻断；
- **AgentMesh**：AI 供应链声誉（2026-06 与 VirusTotal 合作）；
- **OpenAnt**：**开源**漏洞发现工具（Apache-2.0）；
- Shadow AI Spotlight（未授权 AI 使用发现）；CSA Agentic AI Security 创新图谱：治理/可观测/供应链完整性。

**立场/关注点**：AI agent 安全评估、最少权限、供应链声誉、开源工具、行为护栏。**他本人用开源方式（OpenAnt）做事**。

**与我们贡献的契合点（极高）**：C2（评估准则基准）+ C5（开源差距分析 A.1.8）＋ skill-audit 扫描器＋静默失败目录——**我们全部弹药正中他的工作领域**；他认同开源贡献模式，最可能"看得懂且用得上"我们的开源评测工具。

**接触建议**：GitHub 原生路径——他会在 FG-TIDA GitHub 上；以"可复现的评估工具与开源差距数据"切入；先公开互动再一对一。**他是技术判断力最强的受众，也是最能验证我们"真有货"的人。**

## 四、Liangliang Zhang — Vice-Chair（Huawei, China）🟡 观察后接触

**个人背景**：华为标准化资深经理，**16+ 年标准化经验**（ITU-T、ISO、3GPP、IEEE）；SG16 Q22（DLT 及相关服务）副报告人；FG DPM WG3 前主席（数据共享、互操作性、区块链）；WTSA-24 APT 筹备组 WG1 副主席；IEEE Global Initiative on Trust Technology 华为代表（2022）。公开个人材料少。

**公司方向（Huawei）**：通信基础设施 + 云 + AI；标准化参与度极高（ITU/IEEE/3GPP）；关注互操作、安全标准、数字基础设施。

**立场/关注点**：标准流程专家；数据共享/互操作/DLT 背景；中国视角。对"评估准则/互操作"有理解基础，但对"开源评测方法论"的接受度未知。

**契合点**：C2 的互操作评估域（D6）、标准映射；C5 的开源差距有全球视角价值。**接触建议**：观察其在 FG-TIDA 讨论中的活跃度后再定；语言用标准程序词汇（可追溯、互操作、可复现）；**不要第一个接触**（资料少、风险未知）。

---

## 二、公司方向对照速览（Company direction map）

| 公司 | 方向 | 与我们的关系 | 接触关键词 |
|---|---|---|---|
| Cognizant | Provable Trust · 连续保证 · AI 治理平台 | **同频互补**（我们提供"怎么证明"） | evidence, continuous assurance, audit-ready |
| Knostic | agentic AI 安全评估 · 开源工具 · 供应链 | **同频互补**（我们的工具即弹药） | reproducible, open-source, assessment |
| Thales CDI | 身份原语 · FIDO/PKI · 政府生物识别 | **互补衔接**（我们做注册后的生命周期） | lifecycle, identity infrastructure |
| Huawei | 标准/互操作/DLT | 方法互补 | interoperability, traceability |

## 三、"先接触谁"最终结论

1. **首选：Amir Banifatemi**——他在公开卖 "provable trust"，我们的 C2 是现成支撑；最可能乐于接受且影响力最大（Co-Chair + AI for Good 联合创始人）。
2. **技术验证者：Sounil Yu**——最能验证"真有货"，GitHub 原生路径；C2/C5 + 扫描器正中其领域。
3. **正式渠道：Debora Comparin**——C1 走正式提交（她的 ToR 条款）。
4. **观察后定：Liangliang Zhang**——先看活跃度。

**执行建议**：Phase 0 观察期同时盯紧三人（GitHub 互动 + 邮件列表），首个正式贡献仍是 **C2（评估准则）**——Amir/Sounil 双高、无理论竞争、可复现。

---

*Evaluating Autonomy. Verifying Governance. / 评测自治之物，验证治理主张。*
