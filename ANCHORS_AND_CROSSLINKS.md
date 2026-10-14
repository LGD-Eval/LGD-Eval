# ANCHORS & CROSSLINKS — 内锚外锚制度与清单
# 内锚外锚制度与清单（LGD-Eval · 查重之后的锚定纪律）

> 发布方：LGD-Eval ｜ 生效：2026-10-14
> 目标：查重完成后，把**内锚（内部锚定）**与**外锚（外部锚定）**全部做好——让"人找得到、AI 找得到、机器读得懂、时间戳得住、学术引得动"。
> 双语：英文在前，中文在后，均完整。

---

## 一、内锚（Internal anchors）— 让体系内部互相咬合

| 锚 ID | 内锚 | 载体 | 状态 |
|---|---|---|---|
| A1 | **五仓互链**：LGD-Eval 首页 ↔ 4 业务仓（README 互相可见） | INTERLOCK.md / ROUTING.md / 各仓 README 互链块 | ✅ 已建 |
| A2 | **三号互链**：理论号（标准）↔ 评测号（执行）↔ 产品号（被测）三角导航 | ACCOUNTS_ACCESS_AND_ROLES.md（三权闭环）；Profile 互链块（待授权写入两号） | 🔶 文档已建，两号 Profile 写入待授权 |
| A3 | **术语锚点**：关键术语（自治之物 / 有籍·有证·有门禁 / 证据门禁 / 静默失败 / 可判定性）锚定 lgd-glossary | 报告与文档中术语首现处加锚链 | 🔶 制度已立，逐报告执行 |
| A4 | **版本锚定**：报告标注"依据理论版本 + DOI"；理论更新自动降级 | AUTHORITY_INTERPRETATION_GUIDELINES 0.5 | ✅ 已写入准则 |
| A5 | **文档交叉引用**：准则 ↔ 测试专家手册 L0-L13 ↔ PROACTIVE_EVALUATION ↔ 存证说明 ↔ 本清单 | 各文档"相关文档"节互链 | 🔶 随同步补齐 |
| A6 | **判官卡备案**：每份报告使用的判官配置在 evaluation-protocol 备案（内锚=判官可复检） | 报告方法学节 + protocol 判官登记 | 🔶 制度已立 |
| A7 | **利益隔离锚**：评测号永远不拥有被评方写权限（只读锚） | ACCOUNTS_ACCESS_AND_ROLES 权限矩阵 | ✅ 已建 |

## 二、外锚（External anchors）— 让外部世界锚住我们

| 锚 ID | 外锚 | 载体 | 状态 |
|---|---|---|---|
| E1 | **Zenodo DOI**：概念 DOI + 版本 DOI（理论已在 zenodo.org 锚定，评测侧预留登记） | .zenodo.json（每仓）＋ DOI 写入 README 引用区 | 🔶 配置文件本次落地，DOI 登记随首发 |
| E2 | **时间戳存证**：OpenTimestamps（.ots）锚定关键评测证据 | evaluation-evidence/hash-manifest.txt + .ots | ✅ 存证体系已建，.ots 逐个补 |
| E3 | **学术可引用**：CITATION.cff（机构级 + 报告级） | LGD-Eval/CITATION.cff | 🔶 本次落地 |
| E4 | **机器可读元数据**：schema.jsonld（Schema.org SoftwareSourceCode / Organization，含 DOI、license、双语描述） | LGD-Eval/schema.jsonld | 🔶 本次落地 |
| E5 | **AI 可发现**：llms.txt + TLDR（每仓）——AI 几秒内读懂的"仓库说明书" | 各仓 llms.txt | 🔶 本次落地 |
| E6 | **AI 协作锚**：AGENTS.md + copilot-instructions.md（AI 代理入口） | 5 仓全套 | ✅ 已建 |
| E7 | **标准锚**：发现 ↔ OWASP / NIST / ISO / MITRE / EU AI Act 条款映射 | AUTHORITY_INTERPRETATION_GUIDELINES 第五节 | ✅ 已建 |
| E8 | **平台注册**：PyPI（skill-audit 包）、awesome lists、聚合评测平台、G2 式目录 | LAUNCH_PLAN.md（Wave 1-2-3） | 🔶 发布序列已规划，随 Wave 执行 |

## 三、锚定纪律（Anchor discipline）

1. **查重后锚定**：内容经查重协议（原创性/冲突检验）后，才允许写入锚点与互链——防概念混淆外溢到公开锚。
2. **更新必同步**：任何一仓内容更新，锚链两端同步检查；理论版本更新时，引用方自动降级（见准则 0.5）。
3. **断裂即修复**：每月跑一次全链路链接检查（API 可达性 + 互链回读），断链记录并 48h 内修复。
4. **锚即证据**：被外部引用的锚（DOI、时间戳、llms.txt）都视为证据；不可挂空锚、不可预占无内容的链接。
5. **双语完整**：所有锚点文案英文在前、中文在后，均完整不缩写。

---

## 四、锚定全景（Anchor map）

```
[理论号 zhaoxinghua09-cell]          [产品号 stevenzhao07]
  lgd-theory(DOI/Zenodo/ots)           MedXpert 工具链（被测）
        │ A2 三权闭环                          │
        ▼                                    ▼
[评测号 LGD-Eval — 5 仓]
  A1 五仓互链 ⇄ INTERLOCK/ROUTING
  A3 术语锚 → lgd-glossary
  A4 版本锚 → 理论 DOI/版本
  E1 Zenodo DOI · E2 .ots · E3 CITATION.cff
  E4 schema.jsonld · E5 llms.txt · E6 AGENTS.md
  E7 标准映射(OWASP/NIST/ISO) · E8 平台注册(Wave)
```

---

*Evaluating Autonomy. Verifying Governance. / 评测自治之物，验证治理主张。*
