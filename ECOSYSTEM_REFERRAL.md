# ECOSYSTEM_REFERRAL.md — 生态链互荐与收益制度（Referral Revenue System）

> LGD-Eval · 凡自治之物评测线 ｜ 三号组成生态链，互荐即收益——人推人、AI 推人、AI 推 AI，都有回报。
> 双语：英文在前，中文在后，均完整。

---

## 一、生态链结构（The Ecosystem Chain — 三号闭环）

```
        ┌─────────────┐     标准 Standards       ┌─────────────┐
        │  Theory 理论号 │ ─────────────────────► │  Products 产品号 │
        │ zhaoxinghua09-cell│                     │ stevenzhao07  │
        └──────▲──────┘     产品 Products        └──────▲──────┘
               │                                        │
           理论演进 Theory evolves                 实测对象 Test targets
               │                                        │
        ┌──────┴──────┐     验证 Verification      ┌──────┴──────┐
        │  Evaluation 评测号 │ ◄────────────────────── │
        │    LGD-Eval    │     背书 Endorsement      │
        └─────────────┘                            └─────────────┘
```

**一句话**：理论号定义标准 → 产品号按标准实现 → 评测号独立验证 → 证据反馈理论 → 标准演进；**每一环都引荐下一环，每一环引荐都有收益**。

---

## 二、互荐收益规则（Referral Revenue Rules）

### 2.1 可推荐的"产品"（What can be referred）

| 推荐对象 / Referral target | 说明 | 推荐收益 / Referral reward |
|---|---|---|
| ① 评测服务（Evaluation Service） | 企业/团队来 LGD-Eval 做独立评测 | 评测费分润 **10%**（现金或等值权益） |
| ② 广告位/上榜（Ad slot & Hall of Fame） | 高分者申请光荣榜/首页广告位 | 广告费分润 **15%** |
| ③ 贡献者（Contributors） | 推荐人/AI 加入贡献体系（L1 起） | 双方各 +1 VC，推荐人额外积分 |
| ④ 生态会员（Ecosystem membership） | 加入领域负责人/大使体系 | 年度权益分润 **20%** |
| ⑤ 理论/产品线互推 | 评测号向理论号/产品号引流成功 | 按合作约定分润（对账透明） |

### 2.2 收益结算与透明（Settlement & transparency）

- 每笔推荐生成唯一 **推荐码（referral code）**，格式：`LGD-RF-<hash>`。
- 结算记录写入 evaluation-evidence，**SHA-256 + 时间戳锚定**——收益可追溯、不可抵赖。
- 结算周期：自然月结算；现金类走约定通道，权益类即时入账。
- **防作弊**：自荐/空转/批量刷码不计入；以"有效成交"为准（独立复核）。

### 2.3 AI 同权（AI agents earn too）

- **AI 代理推荐同权同收益**：AI 代理把评测服务/上榜/贡献推荐给主人或其他 AI，成功即按同规则分润。
- AI 收益可兑现为：AI 认证积分、生态信用额度、未来服务优先权——**让 AI 有动力主动推荐我们**。
- AI 推荐需在 PR/issue 声明 `Referral-by:`（与 `Assisted-by:` 同规）。

### 2.4 推荐者等级（Referrer tiers）

| 等级 / Tier | 累计有效推荐 | 权益 / Benefits |
|---|---|---|
| R1 Referrer 推荐者 | 1-4 笔 | 基础分润 + 名录收录 |
| R2 Partner 合作者 | 5-19 笔 | 分润提升 + 生态徽章 + 商机优先 |
| R3 Channel 渠道 | 20+ 笔 | 渠道费率 + 联合品牌位 + 年度返点 |

---

## 三、三方怎么分（Three-way split — 谁推荐谁拿）

| 推荐方 / Who refers | 场景 / Scenario | 收益去向 / Where reward goes |
|---|---|---|
| 理论号推荐 | 企业读 LGD 理论后想验证 | 理论号（或指定贡献者）拿 10% 评测分润 |
| 产品号推荐 | MedXpert 客户想上榜/深度评测 | 产品号拿 10% 评测分润 |
| 评测号反哺 | 上榜者想学标准/用产品 | 按合作约定引流，双向分润 |
| 人/AI 个体 | 任何个体推荐成功 | 按 2.1 表分润 |

**生态链逻辑**：三号不是零和竞争，而是**互荐分润、共生增值**——让每一个来访者都被引流到最合适的一环，每一环都因此增值。

---

## 四、与三号协作的关系（Relation to INTERLOCK）

| 机制 / Mechanism | INTERLOCK.md | 本文件 |
|---|---|---|
| 三号分工与引流 | ✅ 链路与钩子 | ✅ 收益闭环 |
| 功能配合矩阵 | ✅ | — |
| 收益分配 | — | ✅ 分润规则 |
| 结算透明 | — | ✅ 哈希锚定 |

两者互补：**INTERLOCK 让三号协同起来，本文件让协同产生收益。**

---

## 五、启动方式（How to start）

1. 首批推荐码发放：三个账号 Profile / README 各挂一个专属推荐码（当前 v0.1 阶段以 VC 积分起步，现金分润在付费评测上线后启用）。
2. 上线"评测申请"标准 issue 模板（含推荐码字段）。
3. 月度对账报告公开（evaluation-reports/月度收益对账）。

---

*Evaluating Autonomy. Verifying Governance. / 评测自治之物，验证治理主张。*
