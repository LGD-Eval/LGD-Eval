# ITU-T FG-TIDA CONTRIBUTION C1 — A Trust Lifecycle Framework for Agentic AI
# ITU-T FG-TIDA 贡献稿 C1 — 代理 AI 信任生命周期框架

- **Contributor / 贡献方**：LGD-Eval（Independent Evaluation）｜理论支撑：LGD 全程治理论（Registry·Evidence·Gates）
- **Corresponds to / 对应 ToR 条款**：Annex A.2.2（A trust lifecycle framework for agentic AI）；also relevant to 4.3（Trust framework(s) and lifecycle management）
- **Status / 状态**：Draft v0.1 for FG-TIDA consideration（供焦点组审议初稿）
- **Working language / 工作语言**：English（中文版随附供内部参考，不用于正式提交）
- **Date / 日期**：2026-10-14

---

## 1. Purpose and scope（目的与范围）

This contribution proposes a **trust lifecycle framework** for human-and-agentic-AI ecosystems, in support of FG-TIDA deliverable A.2.2. Trust is treated as a **dynamic, time-bound property** that must be established, continuously evaluated, degraded and revoked — with **explicit evidence criteria at each lifecycle stage**. The framework covers both agent-to-agent and human-to-agent interaction contexts, and is designed to be implementable in machine-readable form.

本贡献为 FG-TIDA 交付物 A.2.2（代理 AI 信任生命周期框架）提供一套可操作框架：信任被定义为动态、有时限的属性，须经历建立—持续评估—降级—撤销四个阶段，每阶段有明确的证据标准；覆盖代理↔代理与人类↔代理两种交互语境，并支持机器可读实现。

## 2. Core model（核心模型）

The framework anchors trust to three persistent primitives（本框架以三个持久原语为锚）:

| Primitive | Definition（定义） | Lifecycle role（生命周期角色） |
|---|---|---|
| **Registry（有籍）** | A verifiable record of *what an entity is*: identity claims, capabilities, delegated scope（身份与能力注册） | Establishment: trust begins with verifiable identity + declared capability scope |
| **Evidence（有证）** | A tamper-evident record of *what an entity did*: behaviour, outcomes, failures, compliance signals（行为与结果证据链） | Continuous evaluation: trust is a function of accumulated evidence |
| **Gates（有门禁）** | Defined checkpoints with explicit pass criteria, per lifecycle stage（带明确通过标准的阶段门禁） | Degradation & revocation: gates define when trust is downgraded, suspended or revoked |

## 3. Lifecycle stages and evidence criteria（生命周期阶段与证据标准）

| Stage（阶段） | Trigger（触发） | Required evidence（所需证据） | Gate（门禁判定） |
|---|---|---|---|
| **E1 Establish（建立）** | First interaction / delegation request | Identity registration, capability declaration, origin anchor, human-ownership link | Registry verified + scope declared ⇒ minimal trust granted |
| **E2 Continuous evaluation（持续评估）** | Each task / delegation step | Behavioural signals, outcome attestations, exception logs, silent-failure probes | Evidence accumulates; trust score updated per policy |
| **E3 Degradation（降级）** | Evidence of anomaly, deviation from declared scope, failed check | Anomaly record, deviation report, severity assessment | Gate: downgrade to restricted scope or elevated oversight |
| **E4 Revocation（撤销）** | Persistent failure, malicious intent, owner request | Escalation trail, human decision record, audit snapshot | Gate: full revocation + revocation record |

Key design property（关键设计属性）：**each stage transition requires evidence, not assertion** — a gate cannot pass on a claim alone; it must be backed by a verifiable record（每次阶段转换都要求证据而非声明——门禁不能仅凭宣称通过，必须附可验证记录）。

## 4. Human oversight integration（人类监督集成）

- **Escalation triggers**（升级触发）：anomaly thresholds, out-of-scope actions, high-impact transactions.
- **Sign-off authority**（签发权）：remains with humans for E3/E4（degradation/revocation）and for high-impact decisions — matching FG-TIDA A.2.4.
- **Audit trail**（审计轨迹）：all gate outcomes and evidence are recorded immutably（hash-chained / timestamped）.

## 5. Relationship to existing work（与既有工作的关系）

- Complements, and does not duplicate: X.509 evolution（A.1.4）, delegation artefacts（A.1.2）, zero-trust/risk-adaptive models（A.2.3）.
- The evidence-gate discipline aligns with the behaviour-signals data model（A.2.8）and machine-readable trust metadata（4.4）.
- No overlap with out-of-scope items（AI governance / protocols / national digital ID content）.

## 6. Provenance and verifiability（来源与可验证性）

- Theoretical anchor: LGD lifecycle governance theory（papers P0/P3）, DOI 10.5281/zenodo.22456647; evidence-chain practice with .ots timestamps and hash manifests（see silent-failure-catalog, credential-vault-design implementations）.
- All patterns are backed by open, re-runnable implementations; independent verification is welcomed by the contributor（supporter posture）.

## 7. Requested action（请焦点组考虑）

1. Adopt the Registry–Evidence–Gates primitives as candidate terminology for A.2.2.
2. Consider the four-stage lifecycle（E1–E4）with evidence gates as a baseline for the trust lifecycle deliverable.
3. Offer the contributor to co-develop the machine-readable evidence schema with FG-TIDA members.

---

*Submitted in a supporter role; adoption decision rests with FG-TIDA consensus.*
*以支持者身份提交；是否采纳由焦点组共识决定。*
