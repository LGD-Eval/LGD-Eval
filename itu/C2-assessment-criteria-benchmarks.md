# ITU-T FG-TIDA CONTRIBUTION C2 — Assessment Criteria and Benchmarks for Trustworthy Agentic AI Systems
# ITU-T FG-TIDA 贡献稿 C2 — 可信代理 AI 系统的评估准则与基准

- **Contributor / 贡献方**：LGD-Eval（Independent Evaluation）
- **Corresponds to / 对应 ToR 条款**：ToR 3.4（Security assessment criteria and benchmarks）and 4.5（Guidelines, metrics and standardization recommendations）
- **Status / 状态**：Draft v0.1 for FG-TIDA consideration（供焦点组审议初稿）
- **Working language / 工作语言**：English（中文版随附供内部参考）
- **Date / 日期**：2026-10-14

---

## 1. Purpose and scope（目的与范围）

This contribution proposes **assessment criteria and benchmarks** for evaluating the trustworthiness and interoperability of human-and-agentic-AI trust and identity systems, in support of FG-TIDA objectives 3.4 and deliverable 4.5. It defines: what to measure（evaluation domains）, how to measure（methodology and evidence grading）, how to interpret（interpretation levels）, and how to keep conclusions defensible（standards mapping and reproducibility）.

本贡献为 FG-TIDA 目标 3.4 与交付物 4.5 提供一套可操作的评估准则与基准：明确测什么（评估域）、怎么测（方法与证据分级）、怎么解读（解读等级）、如何让结论站得住（标准映射与可复现）。

## 2. Evaluation domains（评估域 —— what to measure）

| Domain（评估域） | Covered characteristics（覆盖特性） |
|---|---|
| D1 Identity & registration（身份与注册） | Identity stack, attestation, delegation artefacts, agent discovery |
| D2 Trust lifecycle（信任生命周期） | Establishment, continuous evaluation, degradation, revocation evidence |
| D3 Security & resilience（安全与韧性） | Prompt-injection resistance, sandboxing, resource bounds, recovery |
| D4 Privacy & data governance（隐私与数据） | Data minimisation, zero-exfil, retention, consent |
| D5 Human oversight & accountability（人类监督与问责） | Escalation triggers, sign-off authority, audit trail, traceability |
| D6 Interoperability（互操作性） | Cross-border/heterogeneous trust establishment, machine-readable exchange |

Each domain is scored **domain-level only**（域级独立评分）；**composite scores are prohibited** to avoid masking trade-offs（禁止复合分，避免掩盖权衡）。

## 3. Methodology（方法学 —— how to measure）

- **Evidence-first（证据优先）**：conclusions must be backed by reproducible work-products（scripts, logs, hashes, timestamps）；automated output alone is insufficient.
- **Evidence grading（证据分级，GRADE 适配）**：V（Verified/reproduced）＞ S（Strong method）＞ M（Moderate）＞ L（Limited）＞ P（Pending）— interpretation wording is capped by the evidence level.
- **Bias controls（偏倚控制）**：multi-judge + human anchoring, AB/BA ordering, inter-rater agreement（κ）, no judge edits the evaluated subject（不自查原则）.
- **Domain-level risk-of-bias assessment（域级偏倚评估）** aligned with QUADAS principles.

## 4. Interpretation levels（解读等级 —— how to interpret）

| Level（等级） | Meaning（含义） | Evidence required（所需证据） |
|---|---|---|
| Verified（确证） | Claim reproduced independently（已独立复现） | Full reproduction kit + hash/timestamp |
| Strong（强证据） | Converging method-level evidence（多方法收敛） | ≥2 independent methods agree |
| Moderate（中等） | Plausible with partial evidence（有部分证据支持） | Partial reproduction or single method |
| Limited（有限） | Anecdotal or single-source（零散/单一来源） | Observation only |
| Pending（待定） | Claim not yet testable（尚不可判定） | Explicit scope statement |

## 5. Standards mapping（标准映射 —— 让结论可辩护）

Findings map to recognised standards for cross-verification（发现须映射公认标准以便交叉验证）：

- OWASP LLM Top 10（LLM01-LLM10）／OWASP Agentic AI Top 10（AAT-1-10）／OWASP LLMSVS v2.0（V1-V8, L1-L3）
- NIST AI RMF（Govern/Map/Measure/Manage）· NIST CSF 2.0
- ISO/IEC 42001（AI management）· 23894（risk）· 42005（impact assessment）
- EU AI Act risk tiers（limited/high-risk）
- MITRE ATLAS（adversarial tactics for AI systems）

## 6. Reproducibility protocol（可复现协议）

1. **Open rubric**（公开评分细则）：criteria and weights published in advance（已公开）。
2. **Evidence appendix**（证据附录）：every report ships reproduction kit + hashes（+ .ots timestamps）。
3. **Response rights**（回应权）：evaluated party gets 14-day response window and 24h factual corrections（被评方 14 天回应期 + 24h 事实更正）。
4. **Machine-readable output**（机器可读输出）：results available in JSON / schema.org-compatible metadata for automated trust decisions（对接 4.4）.

## 7. Provenance（来源与可验证性）

- Methodology is derived from the LGD-Eval authority interpretation guidelines（公开仓 evaluation-protocol, with theory matrix covering LGD doctrines: evidence-gated lifecycle, silent-failure detection, three-law audit, non-self-review）.
- Reference implementations: skill-audit scanner（mojibake/unicode/poisoning detection, adversarial-tested 9/9）; silent-failure-catalog（14 modes with runnable reproductions）; 109-repo evaluation pipeline（full-coverage, evidence-per-repo, 57 py_compile 57/57 pass）.
- All tools are open and re-runnable; independent verification welcomed（supporter posture）.

## 8. Requested action（请焦点组考虑）

1. Consider the domain list（D1-D6）and evidence-graded interpretation as input to deliverable 4.5 metrics.
2. Adopt the "no composite score / domain-level only" discipline to keep benchmarks comparable across ecosystems.
3. Offer the contributor to run pilot assessments on open-source agent frameworks（A.1.8 gap analysis）as benchmark data for the FG.

---

*Submitted in a supporter role; adoption decision rests with FG-TIDA consensus.*
*以支持者身份提交；是否采纳由焦点组共识决定。*
