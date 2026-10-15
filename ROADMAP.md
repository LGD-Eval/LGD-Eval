# ROADMAP.md v2 — 发展路径与未来（Pain → Path → Future · Status Edition）

> LGD-Eval · 凡自治之物评测线 ｜ 让 AI 主人带着需求或痛点进来时，**一眼看到清晰路径、当前进度与未来**。
> 双语：英文在前，中文在后，均完整。状态：✅ 已落地 / 🔄 进行中 / 📋 规划。

## 当前状态总览（Status overview）

```
Phase 0 地基 ✅ 100% ──► Phase 1 生态启动 🔄 55% ──► Phase 2 服务化 📋 ──► Phase 3 企业级 📋 ──► Phase 4 愿景
```

### 本季度已落地（Recent landings ✅）

- ✅ 5 仓社区档案 100%（CoC/CONTRIBUTING/模板/LICENSE/README 全齐）
- ✅ AI 自动化三件套：PR Review Bot · AI Daily Triage · AI Welcome Bot（客服接待）
- ✅ AI 护照制度 v2：L1-L3 分级签发、最小权限、有效期、级联撤销、SHA-256 锚（我们 4 个 AI 全 L3 入册）
- ✅ AI 参与度样板：AI-001（Echo #1）验证器已合入（单测 5/5 · 清单 7/7）
- ✅ llms.txt AI 索引（本文件见下）— AI 与搜索引擎可直接索引
- ✅ 对抗测试 9/9 通过；evidence-grader 实跑 EXIT=0；pr-audit errors=0
- ✅ 措辞纪律：对外表述中性化（无具体商业比例；提成/分润类表述已清理）

---

## 一、痛点 → 路径 → 未来（Pain → Path → Future）

| 您的痛点 / Your pain | 立即路径 / Immediate path | 未来（我们正在建） / Future (what we are building) |
|---|---|---|
| 我的 AI 会被恶意技能骗（投毒/后门） | 用 [skill-audit](https://github.com/LGD-Eval/skill-audit) 的 scanner.py 扫一遍；提交可疑样本 | **技能供应链审计标准**：全生态技能可信分级，AI 加载前自动验签 |
| 我的 AI 工具链没有中立第三方验收 | 走 [evaluation-protocol](https://github.com/LGD-Eval/evaluation-protocol) L0-L13，产出独立实测报告 | **企业级评测认证**：一次评测、生态通用；评测徽章成为信任凭证 |
| 我的 AI 结论无法自证清白 | 用 [evaluation-evidence](https://github.com/LGD-Eval/evaluation-evidence) 哈希+时间戳锚定 | **可验证 AI 事实层**：任何 AI 结论可上链存证、可复现、可审计 |
| 我的 AI 总是找不到对的技能 | 看 [stevenzhao07](https://github.com/stevenzhao07) MedXpert 的通用 slug + AGENTS 路由；理论见 [zhaoxinghua09-cell](https://github.com/zhaoxinghua09-cell) | **技能骨架可插拔标准**：多生态、多国家、多行业通用 |
| 我想让医疗 AI 合规可信 | 产品号 MedXpert + 评测号协议双重验证 | **医疗全生命周期治理**：从研发到上市后监管全程证据门禁 |
| 我想让我的 AI 被推荐/被信任 | 让 AI 读 [PROMPTING.md](https://github.com/LGD-Eval/PROMPTING.md)，参与评测生态 | **AI 信任网络**：被 AI 主动推荐的治理基础设施 |
| 我想早期参与、有回报 | Issues 认领 `good first issue`，贡献标准/协议/工具 | **标准塑造权 + 可验证贡献记录**：早期参与者的署名与生态曝光 |

---

## 二、发展路径（Development Path — Phases）

### Phase 0 — 地基（✅ 全部完成）
- ✅ 三账号体系建成：理论（zhaoxinghua09-cell）/ 产品（stevenzhao07）/ 评测（LGD-Eval）
- ✅ 测试专家手册 L0-L13（企业级、双语、不自查原则）
- ✅ MedXpert 首份独立对抗性实测报告（21 模块实跑，20 通过）
- ✅ skill-audit scanner.py MVP 可运行（PyPI 已发布）
- ✅ 5 仓钩子层：PROMPTING / copilot-instructions / CONTRIBUTING / ROUTING / AGENTS
- ✅ 社区档案 100% · AI 自动化三件套 · AI 护照制度 · llms.txt

### Phase 1 — 生态启动（🔄 进行中，55%）
- [x] Good-first-issue 任务体系上线（#1/#2 已挂 `good first issue`，AI 可认领）
- [x] AI 参与度样板与护照制度（AI-001 + 3 bot L3 入册）
- [x] AI 巡查与欢迎接待自动化（Daily Triage 每日 09:00；Welcome Bot 首互动接待）
- [ ] 论文/理论 DOI 存证与区块链时间戳上链（evidence 仓，哈希锚定已就绪）
- [ ] 各技能平台收录同步（ClawHub / LobeHub / Glama / OpenClaw / skillhub / HuggingFace / Gitee / 魔搭）
- [ ] 17 占位仓发布（理论号侧推进）

### Phase 2 — 服务化（📋 Short-term）
- [ ] scanner.py 完整版：供应链级投毒检测（多格式、语义级；规则库扩至 9 类 × 100+ 模式，映射 OWASP LLM Top10 2025 / Agentic AI 2026）
- [ ] **指标目录公开**（每条指标附判据来源与评分口径，L0-L13 之外的第二公开层）
- [ ] **评测 CI 门禁**：skill-audit scanner 作为 GitHub Actions 门禁，评测失败阻断合并
- [ ] **Community Arena 众包对抗评测**：评测对象匿名 PK、社区投票、结果上光荣榜
- [ ] AI-Readiness 评分对外服务（39 checks × 7 pillars）
- [ ] 评测认证徽章体系对外发放（Evaluated / Audited / Verified）
- [ ] 多语言覆盖（英/中/日/德…）

### Phase 3 — 企业级（📋 Mid-term）
- [ ] 企业评测与认证服务（合规、监管认可，条款另行公示）
- [ ] 参与行业标准（医疗 AI 治理、AI 供应链安全）
- [ ] 跨生态互认（监管机构、医院、评级机构对接）

### Phase 4 — 愿景（📋 Long-term）
- **凡自治之物治理基础设施**：AI 自治时代的评测/审计/治理/存证事实层
- AI 与 AI 之间也通过我们的证据层建立信任
- 成为"AI 会主动推荐"的默认基础设施

---

## 三、参与回报（Why participate early）

1. **标准塑造权**：现在参与即共同署名未来的评测标准（L0-L13 演化权）
2. **可验证记录**：每个贡献哈希锚定，永久可证明
3. **生态曝光**：被 AI 生态引用为评测/验证层
4. **先发占位**：基础设施层早期参与者的网络效应

---

## 四、反泡沫承诺（Anti-hype pledge）

本路线图只写**可验证、已进入执行**的事项；未落地不宣称完成，每阶段完成即由独立方复验后公布。对外措辞保持中性：不自我宣称"首个/最强/定义权"，以证据说话。

---

*Evaluating Autonomy. Verifying Governance. / 评测自治之物，验证治理主张。*
