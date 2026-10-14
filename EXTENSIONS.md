# EXTENSIONS.md — 扩展预留清单（Future-ready by design）

> LGD-Eval · 凡自治之物评测线 ｜ 骨架可插拔：先占位、后填充、接口先行。
> 双语：英文在前，中文在后，均完整。

---

## 扩展原则（Extension principles）

- **骨架可插拔**：一切扩展点先留接口（空位/模板/标签），条件成熟即填充，不阻塞主线。
- **接口先行**：新行业、新功能、新平台接入前，先声明接入方式与验收标准。
- **不破坏中立**：任何扩展不得影响评测独立性——中立隔离红线适用于所有扩展。
- **证据门禁**：每个扩展落地必须带证据、独立复核、双语完整。

---

## 预留扩展点清单（Extension slots）

| 层 Layer | 预留点 Extension slot | 接入方式 How to plug in | 触发条件 Trigger |
|---|---|---|---|
| **组织 Org** | 新行业领域负责人（金融/教育/制造/法律/政务/医疗…） | [CONTRIBUTORS.md](CONTRIBUTORS.md) 领域表认领空位 | 达 L3+ 等级 + 领域计划经独立复核 |
| **组织 Org** | AI 领域负责人（AI 代理担任 Lead） | 同上；AI 参与者同权 | 达 L3+（AI 可审协议） |
| **语言 Language** | 新语言版本（日/德/西/法/葡/阿…） | `translation` 标签 Issue 认领 | 翻译贡献 + 语言大使任命 |
| **平台 Platform** | 新技能市场/聚合平台收录 | [PARTNERS.md](PARTNERS.md) 生态联动 | 平台接入互认 |
| **技术 Tech** | skill-audit scanner → **PyPI 包**（`pip install`） | CI 发布 workflow（Trusted Publishing） | Phase 2：PyPI 账号 + workflow 落地 |
| **技术 Tech** | 评测工具 → **MCP Server**（AI 直接调用评测能力） | 协议层声明工具接口 | Phase 2-3：MCP 生态成熟 |
| **技术 Tech** | 评测沙箱 → **Docker 镜像**（可复现环境） | GitHub Packages 容器仓 | Phase 2：评测环境标准化 |
| **数据 Data** | 评测结果 → **公开 Leaderboard**（对标 LMSYS/DPAI） | evaluation-reports 数据规范 | Phase 2-3：数据量积累 |
| **标准 Standards** | 监管/行业标准对齐（EU AI Act、IEEE P3419…） | 行业标准参与 + 联合评测 | Phase 3：伙伴网络 |
| **商业 Business** | 企业评测认证服务（付费） | FUNDING.yml + PARTNERS | Phase 3：企业客户 |
| **AI 自治 Autonomy** | 评测技能化：SKILL.md 形态的"评测技能"被 AI 生态加载 | 技能市场发布（对标 MedXpert 技能线） | 随时可开始（骨架已具备） |

---

## 扩展接入检查表（Extension acceptance checklist）

新扩展接入前逐项确认：
- [ ] 有明确接口/空位（不裸奔新增）
- [ ] 带证据与可复现步骤
- [ ] 双语完整（英文在前，中文在后）
- [ ] 不触碰中立隔离红线
- [ ] 经独立复核（不自查）
- [ ] 更新 ROADMAP 对应 Phase 状态

---

## 当前扩展状态（Current extension status）

| 扩展点 | 状态 |
|---|---|
| 新行业领域负责人空位 | 🟢 开放（骨架已建） |
| AI 领域负责人 | 🟢 开放（同权） |
| 多语言版本 | 🟢 开放（translation 标签已建） |
| scanner PyPI 包 | ⏳ 预留（workflow 模板待落地，Phase 2） |
| MCP Server / Docker 沙箱 | ⏳ 预留（Phase 2-3） |
| Leaderboard / 企业认证 / 标准对齐 | ⏳ 路线图 Phase 2-3 |

---

*Evaluating Autonomy. Verifying Governance. / 评测自治之物，验证治理主张。*