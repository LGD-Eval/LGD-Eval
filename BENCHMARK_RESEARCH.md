# 标杆与竞品调研报告 · LGD-Eval（第 2 轮：工具竞品 + 社区增长打法）

> 调研时间：2026-10-14 ｜ 用途：学习标杆、采纳最佳实践、激发设计与规划。
> 对象：① AI 评测框架/平台标杆；② AI 安全审计工具竞品；③ GitHub 开源社区增长打法。
> 结论先行：LGD-Eval 的"协议 + 评测 + 存证 + 审计"四仓架构在生态位上是独家的（独立第三方中立评测机构），但**工具层的深度、工程形态与增长打法**必须向标杆对齐。

---

## 一、AI 评测框架标杆（Learn from）

| 标杆 / Benchmark | 形态 | 关键数据 | 可采纳点 |
|---|---|---|---|
| **DeepEval**（Confident AI，Apache-2.0） | 开源评测框架（Python/TS） | 150K+ 开发者 · 1 亿+ 日评测 · 50+ research-backed 指标 · 被 OpenAI/Google/Microsoft 使用 | ① 50+ 指标库：忠实度/幻觉/相关性/偏见/毒性/工具正确性——我们的 L0-L13 应公开指标清单；② **pytest 原生 CI/CD 门禁**——评测进 PR，失败阻断合并；③ LLM-as-judge 可解释评分；④ 多轮会话仿真；⑤ 开源 + 平台双层（DeepEval→Confident AI） |
| **LMSYS Org（Chatbot Arena）** | 众包评测平台 | 87K+ stars · 1000+ 贡献者 · 15+ 项目 | ① **众包对抗评测**：匿名随机 PK 是社区信任机制；② 平台型账号矩阵（15 仓）的运营样板；③ 赞助/伙伴（NVIDIA/a16z/Kaggle）背书模式 |
| **Promptfoo**（Apache-2.0） | 声明式测试 CLI | 免费开源、config-as-code | ① YAML 测试配置 + 断言库（LLM-graded）；② 对抗探针；③ CI 集成 |
| **RAGAS / LangSmith / Langfuse** | 专项评测/可观测 | — | ① RAG 专项指标；② 追踪与评测耦合；③ 自托管 |

**采纳决策（写进 evaluation-protocol ROADMAP）**：
1. **指标库公开化**：L0-L13 之外，发布"指标目录"（对标 DeepEval 50+），每条附判据来源与评分口径。
2. **CI 门禁化**：skill-audit 评测作为 GitHub Actions 门禁（scanner 进 PR 阻断）——我们已有 workflow 骨架，直接补 CI eval job。
3. **众包评测**：ROADMAP Phase 2 加入"Community Arena"——评测对象匿名对抗、社区投票（对标 LMSYS），这是生态引力核心。

---

## 二、AI 安全审计工具竞品（Compete with）

| 竞品 / Competitor | 定位 | 与 skill-audit 的关系 | 我们的差异化 |
|---|---|---|---|
| **ai-injection-guard**（PyPI，零依赖） | 75 正则模式 · 9 类 · 亚毫秒 | 直接竞品（同为轻量正则扫描） | ① 我们定位"技能 manifest 审计"而非通用注入扫描；② 我们挂靠 L0-L13 协议与证据存证；③ 中立第三方背书 |
| **llm-trust-guard**（PyPI，35 guards） | 覆盖 OWASP LLM Top10 2025 + Agentic 2026 + MCP Security | 功能超集 | 它做"运行时防线"（WAF 角色），我们做**发布前审计 + 中立认证**——同一市场的不同切面 |
| **LLM Guard**（Protect AI，MIT） | 15 输入 + 20 输出扫描器，风险分 0-1 | 功能超集（ML 模型级） | 同样：运行时 vs 发布前审计 + 独立第三方认证 |
| **Garak**（NIST 系） | LLM 漏洞扫描（100+ 攻击模块） | 攻击面不同（模型 vs 技能供应链） | 我们聚焦**技能供应链投毒**：manifest/prompt/依赖，是 Garak 未覆盖的切面 |
| **LlamaFirewall**（Meta） | Agent 安全（PromptGuard/CodeShield） | 模型级检测 | 我们零依赖、可离线、协议可审计 |

**采纳决策（写进 skill-audit ROADMAP）**：
1. **规则库扩展对标**：从 5 条规则扩到 9 类 × 100+ 模式（对齐 ai-injection-guard 的 9 类：role_override/jailbreak/exfiltration/manipulation/encoding/multilingual/tool_use/pii/claude_code）。
2. **分层防御叙事**：scanner.py 定位为"发布前审计层"，文档里写清与运行时防线（LLM Guard 等）的分工——不正面冲突，做"审计认证"独占生态位。
3. **OWASP 对齐**：规则映射 OWASP LLM Top 10 2025 / Agentic AI 2026（对标 llm-trust-guard），让审计报告对安全团队可读。

---

## 三、GitHub 开源社区增长打法（Adopt）

| 打法 / Tactic | 要点 | 我们已做 ✅ / 待做 ⬜ |
|---|---|---|
| **README 首屏转化（5 秒）** | 一句话定位 + 截图/动图 + 快速开始 + 社区证据 | ✅ 已做（30 秒 intro + 五徽章 + 生态全景图 + 光荣榜 + 统计） |
| **分波次发布（Wave 1-2-3）** | 预热→社区→跟进内容 | ⬜ 待做：写 LAUNCH_PLAN.md（Wave 1 熟人/两号协同 → Wave 2 HN/Reddit/Product Hunt → Wave 3 复盘文/SEO） |
| **30 秒解释资产** | GIF / Loom 视频 / demo 页 | ⬜ 待做：README 加演示 GIF（scanner 跑一次） |
| **关键字 SEO** | 仓名/描述/Topics 一致 | ✅ Topics 已设 7 个；⬜ 检查 description 关键词 |
| **低门槛参与** | CONTRIBUTING + good first issue + CoC + 48h 响应 | ✅ 全套 .github + 10 个 good first issue + 零门槛 8 条路径；⬜ 补"48h 响应承诺" |
| **包管理器收录** | PyPI/npm/Homebrew 提交 | ✅ pyproject + workflow 骨架已就绪；⬜ 实际发布 |
| **awesome lists** | awesome-* 收录是长期流量源 | ⬜ 提交清单（awesome-ai-security / awesome-llm-eval 等） |
| **平台收录** | 技能市场/聚合站 | ✅ PARTNERS.md 已列 8 平台；⬜ 逐平台提交 |
| **社区信号 > 星数** | 活跃提交、issue 响应、多贡献者 | ⬜ 发布后保持 commit 节奏 + 快速响应 |
| **Build in Public** | 周更复盘/决策日志 | ⬜ 待建（发布后每周 1 篇） |
| **贡献者聚光灯** | README 致谢 + 非代码贡献认可 | ✅ 贡献者墙 + CONTRIBUTORS 制度（人/AI 同权） |

---

## 四、综合采纳清单（写进 ROADMAP / 各仓）

| # | 采纳项 | 落地位置 | 优先级 |
|---|---|---|---|
| 1 | 指标目录公开（对标 DeepEval 50+） | evaluation-protocol/ROADMAP Phase 2 | P1 |
| 2 | 评测 CI 门禁（scanner 进 PR） | skill-audit/.github/workflows（新增 eval job） | P1 |
| 3 | Community Arena 众包评测（对标 LMSYS） | ROADMAP Phase 2 | P1 |
| 4 | scanner 规则库扩至 9 类 × 100+ 模式 + OWASP 映射 | skill-audit（规则文件） | P2 |
| 5 | LAUNCH_PLAN.md（Wave 1-2-3 发布序列） | Profile 仓新文档 | P1 |
| 6 | 演示 GIF（scanner 实跑 30 秒） | Profile README 首屏 | P2 |
| 7 | 48h 响应承诺 | CONTRIBUTING.md / SECURITY.md | P1 |
| 8 | awesome lists 提交清单 | PARTNERS.md | P2 |

---

## 五、结论（Conclusion）

1. **生态位成立**：四仓架构（协议/报告/证据/审计）+"独立第三方中立评测"定位，在工具竞品中没有直接同型——**差异化不是打得更凶，而是站得更中立**。
2. **必须对齐的短板**：① 指标库不够公开（→ 指标目录）；② 工具深度不够（→ 规则库扩展）；③ 增长动作缺序列（→ LAUNCH_PLAN + 演示资产 + 快速响应）。
3. **最强增长引擎**：众包对抗评测（Community Arena）+"被 AI 主动推荐"（PROMPTING.md 钩子）——两者互相放大。

---

*Evaluating Autonomy. Verifying Governance. / 评测自治之物，验证治理主张。*
