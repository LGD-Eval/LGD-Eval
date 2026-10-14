# THEORY ACCOUNT 109-REPO IMPROVEMENT LIST — 理论号 109 仓整改清单
# 理论号 109 仓整改清单（基于 LGD-Eval 全量评测 2026-10-14 · 让评测落地为行动）

> 来源：LGD-Eval 理论号全量评测报告（109/109、均分 71.34）＋ 评测明细表.csv ｜ 状态：待理论号执行；评测号按 R 编号复评验收
> 依据：IMPROVEMENT_RECOMMENDATIONS.md（五要素规范）｜ 优先级：P0 ≤7天 / P1 ≤1月 / P2 ≤1季度
> 说明：本清单为内部整改执行表；逐项整改后申请复评，得分变化将记录在案。

---

## P0 — 立即整改（≤7 天）

| R# | 问题（证据） | 涉及仓 | 整改动作 | 验收标准 |
|---|---|---|---|---|
| R-003 | 许可声明与 GitHub SPDX 识别不一致（README 自称 Apache-2.0/CC0，GitHub 判 NOASSERTION/MIT） | medical-device-reg-expert、medxpert-library-connector、medxpert-reg-connector、medxpert-registration-ops、medxpert-standards-connector、content-publish-ops-swarm-skill、claude-skills-directory | 提交与声明匹配的标准 LICENSE 文件；统一 README 声明 | GitHub license 端点返回 SPDX id 且与 README 声明一致 |
| R-004 | 占位/半成品残留（冒充成品风险） | Nomos（`{THEORY_DOC_URL}`）、nomos-ai（"占位"目录）、krites-eval（2 处占位）、sec2-provenance、didaskalos、logos-ambassador | 清理占位文本/目录；未完成项明确标注 WIP 与完成度 | 全仓无占位占位符；README 明示 WIP 状态 |
| R-005 | 知识库仓无 README.md（readme 端点 404，仅"00-知识库总导航.md"） | medxpert-ai-gov-kb、medxpert-voice-kb | 各补真实 README.md 落地页（双语，含入口导航） | readme 端点 200，README 双语完整 |
| R-007 | homepage 缺失/失效（仅 32/109 设置） | aws-agents-for-humans（404）、claude-skills-directory（指上游）、其余未设仓 | 设置有效 homepage；失效链接修复 | homepage HTTP 200 且指向本仓内容 |

## P1 — 一个发布周期（≤1 月）

| R# | 问题（证据） | 涉及仓 | 整改动作 | 验收标准 |
|---|---|---|---|---|
| R-001 | 双语覆盖仅 30/109（27.5%）：54 仓非双语、23 仓单语 | 全部旗舰 + 头部仓（见右侧） | 发布共享双语模板；旗舰仓先行转双语：lgd-theory、uibc-core、credential-vault-design、silent-failure-catalog、medxpert-llm-library、medxpert-skills、authz-code-design、fingerprint-delivery、agent-skills、uibc-competition、lgd-hub、lgd-glossary、xlgd、LGD | 双语覆盖 ≥60%；旗舰仓 100% 双语（英前中后均完整） |
| R-002 | AGENTS.md 仅 8/109（7.3%）——AI 友好主信号缺失 | 19 个核心理论仓 + 头部工具链仓 | 各补实质 AGENTS.md（参考 lgd-theory/AGENTS.md 模板） | 核心理论仓 100% 有 AGENTS.md；头部工具链 ≥60% |
| R-006 | CONTRIBUTING.md 仅 12/109（11%） | 旗舰仓（5 满分 + uibc-core + fingerprint-delivery） | 补 CONTRIBUTING.md（含贡献流程与署名规则） | 旗舰仓 100% 有 CONTRIBUTING |
| R-008 | 模板薄微仓 ~43 个（5-20KB 近似模板，7KB 同类仓成串） | cross-session-passphrase、data-scientist、debug-pro、todo-tracker、reminder、summarize-file 等 | 每仓加独特可运行示例/证据；或按主题合并去重 | 无"占位模板"仓；每仓有独特内容或明确并入说明 |

## P2 — 持续改进（≤1 季度）

| R# | 问题（证据） | 涉及仓 | 整改动作 | 验收标准 |
|---|---|---|---|---|
| R-009 | `__pycache__/` 等缓存文件入库 | medxpert-library-connector、medxpert-standards-connector | 加 .gitignore；清理缓存文件 | 根目录无 __pycache__ |
| R-010 | README 引用缺失文件 | medical-device-reg-translator（引用 server.py 但根目录无此文件） | 补文件或改文档引用 | README 引用文件存在或文档更正 |
| R-011 | 格式/卫生问题 | medxpert-registration-ops（空行格式错乱） | 修复格式；统一排版 | 格式规范、无异常空行 |
| R-012 | Profile 三角导航缺失（对外互链） | zhaoxinghua09-cell Profile、zhaoxinghua09-cell.github.io（1KB 占位） | Profile 与 github.io 补 LGD-Eval 链接；homepage 仓增厚 | 三号互链可见；github.io 非占位 |
| R-013 | 评测分流链接缺失 | lgd-theory、lgd-hub、lgd-glossary、uibc-core、uibc-competition、LGD、Nomos、nomos-ai、xlgd、xcgs-manifesto ＋ 5 满分仓 | README 加"评测分流链接"块；满分仓加"LGD-Eval 已评测"徽章位 | 10 仓 README 含评测链接；5 满分仓有徽章位 |
| R-014 | 知识库正文深读未覆盖（评测未读部分） | fhir（800MB 镜像）、agent-skills 深目录、synomos-ai-skills、MinisSkills 等 | 对重大仓安排专项深测 | 专项报告产出 |

---

## 复评机制

- 整改完成后（按 R 编号逐项），由评测号复跑同方法（L0-L13 + 同一评分细则），产出复评对照表：`上轮得分 → 本轮得分 → 变化原因`。
- P0 项到期未整改：评测号主动安排复评并在报告"回应与更正记录"注明。
- 采纳率与得分提升将计入评测档案（"评测的意义可度量"）。

---

*Evaluating Autonomy. Verifying Governance. / 评测自治之物，验证治理主张。*
