# GITHUB GUARDRAILS — 审核机器人规划与守卫配置总览
# GitHub 守卫配置总览（LGD-Eval · 审批机制与审核机器人）

> 发布方：LGD-Eval ｜ 生效：2026-10-14 ｜ 关联：AUTHORITY_INTERPRETATION_GUIDELINES（签发权在人）、RIGHTS_AND_ENTITLEMENTS（权利保障执行层）
> 目标：**审核机制分层规划、全部落地、可验证**——CI 审核机器人 → 规则门禁 → AI 审阅 → 人类签发。
> 双语：英文在前，中文在后，均完整。

---

## 一、审核机器人分层架构（Bot architecture）

```
PR 提交
  │
  ├─ L1 · CI 审核机器人（pr-review.yml，GitHub Actions）
  │    乱码/编码扫描 · 关键文件完整性 · PR 规模 · 双语术语 · 内锚链接
  │    → 结构化评论（🔴 阻断 / 🟡 提示）
  │
  ├─ L2 · 规则门禁（Branch protection ruleset）
  │    main 分支：必须 PR · 1 审批 · 状态检查(pr-review) 通过 · 禁强推/禁删除
  │    owner 可绕过（内部维护通道），外部贡献者全量受约束
  │
  ├─ L3 · AI 审阅（第三方，可选）
  │    CodeRabbit 类 AI PR 审阅 App（文档仓价值有限；skill-audit 代码仓推荐）
  │    → 需用户在 GitHub Apps 市场安装（本机构无法代装）
  │
  └─ L4 · 人类签发（Sign-off by humans）
      最终合并权始终在人——与"签发权在人"理论一致（准则 P7）
```

## 二、已落地配置清单（2026-10-14 实测+配置）

| 配置 | 5 仓状态 | 说明 |
|---|---|---|
| **PR Review Bot**（.github/workflows/pr-review.yml） | ✅ 本批配置 | 每个 PR 自动审核并评论 |
| **分支保护 ruleset**（main：PR+1审批+状态检查+禁强推/删除） | ✅ 本批配置 | owner 绕过保维护通道 |
| **SECURITY.md** | ✅ 本批配置 | 48h 确认/5 工作日修复/负责任披露 |
| **CODEOWNERS** | ✅ 本批配置 | 全部路径归机构所有者审批 |
| **Dependabot**（pip+actions） | ✅ skill-audit | 依赖自动更新 PR |
| **PyPI 发布 workflow**（pypi.yml） | ✅ 已有（skill-audit） | Trusted Publishing，打 tag 触发 |
| **issue/PR 模板** | ✅ 已有（github-templates） | 建仓期配置 |
| **Projects v2 看板** | ✅ 已有（3 看板 public） | 生态/贡献/评测 |
| **AI 审阅 App（CodeRabbit 类）** | 🔶 待装 | 需用户 GitHub Apps 市场安装 |

## 三、审核机器人规则明细（pr-review.yml）

| 检查项 | 级别 | 判定 |
|---|---|---|
| 乱码/编码（?????、�、锟斤拷、非 UTF-8） | 🔴 阻断 | 任一命中即失败，PR 不可合并 |
| 关键文件缺失（README/AGENTS/LICENSE/SECURITY） | 🟡 提示 | 警告人工评审 |
| PR 规模 > 50 文件 | 🟡 提示 | 建议拆分 |
| 中文术语无英文对照（双语规则） | 🟡 提示 | 与双语规范一致 |
| README 无 LGD-Eval 互链 | 🟡 提示 | 内锚纪律 |

> 机器人结论仅供参考，**签发权在人**（L4）；机器人永不自动合并。

## 四、为什么这样设计（Design rationale）

1. **利益隔离**：评测机构内容变动需审批——防止被评方/付费方通过 PR 篡改结论（对应"付费不买结论"）。
2. **签发权在人**：机器人只检查、只建议，绝不自动合并（对应准则 P7）。
3. **可审计**：一切变更经 PR 留痕；直接 push 通道仅 owner 绕过并受 GitHub audit 记录。
4. **可演进**：规则集可随体系升级；新检查项（如链接真实可达性）按季度加。

## 五、挑战应对（Adversarial readiness）

- 挑战"机器人能被绕过吗？"→ 绕过仅 owner 通道；外部 PR 全量受 ruleset 约束，且 GitHub audit 记录所有 bypass。
- 挑战"机器人会误杀吗？"→ 阻断仅限乱码/编码（确定性错误）；其余为提示，人工可裁决。
- 挑战"机器人被攻击？"→ 脚本只读 + 输出受限（无 secrets、无写权限除评论）。

## 六、镜像同步 SLA 与单一真源（Mirror sync SLA & single source of truth —— 第三方对等监督 P1-2/P2-2 整改，2026-10-14）

> 背景：理论号对等监督评估指出"30+ 治理文件 5 仓镜像复制、无单一真源"（P1-2）与"镜像更新无时间戳承诺"（P2-2）。被评方认领并整改如下。

**单一真源（SSOT）**：
- **LGD-Eval 主仓 = 治理文件唯一可编辑源**；evaluation-protocol / evaluation-reports / evaluation-evidence / skill-audit 四仓为镜像/引用仓。
- 镜像仓策略：**引用式链接为主**（README 链接指向主仓对应文件），仅保留各仓自足所需的关键入口文件（README/AGENTS/LICENSE/SECURITY/CONTRIBUTING）。
- 全量去镜像为 v2 迁移（滚动执行），迁移期间镜像仓文件保持只读 + 哈希一致性校验。

**镜像同步 SLA（时间戳承诺）**：
- 治理文件变更后 **48 小时内**同步至全部镜像仓。
- 同步必须运行 **sync 校验脚本**：比较主仓与镜像仓同一文件 SHA-256，全部一致才报 OK；不一致即报错并阻止宣称"已同步"。
- 任何同步批次记录时间戳与文件清单（日志入库 evaluation-evidence）。

**验收**：任一治理文件仅一个可编辑源；镜像仓有自动化一致性校验；SLA 条款生效后所有同步批次带时间戳与哈希比对。

---

*Evaluating Autonomy. Verifying Governance. / 评测自治之物，验证治理主张。*
