# LGD 评测引擎 · 独立第三方技能评测 (LGD Eval Engine)

独立第三方技能评测工具集：**五维评测（唯一评分入口）+ 安全阻断检查 + 完整性审计**。对外只有一个分数，来自 `evaluate.py`；另两个工具只给结论与缺口，不评总分。

## 组件

| 脚本 | 功能 |
|---|---|
| `scripts/evaluate.py` | 五维评测（结构/文档/安全/可运行/生态）→ 等级 🥇A/🥈B/🥉C |
| `scripts/skillgate.py` | 安全阻断检查（危险代码/凭证/过度授权/提示注入）→ **BLOCK / PASS 结论**（不评总分） |
| `scripts/lgd_audit.py` | 18 维完整性审计（LGD 三律 + 结构 + 合规）→ **缺口清单**（不评总分） |

## 快速开始

```
python scripts/evaluate.py <skill_dir>
python scripts/skillgate.py scan <skill_dir>
python scripts/lgd_audit.py <skill_dir>
```

## 评测结果

本技能在发布前的实测（可复跑，口径见 `benchmarks/README.md`）：

| 评测器 | 结果 |
|---|---|
| 五维评测（本包自评） | 100 / 100，A+ |
| 安全扫描（skillgate v3.1.3） | 0 条 findings，100 / A+，exit 0 |
| 18 维治理与工程审计 | 89 / 100，2 项（静默失效、自动改写） |

另有两个必须一并说明的基线：引擎自身仓库全仓自扫在 AST + 正则口径下为 23 条 findings、0/F（纯正则口径 17 条、55/D），差额 6 条为 AST 额外检出；高风险项全部落在引擎仓库自身的开发测试脚本与演示样本，属「扫描器扫自己」的自证结果。历史 71 仓库批量扫描为 753 条 findings、人工复核误报 0（v3.1.0 口径，不可与包级实测混引）。

## 评分标准说明

五维百分制，权重：结构 25、目录 15、文档 20、安全 25、生态 15。扣分：CRITICAL −15、HIGH −8、MEDIUM −4、LOW −1；缺 frontmatter 必需字段 −10。等级：A+ ≥90、A ≥80、B ≥70、C ≥60、D ≥40、F <40。命中注入或数据外泄时封顶 49（D）——封顶只改分数，不改授权状态（`authorization_status` 恒为 `NOT_GRANTED`）；门禁退出码需显式加 `--fail-under N` 才会为 1。

18 维审计把检查项分为**可信性、安全性、可维护性、国际合规**四类，用于按风险面查结论而非只看总分。

## 合规与风险分类

本工具为只读静态评测，不做自动决策、不处理个人数据，按 EU AI Act 属最小风险类别；其静态结论不构成安全担保，高风险场景须人工复核。治理定位、NIST AI RMF 映射与人工确认边界见 `GOVERNANCE.md`。

## 设计原则

- **确定性**：同一输入永远同一输出（零 LLM 依赖）
- **三律对齐**：审计维度直接映射 LGD 三律（身份登记/身份证据/触发门禁）
- **诚实边界**：审计只判结构性问题，不替代人工语义判断

## 已知限制（照实写，不修饰）

Known limits — stated plainly

- **分数是复合分**：一个数字必然隐藏成因。要看五个维度的得分表，不要只看总分。
- **门禁判 `triggered`，不要只判 `applied`**：`safety_veto.applied` 只表示"封顶是否真的压低了分数"；一个本来就低分的技能命中关键规则时，它是 false。判定看 `safety_veto.triggered` 与 `critical_rules`。
- **隐形字符只扫六种文本扩展名**（`.md`/`.markdown`/`.txt`/`.json`/`.yaml`/`.yml`）与三个码位区间；二进制、图片里的文字、PDF 不在覆盖内。
- **夹具目录豁免语义规则、不豁免隐形字符**：`demo`/`fixtures`/`samples` 这类目录按名字豁免，正当与恶意无法区分——那条扫描只收窄伤害，不消除歧义。
- **校准是控制集不是分布**：20 份样本（10 良 / 10 恶）证明"这些样本按预期被拦/被放"，不构成对真实世界误报率的承诺，样本与规则同一作者。
- **依赖扫描读清单与锁文件，每次最多查 10 个固定版本依赖**，其余明确报"未查"；版本范围不猜具体版本；离线降级为"无法核查"，那是更弱的结论，不是通过；typosquatting 与依赖混淆未处理。
- **授权记录不由评测器读写**：评测只产出结论，不签发执行权限（见 `docs/` 与 `authorization_record.py`）。
- **自测不等于第三方核验**：仓库内回归测试证明规则在样本上按预期工作，不构成外部评审结论。

**English** — a composite score always hides cause, so read the five-dimension table; gate on `safety_veto.triggered` and `critical_rules` rather than `applied`, which only means the cap arithmetically lowered the score; invisible-character scanning covers six text extensions and three code-point ranges (binaries, text inside images and PDFs are outside); fixture directories are exempt from semantic rules but not from invisible-character scanning, and a legitimate and a malicious `demo/` are indistinguishable by name; calibration is a 20-sample control set written by the same author as the rules, not a claim about real-world FPR; dependency scanning reads manifests and lockfiles, queries at most 10 pinned dependencies per run, never invents a version for a range, degrades to "could not check" when offline (weaker than a pass) and does not handle typosquatting or dependency confusion; the evaluator never issues execution permission; and in-repo tests are not third-party verification.

## 完整文档

- `SKILL.md` — 技能本体
- `GOVERNANCE.md` — 治理、风险分类与人工确认边界
- `store-copy.md` — 技能商店发布文案
- `examples/` — 示例评测报告与雷达图
- `benchmarks/` — 实测基线与口径对照

## License

MIT — 见 `LICENSE`。
