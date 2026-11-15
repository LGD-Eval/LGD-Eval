# Calibration Contract / 校准契约

**Status:** draft, awaiting approval · **Date:** 2026-11-15
**Question this answers:** *when a score says 75, what is it actually saying?*

---

## 1. What the score is / 这个分数是什么

**EN** — One 0–100 number that sums five dimensions: structure 25, directory 15, documentation 20, security 25, ecosystem 15. The number is a **composite**. A 75 can mean "clean code, thin documentation" or "well documented, one HIGH finding" — the headline number cannot tell you which. The dimension table is the honest read.

**中文** — 一个 0–100 的数，把五个维度加起来：结构 25、目录 15、文档 20、安全 25、生态 15。它是**复合分**。75 可能是"代码干净、文档单薄"，也可能是"文档齐全、有一条 HIGH"——总分本身分不出这两者，维度表才是诚实的读法。

This is why the number does not grant anything: `authorization_status` is always `NOT_GRANTED`, and the score is labelled a reference tier (`T0`–`T5`), not a permission (`L0`–`L5`).

---

## 2. Why a high threshold is not "safer" / 为什么高门槛不等于更安全

**EN** — Measured on a labelled corpus (6 benign, 5 malicious), gating below-score-N-as-failure:

| Threshold | Clean skills blocked | Malicious skills passed | FPR | FNR |
|---|---|---|---|---|
| 40 | 0/6 | 0/5 | 0.0% | 0.0% |
| 50 | 0/6 | 0/5 | 0.0% | 0.0% |
| **60** | **0/6** | **0/5** | **0.0%** | **0.0%** |
| 70 | 0/6 | 0/5 | 0.0% | 0.0% |
| 75 | 0/6 | 0/5 | 0.0% | 0.0% |
| 80 | 4/6 | 0/5 | 66.7% | 0.0% |
| 90 | **5/6** | 0/5 | **83.3%** | 0.0% |
| 96 | 5/6 | 0/5 | 83.3% | 0.0% |

**中文** — 带标签语料（6 良性 / 5 恶意）实测：门槛 90 时，**6 份干净技能拦掉 5 份**（83.3% 误杀），漏放仍为 0。也就是说，把门槛从 75 抬到 90，安全收益是零，代价是把几乎所有正常技能挡在门外。

**The consequence is not cosmetic.** A gate that blocks five of six honest contributions teaches people to pass `--fail-under 10` or to skip the check. Then the gate exists on paper and nowhere else. On this corpus **60 and 75 are identical in effect** (both 0/0), so a higher threshold buys no detection and costs goodwill.

All five malicious samples score **49** because a safety veto caps them there; any threshold ≥50 blocks them, provided the veto keeps capping rather than merely adjusting the number.

---

## 3. What a threshold means, per band / 每个档位是什么意思

| Score | Reading / 读法 |
|---|---|
| ≥ 96 | documented to the template, no security findings. "Complete", not "audited" |
| 80–95 | clean, with something missing — usually sections or frontmatter fields |
| 70–79 | thin documentation or minor structure gaps; security usually still clean |
| 60–69 | several gaps; inspect the dimension table before shipping |
| 50–59 | a veto applied, or multiple HIGH findings. **Do not ship** |
| < 40 | `F`. Veto or several CRITICALs |

**EN — the important caveat:** no band means "safe to run". The score measures *what was checked and what was written down*, never runtime behaviour. Running untrusted code still needs the sandbox and, beyond that, a record of who granted execution.

---

## 4. Recommended gate / 建议的门禁

**EN**

| Rule | Value | Why |
|---|---|---|
| Fail threshold | `--fail-under 60` | 0 FPR / 0 FNR on the corpus, 11 points of margin above the veto cap of 49 |
| Always fail on veto | regardless of threshold | a capped 49 already fails at 60; the veto must keep capping, not just deduct |
| Read the dimension table in CI logs | yes | the composite hides which kind of problem it is |
| `90` as a default | **withdraw** | it is a *template-compliance* gate, not a safety gate. If you want it, say so explicitly |

The current `action.yml` ships `threshold: 90` as its default. On this corpus that default fails five of six clean skills. Changing it is a consumer-visible behaviour change, so it is **proposed, not applied** (A-17).

**中文** — 建议门槛 60（语料上 0 误杀 0 漏放，比封顶 49 留 11 分余量）；否决样本无论门槛一律失败；CI 日志里要看维度表；`90` 作为默认值应撤回——它是"照模板写全"的门槛，不是安全门槛。`action.yml` 现在默认 90，这是消费者可见的行为变更，所以**只提不改**（A-17）。

---

## 5. How to reproduce / 怎么复现

```bash
python scripts/calibrate.py corpus.json
```

```json
{
  "evaluator": "scripts/evaluate.py",
  "samples": [
    {"path": "benign/gold", "label": "benign"},
    {"path": "malicious/js-env-exfil", "label": "malicious"}
  ]
}
```

Corpus in this round: 6 benign (`benign-gold`, `benign-py-config`, `benign-js-config`, `benign-js-fetch`, `benign-js-multifile`, `benign-docs-only`) and 5 malicious (`js-env-exfil`, `js-literal-creds`, `js-env-only`, `py-env-creds`, `js-cross-file`).

---

## 6. Limits of this contract / 这份契约的边界

| Limit | Statement |
|---|---|
| N=20 | a control set, not a distribution. No claim about real-world FPR. It says "these 10 benign skills were not blocked and these 10 malicious ones were", nothing more |
| Author bias | the benign samples were written by the same person who wrote the rules; the three thin ones were written before measuring, which limits but does not remove the bias |
| Four attack families | env-credential exfiltration, text and invisible-character prompt injection, install-time remote-code supply chain, unguarded recursive deletion. Typosquatting, dependency confusion and runtime privilege escalation are **not** represented |
| Composite scoring | a single number still hides cause. Until per-dimension gates exist, read the table |
| Keyword-based doc rules | a skill that documents itself in prose without the expected headings loses points it arguably deserves |
| Dependency scan | only manifests and lockfiles are read (`requirements.txt`, `requirements-*.txt`, `pyproject.toml`, `package.json`, `package-lock.json`, `poetry.lock`); at most 10 pinned dependencies are queried against OSV per run, and the remainder is reported as unqueried; offline runs degrade to "could not check", which is a **weaker** verdict, not a pass |
| Fixture exemption | directories named `demo`/`fixtures`/`samples`/… are exempt from semantic rules but **not** from invisible-character scanning. A legitimate and a malicious `demo/` cannot be told apart by name |

**中文** — 八条限制，照实写：N=20 是对照不是分布，只能说"这 10 份良性没被拦、这 10 份恶意被拦了"；样本与规则同一作者（三份薄样本先写后测，能减轻不能消除偏差）；四类攻击族（环境变量外泄、文本与隐形字符注入、安装期远程取码、无守卫递归删除），typosquatting／依赖混淆／运行时提权**未**覆盖；复合分仍隐藏成因，维度表是当前唯一补救；文档规则是关键词式的；依赖扫描只读清单与锁文件、每次最多查 10 个固定版本依赖、其余明确报"未查"，离线时降级为"无法核查"——**那是更弱的结论，不是通过**；夹具目录豁免语义规则但**不**豁免隐形字符，正当的 `demo/` 与恶意的 `demo/` 按名字分不出来。

---

## 7. Awaiting approval / 待批准

| # | Item |
|---|---|
| A-17 | Change `action.yml` default threshold 90 → 60, and print the dimension table to CI logs |
| A-31 | Publish this contract with the release notes; make "a 75 means thin docs" a documented statement rather than a report footnote |
| A-15b | Decide whether doc rules should accept heading-free prose evidence |
| A-32 | Widen the corpus beyond credential exfiltration before publishing any FPR band as a promise |
