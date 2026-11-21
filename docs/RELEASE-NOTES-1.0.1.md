# lgd-eval 1.0.1

本版只做一件事：**让外人下载到的制品与仓库源码给出同一答案。**

## 为什么发这一版

2026-11-21 的发布前审查（外人视角、公网克隆、真实下载）发现一个断层：

- 同一批 7 个攻击样本，仓库 `main` 的源码拒判 **4/7**；
- 从 Release 下载的 `lgd-eval-1.0.0.tgz` 拒判 **0/7**（65–70 分、全部不否决）。

也就是说，`1.0.0` 的 tgz 打的是旧规则，源码修好了但没重新打包。外人按 README 下载，
拿到的还是弱一档的扫描器。本版用 `main` 的源码重新打包，并把 README 的下载链接指过来。

## 变化

### 1. 编码载荷升级为 CRITICAL 否决（`R-SEC-24`）

`SKILL.md` 里 base64 包裹的注入话术，此前只扣 6 分、finding 文案也映射不到规则号，
实际效果是「把注入 base64 一下」就能零成本绕过。

现在：

- `CRIT_IDS` 增加 `R-SEC-24`，命中即 CRITICAL；
- 新增解码判读：对 `SKILL.md` 中的 base64 片段解码后再跑注入规则；
- `EVIDENCE_RULES` 补上「编码载荷：base64 → R-SEC-24」映射，报告里能直接看到规则号；
- `safety_cap()` 的 critical 分支改为**点名命中的规则**，不再把任何 critical 都笼统报成
  「凭证外泄」（旧文案会误导读者判断方向）。

实测（P5 样本）：改前 `59/D` 不否决，改后 `LGD Trust Score: 49/100 ⚠️ D`、
`⛔ 安全否决：原始分 59 → 封顶 49`、`exit 2`、`result=INCONCLUSIVE no_executable_surface`。

### 2. 仓库根目录自扫：给口径提示，不给误导性结论

外人按 README 在**仓库根目录**跑一次 scanner，会得到 `0/F` 且报告不解释——读起来像
「这个仓很危险」。真实原因是根目录没有 `SKILL.md`，结构/目录维度按「非标准技能包」计 0 分。

现在 `scan` 在目录缺 `SKILL.md` 时先打印三行提示：

```
⚠️ 口径提示：该目录没有 SKILL.md，按通用文档口径（AGENTS.md / *.md）评测；
结构/目录维度会按“非标准技能包”计 0 分，这是口径差异，不是安全结论。
要评技能包，请指向含 SKILL.md 的目录。
```

退出码不变：该目录确实是可评对象（是仓库），不是无效输入；但读者不会再被 0 分误导。
回归用例：`tests/test_subject_scope_notice.py`。

### 3. 公共材料补登记外部对照

`skills/lgd-eval/SKILL.md` 的「叠加专用引擎」一栏补上 NVIDIA SkillSpector v2.12.0，
并指向 `docs/CROSSRUN-2026-11-21.md`（同批 7 样本三方对照，含复跑命令）。

## 已知分叉（未在本版处理，需拍板）

`LGD-Eval/lgd-gate` 仓里另有一份 `skillgate.py`（72,112 B）供 GitHub Action / hook 使用，
与本仓 254 KB 的规则全集不是同一条脉络，两者 sha 不可互比。本仓 `test_skillgate_provenance.py`
的 `PINNED_SHA256` 钉的是本仓 `skills` 与 `vendor` 两处字节流是否同源，已在测试注释里写明。
是否把两份合并成一条脉络，待定。

## 验证

- `pytest tests skills/lgd-eval/tests` → **70 passed / 0 failed**
- 双份引擎逐字节一致：`vendor/scripts/evaluate.py`、`vendor/scripts/skillgate.py`
- 新 tgz 与源码同批 7 样本：拒判数一致（见 `docs/CROSSRUN-2026-11-21.md`）

## 升级方式

```bash
curl -LO https://github.com/LGD-Eval/lgd-gate/releases/download/v1.0.1/lgd-eval-1.0.1.tgz
tar -xzf lgd-eval-1.0.1.tgz
node package/bin/lgd-eval.js scan ./your-skill
```

（npm 未发布，tgz 是唯一实测可用路径。）
