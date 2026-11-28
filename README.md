> **LGD 生态入口** —— 从任一入口都能走到全部入口
>
> [官网 medxpert.cn](https://medxpert.cn/) · [评测门禁 lgd-gate](https://github.com/LGD-Eval/lgd-gate) · [npm 包 lgd-eval](https://github.com/LGD-Eval/lgd-eval) · [公开评分卡](https://github.com/LGD-Eval/evaluation-evidence/blob/main/scores.md) · [排行榜](https://github.com/LGD-Eval/evaluation-evidence/blob/main/LEADERBOARD.md) · [一行安装（免 VPN）](https://github.com/LGD-Eval/lgd-gate/releases/download/v1.0.1/lgd-eval-1.0.1.tgz)
>
> 三律：**有籍**（可追溯）· **有证**（有证据）· **有门禁**（有检查）

# lgd-eval

> 技能能不能上架，不由下载量决定，由五维分数和三律决定。

AI Agent 技能评测引擎。给任意技能目录打一个 0–100 的 Trust Score，同时判断它是否满足 LGD 三律（有籍 / 有证 / 有门禁），并输出**能被机器执行的整改清单**。

## 一行跑

```bash
# 方式 A（今天就能用）：从 Release 下 tgz，解包后运行 —— 这条路线已实测通过
#   https://github.com/LGD-Eval/lgd-gate/releases/download/v1.0.1/lgd-eval-1.0.1.tgz
# 方式 B（尚未发布）：npx lgd-eval —— 该包还没有发布到 npm registry，
#   现在请求 registry 的 `lgd-eval` 包元数据，返回 404，所以这条命令暂时会失败。
npx lgd-eval ./my-skill
```

> 诚实说明：`package.json` 里声明了 `name: lgd-eval` / `bin: lgd-eval`，但**没有发布**。
> 在没有发布之前跑 `npx` 会去 registry 拉一个不存在的包——所以我们把「能用的那条」写在前面。
> 发布属于对外动作，需要作者单独批准。

## 卡住不合格的 PR

```bash
npx lgd-eval ./my-skill --fail-under 90 --fix-json fix-plan.json
```

（同上：该命令依赖已发布的 npm 包。tgz 路线里用 `bin/lgd-eval.js` 直接运行即可。）

## 用 tgz 装完之后怎么跑（外人最常卡在这）

解包后你手上是一个 `package/` 目录，里面**没有 node_modules**，所以 `npx` 那条在这里跑不了。
**下面三条都在 tgz 所在的那层目录执行（不是 `package/` 里面）**：

```bash
# 在 tgz 所在目录（解包后出现 package/ 的那一层）
tar -xzf lgd-eval-<版本>.tgz
node package/bin/lgd-eval.js --version
# 把 ./my-skill 换成你自己的技能目录
node package/bin/lgd-eval.js ./my-skill
```

- 需要本机有 **Python 3**：`bin/lgd-eval.js` 只做启动器，打分在包内 `vendor/scripts/evaluate.py`；
- 分数 < 90 想直接卡 CI：`node package/bin/lgd-eval.js ./my-skill --fail-under 90`（退出码 1）；
- 看五维雷达：`node package/bin/lgd-eval.js ./my-skill --ascii`。

- 分数 < 90 → 退出码 1，CI 直接红
- `fix-plan.json` 里每一项都是「缺口 → 整改动作 → 可判定验收」，AI 或人改完再跑一次即闭环

## 输出是什么

```
Trust Score: 100/100
等级: 🏆 A+

<!-- CI-GATE-NOTE -->
> 这个分数不是手填的：`.github/workflows/auto-eval.yml` 每次推送到 main 都会实跑一遍，**低于 90 分直接让 CI 变红**。复跑：`python3 skills/lgd-eval/scripts/evaluate.py skills/lgd-eval`
<!-- /CI-GATE-NOTE -->

五维: 结构完整性(25) / 目录结构(15) / 文档质量(20) / 安全检查(25) / 生态兼容(15)

LGD 三律
  L1 有籍（档案可追溯）  ✅
  L2 有证（结论有证据）  ✅
  L3 有门禁（有检查）    ✅
```

## 评测与授权分离（分数不签发权限）

评测的终点是一个**风险结论**，不是一个权限决定。分数用来排优先级，授权必须另外授予：

| 分数 | 风险档位（参考） | authorization_status |
|---|---|---|
| ≥ 96 | T0 风险极低 | NOT_GRANTED |
| 81–95 | T1 风险低 | NOT_GRANTED |
| 51–80 | T2 风险中等 | NOT_GRANTED |
| 31–50 | T3 风险较高 | NOT_GRANTED |
| 11–30 | T4 风险高 | NOT_GRANTED |
| ≤ 10 | T5 风险极高 | NOT_GRANTED |

`authorization_status` 默认恒为 `NOT_GRANTED`，同时出现在终端输出与 `--evidence-json` 里。要变成 `GRANTED`，只能由维护者或无关联第三方**单独书面授予**——评测引擎本身没有这个能力，代码里也没有这条路径。风险高的档位建议走沙箱与人工复核，但那是建议，不是豁免。

**三件事不要混：分数、档位、门禁。** `action.yml` 的默认门槛是 **90**，它是一个 CI 拦截值：低于 90 分 CI 失败。档位是**描述**（“81–95 属 T1 风险低”），门禁是**拦截**（“不到 90 就拦”），授权是**签发**（恒为 `NOT_GRANTED`）。因此 `T1` 的技能在默认门禁下仍会被拦——这不是矛盾，是两个不同的问题：档位回答“有多危险”，门禁回答“这次让不让过”。要放行 81–89 分的对象，须显式调低门槛并自行承担后果；门槛低于 49（安全否决封顶线）必须禁止，否则被否决的技能会被放行。校准数据显示默认 90 会拦掉 6 份干净技能里的 5 份，原因见 `docs/CALIBRATION.md` §5。

评测来源也必须可区分：`--provenance self|automated|third_party`，默认 `self`（维护者自评）。自评与 CI 自动跑都不构成第三方复核，对外不得称第三方认证。

同一个引擎在 GitHub Actions 里直接可用：

```yaml
- uses: LGD-Eval/lgd-gate@v1
  with:
    path: ./my-skill
    threshold: 90
```

## 为什么分数可信

npm 包**不含第二套打分算法**。它只是一个启动器，转发给随包分发的 Python 实现（`vendor/scripts/evaluate.py`），与 GitHub 源码逐字节相同。任何人 clone 源码、跑同一条命令，得到的分数一样。

## 依赖

需要本机有 **Python 3**（打分逻辑在 Python 上）。没装会明确报错并给出安装指引，不会静默给出错误分数。

## 相关

- 源码与方法论：https://github.com/LGD-Eval/lgd-gate
- 认证榜单：https://github.com/LGD-Eval/evaluation-evidence
- 理论：LGD 三律（有籍 / 有证 / 有门禁）

## License

**代码 Apache-2.0 / 正文 CC BY 4.0**（从 `v0.2.0` 起；`v0.1.0` 仍按 CC BY 4.0，不追溯）。

- 代码（`bin/`、`skills/`、`ai-index-gate/`、`audit/`、`tests/`、`vendor/` 内的脚本）：[Apache-2.0](LICENSE)，含专利授权与专利报复条款。
- 正文（`docs/`、根目录 `*.md`、`diagrams/`、`assets/`）：CC BY 4.0，署名即可引用。
- 逐路径的判据与时间边界见 [LICENSE-CONTENT.md](LICENSE-CONTENT.md)；第三方内容以原证为准。
- [skill-audit](https://github.com/LGD-Eval/skill-audit) 亦为 Apache-2.0；理论文本（LGD 三律）仍保留全部权利。
