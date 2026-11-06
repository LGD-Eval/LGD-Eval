# lgd-eval

> 技能能不能上架，不由下载量决定，由五维分数和三律决定。

AI Agent 技能评测引擎。给任意技能目录打一个 0–100 的 Trust Score，同时判断它是否满足 LGD 三律（有籍 / 有证 / 有门禁），并输出**能被机器执行的整改清单**。

## 一行跑

```bash
npx lgd-eval ./my-skill
```

## 卡住不合格的 PR

```bash
npx lgd-eval ./my-skill --fail-under 90 --fix-json fix-plan.json
```

- 分数 < 90 → 退出码 1，CI 直接红
- `fix-plan.json` 里每一项都是「缺口 → 整改动作 → 可判定验收」，AI 或人改完再跑一次即闭环

## 输出是什么

```
Trust Score: 100/100
等级: 🏆 A+

五维: 结构完整性(25) / 目录结构(15) / 文档质量(20) / 安全检查(25) / 生态兼容(15)

LGD 三律
  L1 有籍（档案可追溯）  ✅
  L2 有证（结论有证据）  ✅
  L3 有门禁（有检查）    ✅
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

MIT © 2026 SynomosAI / LGD Ecosystem
