# EVIDENCE-INDEX — LGD-Eval

## 现状

| 级 | 结果 | 证据位置 | 说明 |
|---|---|---|---|
| L1 自我复现 | **有（新补）** | `tests/test_copy_parity.py`、`tests/test_scorecard_contract.py`、`.github/scripts/pr-audit.py`、`.github/scripts/welcome-self-test.py`、`skills/lgd-eval/benchmarks/{eval-5d,audit-18d}.txt`、`.github/workflows/{auto-eval,scanner-gate,sbom,codeql}.yml` | 新增两组可跑用例：评分卡纯函数契约、双副本一致性；benchmarks 是历史跑分记录 |
| L2 异体审查 | **0** | — | 无外部审查记录。机构内部的多账号流程（作者+审批）不是外部审查，不计 |
| L3 第二实现 | **0** | — | 评测器只有一套实现 |
| L3.5 外部语料 | **0** | `skills/lgd-eval/benchmarks/*.txt` 为自家跑分 | 非外部独立技能集 |
| L4 外部节点 | **0** | — | `evaluation-evidence` 的评分卡与排行榜均为自家生成 |

## 已知不硬的地方

1. **同一批脚本存在两份副本。** `skills/lgd-eval/scripts/` 与 `vendor/scripts/` 各 12 个同名文件，其中 `ast_analyzer.py` 已经分叉（6629 vs 6277 字节）。新增分叉现由 `tests/test_copy_parity.py` 拦截，但**已登记的这一处尚未收敛**，`known_divergence.txt` 清空才算解决。
2. **`tests/README.md` 说明了为什么公开包里没有恶意样本**——这个理由成立（样本本身是载荷），但它同时意味着**外人无法独立验证检测能力**，只能看自家 benchmark 文本。所以检测能力目前只到 L1。
3. **分数由被评对象之外的一套逻辑给出，但那套逻辑没有被评。** 评测器自身的准确性没有对照基准（没有人工标注的"应得分数"集合）。
4. **排行榜与评分卡同源。** `evaluation-evidence` 的数据由本仓产出，两者互证等于自证。

## 维护约定

- 任何脚本改动 → 先跑 `test_copy_parity.py` 与 `test_scorecard_contract.py`。
- 新增分叉必须登记到 `tests/known_divergence.txt`，且**登记即负债**，需在 CHANGELOG 记一笔。
- 等级只降不升。
