# STRUCTURE — 分层与改动代价

## 五层

| 层 | 位置 | 内容 |
|---|---|---|
| L1 评测内核 | `skills/lgd-eval/scripts/evaluate.py`（78 KB）、`skillgate.py`（72 KB） | 五维打分、整改清单、安全扫描 |
| L2 分析与辅助 | `ast_analyzer.py`、`js_analyzer.py`、`autofix.py`、`sandbox.py` | 语言分析、自动修复、沙箱 |
| L3 出口 | `scorecard.py`、`lgd_web.py`、`lgd_mcp_server.py`、`eval_mcp.py`、`bin/lgd-eval.js`、`package.json` | 评分卡、Web、MCP、CLI |
| L4 治理文本 | `GOVERNANCE.md`、`AUTHORITY_INTERPRETATION_GUIDELINES.md`、`CONFLICT_OF_INTEREST_DISCLOSURE.md`、`itu/*`、`ROUTING.md` | 权限、解释口径、利益冲突声明、ITU 材料 |
| L5 检验 | `tests/`、`.github/scripts/`、`.github/workflows/`（9 个） | 契约测试、PR 审计、扫描门禁、SBOM、CodeQL |

## 改动代价

| 你想做 | 改哪里 | 必须重跑 | 必须同步 |
|---|---|---|---|
| 改五维权重 | `evaluate.py` + `scorecard.py` 的 `MAXS` | `test_scorecard_contract.py`（满分必须仍为 100）、`benchmarks/` 基准 | README 分数说明、`evaluation-evidence` 评分卡 |
| 改任一脚本 | `skills/lgd-eval/scripts/` | `test_copy_parity.py` | `vendor/scripts/`（或在 `known_divergence.txt` 登记） |
| 改评分卡版式 | `scorecard.py` | `test_scorecard_contract.py` | `scores.md`、排行榜 |
| 改治理口径 | L4 文本 | `pr-audit.py` | README 的"三律"段 |

## 边界

本仓是**评测器**（给技能打分），不产出被评对象，也不替代外部评审。
判定"变更是否越界"归 `lcas`，"记录是否被篡改"归 `lgd-xverify`。
