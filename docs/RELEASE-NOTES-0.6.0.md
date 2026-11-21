# RELEASE NOTES · LGD-Eval 0.6.0-hardening（提案，未发布）

> 状态：本地已实现，`tests/` 4 passed，双副本 sha256 一致（`tests/test_copy_parity.py` OK）。
> 动因：本日第一阶段对抗实测——**凭证外发载荷 100/A+（安全 25/25）**。这不是"检测弱"，是"检测根本没看那里"。

## 修正（四处，全部有前后对照）

| # | 问题（实测证据） | 修法 | 前后对照 |
|---|---|---|---|
| F1 | `os.environ.get("GITHUB_TOKEN")` 读后 POST 外网 → 100/A+ | 单项凭证环境变量纳入污点源（原先只认整份 `os.environ` 打包） | 86/A → **49/D**（critical 否决） |
| F2 | 行内 `# skillgate: ignore` 使规则失效 → 100/A+ | 取消无备案豁免；改为 `.lgd/allowlist.json`（规则号 + 文件 + 该行内容 sha256 + 理由 + 复核人），**CRITICAL 类永不豁免**；未备案的豁免注释本身计 8 分 + 封顶 | 86/A → **62/C**；带真实 exfil + 伪豁免 → **49/D** |
| F3 | 载荷放进 `demo/`、`samples/`、`benchmarks/` 完全不扫描 | 默认只跳过工具/缓存目录；`fixtures` 类目录必须由 `.lgd/scope.json` 显式声明才跳过，且跳过行为写入报告 | demo/ 下载荷 86/A → **49/D** |
| F4 | 空目录 67/C、仅 SKILL.md 87/A | 缺 `SKILL.md` → `INVALID_SUBJECT, exit 2`；无可执行面 → `INCONCLUSIVE, exit 2` | 空目录 72/B → **exit 2**；仅文档 86/A → **exit 2** |

## 防误报（同等重要）

- 新增端点分级：读凭证后发给 `api.openai.com` 一类**常规服务端点**不扣分、只登记并封顶 A；
  发给陌生主机才走 critical 否决。
- 实测：正常用法样本 **86/A → 86/A**（零回归）；干净基线 **86/A → 86/A**。

## 对照实验（同一批样本，两套评测器）

| 样本 | 旧 | 新 |
|---|---|---|
| good_rich_docs（干净基线） | 86/A | 86/A |
| exfil_single_env | 86/A | **49/D** |
| exfil_under_demo | 86/A | **49/D** |
| exfil_with_ignore | 86/A | **49/D** |
| ignore_only（仅一行注释） | 86/A | **62/C** |
| legit_api_key（正常用法） | 86/A | 86/A |
| empty_dir | 72/B | **exit 2 INVALID_SUBJECT** |
| docs_only | 86/A | **exit 2 INCONCLUSIVE** |
| exempt_declared（备案豁免） | 86/A | 86/A（记录豁免，封顶 A） |
| crit_exempt_attempt（给 critical 规则备案） | — | **仍 49/D**（豁免被拒） |

原始数据：`hardening_before_after.json`；复跑：`python verify_hardening.py`。

## 新增文件（均为提案）

- `.lgd/allowlist.json` 规范（随本文件说明，示例见 `verify_hardening.py`）
- `.lgd/scope.json`（夹具声明）
- `docs/RELEASE-NOTES-0.6.0.md`（本文件）

## 未做（需单独批准）

- 未改 `LICENSE`（CC BY 4.0 → Apache-2.0，见 `LICENSE-DECISION.md`）
- 未推送、未打 tag
- 评分权重与"A+/A/B/C/D"分档未动（仍为 EXPERIMENTAL；本轮只让否决生效）
- `vendor/scripts/evaluate.py` 与 `skills/lgd-eval/scripts/evaluate.py` 双副本已同步（parity test 通过）
