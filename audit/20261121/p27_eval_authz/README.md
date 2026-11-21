# LGD-Eval P0-2 评测与授权分离 —— 候选补丁包（未应用）

**性质**：候选 PR 方案。**未修改任何仓库、未提交、未推送。**
**日期**：2026-11-19
**仓库**：`LGD-Eval/lgd-gate`（本地克隆基线 `10b3a22`）

---

## 1. 原始问题（FACT）

`action.yml:86`：

```bash
if [ "$SCORE" -ge 96 ]; then TIER="L0"; SUGGEST="免审批直接执行"
```

即：**评分 ≥96 直接宣称"免审批执行"**。这是五份任务书里被重复点名最多的单点缺陷：

- 第一轮任务书 B.6「核查 UNKNOWN、INCOMPLETE、NOT GRANTED 等状态的安全门禁」
- 第二轮 P0-2「清除评分直接授予执行权限的歧义；Evaluation、Risk、Authorization 完全分离；默认 NOT GRANTED」
- 第五轮 B.4「检查评分是否仍能自动产生执行权限」
- 第六轮 1「禁止将评测 PASS 自动映射为授权」
- 第七轮 C「审计登记、评测、授权…找出状态断层」

改前实测（原仓）：

```
action.yml:86  → TIER=L0; SUGGEST="免审批直接执行"
outputs        → score / grade / tier / sarif（无 authorization）
```

**它不是"文档措辞问题"**：`tier=L0` 是 action 的输出，下游按 tier 决定是否加人工审批时，会直接读到"免审批"。

---

## 2. 改了什么

| 文件 | 类型 | 说明 |
|---|---|---|
| `authorization.py` | 新增 | 授权裁决纯函数：`decide(score, evaluation_status, grant, ...)` |
| `authorize.py` | 新增 | CLI：给 Action 调用，输出 `authorization=` / `exec_tier=`，退出码 0/1 |
| `action.yml` | 修改 | 6 处：新增 2 个 input、L0 措辞改为"不授予执行权限"、新增授权判定步骤、新增 2 个 output、summary 增加授权行、可选 fail-on-not-granted |

改动量：`3 files changed, 256 insertions(+), 3 deletions(-)`（其中 218 行是新增模块与 CLI）。

---

## 3. 语义对照

| 场景 | 改前 | 改后 |
|---|---|---|
| score=100，无授权 | `tier=L0 免审批直接执行` | `authorization=NOT_GRANTED`，`exec_tier=L5` |
| score=96（边界） | 同上 | 同上 |
| score=100，有合法 grant | 同上 | `GRANTED`，`exec_tier` 取 grant 声明（封顶 L1） |
| score=20，有合法 grant | `L4 隔离只读` | `GRANTED`，`exec_tier` 由 grant 决定（如 L2） |
| grant 过期 / 撤销 / 摘要不符 / 越权 scope / 缺字段 | 不适用 | 分别 `EXPIRED` / `REVOKED` / `NOT_GRANTED` |
| `evaluation_status=UNKNOWN/INCOMPLETE` | 无此概念 | `UNKNOWN` / `INCOMPLETE`，fail-closed |
| grant 要求 `exec_tier=L0` | — | **拒绝**（L0 永不得作为权限档） |

**关键取舍（我改过一版，这里说清）**：第一版让执行档位由分数推导（高分封顶 L1），P01 用例立刻暴露矛盾——score=20 + 人工授权却只能拿到 L4，"授权"等于没用。所以最终定为**执行档位由授权对象决定，分数只作建议**。这才是真正的分离，两个方向都成立：
- 高分 ≠ 有权限（N01/N02）
- 低分 ≠ 无权限（P01）

---

## 4. 测试命令与结果

```powershell
cd proposals\p27_eval_authz
python test_authz.py
```

| 组 | 用例 | 结果 |
|---|---|---|
| 负向（高分无授权 / 未知 / 不完整 / 越界 / 缺字段 / 过期 / 撤销 / 摘要不符 / 越权 / L0 授权） | 14 | **全通过** |
| 正向（低分+授权 / 满分+授权） | 4 | 全通过 |
| 合计 | 18 | **18/18 PASS** |

授权 CLI 三条路径实测（`_demo` 目录真实摘要）：

```
A1 score=96 无 grant     → AUTHORIZATION: NOT_GRANTED  exec_tier=L5   exit 1
A2 score=96 + 合法 grant → AUTHORIZATION: GRANTED      exec_tier=L1   exit 0
A3 同 A2 但 grant 被撤销 → AUTHORIZATION: REVOKED      exec_tier=L5   exit 1
```

`action.yml` YAML 可解析，outputs = `authorization / exec-tier / grade / sarif / score / tier`。

---

## 5. 剩余风险

| 风险 | 级别 | 说明 |
|---|---|---|
| **composite step 的 bash 逻辑未实跑** | P1 | 本机无 bash，只验证了被调用的 `authorize.py` 与 YAML 结构。需在 CI 里跑一次 action 才能算验证 |
| 默认不失败（`fail-on-not-granted=false`） | P2 | 为避免破坏既有用户。这意味着"默认仍然不拦"，只是不再宣称"免审批"。是否改默认为 true 需产品决策 |
| 下游若把 `tier` 当权限用 | P1 | 本补丁新增 `authorization`/`exec_tier`，但**没有强制**下游改读新字段。彻底闭合需要文档 + 变更说明 |
| `tree_digest` 对大目录有性能成本 | P3 | 被评测目录通常很小；若用于大仓需加排除规则 |
| grant 的签名 | P1 | 当前 grant 是明文 JSON，未签名。真正的可信授权需要签名与钉扎（可复用 `gtp-rev/1` 的 Ed25519 方案） |

---

## 6. 审批与复核

- **独立复核**：需要。改的是"是否允许执行"的判定入口，属安全语义。
- **Steven Zhao 审批**：需要。合并、推送、建分支、发版均须单独批准。
- 本包只到"补丁可应用 + 用例全过 + 语义说清"。

---

## 7. 应用方式（待批准）

```powershell
git checkout -b fix/p0-2-eval-authz-separation
git apply proposals/p27_eval_authz/eval_authz.patch
python test_authz.py
```

补丁已对原仓 `git apply --check` 通过（exit 0），原仓 `git status` 为空。
