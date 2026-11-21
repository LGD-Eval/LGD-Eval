# audit/20261121 — 评测/授权语义与治理模型审计产物

性质：**只读审计与候选方案**；未修改 main，未发布，未对外承诺。

## 目录

- `p20_trust_lifecycle/` — 信任生命周期模型 + 两组对抗套件（`lifecycle_model.py`、`test_adversarial_suite.py`、`test_adversarial_v2.py`）
- `p21_agent_trust/` — Agent 信任验收测试（`trust_model.py`、`test_acceptance.py`）
- `p23_global_registry/` — 全球信任注册可行性 demo（`feasibility_demo.py`），**仅为可行性验证，不是生产服务**
- `p27_eval_authz/` — 评测与授权分离候选方案
  - `authorization.py` / `eval_authz.patch` / `test_authz.py`（18/18）
  - 核心约束：Evaluation、Risk、Authorization 三轴分离；默认 `NOT GRANTED`；`UNKNOWN`、`INCOMPLETE` fail-closed

## 复现

```bash
cd audit/20261121/p27_eval_authz && python test_authz.py
cd audit/20261121/p20_trust_lifecycle && python test_adversarial_suite.py && python test_adversarial_v2.py
cd audit/20261121/p21_agent_trust && python test_acceptance.py
```

## 边界

- 评分高 ≠ 授予执行权限；本目录的授权模型默认拒绝，任何放行都需要显式授权记录。
- `p23` 只演示跨平台查询与撤销传播的可行性，不构成注册服务承诺。
- 所有数字为本地实跑；独立第三方复现为 0。
