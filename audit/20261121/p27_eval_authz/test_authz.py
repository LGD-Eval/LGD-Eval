# -*- coding: utf-8 -*-
"""Evaluation ≠ Authorization —— 正向 / 负向 / 边界用例（P0-2）。"""
import datetime
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import authz as az  # noqa: E402

NOW = datetime.datetime(2026, 11, 19, 9, 0, tzinfo=datetime.timezone.utc)
DIGEST = "sha256:aaaa"
RESULTS = []


def case(cid, desc, got, want):
    ok = got == want
    RESULTS.append({"id": cid, "desc": desc, "got": str(got), "want": str(want), "pass": ok})
    print(f"{'PASS' if ok else 'FAIL'}  {cid}  {desc}\n       got={got} want={want}")


GOOD = {
    "grant_id": "G-001", "approved_by": "steven.zhao",
    "approved_at": "2026-11-19T08:00:00Z",
    "expires_at": "2026-11-20T08:00:00Z",
    "artifact_digest": DIGEST, "scope": ["read", "suggest"], "exec_tier": "L2",
}


def run(**kw):
    base = dict(score=100, evaluation_status="COMPLETE", grant=None,
                artifact_digest=DIGEST, requested_scope=None,
                revoked_grants=(), now=NOW)
    base.update(kw)
    return az.decide(**base)


# N01 核心缺陷：满分但无授权 → 必须拒绝
case("N01", "score=100 且无 grant → NOT_GRANTED（评分不授予权限）",
     run(score=100)["authorization"], az.NOT_GRANTED)

# N02 边界：正好 96（原 action.yml 的"免审批"线）
case("N02", "score=96 且无 grant → NOT_GRANTED",
     run(score=96)["authorization"], az.NOT_GRANTED)

# N03 评测未知 → fail-closed
case("N03", "evaluation_status=UNKNOWN → UNKNOWN（不接受下游策略代判）",
     run(evaluation_status="UNKNOWN")["authorization"], az.UNKNOWN)

# N04 评测不完整
case("N04", "evaluation_status=INCOMPLETE → INCOMPLETE",
     run(evaluation_status="INCOMPLETE")["authorization"], az.INCOMPLETE)

# N05 缺分
case("N05", "score=None → INCOMPLETE", run(score=None)["authorization"], az.INCOMPLETE)

# N06 越界分
case("N06", "score=120 → INCOMPLETE", run(score=120)["authorization"], az.INCOMPLETE)

# N07 授权对象缺字段（无批准人）
g = dict(GOOD); g.pop("approved_by")
case("N07", "grant 缺 approved_by → NOT_GRANTED",
     run(grant=g)["authorization"], az.NOT_GRANTED)

# N08 授权无有效期
g = dict(GOOD); g.pop("expires_at")
case("N08", "grant 无 expires_at → NOT_GRANTED（fail-closed）",
     run(grant=g)["authorization"], az.NOT_GRANTED)

# N09 已过期
g = dict(GOOD, expires_at="2026-11-18T08:00:00Z")
case("N09", "grant 已过期 → EXPIRED", run(grant=g)["authorization"], az.EXPIRED)

# N10 已撤销
case("N10", "grant 被撤销 → REVOKED",
     run(grant=GOOD, revoked_grants=("G-001",))["authorization"], az.REVOKED)

# N11 摘要不符（换了个包）
case("N11", "artifact_digest 不匹配 → NOT_GRANTED（授权不能跨产物复用）",
     run(grant=GOOD, artifact_digest="sha256:bbbb")["authorization"], az.NOT_GRANTED)

# N12 无法核验摘要
case("N12", "artifact_digest 未提供 → NOT_GRANTED",
     run(grant=GOOD, artifact_digest=None)["authorization"], az.NOT_GRANTED)

# N13 范围越权
case("N13", "请求 scope 超出授权 → NOT_GRANTED",
     run(grant=GOOD, requested_scope=["read", "write"])["authorization"], az.NOT_GRANTED)

# P01 反向分离：低分但有合法人工授权 → 允许（证明评分不否决人工判断）
case("P01", "score=20 + 合法 grant → GRANTED，且 exec_tier=L2",
     (run(score=20, grant=GOOD)["authorization"], run(score=20, grant=GOOD)["exec_tier"]),
     (az.GRANTED, "L2"))

# P02 满分 + 合法授权：档位封顶 L1，永不为 L0
r = run(score=100, grant=dict(GOOD, exec_tier="L1"))
case("P02", "score=100 + 授权 L1 → exec_tier=L1（L0 永不可作为权限档）",
     (r["authorization"], r["exec_tier"], r["suggested_tier"]), (az.GRANTED, "L1", "L0"))

# P03 范围是子集 → 通过
case("P03", "请求 scope 为授权子集 → GRANTED",
     run(grant=GOOD, requested_scope=["read"])["authorization"], az.GRANTED)

# P04 建议档位仍如实反映分数（评分不被抹掉）
case("P04", "score=100 时 suggested_tier=L0（评分照常表达，但无权限含义）",
     run(score=100)["suggested_tier"], "L0")

# P05 授权试图直接要 L0 → 拒绝
g0 = dict(GOOD, exec_tier="L0")
case("P05", "grant 要求 exec_tier=L0 → NOT_GRANTED（L0 不可作为权限档）",
     run(grant=g0)["authorization"], az.NOT_GRANTED)

n = sum(1 for r in RESULTS if r["pass"])
print(f"\n{'-'*50}\ncases={len(RESULTS)} pass={n} fail={len(RESULTS)-n}")
path = Path(__file__).with_name("authz_results.json")
with open(path, "w", encoding="utf-8") as fh:
    json.dump({"total": len(RESULTS), "pass": n, "results": RESULTS}, fh, ensure_ascii=False, indent=2)
raise SystemExit(0 if n == len(RESULTS) else 1)
