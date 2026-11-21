# -*- coding: utf-8 -*-
"""7 个关键验收场景的本地可执行测试（研究原型，非产品）。"""
import json
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import trust_model as tm
from trust_model import (AgentIdentity, Delegation, DepNode, Evidence, SupplyChain,
                         TrustRegistry, TrustSnapshot, make_evidence, NOW)

tm.KEYS.update({"k-A": "secret-A", "k-B": "secret-B", "k-C": "secret-C"})

RESULTS = []


def run(sid, name, fn, expect):
    try:
        ok, detail = fn()
    except Exception as exc:  # 原型缺陷也如实记录
        ok, detail = False, f"EXCEPTION: {exc}"
    verdict = "PASS" if ok == expect else "FAIL"
    RESULTS.append({"scenario": sid, "name": name, "expected": expect,
                    "observed": ok, "verdict": verdict, "detail": str(detail)[:180]})


def build():
    reg = TrustRegistry()
    a = AgentIdentity("agent-A", "creator-X", "op-X", "impl-X", ["1.0.0"],
                      key_fingerprint="fp-A")
    b = AgentIdentity("agent-B", "creator-X", "op-Y", "impl-Y", ["2.0.0"],
                      key_fingerprint="fp-B")
    c = AgentIdentity("agent-C", "creator-Z", "op-Z", "impl-Z", ["1.0.0"],
                      key_fingerprint="fp-C")
    for x in (a, b, c):
        reg.agents[x.agent_id] = x
    ev = make_evidence("ev-A-1", "agent-A", "1.0.0", "observed", "monitor-1",
                       {"action": "read_crm"}, "k-A")
    reg.evidence.append(ev)
    return reg, a, b, c


def main():
    reg, a, b, c = build()

    # S1 版本变更后旧证据识别
    def s1():
        a.add_version("1.1.0")
        st = reg.query_evidence("agent-A", "1.1.0")["state"]
        old = reg.query_evidence("agent-A", "1.0.0")["state"]
        return (st == "STALE" and old == "VERIFIED"), f"new={st} old={old}"
    run("S1", "版本变更后旧评测证据被识别为 STALE", s1, True)

    # S2 身份冒用 → 撤销 → 传播
    def s2():
        ok, why = a.check_key("fp-IMPOSTOR")
        if ok:
            return False, "impersonation not detected"
        affected = reg.revoke("agent-A", "key mismatch / impersonation")
        return ("agent-A" in affected), f"affected={affected}"
    run("S2", "身份冒用被识别并撤销传播", s2, True)

    # S3 B 超出 A 授权范围 → 阻断
    def s3():
        reg.ledger.grant(Delegation("d-1", "root", "agent-A", {"read", "write"}))
        reg.ledger.grant(Delegation("d-2", "agent-A", "agent-B", {"read"},
                                    depth=2, max_depth=2, allow_redelegation=True))
        ok, why = reg.ledger.can_act("agent-B", {"read", "write"})
        ok2, _ = reg.ledger.can_act("agent-B", {"read"})
        return (not ok and ok2), f"exceed={why}; within_ok={ok2}"
    run("S3", "B 超出 A 授权范围被阻断", s3, True)

    # S4 C 被撤销 → 上游依赖感知
    def s4():
        reg.chain.add("agent-B", DepNode("agent-C", "1.0.0", "registry"))
        affected = reg.revoke("agent-C", "identity revoked by operator")
        risk, msg = reg.chain.risk("agent-B")
        deps = reg.chain.dependents("agent-C")
        return (risk and "agent-B" in deps and "agent-B" in affected), \
            f"risk={msg} dependents={deps} affected={affected}"
    run("S4", "C 被撤销后依赖它的上游可感知", s4, True)

    # S5 第三方评测结果可否独立验证
    def s5():
        report = {"agent": "agent-C", "version": "1.0.0", "score": 88,
                  "rule_version": "rules/2", "engine": "engine/3", "evaluator": "ext-1"}
        mac = tm.sign(report, "k-B")
        tampered = dict(report, score=99)
        ok_good = tm.sign(report, "k-B") == mac
        ok_bad = tm.sign(tampered, "k-B") == mac
        return (ok_good and not ok_bad), "recompute digest identical for genuine, differs for tampered"
    run("S5", "第三方评测结果可独立复算验证", s5, True)

    # S6 跨平台证据交换（规范化后解释一致）
    def s6():
        e = {"agent": "agent-A", "v": "1.0.0", "act": "read_crm", "ts": "2026-11-19T10:00:00Z"}
        e2 = {"ts": "2026-11-19T10:00:00Z", "act": "read_crm", "v": "1.0.0", "agent": "agent-A"}
        h1, h2 = tm.sha(e), tm.sha(e2)
        return (h1 == h2), f"canonical_equal={h1 == h2}"
    run("S6", "键序不同的同一证据规范化后一致", s6, True)

    # S7 UNKNOWN / INCOMPLETE 不放行
    def s7():
        snap_u = TrustSnapshot("agent-B", "2.0.0", True, 96.0, "UNKNOWN", None)
        snap_i = TrustSnapshot("agent-B", "2.0.0", True, 96.0, "INCOMPLETE", None)
        snap_s = TrustSnapshot("agent-B", "2.0.0", True, 96.0, "VERIFIED", None)
        d1, _ = snap_u.decision({"read"})
        d2, _ = snap_i.decision({"read"})
        d3, why3 = snap_s.decision({"read"})
        return (d1 == "DENY" and d2 == "DENY" and d3 == "DENY"), f"U={d1} I={d2} score_only={why3}"
    run("S7", "UNKNOWN/INCOMPLETE 及仅评分均不放行", s7, True)

    # 附加负向/正向对照
    def s8():
        snap = TrustSnapshot("agent-B", "2.0.0", True, 96.0, "VERIFIED",
                             {"subject": "agent-B", "scope": ["read"],
                              "expires_at": (NOW + timedelta(days=10)).isoformat()})
        d, _ = snap.decision({"read"})
        return d == "ALLOW", d
    run("C1", "完整授权链路可放行（防过杀）", s8, True)

    def s9():
        e = Evidence("ev-x", "agent-A", "1.0.0", "declared", "self", {"a": 1},
                     NOW, 30, key_id="k-A")
        e.mac = "deadbeef"
        return (not e.integrity_ok()), "bad mac rejected"
    run("C2", "声明证据被篡改则完整性失败", s9, True)

    fails = [r for r in RESULTS if r["verdict"] == "FAIL"]
    print(json.dumps({"total": len(RESULTS), "passed": len(RESULTS) - len(fails),
                      "failed": len(fails), "results": RESULTS},
                     ensure_ascii=False, indent=2))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
