# -*- coding: utf-8 -*-
"""全球信任注册 · 跨平台可行性实验（可行性分析件，不是服务）。

场景：Agent 在 A 注册、在 B 评测、在 C 被调用。
约束：C 完全不能访问 A 或 B 的内部数据库，只能读 Agent 自带的 passport bundle。
目的：量出「哪些字段今天就能验、哪些必须依赖一个公开注册源」。
"""
import hashlib
import hmac
import json
import sys
from datetime import datetime, timedelta, timezone

NOW = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)
KEYS = {"A": "key-A-secret", "B": "key-B-secret", "AUTH": "auth-issuer-secret"}


def canon(o):
    return json.dumps(o, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def mac(body, k):
    return hmac.new(KEYS[k].encode(), canon(body), hashlib.sha256).hexdigest()


# ============ 平台 A：注册（有自己的库） ============
class PlatformA:
    def __init__(self):
        self.registry = {}

    def register(self, agent_id, fp, version):
        rec = {"agent_id": agent_id, "key_fp": fp, "version": version,
                "status": "REGISTERED"}
        self.registry[agent_id] = rec
        return rec

    def issue_passport(self, agent_id, evidence, evaluation, authorization, revoked=False):
        return {
            "bundle_version": "gtp/1",
            "identity": self.registry[agent_id],
            "evidence": evidence,
            "evaluation": evaluation,
            "authorization": authorization,
            "revocation": {"revoked": revoked, "checked_at": NOW.isoformat(),
                           "source": "platform-A"},
        }


# ============ 平台 B：评测（有自己的库） ============
class PlatformB:
    def evaluate(self, agent_id, version, rule_version, engine_version, score):
        report = {"agent_id": agent_id, "version": version, "score": score,
                  "rule_version": rule_version, "engine_version": engine_version,
                  "evaluator": "platform-B"}
        signed = dict(report, mac=mac(report, "B"))
        return signed


# ============ 平台 C：调用方（没有 A、B 的库） ============
class PlatformC:
    """C 只有：公开规则表 + 自己的信任锚 + 撤销快照（可不可靠）。"""

    MAX_SNAPSHOT_AGE = timedelta(hours=6)

    def __init__(self, pinned_fp, compat_table, revocation_snapshot=None):
        self.pinned_fp = pinned_fp                 # 本地钉扎：agent -> fp
        self.compat = compat_table                 # 兼容三元组
        self.snapshot = revocation_snapshot        # 公开撤销源快照（可能没有）

    def verify(self, bundle, requested_scope, tool_class):
        res = {"identity": "?", "evidence": "?", "evaluation": "?",
               "authorization": "?", "revocation": "?", "decision": "?"}

        # 1 身份
        ident = bundle["identity"]
        if ident["key_fp"] != self.pinned_fp.get(ident["agent_id"]):
            res["identity"] = "MISMATCH"
            res["decision"] = "DENY"
            return res
        res["identity"] = "VERIFIED"

        # 2 证据完整性
        ev = bundle["evidence"]
        body = dict(ev)
        m = body.pop("mac")
        ok_ev = hmac.compare_digest(mac(body, "A"), m)
        res["evidence"] = "VERIFIED" if ok_ev else "TAMPERED"
        if not ok_ev:
            res["decision"] = "DENY"
            return res

        # 3 评测结果（版本 + 签名）
        evl = bundle["evaluation"]
        ebody = dict(evl)
        em = ebody.pop("mac")
        ok_sig = hmac.compare_digest(mac(ebody, "B"), em)
        key = (evl["rule_version"], evl["engine_version"])
        ok_ver = key in self.compat
        res["evaluation"] = "VERIFIED" if (ok_sig and ok_ver) else (
            "SIG_FAIL" if not ok_sig else "VERSION_UNKNOWN")
        if not (ok_sig and ok_ver):
            res["decision"] = "DENY"
            return res

        # 4 授权
        auth = bundle["authorization"]
        if datetime.fromisoformat(auth["expires_at"]) <= NOW:
            res["authorization"] = "EXPIRED"
            res["decision"] = "DENY"
            return res
        if requested_scope - set(auth["scope"]):
            res["authorization"] = "SCOPE_INSUFFICIENT"
            res["decision"] = "DENY"
            return res
        res["authorization"] = "VALID"

        # 5 撤销 —— 这里是关键：C 唯一的信息来源是快照
        if self.snapshot is None:
            res["revocation"] = "NO_SOURCE"
            res["decision"] = "DENY"
            return res
        age = NOW - self.snapshot["fetched_at"]
        if age > self.MAX_SNAPSHOT_AGE:
            res["revocation"] = "STALE_SNAPSHOT"
            res["decision"] = "DENY"
            return res
        if bundle["identity"]["agent_id"] in self.snapshot["revoked"]:
            res["revocation"] = "REVOKED"
            res["decision"] = "DENY"
            return res
        res["revocation"] = "NOT_REVOKED"

        res["decision"] = "ALLOW"
        return res


COMPAT = {("rules/2", "engine/3"), ("rules/2", "engine/2")}
CASES = []


def case(cid, name, fn, expect):
    got = fn()
    verdict = "PASS" if got["decision"] == expect else "FAIL"
    CASES.append({"id": cid, "name": name, "expected": expect,
                  "actual": got["decision"], "checks": got, "verdict": verdict})


def main():
    a, b = PlatformA(), PlatformB()
    ident = a.register("agent-A", "fp-A", "1.1.0")
    evidence = {"agent_id": "agent-A", "version": "1.1.0", "source": "observed",
                "action": "read_crm"}
    ev = dict(evidence, mac=mac(evidence, "A"))
    evalr = b.evaluate("agent-A", "1.1.0", "rules/2", "engine/3", 91)
    auth = {"subject": "agent-A", "scope": ["read"], "tool_class": ["read"],
            "expires_at": (NOW + timedelta(days=20)).isoformat(),
            "issuer": "auth-issuer"}
    auth = dict(auth, mac=mac(auth, "AUTH"))

    snap = {"fetched_at": NOW - timedelta(hours=1), "revoked": [], "source": "platform-A/public"}
    c = PlatformC({"agent-A": "fp-A"}, COMPAT, snap)

    # D1 全链路正常
    case("D1", "完整护照 + 新鲜快照", lambda: c.verify(
        a.issue_passport("agent-A", ev, evalr, auth), {"read"}, "read"), "ALLOW")

    # D2 身份指纹不符
    c_bad_fp = PlatformC({"agent-A": "fp-EVIL"}, COMPAT, snap)
    case("D2", "身份指纹不符", lambda: c_bad_fp.verify(
        a.issue_passport("agent-A", ev, evalr, auth), {"read"}, "read"), "DENY")

    # D3 证据被篡改
    bad_ev = dict(ev, action="delete_all")
    case("D3", "证据被篡改", lambda: c.verify(
        a.issue_passport("agent-A", bad_ev, evalr, auth), {"read"}, "read"), "DENY")

    # D4 评测版本 C 不认识
    ev_unknown = b.evaluate("agent-A", "1.1.0", "rules/1", "engine/1", 91)
    case("D4", "评测版本不在兼容表", lambda: c.verify(
        a.issue_passport("agent-A", ev, ev_unknown, auth), {"read"}, "read"), "DENY")

    # D5 授权过期
    auth_exp = dict(auth, expires_at=(NOW - timedelta(days=1)).isoformat())
    auth_exp["mac"] = mac({k: v for k, v in auth_exp.items() if k != "mac"}, "AUTH")
    case("D5", "授权已过期", lambda: c.verify(
        a.issue_passport("agent-A", ev, evalr, auth_exp), {"read"}, "read"), "DENY")

    # D6 授权范围不足
    case("D6", "请求 write 但只授 read", lambda: c.verify(
        a.issue_passport("agent-A", ev, evalr, auth), {"read", "write"}, "write"), "DENY")

    # D7 已撤销 + 新鲜快照
    snap_rev = {"fetched_at": NOW - timedelta(hours=1), "revoked": ["agent-A"], "source": "platform-A/public"}
    c_rev = PlatformC({"agent-A": "fp-A"}, COMPAT, snap_rev)
    case("D7", "已撤销，快照新鲜", lambda: c_rev.verify(
        a.issue_passport("agent-A", ev, evalr, auth, revoked=True), {"read"}, "read"), "DENY")

    # D8 快照过期（撤销状态不可确认）→ 必须 fail-closed
    snap_old = {"fetched_at": NOW - timedelta(hours=30), "revoked": [], "source": "platform-A/public"}
    c_old = PlatformC({"agent-A": "fp-A"}, COMPAT, snap_old)
    case("D8", "撤销快照过期 → fail-closed", lambda: c_old.verify(
        a.issue_passport("agent-A", ev, evalr, auth), {"read"}, "read"), "DENY")

    # D9 完全没有撤销源
    c_none = PlatformC({"agent-A": "fp-A"}, COMPAT, None)
    case("D9", "无公开撤销源", lambda: c_none.verify(
        a.issue_passport("agent-A", ev, evalr, auth), {"read"}, "read"), "DENY")

    # D10 撤销后 C 若误信过期快照（模拟错误实现）→ 会放行，说明风险
    class C_Lax(PlatformC):
        MAX_SNAPSHOT_AGE = timedelta(days=30)
    c_lax = C_Lax({"agent-A": "fp-A"}, COMPAT, snap_old)
    case("D10", "宽松实现误信过期快照（应暴露）", lambda: c_lax.verify(
        a.issue_passport("agent-A", ev, evalr, auth), {"read"}, "read"), "ALLOW")

    fails = [x for x in CASES if x["verdict"] == "FAIL"]
    out = {
        "experiment": "A 注册 / B 评测 / C 调用（C 无 A、B 数据库）",
        "total": len(CASES), "passed": len(CASES) - len(fails), "failed": len(fails),
        "revocation_dependent_cases": [x["id"] for x in CASES if "撤销" in x["name"] or "快照" in x["name"]],
        "results": CASES,
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
