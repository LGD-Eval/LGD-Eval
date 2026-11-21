# -*- coding: utf-8 -*-
"""对抗套件 v2：把 v1 里两处"自证式断言"换成真实检测，并补齐 IDENTITY / VERSION 撤销与导出往返。

v1 问题：A1b、A2 直接 return False，没有检测逻辑。
v2 做法：A2 改为真实绑定校验（签名者公钥指纹 vs 授权主体登记指纹）；A1b 改为
         与"原始登记摘要"比对（重签后 mac 必变）。
"""
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lifecycle_model import (Revocation, RevocationRegistry, TransitionRequest,
                             compat, is_usable, transition)

NOW = datetime(2026, 11, 19, 9, 0, tzinfo=timezone.utc)
KEYS = {"key-A": "secret-A", "key-B": "secret-B", "key-EVIL": "secret-EVIL"}

# 主体登记表：subject -> 允许的 key_id（身份绑定）
SUBJECT_REGISTRY = {"skill-x": "key-A", "skill-y": "key-B"}


def sign(body: dict, key_id: str) -> dict:
    raw = json.dumps(body, sort_keys=True, ensure_ascii=False).encode()
    mac = hmac.new(KEYS[key_id].encode(), raw, hashlib.sha256).hexdigest()
    return {"key_id": key_id, "mac": mac, "body": body}


def digest(body: dict) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def verify_binding(signed: dict, expected_subject: str, original_digest: str) -> tuple:
    """真实检测：签名者必须等于该主体登记密钥；内容必须等于原始登记摘要。"""
    subj = signed.get("body", {}).get("subject")
    if subj != expected_subject:
        return False, "subject mismatch"
    allowed = SUBJECT_REGISTRY.get(subj)
    if allowed is None:
        return False, "subject not registered"
    if signed.get("key_id") != allowed:
        return False, f"signer {signed.get('key_id')} != registered {allowed}"
    raw = json.dumps(signed["body"], sort_keys=True, ensure_ascii=False).encode()
    mac = hmac.new(KEYS[allowed].encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, signed.get("mac", "")):
        return False, "mac mismatch"
    if digest(signed["body"]) != original_digest:
        return False, "content diverged from registered digest"
    return True, "ok"


TESTS = []


def add(cid, kind, fn, expected):
    ok, detail = fn()
    rejected = not ok
    good = (rejected and expected == "REJECT") or (ok and expected == "ALLOW")
    TESTS.append({"id": cid, "kind": kind, "expected": expected,
                  "actual": "REJECT" if rejected else "ALLOW",
                  "verdict": "PASS" if good else "FAIL", "detail": detail})


def main():
    body = {"subject": "skill-x", "issued_at": NOW.isoformat(), "verdict": "clean"}
    d0 = digest(body)

    # A2' 真实身份绑定：用 skill-y 的 key 给 skill-x 的 body 签名
    add("A2-signer-mismatch", "身份冒用", lambda: verify_binding(sign(body, "key-B"), "skill-x", d0), "REJECT")
    # A3' 未登记密钥
    add("A3-unregistered-key", "密钥替换", lambda: verify_binding(sign(body, "key-EVIL"), "skill-x", d0), "REJECT")
    # A1b' 合法重签但内容已变（与登记摘要比对）
    changed = dict(body, verdict="risky")
    add("A1b-resigned-content", "合法重签篡改内容", lambda: verify_binding(sign(changed, "key-A"), "skill-x", d0), "REJECT")
    # 对照：合法路径
    add("C6-valid-binding", "合法签名", lambda: verify_binding(sign(body, "key-A"), "skill-x", d0), "ALLOW")

    # IDENTITY 撤销：主体密钥撤销 → 其授权全部失效
    reg = RevocationRegistry()
    reg.revoke(Revocation("R-ID-1", "IDENTITY", "skill-x", "key compromised",
                          NOW.isoformat(), propagates_to=["auth-x-1", "auth-x-2"]))
    add("A13-identity-revoke", "身份撤销后旧授权仍可用",
        lambda: (False, "identity revoked") if reg.is_revoked("auth-x-1")[0] else (True, "still valid"), "REJECT")
    add("A14-identity-scope", "身份撤销波及全部授权",
        lambda: (False, "all revoked") if reg.is_revoked("auth-x-2")[0] else (True, "missed"), "REJECT")
    add("C7-other-subject-unaffected", "无关主体不受影响",
        lambda: (True, "ok") if not reg.is_revoked("auth-y-1")[0] else (False, "over-revoked"), "ALLOW")

    # VERSION 撤销：engine/2 有缺陷 → 该版本产出的证据全部失效
    ver_reg = RevocationRegistry()
    ver_reg.revoke(Revocation("R-VER-1", "VERSION", "engine/2", "defect in rule eval",
                              NOW.isoformat(), propagates_to=["ev-e2-1", "ev-e2-2"]))
    add("A15-version-revoke", "已撤销版本产出的证据仍被使用",
        lambda: (False, "version revoked") if ver_reg.is_revoked("ev-e2-1")[0] else (True, ""), "REJECT")
    add("C8-other-version-unaffected", "未撤销版本证据仍有效",
        lambda: (True, "ok") if not ver_reg.is_revoked("ev-e1-1")[0] else (False, ""), "ALLOW")

    # 导出往返（WP6）：导出包重新验证后结论不变
    bundle = {"bundle_version": "1", "subject": "skill-x", "evidence": sign(body, "key-A"),
              "authorization": {"subject": "skill-x", "scope": "runtime",
                                "expires_at": (NOW + timedelta(days=20)).isoformat()},
              "exported_at": NOW.isoformat()}
    exported = json.loads(json.dumps(bundle))
    add("C9-bundle-roundtrip", "导出包往返后仍可验证",
        lambda: verify_binding(exported["evidence"], "skill-x", d0), "ALLOW")

    tampered = json.loads(json.dumps(bundle))
    tampered["evidence"] = sign(dict(body, verdict="risky"), "key-A")
    add("A16-bundle-tamper", "导出包被改动",
        lambda: verify_binding(tampered["evidence"], "skill-x", d0), "REJECT")

    # 授权有效性（导出后仍要过 expires 检查）
    add("C10-exported-auth-usable", "导出授权未过期",
        lambda: is_usable("AUTHORIZED", NOW + timedelta(days=20), NOW), "ALLOW")
    add("A17-exported-auth-expired", "导出授权已过期",
        lambda: is_usable("AUTHORIZED", NOW - timedelta(days=1), NOW), "REJECT")

    fails = [t for t in TESTS if t["verdict"] == "FAIL"]
    print(json.dumps({"total": len(TESTS), "passed": len(TESTS) - len(fails),
                      "failed": len(fails), "results": TESTS}, ensure_ascii=False, indent=2))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
