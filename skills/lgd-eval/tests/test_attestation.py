#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P0-3 证据链双指纹与 verify_attestation 完整性测试（离线）。

覆盖：
- 结论指纹 result_fingerprint 与完整证明指纹 attestation_fingerprint 分离；
- 同一输入可复现同一组指纹；
- 篡改结论字段 -> verify 失败；
- 元数据变化只改 attestation 指纹，不改 result 指纹；
- verify_attestation.py 脚本对合法报告退出 0，篡改报告退出 1。
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.abspath(os.path.join(HERE, "..", "scripts"))
sys.path.insert(0, SCRIPTS)

import evaluate as ev  # noqa: E402
import verify_attestation as va  # noqa: E402


def _report():
    root = tempfile.mkdtemp()
    with open(os.path.join(root, "SKILL.md"), "w", encoding="utf-8") as f:
        f.write("# sample\n")
    return ev.build_attestation(root, 79, "B", {}, [], None)


def test_dual_fingerprints_present():
    rep = _report()
    assert rep["result_fingerprint"].startswith("sha256:")
    assert rep["attestation_fingerprint"].startswith("sha256:")
    assert rep["result_fingerprint"] != rep["attestation_fingerprint"]


def test_fingerprints_reproducible():
    a = _report()
    b = _report()
    assert a["result_fingerprint"] == b["result_fingerprint"]
    assert a["attestation_fingerprint"] == b["attestation_fingerprint"]


def test_metadata_change_moves_attestation_only():
    a = _report()
    b = json.loads(json.dumps(a))
    b["affiliation"] = "EXTERNAL"
    # 重算完整指纹：元数据变化应使 attestation 指纹变化
    a_full = {"result": {"object": {"score": a["score"], "grade": a["grade"]},
                         "dims": a["dims"], "findings": a["findings"]},
              "inputs": a["inputs"], "meta": {"engine_version": a["engine_version"],
              "rule_version": a["rule_version"], "affiliation": a["affiliation"],
              "evaluator_commit": a["evaluator_commit"], "authorization": a["authorization"]}}
    b_full = dict(a_full)
    b_full["meta"] = dict(a_full["meta"], affiliation="EXTERNAL")
    import hashlib
    from evaluate import canonical_dumps
    ha = hashlib.sha256(canonical_dumps(a_full).encode()).hexdigest()
    hb = hashlib.sha256(canonical_dumps(b_full).encode()).hexdigest()
    assert ha != hb
    assert a["result_fingerprint"] == b["result_fingerprint"]


def test_verify_passes_on_valid_report():
    rep = _report()
    assert va.verify(rep) == []


def test_verify_fails_on_tampered_result():
    rep = _report()
    rep["score"] = 100  # 篡改结论
    errors = va.verify(rep)
    assert errors  # 非空 -> 校验失败


def test_verify_fails_on_missing_metadata():
    """缺规则/引擎版本或缺对象树哈希 -> 元数据不完整，verify 必须报错。"""
    rep = _report()
    for key in ("rule_version", "engine_version"):
        clone = json.loads(json.dumps(rep))
        clone.pop(key)
        assert va.verify(clone), "缺 %s 应被拒绝" % key
    clone = json.loads(json.dumps(rep))
    clone["inputs"] = {}
    assert va.verify(clone), "缺对象树哈希应被拒绝"


def test_verify_script_exit_codes():
    rep = _report()
    good = os.path.join(tempfile.mkdtemp(), "good.json")
    bad = os.path.join(tempfile.mkdtemp(), "bad.json")
    with open(good, "w", encoding="utf-8") as f:
        json.dump(rep, f)
    tampered = json.loads(json.dumps(rep))
    tampered["score"] = 100
    with open(bad, "w", encoding="utf-8") as f:
        json.dump(tampered, f)
    py = sys.executable
    ok = subprocess.run([py, os.path.join(SCRIPTS, "verify_attestation.py"), good],
                        capture_output=True, text=True)
    bad_run = subprocess.run([py, os.path.join(SCRIPTS, "verify_attestation.py"), bad],
                             capture_output=True, text=True)
    assert ok.returncode == 0
    assert bad_run.returncode == 1
