#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify_attestation.py —— 独立校验评测证明（attestation）的完整性。

用法：
    python verify_attestation.py <report.json>

校验项：
  1. result_fingerprint 可由报告内结论字段重算复现；
  2. attestation_fingerprint 可由结论 + 对象证据 + 元数据重算复现；
  3. 必要元数据存在（对象树 SHA、规则版本、引擎版本、授权状态）。

任一校验失败：打印原因并以退出码 1 结束；全部通过退出码 0。
本脚本只读报告文件，不触网、不写生产。
"""

import hashlib
import json
import sys


def canonical_dumps(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def verify(report: dict) -> list:
    """返回错误原因列表；空即通过。"""
    errors: list = []

    # 1. 重建结论载荷并比对 result_fingerprint
    payload = {
        "object": {"score": report.get("score"), "grade": report.get("grade")},
        "dims": report.get("dims", {}),
        "findings": report.get("findings", []),
    }
    veto = report.get("safety_veto")
    if veto and veto.get("applied"):
        payload["veto"] = veto
    result_fp = "sha256:" + _sha256_hex(canonical_dumps(payload))
    if result_fp != report.get("result_fingerprint"):
        errors.append("result_fingerprint 不匹配：结论字段可能被篡改")

    # 2. 重建完整证明载荷并比对 attestation_fingerprint
    full = {
        "result": payload,
        "inputs": report.get("inputs", {}),
        "meta": {
            "engine_version": report.get("engine_version"),
            "rule_version": report.get("rule_version"),
            "affiliation": report.get("affiliation"),
            "evaluator_commit": report.get("evaluator_commit"),
            "authorization": report.get("authorization"),
            "analysis": report.get("analysis"),
        },
    }
    attest_fp = "sha256:" + _sha256_hex(canonical_dumps(full))
    if attest_fp != report.get("attestation_fingerprint"):
        errors.append("attestation_fingerprint 不匹配：对象证据或元数据可能被篡改")

    # 3. 必要元数据存在性
    inputs = report.get("inputs") or {}
    if not inputs.get("tree_sha256"):
        errors.append("缺少对象树 SHA-256（inputs.tree_sha256）")
    if not report.get("rule_version"):
        errors.append("缺少规则版本（rule_version）")
    if not report.get("engine_version"):
        errors.append("缺少评测器版本（engine_version）")
    auth = report.get("authorization") or {}
    if auth.get("status") != "NOT GRANTED":
        errors.append("授权状态异常：评测证明必须标注 NOT GRANTED，不得自带执行授权")

    return errors


def main(argv) -> int:
    if len(argv) != 2:
        print("用法: python verify_attestation.py <report.json>")
        return 2
    try:
        with open(argv[1], encoding="utf-8") as f:
            report = json.load(f)
    except OSError as exc:
        print("读取报告失败: %s" % exc)
        return 1
    except json.JSONDecodeError as exc:
        print("报告不是合法 JSON: %s" % exc)
        return 1

    errors = verify(report)
    if errors:
        print("❌ 校验未通过：")
        for e in errors:
            print("  - %s" % e)
        return 1
    print("✅ 校验通过：结论指纹与完整证明指纹均可复现，元数据完整。")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
