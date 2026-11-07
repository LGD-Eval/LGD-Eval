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

from trust_model import fingerprint_subject


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
            "evaluator_tree_sha256": report.get("evaluator_tree_sha256"),
            "authorization": report.get("authorization"),
            "analysis": report.get("analysis"),
            "blocking_findings": report.get("blocking_findings"),
            "trust_model": report.get("trust_model"),
            "subject": fingerprint_subject(report.get("subject") or {}),
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
    if not report.get("evidence_grade"):
        errors.append("缺少证据等级（evidence_grade，E0–E4）")

    # 4. 枚举校验（授权状态含 NOT_GRANTED）
    auth_status = report.get("authorization_status")
    if auth_status not in ("VALID", "INVALID", "EXPIRED", "REVOKED", "UNKNOWN", "NOT_GRANTED"):
        errors.append("非法授权状态（authorization_status=%r）" % auth_status)
    outcome = report.get("assessment_outcome") or report.get("verdict")
    if outcome not in ("PASS", "FAIL", "INCOMPLETE"):
        errors.append("缺少或非法验收结论（assessment_outcome/verdict，应为 PASS/FAIL/INCOMPLETE）")
    if report.get("execution_decision") not in ("ALLOW", "DENY", "NOT_APPLICABLE"):
        errors.append("缺少或非法执行决策（execution_decision）")

    # 5. 评测器身份不得冒充可复现：空值/null 必须记 UNKNOWN，不得留空
    for ident in ("evaluator_commit", "evaluator_tree_sha256"):
        v = report.get(ident)
        if v is None or (isinstance(v, str) and not v.strip()):
            errors.append("评测器身份 %s 缺失：不得以空值冒充可复现评测环境" % ident)

    # 6. blocking_findings 子集一致性：每项须能在 findings 按 rule_id/file/line 回链
    def _link(it):
        return (it.get("rule_id"), it.get("file"), it.get("line"))
    finding_keys = {_link(f) for f in report.get("findings", [])}
    for b in report.get("blocking_findings", []):
        if _link(b) not in finding_keys:
            errors.append("blocking_findings 项未在 findings 回链：%s" % b.get("rule_id"))
        if b.get("level") not in ("critical", "high"):
            errors.append("blocking_findings 项 level 非法：%s" % b.get("rule_id"))

    # 7. 结论与否决/等级一致性：否决生效或 grade=D 必须 FAIL
    veto = report.get("safety_veto") or {}
    if (veto.get("applied") or report.get("grade") == "D") and outcome != "FAIL":
        errors.append("安全否决生效或 grade=D 时，验收结论必须 FAIL")

    # 8. 顶层三轴镜像须与 trust_model 子块一致
    tm = report.get("trust_model") or {}
    for field in ("evidence_grade", "authorization_status", "verdict", "execution_decision",
                  "assessment_outcome", "execution_applicability"):
        if tm.get(field) is not None and tm.get(field) != report.get(field):
            errors.append("trust_model.%s 与顶层 %s 不一致" % (field, field))

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
