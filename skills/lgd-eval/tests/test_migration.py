#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P1-8 旧报告兼容迁移测试（离线）。

覆盖：
- 缺新字段时按默认降级补齐，不臆造；
- migrated_from 记录旧 schema_version；
- 历史 result/attestation 指纹原样保留，不被重算；
- 旧 verdict 镜像到 assessment_outcome，不作为新事实来源；
- 迁移不修改入参 dict。
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.abspath(os.path.join(HERE, "..", "scripts"))
sys.path.insert(0, SCRIPTS)

import evaluate as ev  # noqa: E402
import report_migration as rm  # noqa: E402


def _legacy_report():
    root = tempfile.mkdtemp()
    with open(os.path.join(root, "SKILL.md"), "w", encoding="utf-8") as f:
        f.write("# sample\n")
    rep = ev.build_attestation(root, 79, "B", {}, [], None)
    # 模拟旧报告：剥离 P0/P1 新增字段
    for key in ("assessment_outcome", "evaluation_status", "safety_check_status",
                "safety_clear", "execution_applicability", "evaluator_tree_sha256"):
        rep.pop(key, None)
    return rep


def test_migration_fills_defaults():
    legacy = _legacy_report()
    out = rm.migrate_report(legacy)
    assert out["evaluation_status"] in ("COMPLETE", "INCOMPLETE")
    assert out["assessment_outcome"] in ("PASS", "FAIL", "INCOMPLETE", "INCONCLUSIVE")
    assert out["safety_check_status"] in ("COMPLETE", "INCOMPLETE", "UNKNOWN")
    assert out["safety_clear"] is False
    assert out["execution_applicability"] == "NOT_APPLICABLE"
    assert out["evaluator_commit"]
    assert out["evaluator_tree_sha256"]


def test_migration_records_source():
    legacy = _legacy_report()
    legacy["schema_version"] = "1.0.0"
    out = rm.migrate_report(legacy)
    assert out["migrated_from"] == "1.0.0"


def test_history_fingerprints_preserved():
    legacy = _legacy_report()
    rp, ap = legacy["result_fingerprint"], legacy["attestation_fingerprint"]
    out = rm.migrate_report(legacy)
    assert out["result_fingerprint"] == rp
    assert out["attestation_fingerprint"] == ap


def test_legacy_verdict_mirrors_outcome():
    legacy = _legacy_report()
    legacy["verdict"] = "FAIL"
    out = rm.migrate_report(legacy)
    assert out["assessment_outcome"] == "FAIL"


def test_migration_does_not_mutate_input():
    legacy = _legacy_report()
    before = dict(legacy)
    rm.migrate_report(legacy)
    assert legacy == before
