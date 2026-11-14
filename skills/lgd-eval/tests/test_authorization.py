"""评测与授权分离的回归测试（P0）。

存在原因：审计发现 evaluate.py 按分数直接打印「L0 免审批（可直接运行）」，
README 章节名就叫「分数决定权限」，全仓没有 authorization_status 字段。
一个分数替人签了授权 —— 这必须被钉住，否则下次改文案又会长回来。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from evaluate import (  # noqa: E402
    AUTHORIZATION_STATUS, PROVENANCE_LABELS, build_attestation,
    grade_for, risk_tier_for,
)


def test_authorization_status_defaults_to_not_granted():
    assert AUTHORIZATION_STATUS == "NOT_GRANTED"


def test_provenance_never_claims_third_party_by_default():
    assert set(PROVENANCE_LABELS) == {"self", "automated", "third_party"}
    assert "第三方" not in PROVENANCE_LABELS["self"]


def test_grade_scale_matches_skillgate():
    """两引擎同一分数必须同一字母；34 分曾经是 evaluate 的 D、gate 的 F。"""
    assert grade_for(96)[0] == "A+"
    assert grade_for(79)[0] == "B"
    assert grade_for(49)[0] == "D"
    assert grade_for(34)[0] == "F"
    assert grade_for(10)[0] == "F"


def test_risk_tier_is_advisory_only():
    """最高分也只能给 T0，不能出现任何「免审批 / 授权」字样。"""
    for score in (100, 96, 79, 49, 34, 5):
        tier = risk_tier_for(score)
        assert tier.startswith("T")
        for banned in ("免审批", "授权", "直接运行", "L0"):
            assert banned not in tier


def test_attestation_carries_authorization_and_provenance(tmp_path):
    (tmp_path / "SKILL.md").write_text("---\nname: t\n---\n", encoding="utf-8")
    att = build_attestation(tmp_path, 49, "D", {"a": 1}, [], provenance="self")
    assert att["authorization_status"] == "NOT_GRANTED"
    assert att["evaluation_provenance"] == "self"
    assert "第三方" not in att["provenance_label"]
    att2 = build_attestation(tmp_path, 49, "D", {"a": 1}, [], provenance="third_party")
    assert att2["provenance_label"] == "无关联第三方复核"
