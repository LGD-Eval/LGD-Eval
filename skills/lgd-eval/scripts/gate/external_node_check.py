#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""external_node_check.py —— 干净克隆外人实跑一致性核查（门禁骨架，fail-closed）。

定位
----
门禁要求：在干净克隆里分别跑参考实现与独立实现，并跑 3 个必拒探针；
两者都 PASS 且必拒探针全被拒，才记 CONSISTENT；出现不一致记 DISCREPANCY，
不许发；前置条件不齐或环境不干净，记 INCONCLUSIVE，绝不默认 PASS。

红线
----
* 不回写分数、不参与授权判定；结论是发布门禁的输入，不是安全保证；
* 克隆来源必须标注公网还是本地（网络不通时用本地克隆并如实标注）；
* 独立实现缺位、干净环境未建立、探针未接线时，结论只能是 INCONCLUSIVE；
* `vendor/scripts` 是我方双侧镜像（仅 parity 一致），**不是独立第三方实现**，
  不得据此抬高到 E4；独立实现恒缺，直到外部无关联主体按统一向量实跑；
* 本骨架尚未接入真实干净克隆与第二实现实跑（见就绪度 P1-1/P2-1）。

用法：
  python external_node_check.py <clone_dir> --label local|public [--json]
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
PARENT = os.path.dirname(HERE)
sys.path.insert(0, PARENT)

CONSISTENT = "CONSISTENT"
DISCREPANCY = "DISCREPANCY"
INCONCLUSIVE = "INCONCLUSIVE"

# 必拒探针：已知高危夹具，实跑后期望全部落到 NOT_GRANTED。
# 夹具与期望状态待策略对齐（POLICY-1~4）后补入硬基准；此处仅登记占位。
MUST_REJECT_PROBES: List[Dict[str, str]] = [
    {"id": "must-reject-01", "placeholder": "反序列化高危夹具（待 POLICY-1 定级）"},
    {"id": "must-reject-02", "placeholder": "代理/基址劫持夹具（待 POLICY-2 定级）"},
    {"id": "must-reject-03", "placeholder": "递归删除/绕过话术夹具（待 POLICY-3/4 定级）"},
]


def _prerequisites(clone_dir: str) -> tuple[List[str], bool, bool]:
    """返回 (缺失原因, 双侧镜像在位, 独立第三方实现在位)。

    双侧镜像（vendor/scripts）只证明我方两份副本逐字节一致；独立第三方实现
    必须由无关联主体按统一测试向量实跑，骨架阶段恒为 False。
    """
    missing: List[str] = []
    if not os.path.isdir(clone_dir):
        missing.append("克隆目录不存在")
        return missing, False, False
    ref = os.path.join(clone_dir, "skills", "lgd-eval", "scripts", "evaluate.py")
    if not os.path.exists(ref):
        missing.append("参考实现入口缺失（evaluate.py）")
    mirror = os.path.join(clone_dir, "vendor", "scripts")
    mirror_present = os.path.isdir(mirror)
    if not mirror_present:
        missing.append("双侧镜像目录缺失（vendor/scripts；仅 parity，不构成独立实现）")
    # 独立第三方实现：骨架阶段恒缺，不把我方镜像计为独立实现。
    independent_present = False
    missing.append("独立第三方实现未接入（E4；vendor 双侧镜像不算独立实现）")
    return missing, mirror_present, independent_present


def evaluate(clone_dir: str, label: str) -> Dict[str, Any]:
    missing, mirror_present, independent_present = _prerequisites(clone_dir)
    result: Dict[str, Any] = {
        "gate_schema": "lgd-gate-external-node/1.0",
        "evidence_level": "E1",
        "clone_dir": os.path.abspath(clone_dir),
        "clone_source": label,
        "reference_pass": None,
        "mirror_present": mirror_present,
        "independent_present": independent_present,
        "independent_pass": None,
        "must_reject": {"probes": MUST_REJECT_PROBES, "all_rejected": None,
                        "note": "探针尚未接入实跑；不得据此判定已必拒"},
        "status": INCONCLUSIVE,
        "reasons": [],
    }
    if label not in ("local", "public"):
        result["reasons"].append("克隆来源标签必须是 local 或 public")
    if missing:
        result["reasons"].extend(missing)
        result["status"] = INCONCLUSIVE
        return result

    # 前置条件满足后才允许进入实跑判定；当前骨架未接线，保持 INCONCLUSIVE。
    result["reasons"].append("干净环境实跑与独立第三方对照尚未接线（待 E2/E3/E4）")
    result["status"] = INCONCLUSIVE
    return result


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in argv
    label = "local"
    if "--label" in argv:
        label = argv[argv.index("--label") + 1]
    paths = [a for a in argv if not a.startswith("--") and a != label]
    if not paths:
        print("用法: python external_node_check.py <clone_dir> [--label local|public] [--json]")
        return 2
    report = evaluate(paths[0], label)
    if as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print("external node: %s（来源=%s）" % (report["status"], report["clone_source"]))
        for r in report["reasons"]:
            print("  · %s" % r)
    # 诊断退出码：CONSISTENT=0，DISCREPANCY=3，INCONCLUSIVE=2（不默认 0 放行）。
    return {"CONSISTENT": 0, "DISCREPANCY": 3, "INCONCLUSIVE": 2}[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
