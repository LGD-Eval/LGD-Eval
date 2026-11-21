#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pre_push_gate.py —— 推送前账号与密钥核查（门禁骨架，本地只读）。

定位
----
推送前核对身份，不是推送后补看：认证成功只证明"有写权限"，不证明"是谁"。
本骨架在本地扫描疑似密钥与环境变量日志；身份比对依赖环境变量，未提供则记
IDENTITY_UNVERIFIED，不默认通过。

红线
----
* 不联网、不调用远端账号接口；远端 login 核对待推送授权后用专用端点完成；
* 检出疑似密钥即 BLOCKED；环境变量日志（如 gcm-diagnose.log）不得进仓库；
* Windows 下 git hook 执行位不可靠，以本包装器为准，hook 只作双保险。

用法：
  python pre_push_gate.py [--repo <dir>] [--json]
  环境：GATE_EXPECTED_LOGIN=期望账号  GATE_CURRENT_LOGIN=当前账号（可选）
"""
from __future__ import annotations

import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub Token"),
    (re.compile(r"sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}"), "模型 API Key"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "Slack Token"),
]
ENV_LOG_NAMES = ("gcm-diagnose.log",)
EXCLUDE_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules"}


def scan_repo(repo: str) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    for dp, dirs, fns in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for fn in fns:
            rel = os.path.join(os.path.relpath(dp, repo), fn)
            if fn.lower() in ENV_LOG_NAMES:
                findings.append({"file": rel, "type": "env-log", "detail": "环境变量日志不得入库"})
            fp = os.path.join(dp, fn)
            try:
                with open(fp, encoding="utf-8", errors="ignore") as f:
                    for i, line in enumerate(f, 1):
                        for rx, label in SECRET_PATTERNS:
                            if rx.search(line):
                                findings.append({"file": rel, "line": str(i),
                                                 "type": "secret", "detail": label})
            except OSError:
                continue
    return findings


def check(repo: str) -> Dict[str, Any]:
    secrets = scan_repo(repo)
    expected = os.environ.get("GATE_EXPECTED_LOGIN")
    current = os.environ.get("GATE_CURRENT_LOGIN")
    if not expected or not current:
        identity = {"status": "IDENTITY_UNVERIFIED",
                    "note": "未提供 GATE_EXPECTED_LOGIN/GATE_CURRENT_LOGIN；远端身份待专用端点核对。"}
    elif expected == current:
        identity = {"status": "IDENTITY_MATCH", "expected": expected, "current": current}
    else:
        identity = {"status": "IDENTITY_MISMATCH", "expected": expected, "current": current}

    if secrets:
        status = "BLOCKED"
    elif identity["status"] == "IDENTITY_MISMATCH":
        status = "BLOCKED"
    elif identity["status"] == "IDENTITY_UNVERIFIED":
        status = "WARN"
    else:
        status = "PASS"
    return {
        "gate_schema": "lgd-gate-pre-push/1.0",
        "evidence_level": "E1",
        "repo": os.path.abspath(repo),
        "identity": identity,
        "secret_findings": secrets,
        "status": status,
        "note": "本地骨架核查；远端 login=owner 须在推送前用专用端点复核。",
    }


def main(argv: Optional[list] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    repo = opt = argv[argv.index("--repo") + 1] if "--repo" in argv else os.getcwd()
    report = check(repo)
    if "--json" in argv:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print("pre-push gate: %s（密钥/日志问题 %d）" % (report["status"], len(report["secret_findings"])))
        print("  身份: %s" % report["identity"]["status"])
    return {"PASS": 0, "WARN": 0, "BLOCKED": 1}[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
