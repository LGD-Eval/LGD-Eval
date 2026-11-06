#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lgd_mcp_server.py —— LGD 评测引擎的 MCP Server 形态。

为什么需要它：CLI 只能在有 Python/Node 的桌面系统跑。鸿蒙（HarmonyOS NEXT）
设备无法直接 spawn node/python 子进程，iOS 同样不能跑命令行。而 MCP 是跨生态
的通用协议——任何支持 MCP 的 AI 客户端（桌面、移动、鸿蒙、苹果）都能连上来
调用同一套评测算法，不必关心底层是什么系统。

一套算法，三种接入：
  CLI          → Windows / macOS / Linux
  MCP Server   → 任何支持 MCP 的 AI 客户端（含鸿蒙、iOS、Android 上的 AI 应用）
  HTTP（后续） → 浏览器 / 小程序

协议：MCP over stdio（JSON-RPC 2.0，逐行）。
用法：python lgd_mcp_server.py     （客户端通过 stdio 通讯）

工具：
  evaluate_skill  评测一个技能目录或单个 SKILL.md
  evaluate_mcp    评测一个 MCP server 目录
"""

import json
import os
import sys
import io
import contextlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

try:
    from evaluate import evaluate_skill as _eval_skill
except Exception:
    _eval_skill = None
try:
    import importlib.util
    _spec = importlib.util.spec_from_file_location("eval_mcp_mod", os.path.join(HERE, "eval_mcp.py"))
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    _mcp_mod = _mod
except Exception:
    _mcp_mod = None

PROTO = "2024-11-05"

TOOLS = [
    {
        "name": "evaluate_skill",
        "description": "评测一个 AI 技能（目录或单个 SKILL.md），返回五维分数、等级、发现的问题与整改建议。",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "技能目录或 SKILL.md 的绝对路径"}},
            "required": ["path"],
        },
    },
    {
        "name": "evaluate_mcp",
        "description": "评测一个 MCP Server（目录含 package.json），返回工具定义/权限安全/可运行性/文档/生态五维分数。",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "MCP server 目录的绝对路径"}},
            "required": ["path"],
        },
    },
]


def _ok(id_, result):
    return {"jsonrpc": "2.0", "id": id_, "result": result}


def _err(id_, code, msg):
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": msg}}


def call_tool(name, args):
    path = (args or {}).get("path", "")
    if not path:
        raise ValueError("缺少 path 参数")
    path = os.path.abspath(path)
    if not os.path.exists(path):
        raise ValueError("路径不存在：%s" % path)

    if name == "evaluate_skill":
        if _eval_skill is None:
            raise ValueError("评测模块加载失败")
        # evaluate_skill 会把人类可读报告 print 到 stdout；MCP 的 stdio 通道
        # 只允许 JSON-RPC 消息，混入报告会让客户端解析失败，必须就地捕获
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            score, grade, dims, findings, warnings = _eval_skill(path)
        return {
            "content": [{"type": "text", "text": json.dumps({
                "score": score, "grade": grade,
                "dims": {k: v for k, v in (dims or {}).items()} if isinstance(dims, dict) else dims,
                "findings": findings[:20] if isinstance(findings, list) else findings,
            }, ensure_ascii=False, indent=2)}],
            "isError": False,
        }
    if name == "evaluate_mcp":
        if _mcp_mod is None:
            raise ValueError("MCP 评测模块加载失败")
        text = _mcp_mod.read_all(path)
        dims = {}
        notes = {}
        dims["工具定义"], notes["工具定义"] = _mcp_mod.score_tools(path, text)
        dims["权限与安全"], notes["权限与安全"] = _mcp_mod.score_safety(text)
        dims["可运行性"], notes["可运行性"] = _mcp_mod.score_runnable(path)
        dims["文档与示例"], notes["文档与示例"] = _mcp_mod.score_docs(path, text)
        dims["生态兼容"], notes["生态兼容"] = _mcp_mod.score_eco(path)
        total = sum(dims.values())
        return {
            "content": [{"type": "text", "text": json.dumps({
                "score": total, "grade": _mcp_mod.grade_of(total),
                "dims": dims, "notes": notes,
            }, ensure_ascii=False, indent=2)}],
            "isError": False,
        }
    raise ValueError("未知工具：%s" % name)


def handle(msg):
    mid = msg.get("id")
    method = msg.get("method")
    params = msg.get("params") or {}
    if method == "initialize":
        return _ok(mid, {
            "protocolVersion": PROTO,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "lgd-eval", "version": "1.0.0"},
            "instructions": "LGD 独立技能评测：给技能或 MCP server 打分、找出缺口、给出可执行整改清单。",
        })
    if method in ("notifications/initialized", "initialized"):
        return None
    if method == "tools/list":
        return _ok(mid, {"tools": TOOLS})
    if method == "tools/call":
        try:
            return _ok(mid, call_tool(params.get("name"), params.get("arguments")))
        except Exception as e:
            return _ok(mid, {"content": [{"type": "text", "text": "ERROR: %s" % e}], "isError": True})
    if method == "ping":
        return _ok(mid, {})
    return _err(mid, -32601, "Method not found: %s" % method)


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:
            sys.stdout.write(json.dumps(_err(None, -32700, "Parse error")) + "\n")
            sys.stdout.flush()
            continue
        resp = handle(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
