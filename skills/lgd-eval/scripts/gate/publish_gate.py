#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""publish_gate.py —— 发布前看板生成器（门禁骨架，数字现读 JSON）。

定位
----
看板上每个数字必须从结果 JSON 现读，禁止手打；并必须写明本地 HEAD 与公网 HEAD
是否同步。本地提交不等于已发布：公网 HEAD 缺位时明确标 NOT_SYNCED/UNKNOWN。

红线
----
* 不联网取数；公网 HEAD 未提供时记 UNKNOWN，不猜测与本地一致；
* 看板只呈现观测结果，不把 E1 自测表述为独立验证；
* 本骨架尚未接入 CI E3 与独立复核 E4 结果位。

用法：
  python publish_gate.py --bench <bench.json> --probe <probe.json> --readiness <ready.json> \
      [--local-head <sha>] [--public-head <sha>] --out board.html
"""
from __future__ import annotations

import html
import json
import os
import sys
from typing import Any, Dict, Optional


def _load(path: Optional[str]) -> Optional[Dict[str, Any]]:
    if not path:
        return None
    if not os.path.exists(path):
        return {"_missing": True, "path": path}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return {"_missing": True, "path": path, "error": "%s: %s" % (type(e).__name__, str(e)[:120])}


#: 看板摘要层保留的基准聚合字段；行级明细（rows）不进入看板，避免摘要层臃肿。
BENCH_SUMMARY_KEYS = (
    "total", "matched", "accuracy", "all_match", "confusion",
    "precision", "recall", "f1", "ci", "infra_errors", "infra_error_ids", "latency_ms",
)


def _filter_bench_summary(summary: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in summary.items() if k in BENCH_SUMMARY_KEYS}


def _sync_status(local: Optional[str], public: Optional[str]) -> Dict[str, str]:
    if not public:
        return {"status": "NOT_SYNCED", "note": "公网 HEAD 缺位（未推送）；本地提交不等于已发布。"}
    if local == public:
        return {"status": "SYNCED", "note": "本地与公网 HEAD 一致。"}
    return {"status": "DIVERGED", "note": "本地与公网 HEAD 不一致。"}


def build(bench: Optional[Dict[str, Any]], probe: Optional[Dict[str, Any]],
          readiness: Optional[Dict[str, Any]], local_head: Optional[str],
          public_head: Optional[str]) -> Dict[str, Any]:
    bench_sum = _filter_bench_summary((bench or {}).get("summary", {})) if bench and not bench.get("_missing") else {}
    probe_sum = (probe or {}).get("summary", {}) if probe and not probe.get("_missing") else {}
    gaps = (readiness or {}).get("gaps", []) if readiness and not readiness.get("_missing") else []
    gap_pri: Dict[str, int] = {}
    for g in gaps:
        gap_pri[g.get("priority", "?")] = gap_pri.get(g.get("priority", "?"), 0) + 1
    sync = _sync_status(local_head, public_head)
    return {
        "gate_schema": "lgd-gate-publish-board/1.0",
        "evidence_level": "E1",
        "head": {"local": local_head or "UNKNOWN", "public": public_head or "UNKNOWN", **sync},
        "benchmark": {"summary": bench_sum, "present": bool(bench_sum)},
        "probe": {"summary": probe_sum, "present": bool(probe_sum)},
        "readiness": {"gaps_total": len(gaps), "by_priority": gap_pri,
                      "present": bool(gaps)},
        "boundary": "看板数字现读自结果 JSON；E1 本机自测，非 E3 CI / E4 独立复核。",
    }


def _row(label: str, value: Any) -> str:
    return "<tr><td>%s</td><td>%s</td></tr>" % (html.escape(str(label)), html.escape(str(value)))


def render(board: Dict[str, Any]) -> str:
    h = ["<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'>",
         "<title>LGD 发布门禁看板</title></head><body>",
         "<h1>LGD 发布门禁看板（E1 本机）</h1>",
         "<p>%s</p>" % html.escape(board["boundary"]),
         "<h2>HEAD 同步</h2><table>",
         _row("本地 HEAD", board["head"]["local"]),
         _row("公网 HEAD", board["head"]["public"]),
         _row("同步状态", board["head"]["status"]),
         _row("说明", board["head"]["note"]), "</table>",
         "<h2>基准</h2><table>"]
    if board["benchmark"]["present"]:
        for k, v in board["benchmark"]["summary"].items():
            h.append(_row(k, v))
    else:
        h.append("<tr><td>基准结果</td><td>缺结果 JSON</td></tr>")
    h.append("</table><h2>探针</h2><table>")
    if board["probe"]["present"]:
        for k, v in board["probe"]["summary"].items():
            h.append(_row(k, v))
    else:
        h.append("<tr><td>探针结果</td><td>缺结果 JSON</td></tr>")
    h.extend(["</table><h2>就绪度缺口</h2><table>",
              _row("缺口总数", board["readiness"]["gaps_total"]),
              _row("按优先级", json.dumps(board["readiness"]["by_priority"], ensure_ascii=False)),
              "</table></body></html>"])
    return "\n".join(h)


def main(argv: Optional[list] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    def opt(name: str) -> Optional[str]:
        return argv[argv.index(name) + 1] if name in argv else None

    board = build(_load(opt("--bench")), _load(opt("--probe")), _load(opt("--readiness")),
                  opt("--local-head"), opt("--public-head"))
    out = opt("--out")
    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write(render(board))
        print("board: %s" % out)
    json_out = opt("--json-out")
    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(board, f, ensure_ascii=False, indent=2)
        print("board-json: %s" % json_out)
    if "--json" in argv:
        print(json.dumps(board, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
