"""L3 沙箱：在可审计的子进程里跑技能脚本，给出运行时行为报告。

定位：静态评测回答"这段代码能不能信"，沙箱回答"它跑起来到底做了什么"。
两者是同一套三律里的"有证"——静态规则给结论，运行记录给证据。

能力边界（不夸大）：
  ✅ 看得见：读了哪些敏感文件、解析了哪些域名、连了哪些地址、起了哪些子进程
  ✅ 抓得住：编码后外泄、DNS 隧道——因为它们最终都要落到一次 dns/connect
  ❌ 挡不住：直接 syscall、C 扩展、外部二进制。那需要 strace/eBPF，Linux 才有权限
  ❌ 不做容器隔离：公司机无 docker，本实现用"进程内审计 + 超时 + 环境变量清洗"

用法：
  python sandbox.py <脚本或技能目录> [--timeout 10] [--json]
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

BOOT = (
    "import runpy, sys, _lgd_hook\n"
    "_lgd_hook.install()\n"
    "sys.argv = [sys.argv[1]]\n"
    "runpy.run_path(sys.argv[0], run_name='__main__')\n"
)

# 代理会把沙箱内所有流量改道，审计目标就不再是程序真实意图
PROXY_VARS = ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
              "all_proxy", "ALL_PROXY", "ftp_proxy", "FTP_PROXY", "no_proxy", "NO_PROXY")

# 保留域名：永远解析不到真实主机，样本不会真的把数据送出去
SAFE_SUFFIX = (".example.com", ".example.org", ".test", ".invalid", "localhost")


def _pick_entry(path):
    if os.path.isfile(path):
        return path
    cands = []
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = [d for d in dirnames if d not in
                       {".git", "__pycache__", "node_modules", "tests", "fixtures"}]
        for fn in sorted(filenames):
            if fn.endswith(".py") and fn != "SKILL.md":
                cands.append(os.path.join(dirpath, fn))
    return cands[0] if cands else None


def analyse(events):
    findings = []
    dns = [e for e in events if e["event"] == "dns"]
    sens = [e for e in events if e["event"] == "read_sensitive"]
    conns = [e for e in events if e["event"] == "connect"]
    spawns = [e for e in events if e["event"] == "spawn"]

    for e in sens:
        findings.append({"level": "HIGH", "rule": "R-RT-01",
                         "msg": "运行时读取敏感文件：%s" % e["path"]})
    for e in dns:
        # 正常域名 15~30 字符；把数据编码进子域名会明显变长
        if e["len"] > 45:
            findings.append({"level": "CRITICAL", "rule": "R-RT-02",
                             "msg": "DNS 隧道可疑：查询域名长度 %d（%s...）"
                                    % (e["len"], e["host"][:46])})
    for e in conns:
        findings.append({"level": "INFO", "rule": "R-RT-03",
                         "msg": "网络连接：%s" % e["addr"]})
    for e in spawns:
        findings.append({"level": "MEDIUM", "rule": "R-RT-04",
                         "msg": "启动子进程：%s" % (e["args"],)})
    return findings


def run(target, timeout=10):
    entry = _pick_entry(target)
    if not entry:
        return {"error": "没有找到可执行的 .py 入口"}
    log = tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl").name
    env = {k: v for k, v in os.environ.items() if k not in PROXY_VARS}
    env["LGD_AUDIT_LOG"] = log
    env["PYTHONPATH"] = HERE + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    try:
        p = subprocess.run([sys.executable, "-c", BOOT, entry], cwd=os.path.dirname(entry) or ".",
                           env=env, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        rc = p.returncode
        out = (p.stdout or "")[-800:]
        err_lines = (p.stderr or "").strip().splitlines()
        err_tail = err_lines[-1].strip() if err_lines else ""
    except subprocess.TimeoutExpired:
        rc, out, err_tail = "timeout", "", ""
    events = []
    try:
        with open(log, encoding="utf-8") as f:
            events = [json.loads(l) for l in f if l.strip()]
    except OSError:
        pass
    finally:
        try:
            os.unlink(log)
        except OSError:
            pass
    return {"entry": entry, "exit": rc, "stdout": out, "stderr_tail": err_tail,
            "events": events, "findings": analyse(events)}


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print("用法: python sandbox.py <脚本或技能目录> [--timeout 10] [--json]")
        return 2
    timeout = 10
    if "--timeout" in sys.argv:
        timeout = int(sys.argv[sys.argv.index("--timeout") + 1])
    r = run(args[0], timeout)

    if "--json" in sys.argv:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print("== L3 运行时审计 ==")
        print("入口: %s" % r.get("entry"))
        print("退出码: %s" % r.get("exit"))
        print("事件数: %d" % len(r.get("events", [])))
        for f in r.get("findings", []):
            print("  [%s] %s %s" % (f["level"], f["rule"], f["msg"]))
        # 崩溃 / 超时 != 干净。不把"没跑起来"说成"没外发"，这是审计最基本的诚实
        if r.get("exit") not in (0,):
            print("  ⚠️  脚本未正常退出（exit=%s），以上记录不构成结论" % r.get("exit"))
            if r.get("stderr_tail"):
                print("  ⚠️  最后一行错误: %s" % r["stderr_tail"][:120])
        elif not r.get("findings"):
            print("  ✅ 未观察到敏感读取 / 异常外发 / 子进程")
    crit = any(f["level"] == "CRITICAL" for f in r.get("findings", []))
    return 3 if crit else 0


if __name__ == "__main__":
    sys.exit(main())
