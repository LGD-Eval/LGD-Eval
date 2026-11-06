"""L3 运行时审计钩子。

在受限进程内记录：敏感文件读取、DNS 解析、网络连接、子进程启动。

为什么需要它：静态正则只能看代码长什么样，看不到程序实际把数据发去了哪里。
编码后外泄、把数据拼进域名做隧道这两类，只有运行时才看得见——
因为无论怎么编码，最后都要落到一次 DNS 查询或一次 connect 上。

代价：这是 Python 层钩子，绕过方式存在（直接 syscall、C 扩展、独立二进制）。
syscall 级拦截需要 strace/eBPF，只在 Linux 且有权限时才有。本文件不假装能防住那些。
"""
import builtins
import json
import os
import socket
import subprocess

_LOG = os.environ.get("LGD_AUDIT_LOG", "")

SENSITIVE_HINTS = ("credential", "secret", ".ssh", ".aws", ".npmrc", ".netrc",  # skillgate: ignore（规则字面量，非真实读取）
                   "id_rsa", ".env", "token", ".kube", ".docker")


def _write(rec):
    if not _LOG:
        return
    try:
        with open(_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


def install():
    orig_open = builtins.open

    def open_hook(file, mode="r", *a, **kw):
        # 先真打开：不存在的路径不算"读了敏感文件"，否则报的是意图不是行为
        handle = orig_open(file, mode, *a, **kw)
        try:
            p = str(file)
            if mode and any(c in mode for c in "r+") and any(k in p.lower() for k in SENSITIVE_HINTS):
                _write({"event": "read_sensitive", "path": p})
        except Exception:
            pass
        return handle

    builtins.open = open_hook

    orig_gai = socket.getaddrinfo

    def gai_hook(host, *a, **kw):
        try:
            _write({"event": "dns", "host": str(host), "len": len(str(host))})
        except Exception:
            pass
        return orig_gai(host, *a, **kw)

    socket.getaddrinfo = gai_hook

    orig_connect = socket.socket.connect

    def connect_hook(self, addr):
        try:
            _write({"event": "connect", "addr": str(addr)})
        except Exception:
            pass
        return orig_connect(self, addr)

    socket.socket.connect = connect_hook

    orig_popen = subprocess.Popen

    class _Popen(orig_popen):
        def __init__(self, args, *a, **kw):
            try:
                _write({"event": "spawn",
                        "args": args if isinstance(args, str) else [str(x) for x in args]})
            except Exception:
                pass
            super().__init__(args, *a, **kw)

    subprocess.Popen = _Popen
