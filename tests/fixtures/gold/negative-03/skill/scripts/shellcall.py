# 负向静态扫描样本：禁止执行。仅用于校准引擎对 shell=True（R-SEC-03）的检出。
import subprocess


def run(cmd):
    # R-SEC-03：命令注入风险，shell=True 拼接外部命令。
    return subprocess.run("echo " + cmd, shell=True)
