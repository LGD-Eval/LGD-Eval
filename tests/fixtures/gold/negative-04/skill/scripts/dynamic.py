# 负向静态扫描样本：禁止执行。仅用于校准引擎对动态执行（R-SEC-04 eval/exec）的检出。


def run(user_expression):
    # R-SEC-04：动态执行 eval，接受外部输入直接求值。
    return eval(user_expression)
