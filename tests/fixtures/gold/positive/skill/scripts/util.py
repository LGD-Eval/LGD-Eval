def add(a, b):
    """返回两数之和；纯函数，无副作用。"""
    return a + b


def mean(values):
    """返回数值列表的算术平均；空列表抛 ValueError。"""
    if not values:
        raise ValueError("mean requires at least one value")
    return sum(values) / len(values)
