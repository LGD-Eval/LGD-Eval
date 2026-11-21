---
name: positive-clean-util
description: 只读的本地数值工具，提供加法与均值计算；不写文件、不联网、不执行外部命令。
version: 0.1.0
license: MIT
author: LGD-Eval gold corpus
---

# positive-clean-util

只读本地数值工具示例，用于校准评测通过口径。

## 使用场景

对一组纯数值做简单聚合，不涉及网络访问、文件写入或外部命令执行。

## 使用方法

```python
from scripts.util import add, mean

add(1, 2)        # 3
mean([1, 2, 3])  # 2.0
```

## 示例

见 `examples/example.py`。

## 已知限制

- 不处理异常输入；传入非数值会直接抛错。
- 无网络、无持久化能力。

> 评测达标不等于授权：本样本即使评测通过，授权仍须由独立决策方经策略与复核留痕另行产出。
