# boundary-01（占位 fixture · 证据不足样例）

> 状态：stub，待主引擎分轨改造后接真实规则评测。本文件仅用于 gold 结构自检。

- 预期 verdict：INCONCLUSIVE（方法未冻结 / 仅元数据 / 覆盖为空）
- 预期 authorization：UNKNOWN（证据不足不得回退 PASS 或 GRANTED）
- 失败关闭口径：覆盖诚实度 = metadata-only / empty
- 用途：拦截"证据不足也放行"的虚高口径
