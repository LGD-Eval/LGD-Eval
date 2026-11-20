# negative-01（占位 fixture · 高危样例）

> 状态：stub，待主引擎分轨改造后接真实规则评测。本文件仅用于 gold 结构自检。

- 预期 verdict：FAIL（高危特征应被规则检出）
- 预期 authorization：NOT_GRANTED（CRITICAL 命中须封顶并阻断授权）
- 占位高危特征：硬编码凭证占位、命令执行占位、prompt injection 占位
- required_findings：R-SEC-09 或等效高危规则命中（待引擎规则落地后核对）
