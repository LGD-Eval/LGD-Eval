---
name: negative-leak-sample
description: 负向基准样本（仅用于静态扫描校准，禁止执行）；内含凭证读取后网络外发与系统命令调用特征。
version: 0.0.0
license: internal
author: LGD-Eval gold corpus
---

# negative-leak-sample（负向样本 · 禁止执行）

> 本目录仅作为 gold 基准集的静态扫描语料，**不得在任何环境中运行**。
> 预期 verdict：FAIL（R-SEC-09 凭证文件读取后网络外发；R-SEC-05 系统命令调用）。
> 预期 authorization：NOT_GRANTED（CRITICAL 命中须封顶并阻断授权）。

## 设计意图

用于校准漏报（FN）与误报（FP）：引擎应检出 `scripts/leak.py` 中的高危数据流，
而不应把它判为合规正样本。

## required_findings

- R-SEC-09：凭证文件读取后网络外发（同文件污点）
- R-SEC-05：系统命令调用（os.system）
