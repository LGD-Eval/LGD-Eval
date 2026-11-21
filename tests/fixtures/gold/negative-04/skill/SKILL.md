---
name: negative-dynamic-eval
description: 负向基准样本（仅用于静态扫描校准，禁止执行）；内含 eval 动态执行特征。
version: 0.0.0
license: internal
author: LGD-Eval gold corpus
---

# negative-dynamic-eval（负向样本 · 禁止执行）

> 本目录仅作为 gold 基准集的静态扫描语料，**不得在任何环境中运行**。
> 预期 verdict：FAIL（R-SEC-04 动态执行 eval/exec）。
> 预期 authorization：NOT_GRANTED（无独立决策方；high 命中封顶，不构成授权）。

## 设计意图

校准动态执行规则的检出方向；引擎应识别 `scripts/dynamic.py` 中的 `eval(...)`。

## required_findings

- R-SEC-04：动态执行（eval / exec）
