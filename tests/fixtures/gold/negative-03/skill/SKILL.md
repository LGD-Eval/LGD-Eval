---
name: negative-shell-true
description: 负向基准样本（仅用于静态扫描校准，禁止执行）；内含 shell=True 命令注入特征。
version: 0.0.0
license: internal
author: LGD-Eval gold corpus
---

# negative-shell-true（负向样本 · 禁止执行）

> 本目录仅作为 gold 基准集的静态扫描语料，**不得在任何环境中运行**。
> 预期 verdict：FAIL（R-SEC-03 命令注入风险 shell=True）。
> 预期 authorization：NOT_GRANTED（无独立决策方；high 命中封顶，不构成授权）。

## 设计意图

校准命令注入规则的检出方向；引擎应识别 `scripts/shellcall.py` 中的 `shell=True`。

## required_findings

- R-SEC-03：命令注入风险（shell=True）
