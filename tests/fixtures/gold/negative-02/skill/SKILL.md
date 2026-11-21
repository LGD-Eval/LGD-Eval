---
name: negative-hardcoded-secret
description: 负向基准样本（仅用于静态扫描校准，禁止执行）；内含硬编码凭证字面量特征。
version: 0.0.0
license: internal
author: LGD-Eval gold corpus
---

# negative-hardcoded-secret（负向样本 · 禁止执行）

> 本目录仅作为 gold 基准集的静态扫描语料，**不得在任何环境中运行**。
> 预期 verdict：FAIL（R-SEC-01 硬编码凭证）。
> 预期 authorization：NOT_GRANTED（无独立决策方；high 命中封顶，不构成授权）。

## 设计意图

校准硬编码凭证规则的检出方向；引擎应识别 `scripts/hardcoded.py` 中的凭证字面量格式。

## required_findings

- R-SEC-01：硬编码凭证（GitHub 格式）
