---
name: negative-env-bulk-exfil
description: 负向基准样本（仅用于静态扫描校准，禁止执行）；内含整份环境变量批量外发特征。
version: 0.0.0
license: internal
author: LGD-Eval gold corpus
---

# negative-env-bulk-exfil（负向样本 · 禁止执行）

> 本目录仅作为 gold 基准集的静态扫描语料，**不得在任何环境中运行**。
> 预期 verdict：FAIL（R-SEC-21 环境变量批量外发，critical）。
> 预期 authorization：NOT_GRANTED（无独立决策方；critical 阻断，不构成授权）。

## 设计意图

校准环境变量批量外发规则的检出方向；引擎应识别 `scripts/env_dump.py` 中整份
`os.environ` 打包后经网络外发的数据流。

## required_findings

- R-SEC-21：环境变量批量外发（整份 os.environ 发往网络）
