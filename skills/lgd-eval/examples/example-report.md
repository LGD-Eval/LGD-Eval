# 示例评测报告：一个「会议纪要」技能

> 下面是引擎对示例技能 `meeting-notes`（把会议录音文本整理成结构化纪要）跑出的报告样例。
> 复现方式：`python scripts/skillgate.py scan ./meeting-notes --format json` ＋ `python scripts/evaluate.py ./meeting-notes`。

## 一、安全门禁（skillgate）

```
扫描对象 : ./meeting-notes
rule_version : v3.1.3
findings : 2 (MEDIUM×1 / LOW×1)
trust_score : 91
grade : A+
exit_code : 0
```

| 级别 | 规则 | 位置 | 说明 |
|---|---|---|---|
| MEDIUM | 外部写入未校验 | `scripts/export.py:42` | 导出文件名直接取自用户输入，建议做白名单校验 |
| LOW | 缺少 license 字段 | `SKILL.md:1` | frontmatter 未声明 license |

结论：**可上架**（无 CRITICAL/HIGH；两条建议性整改）。

## 二、五维评测（evaluate）

| 维度 | 得分 | 满分 | 说明 |
|---|---|---|---|
| 结构完整性 | 23 | 25 | frontmatter 完整，缺 `allowed-tools` |
| 目录结构 | 15 | 15 | scripts/ 与 examples/ 齐备 |
| 文档质量 | 18 | 20 | 有「何时用 / 何时不用」，缺失败处理说明 |
| 安全检查 | 25 | 25 | 无高危模式 |
| 生态兼容 | 15 | 15 | 平台声明与标准目录结构完整 |
| **合计** | **96** | **100** | 等级 **A+** |

```
Structure      ████████████████████▎  23/25
Layout         ██████████████████████ 15/15
Docs           ████████████████████▏  18/20
Security       ██████████████████████ 25/25
Ecosystem      ██████████████████████ 15/15
```

## 三、缺口与整改建议（按优先级）

1. **MEDIUM** 导出文件名白名单校验（`export.py:42`）——15 分钟可改，改后复扫应转 0 命中。
2. **LOW** frontmatter 补 `license: MIT`。
3. 文档补「失败处理」一节：录音为空、转写失败、超长文本三种情况的处理说明。

## 四、复现声明

- 同一输入、同一版本、同一机器 → 输出完全一致（静态规则，无模型采样）。
- 报告中的行号与文件路径均由引擎实际扫描得出，可直接对照源码核查。
- 雷达图样式参考：`radar-example.svg`（同目录）。
