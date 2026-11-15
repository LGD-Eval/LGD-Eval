# 基准（Benchmarks）

记录评测引擎的实测基线，全部可复跑。静态规则判定，无模型采样。

> **口径与日期纪律**：下表的数字必须与「当日实跑、当前引擎」一致。改规则就会改分数，
> 改完不重跑就写结论，等于把过期数字当承诺发布。每次更新请连命令与日期一起写。

## 1. 对上架技能包的实测（评测器作为门禁使用）

| 被测对象 | 五维 / 安全扫描 | 结论 | 复跑 |
|---|---|---|---|
| LGD 评测引擎（lgd-eval-engine，本包） | 自扫 **89 / A**：1 MEDIUM + 7 LOW + INFO 若干 | 通过（无 HIGH/CRITICAL） | `python scripts/skillgate.py scan .`，2026-11-15，rule_version v3.1.3 |
| LGD 门禁法（lgd-gate-methodology） | 未于本次复测（NOT RE-RUN） | 待复测，不沿用旧结论 | 需在被测目录实跑后回填 |

本包那条 `sandbox.py:96` 的 MEDIUM 是 `{k: v for k, v in os.environ.items() if k not in PROXY_VARS}`
——沙箱为子进程重建环境变量而遍历 `os.environ`，是**真阳性但属设计意图**。7 条 LOW 为
`urlopen`、`tempfile.mkdtemp`、`socket`、开发依赖未钉版本这类通用形态。

关于 **coverage 披露**：`tests/test_js_combination.py` 里有故意投毒的检测夹具，位于引擎默认排除目录。
新口径是"默认排除目录里的执行面不计分，但必须披露"。本条记录曾据此把分数写成 85 ——
那是**错的**，因为计数当时只按 severity、不看 category，"不计分"这句并没实现
（实测 `audit2/probe_counted_disclosure.py`：一个只含未拆包 zip 的技能被从 100 打到 98）。
2026-11-15 已给 `Finding` 加 `scoring` 字段，coverage 类披露统一标记 `scoring=False`；
**披露不再影响分数**，`scan .` 与 `scan . --exclude tests` 都是 **89 / A**（1 MEDIUM + 7 LOW）。
**这条记录以前写着「0 findings，100/A+」，也与实测不符，已按当日实跑更正。**

## 2. 引擎自身仓库全仓自扫（内部基线）

同一棵干净克隆（`zhaoxinghua09-cell/skillgate` @948b0ff，189 文件），因扫描通道不同产生两个数字，引用时必须注明口径：

| 口径 | findings | 分数 | 分布 |
|---|---|---|---|
| 纯正则（AST 模块未加载） | 17 | 55 / D | CRIT1 / HIGH1 / MED4 / LOW6 / INFO5 |
| AST + 正则（rule_version v3.1.3） | 23 | 0 / F | CRIT4 / HIGH4 / MED4 / LOW6 / INFO5 |

差额 6 条均为 AST 通道额外检出的 `subprocess(shell=True)` 与 `shutil.rmtree`。命中的高危项全部落在引擎仓库自身的开发与测试脚本、以及 `examples/bad-skill` 演示样本，属「扫描器扫自己源码」的自证结果，不代表交付包质量。

v3.1.2 曾把 AST 分析在同一函数内执行两次，导致同一命中报两条；v3.1.3 已删除重复块，两个数字随之对齐。

## 3. 历史批量扫描（不同口径，不可与上表混引）

71 个仓库全量扫描：753 条 findings（CRIT1 / HIGH8 / MED62 / LOW101 / INFO581），人工复核误报 0。该组数据基于 v3.1.0 引擎与批量对象，与上面的包级实测不是同一组比较。

## 复跑命令

```bash
python scripts/evaluate.py <技能目录>
python scripts/skillgate.py scan <技能目录>
python scripts/lgd_audit.py <技能目录>
```

## 阅读口径

引用分数须同时给出引擎名、rule_version、扫描对象、日期四项。静态分析不覆盖运行期行为，未命中不等于无风险。
