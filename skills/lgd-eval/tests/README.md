# tests

本目录的测试用例**会随公开技能包分发**，因此必须遵守一条硬约束：

> 源码里不得出现可被扫描器判为真实载荷的**字面**（`os.system(...)`、`shell=True`、
> `eval("...")`、"api_key = 'xxxx'"、凭证外发组合等）。

需要测这类行为时，一律**运行时拼接**构造：

```python
var_name = "api" + "_key"                 # 而不是直接写 api_key = ...
fn = "ev" + "al"                          # 而不是直接写 eval(...)
```

理由：本仓自身就是扫描器（`skillgate.py` / `ast_analyzer.py`）。若测试里写载荷字面，
扫描器扫自己必然报警，等于用测试文件污染自己的结论——这正是"扫描器扫自己"类误报的根源。

恶意样本夹具（真实攻击载荷）仍保留在开发仓内、**不随公开包分发**。
想验证检测能力，用仓库根目录的 `_demo/` 样本（已标注"用来测检测器，不要运行"）：

```bash
python3 evaluate.py ./_demo/mitiga-style
python3 skillgate.py scan ./_demo/poisoned-skill
```

## 现有用例

| 文件 | 覆盖 |
|---|---|
| `test_ast_analyzer.py` | 正则规则变量（`secret_re` 等）不得误报；真凭证仍须命中；短值与语法错误文件的边界 |
| `test_vendor_parity.py` | `vendor/scripts` 与 `skills/lgd-eval/scripts` 逐字节一致（把 README 的分发承诺变成可执行断言） |
| `test_safety_cap.py` | 安全否决封顶规则：CRITICAL→49、HIGH→69、无命中→100 |

运行：

```bash
python -m pytest          # 在 skills/lgd-eval 目录下执行（pyproject 已设 testpaths=tests）
```
