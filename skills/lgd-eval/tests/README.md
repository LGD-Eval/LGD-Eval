# tests

本目录的测试用例与恶意样本夹具保留在开发仓内，**不随公开技能包分发**——
它们本身就是「恶意技能长什么样」的样本（`os.system`、`shell=True`、`eval`、
凭证外发），放进公开包会让任何扫描器（包括本仓的 `skillgate.py`）
把它们当真实载荷报出来。

想验证检测能力，用仓库根目录的 `_demo/` 样本：那里是**故意做的攻击样本**，
已经在 README 里标注为「用来测检测器，不要运行」。

```bash
python3 evaluate.py ./_demo/mitiga-style
python3 skillgate.py scan ./_demo/poisoned-skill
```
