# boundary-01（证据不足边界样本）

> 仅含元数据、无可执行代码、无 README/examples；覆盖诚实度 = metadata-only/empty。
> 预期 verdict：INCONCLUSIVE（方法未冻结 / 证据不足）。
> 预期 authorization：UNKNOWN（失败关闭，证据不足不得回退 PASS 或 GRANTED）。

## 失败关闭口径

- 覆盖为空或仅元数据时，评测不得给出高分通过结论。
- 授权不可判定即 UNKNOWN，禁止由分数自动导出 GRANTED。

## 用途

拦截"证据不足也放行"的虚高口径；与 uibc-core S19 首观 INCONCLUSIVE 口径对齐。
