# Changelog

## [1.0.0] - 2026-11-04

### Added
- 初始发布：技能包 + 评测/方法论内容
- LGD 三律对齐

## [v3.1.0] - 2026-11-04

### Fixed
- 确定性降误报：re.compile( 不再被 \bcompile\( 误命中（负向后顾）；善意 INFO 环境变量规则跳过字符串内命中；
  新增整文件级字符串感知剥离（跨行三引号 docstring）；固定参数 vs 动态调用结构性降级（eval/exec/__import__/
  os.system/os.popen/subprocess shell=True/POST-URL 固定参数降 LOW，动态保持原级别）；md 注入规则三条角色
  定义类降 LOW 并增强讨论语境跳过；skillgate.py 自指处加 # skillgate: ignore；_backup 目录排除。
- 回归测试：tests/test_fp_regression.py + tests/fixtures/good-skill|bad-skill，防回退。
- 评审加固：r/b/u 字符串前缀视为字面量（f 前缀仍判动态）；注入跳过按级别分层，CRITICAL/HIGH 仅安全主题框架可跳过，标记词/引号跳过仅作用 MEDIUM/LOW。

