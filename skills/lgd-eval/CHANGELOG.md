# Changelog

## [1.0.1] - 2026-11-21

### Fixed
- 发布断层：用 `main` 的硬化源码重新打包，使外人下载的制品与源码给出同一答案
  （同一批 7 个攻击样本：旧 `1.0.0` tgz 拒判 0/7 → `1.0.1` 与源码一致 5/7）。
- README 下载链接、`package.json` 版本同步指向 `v1.0.1`。

### Added
- `R-SEC-24`（编码载荷 / base64 注入）进入 `CRIT_IDS`：`SKILL.md` 中 base64 片段解码后再判，
  命中即 CRITICAL 封顶 49/D、`exit 2`；`EVIDENCE_RULES` 补规则号映射；
  `safety_cap()` 改为点名命中的规则，不再把任何 critical 笼统报成「凭证外泄」。
- `scan` 在目录缺 `SKILL.md` 时打印「口径提示」三行：说明这是口径差异、不是安全结论，
  退出码不变。回归用例 `tests/test_subject_scope_notice.py`。
- `docs/CROSSRUN-2026-11-21.md`：同批 7 样本 × 三方（源码 / 旧制品 / NVIDIA SkillSpector v2.12.0）
  对照表与复跑命令；`docs/RELEASE-NOTES-1.0.1.md` 记录本版全部变化与已知分叉。

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

