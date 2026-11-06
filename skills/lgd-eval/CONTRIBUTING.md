# Contributing / 贡献指南

感谢你愿意贡献！请遵循以下流程：

## 开发流程
1. Fork 本仓库并基于 `main` 新建分支（`feat/xxx` 或 `fix/xxx`）。
2. 修改代码，并确保：
   - 所有测试通过：`python -m pytest`
   - 自扫描通过：`python scripts/skillgate.py scan .`
3. 提交信息遵循 Conventional Commits（`feat:` / `fix:` / `docs:` / `chore:`）。
4. 发起 Pull Request，描述改动动机与验证结果。

## 质量门禁（LGD 三律）
- **有籍**：每次变更更新 `CHANGELOG.md`。
- **有证**：每个功能附带测试与实跑数据。
- **有门禁**：CI 全绿、红队测试通过后才可合并。

## Code of Conduct
所有参与者须遵守 `CODE_OF_CONDUCT.md`。
