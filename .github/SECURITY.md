# Security Policy / 安全政策

> LGD-Eval · 凡自治之物评测线 ｜ 我们的立场：防投毒、防篡改、证据门禁。

## Our security stance / 安全立场

- **Anti-poisoning / 防投毒**：技能与工具接受 manifest/prompt 投毒检测（skill-audit scanner）。
- **Anti-tampering / 防篡改**：关键产物 SHA-256 锚定；证据文件独立复验，不自查。
- **Evidence-gated / 证据门禁**：任何声称以可复现证据为准；无证据不成立。
- **Zero secrets / 零密钥**：本组织所有仓库禁止提交任何密钥、令牌或敏感配置。

## Reporting a vulnerability / 报告漏洞

请通过以下任一渠道报告（请勿公开披露未修复漏洞）：

- **GitHub Security Advisory**（首选）：仓库 → Security → Report a vulnerability
- **Issues**：创建时标注 `[SECURITY]` 前缀（敏感内容勿写入公开 Issue）

**Responsible disclosure / 负责任披露**：
1. 私密报告 → 维护者 72 小时内确认
2. 修复与公告 → 修复后由维护者公开披露与致谢
3. 报告者可获 VC 贡献积分与致谢名录

## Supported / 支持版本

| 仓库 / Repo | 支持版本 / Supported |
|---|---|
| evaluation-protocol | 全部已发布 tag |
| evaluation-reports | 全部已发布 tag |
| evaluation-evidence | 全部已发布 tag |
| skill-audit | 全部已发布 tag |