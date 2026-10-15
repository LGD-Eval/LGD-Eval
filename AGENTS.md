# AGENTS.md — Agent Guidance / AI 代理引导

This file helps AI agents and humans understand and work in this repository autonomously. Read this first, before any change. / 本文件帮助 AI 代理与人类自主理解并使用本仓库。任何改动前请先读本文件。

## What this repository is / 本仓库是什么

This is the **profile repository** of LGD-Eval, the independent evaluation institute of the 凡自治之物 (All-Autonomous-Beings) ecosystem. It is the account homepage: who we are, neutrality statement, capabilities, standards, and links to all sub-repositories. It is a documentation repository — it contains no application code. / 本仓库是 LGD-Eval（凡自治之物生态的独立评测机构）的**主页仓库**：机构介绍、中立声明、能力、标准与全部子仓库链接。本仓库为文档仓库，不含应用代码。

## Commands / 命令（在仓库根目录执行）

- Local self-check / 本地自检（改动后必须运行）: `python3 .github/scripts/pr-audit.py`
- Link health check / 链接检查: `python3 -c "import urllib.request,re,pathlib; [print(p, urllib.request.urlopen(urllib.request.Request(m.group(1),method='HEAD')).status) for p in pathlib.Path('.').rglob('*.md') for m in re.finditer(r'https?://[^)\s\]]+', p.read_text(encoding='utf-8'))]"`
- Bilingual rule / 双语规则: every published file must be English-first with complete Chinese following — never abbreviate either language. / 所有发布文件英文在前、中文在后且完整，两门语言都不缩写。
- Sub-repository navigation / 子仓库导航:
  - `/evaluation-protocol` — protocol, roles, evidence grading / 协议、角色、证据评级
  - `/evaluation-reports` — published evaluation reports / 已发布评测报告
  - `/evaluation-evidence` — hash-anchored evidence, check-catalog / 哈希锚定证据与静默失败目录
  - `/skill-audit` — skill/agent capability audits, PyPI package / 技能与代理能力审计、PyPI 包

## Project layout / 目录结构

- `README.md` — full bilingual profile / 完整双语主页
- `CONTRIBUTING.md` — contribution rules / 贡献规则
- `AGENTS.md` — this file / 本文件
- `.github/scripts/pr-audit.py` — PR audit bot script (mojibake/completeness/terms/links) / 审核机器人脚本（乱码/完整/术语/链接）
- `.github/workflows/` — CI workflows / CI 工作流
- `assets/` — static images (ecosystem map, badges) / 静态图（生态全景图、徽章）

## Conventions / 约定

- **Neutral wording**: do not add self-claimed superlatives ("first", "defining", "authoritative"); let evidence speak. / **中性措辞**：不添加自我宣称的修饰词（"首个""定义""权威"），让证据说话。
- **Evidence**: every claim must trace to a reproducible source; evidence files live in `evaluation-evidence`, hash-anchored (SHA-256 manifest). / **证据**：每条结论必须可复现溯源；证据文件位于 `evaluation-evidence`，哈希锚定。
- **Machine-readable**: tables, clear headers, explicit links, ASCII-safe markdown (no mojibake). / **机器可读**：表格、清晰标题、显式链接、无乱码。
- Match the style of surrounding files; do not reformat existing sections. / 与周围文件风格保持一致，不改排既有段落。

## Boundaries / 边界（永远不做 / never-do）

- 🚫 Never push to `main` directly without a reviewed PR; never force-push. / 未经评审 PR 不得直接推送 `main`；绝不 force-push。
- 🚫 Never alter or remove evidence anchors (hash manifests, `.ots` files, DOI records). / 绝不改动或删除证据锚（哈希清单、`.ots` 文件、DOI 记录）。
- 🚫 Never fabricate evaluation results, hashes, or citations. / 绝不伪造评测结果、哈希或引用。
- 🚫 Never commit secrets, tokens, or personal emails. / 绝不提交密钥、令牌或私人邮箱。
- 🚫 Never modify `.github/workflows/` or CI config without maintainer review. / 未经维护者评审不得修改 CI 配置。
- ⚠️ Ask first before deleting files, renaming public paths, or rewriting published reports. / 删除文件、重命名公开路径、重写已发布报告前先询问。
- ✅ Always: run `pr-audit.py` after any change; keep bilingual completeness; reference the related issue. / 任何改动后运行自检；保持双语完整；引用关联 issue。

## Verification / 验证（完成判据 / closure criteria）

"Done" means: `python3 .github/scripts/pr-audit.py` passes (no mojibake, key files complete, bilingual terms OK, links resolve), and the change is scoped to the single stated goal. Do not report a change as complete if the audit fails. / "完成"意味着：自检通过（无乱码、关键文件完整、双语术语正确、链接可达），且改动范围聚焦单一目标。自检未通过不得宣称完成。

## When blocked / 受阻时

- If a link returns 404: fix the target path or replace with a permanent URL (repo-local asset or shields.io), never leave a dead link. / 链接 404：修复目标路径或换成永久链接，绝不留下死链。
- If the audit reports mojibake: fix the file encoding (UTF-8, no BOM issues), then re-run. / 自检报乱码：修复文件编码，重跑。
- If a change would break bilingual completeness: split the change or translate fully, then re-run. / 会破坏双语完整：拆分或补全翻译，重跑。
- After two failed attempts on the same issue: stop, summarize what was learned, and ask a maintainer. / 同一问题两次失败：停止并询问维护者。

## Ecosystem / 生态

- Theory / 理论: `zhaoxinghua09-cell` (LGD Theory) / 理论号
- Product line / 产品线: `stevenzhao07` (MedXpert Medical AI Toolchain) / 产品号
- Evaluation / 评测: **this account** / 本账号
