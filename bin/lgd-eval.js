#!/usr/bin/env node
/**
 * lgd-eval —— LGD 技能评测引擎的命令行入口。
 *
 * 设计原则：不重写打分算法。
 * 本 CLI 只负责找到 Python 解释器并把请求转发给随包分发的 vendor/scripts，
 * 保证 npm 用户与 GitHub 源码用户拿到的是同一套权重、同一个分数。
 *
 * 两个子命令：
 *   lgd-eval <dir>             评测（默认）
 *   lgd-eval autofix <dir>     自动整改：读整改清单施工，循环重测到达标
 */

const { spawnSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const ROOT = path.resolve(__dirname, "..");
const pkg = require(path.join(ROOT, "package.json"));

const args = process.argv.slice(2);
const isAutofix = args[0] === "autofix";
const SCRIPT = path.join(ROOT, "vendor", "scripts", isAutofix ? "autofix.py" : "evaluate.py");
const fwd = isAutofix ? args.slice(1) : args;

if (args.includes("--version") || args.includes("-v")) {
  console.log(`lgd-eval ${pkg.version}`);
  console.log("framework: LGD 三律（有籍 / 有证 / 有门禁）");
  process.exit(0);
}

if (args.includes("--help") || args.includes("-h") || args.length === 0) {
  console.log(`lgd-eval ${pkg.version} —— LGD 技能评测引擎

用法:
  npx lgd-eval <技能目录> [选项]
  npx lgd-eval autofix <技能目录> [选项]

评测选项:
  --fail-under <N>    门禁模式：分数低于 N 时退出码 1（可直接卡 CI）
  --fix-json <PATH>   输出机器可读整改清单（缺口 + 整改动作 + 可判定验收）
  --ascii             输出五维 ASCII 雷达
  --chart             生成 radar.svg

自动整改选项:
  --target <N>        目标分数，默认 90
  --max-rounds <N>    最多循环轮数，默认 4
  --dry-run           只列出将被执行的整改项，不改文件

示例:
  npx lgd-eval ./my-skill
  npx lgd-eval ./my-skill --fail-under 90 --fix-json fix-plan.json
  npx lgd-eval autofix ./my-skill --target 90

说明:
  · 评分口径与 https://github.com/LGD-Eval/lgd-gate 的 Python 实现完全一致
  · autofix 只补结构合规（缺文件/缺字段/缺章节），不编造内容；
    生成的模板带占位标记，评测器会识别并扣分，满分仍需真实内容
  · 需要本机已有 Python 3（node 只做启动器，不参与打分）
`);
  process.exit(0);
}

function findPython() {
  const cands = process.platform === "win32"
    ? ["python", "py", "python3"]
    : ["python3", "python"];
  for (const c of cands) {
    const r = spawnSync(c, ["-c", "import sys;print(sys.version_info[0])"], { encoding: "utf8" });
    if (!r.error && r.status === 0 && String(r.stdout).trim() === "3") return c;
  }
  return null;
}

if (!fs.existsSync(SCRIPT)) {
  console.error(`错误：未找到 vendor/scripts/${path.basename(SCRIPT)}，包可能未完整安装。`);
  process.exit(2);
}

const py = findPython();
if (!py) {
  console.error(`错误：未检测到 Python 3。

lgd-eval 的评分逻辑运行在 Python 上（与源码实现保持同一口径），因此需要本机有 Python 3。
  · macOS/Linux：通常已自带 python3
  · Windows：安装 https://www.python.org/downloads/ 并勾选 "Add python.exe to PATH"

检测方法：python3 -c "import sys;print(sys.version_info[0])"`);
  process.exit(3);
}

const r = spawnSync(py, [SCRIPT, ...fwd], { stdio: "inherit" });

if (r.error) {
  console.error(`执行失败：${r.error.message}`);
  process.exit(4);
}
process.exit(r.status === null ? 5 : r.status);
