"""README 里的 npx/npm 命令，必须在旁边写明"发了还是没发"。

存在原因：README 把 `npx lgd-eval ./my-skill` 写成"一行跑"，作为第一入口。
但 npm registry 上 `lgd-eval` 是 404 —— 每一个照文档操作外人都会失败，
而我这边的自动分类器把它当"Node 形态，本机无 Node"跳过了，差点记成 PASS。

这类缺陷的形状是：**文档承诺了一个尚不存在的东西，而测试装置看不见它**。
所以这条守卫不查网络（CI 不能依赖网络），只查"说了没"：
凡出现 npx / npm i 的行，三行之内必须有发布的明确状态（已发布 / 尚未发布）。
"""
import io
import os
import re

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # skills/lgd-eval
REPO = os.path.dirname(os.path.dirname(HERE))                        # repo root
READMES = [os.path.join(REPO, "README.md"), os.path.join(HERE, "README.md")]

# 说明发布状态的措辞（任一命中即可）
STATUS = ("尚未发布", "未发布", "not yet published", "not published", "已发布", "published")


def npx_lines(text):
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if s.startswith("#"):
            continue
        if re.search(r"\bnpx\s+[@a-z0-9][a-z0-9@/._-]*", s) or \
           re.search(r"\bnpm\s+(i|install)\s+[@a-z0-9][a-z0-9@/._-]*", s):
            out.append((i, s))
    return out


def check(text):
    bad = []
    lines = text.splitlines()
    for i, s in npx_lines(text):
        window = lines[max(0, i - 4):min(len(lines), i + 3)]
        if not any(any(k in w for k in STATUS) for w in window):
            bad.append("%d: %s" % (i, s[:80]))
    return bad


def test_readme_states_npm_publication_status():
    bad = []
    for p in READMES:
        if not os.path.exists(p):
            continue
        text = io.open(p, encoding="utf-8").read()
        for b in check(text):
            bad.append("%s -> %s" % (os.path.basename(os.path.dirname(p)) or p, b))
    assert not bad, ("README 里有 npx/npm 命令但没写明发布状态（外人照着跑会失败）：\n"
                     + "\n".join(bad))


def test_the_checker_catches_the_shape_it_targets():
    """反面：复刻当年那段 README，必须报红。"""
    sample = "# lgd-eval\n\n## 一行跑\n\n```bash\nnpx lgd-eval ./my-skill\n```\n"
    assert check(sample), "检测器没有抓到「npx 无发布状态」这个形状"


def test_the_checker_accepts_the_fixed_shape():
    good = ("# lgd-eval\n\n```bash\n# 尚未发布：registry 返回 404\n"
            "npx lgd-eval ./my-skill\n```\n")
    assert not check(good)


def test_readme_teaches_the_tgz_entry():
    """tgz 解包后没有 node_modules，`npx` 跑不了 —— README 必须给出可直接执行的入口。

    这条是外人席实测出来的：包内 README 只教 npx，外人解包后卡住，
    靠「自己想到 bin/lgd-eval.js」才走通。文档不该指望外人猜。
    """
    text = io.open(READMES[0], encoding="utf-8").read()
    assert "bin/lgd-eval.js" in text, "README 没写 tgz 解包后怎么跑（bin/lgd-eval.js）"
    assert "Python 3" in text, "README 没写需要本机 Python 3（否则外人会以为是纯 Node 包）"
