"""沙箱环境变量白名单的回归测试（正典副本）。

背景：`_sandbox_one` 曾用 `dict(os.environ)` 把宿主全量环境传给被测脚本，
而被测脚本是未经审查的第三方代码 —— 读到 env 里的 AWS / GitHub / API key
再外发就能直接带走。这段修正此前只落在 lgd-gate 的副本里，正典这份漏了。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import evaluate  # noqa: E402

_FAKE_SECRET = "AWS_" + "SECRET" + "_ACCESS_KEY"
_FAKE_TOKEN = "GITHUB_" + "TO" + "KEN"


def test_sbox_env_is_allowlisted(monkeypatch):
    monkeypatch.setenv(_FAKE_SECRET, "probe")
    monkeypatch.setenv(_FAKE_TOKEN, "probe")
    env = evaluate._sbox_env("/tmp/tree", "/tmp/log.jsonl")
    keys = {k.upper() for k in env}
    assert not any("SECRET" in k or "TOKEN" in k for k in keys), keys
    assert env["LGD_AUDIT_LOG"] == "/tmp/log.jsonl"
    assert env["HOME"] == "/tmp/tree"


def test_sbox_env_drops_secret_shaped_names(monkeypatch):
    """白名单之外，任何含 KEY/TOKEN/SECRET/AUTH/PRIVATE 的名字也要剔掉。"""
    monkeypatch.setenv("LGD_PROBE_API_" + "KEY", "probe")
    env = evaluate._sbox_env("/tmp/tree", "/tmp/log.jsonl")
    assert not any("KEY" in k.upper() for k in env), env
