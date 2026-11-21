#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_sandbox_env.py —— 沙箱环境变量最小白名单与密钥不可见负向测试。

覆盖 2026-11-19 任务书 P0「LGD Gate」：
  * sandbox.py / evaluate.py 子进程只拿到最小允许白名单变量；
  * 父进程注入的真实形态密钥（令牌 / API Key）在子进程环境与输出中均不可见；
  * 运行 Python 所需的 PATH 等基础变量仍保留（正向对照）；
  * 不削弱原有攻击检测：本测试只验证环境隔离，不改动规则族。

跑法：python tests/test_sandbox_env.py
"""
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "lgd-eval" / "scripts"))

import sandbox  # noqa: E402
import evaluate  # noqa: E402

# 注入到父进程、但绝不能进入沙箱子进程的密钥形态变量。
FAKE_SECRETS = {
    "LGD_FAKE_SECRET": "ghp_" + "a" * 36,
    "OPENAI_API_KEY": "sk-" + "b" * 32,
    "GH_TOKEN": "gho_" + "c" * 36,
    "AWS_SECRET_ACCESS_KEY": "d" * 40,
}

DUMP_SCRIPT = (
    "import os\n"
    "print('ENVKEYS=' + ','.join(sorted(os.environ.keys())))\n"
    "for k in ('LGD_FAKE_SECRET', 'OPENAI_API_KEY', 'GH_TOKEN', "
    "'AWS_SECRET_ACCESS_KEY'):\n"
    "    print('HAS_%s=%s' % (k, k in os.environ))\n"
)


class CleanEnvAllowlistTest(unittest.TestCase):
    """纯函数：白名单剔除密钥、保留基础运行变量。"""

    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in FAKE_SECRETS}
        for k, v in FAKE_SECRETS.items():
            os.environ[k] = v

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_clean_env_excludes_secrets(self):
        for mod in (sandbox, evaluate):
            env = mod._clean_env()
            for k in FAKE_SECRETS:
                self.assertNotIn(k, env, "%s 不应传入 %s" % (k, mod.__name__))

    def test_clean_env_keeps_path(self):
        for mod in (sandbox, evaluate):
            env = mod._clean_env()
            self.assertIn("PATH", env)
            self.assertEqual(env["PATH"], os.environ.get("PATH"))


class SandboxChildSecretsInvisibleTest(unittest.TestCase):
    """集成：被评测脚本在子进程里也读不到父进程注入的密钥。"""

    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in FAKE_SECRETS}
        for k, v in FAKE_SECRETS.items():
            os.environ[k] = v
        self._tmp = tempfile.mkdtemp(prefix="lgd-sandbox-env-")
        self._script = os.path.join(self._tmp, "dump_env.py")
        with open(self._script, "w", encoding="utf-8") as f:
            f.write(DUMP_SCRIPT)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_secret_not_visible_to_child(self):
        r = sandbox.run(self._script, timeout=10)
        self.assertEqual(r.get("exit"), 0, "子进程应正常退出：%s" % r.get("stderr_tail"))
        out = r.get("stdout", "")
        # 子进程不得声明持有任一注入密钥。
        for k in FAKE_SECRETS:
            self.assertNotIn("HAS_%s=True" % k, out,
                             "子进程环境不应包含 %s" % k)
            self.assertNotIn(FAKE_SECRETS[k], out,
                             "子进程输出不应泄露 %s 的值" % k)
        # 正向对照：PATH 仍可被子进程看到。
        self.assertIn("PATH", out)


if __name__ == "__main__":
    unittest.main()
