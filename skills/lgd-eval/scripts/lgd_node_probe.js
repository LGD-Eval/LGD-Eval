// LGD 沙箱的 Node 侧审计探针。
//
// 存在原因：sandbox.py 的 _pick_entry 只认 .py，Node 技能根本启动不了，
// 静态规则漏掉时就没有第二道防线。本探针用 monkey-patch 记录
// 读敏感文件 / DNS / 连接 / 子进程四类事件，写进 LGD_AUDIT_LOG，
// 事件 schema 与 Python 侧 _lgd_hook 一致，analyse() 直接复用。
//
// 边界：只覆盖 Node 内置模块；直接 syscall、原生扩展、外部二进制不覆盖。

const fs = require('fs');
const path = require('path');

const LOG = process.env.LGD_AUDIT_LOG || '';

function rec(obj) {
  if (!LOG) return;
  try {
    fs.appendFileSync(LOG, JSON.stringify(obj) + '\n');
  } catch (e) {
    /* 记录失败不能影响被测程序 */
  }
}

const SENSITIVE = /(\.aws|\.ssh|id_rsa|id_ed25519|credentials|\.npmrc|netrc|\.kube|\.docker|\.pgpass|\.config\/gcloud)/i;

function watchRead(name) {
  const orig = fs[name];
  if (typeof orig !== 'function') return;
  fs[name] = function (p, ...rest) {
    try {
      const s = String(p);
      if (SENSITIVE.test(s)) rec({ event: 'read_sensitive', path: s });
    } catch (e) {}
    return orig.apply(fs, [p, ...rest]);
  };
}

['readFileSync', 'readFile', 'createReadStream', 'openSync', 'open'].forEach(watchRead);

if (fs.promises) {
  ['readFile', 'open'].forEach((n) => {
    const orig = fs.promises[n];
    if (typeof orig !== 'function') return;
    fs.promises[n] = function (p, ...rest) {
      try {
        const s = String(p);
        if (SENSITIVE.test(s)) rec({ event: 'read_sensitive', path: s });
      } catch (e) {}
      return orig.apply(fs.promises, [p, ...rest]);
    };
  });
}

function watchHttp(mod) {
  const orig = mod.request;
  if (typeof orig !== 'function') return;
  mod.request = function (...args) {
    try {
      let host = '';
      if (typeof args[0] === 'string') {
        host = args[0];
      } else if (args[0] && typeof args[0] === 'object') {
        host = args[0].hostname || args[0].host || '';
      } else if (args[1] && typeof args[1] === 'object') {
        host = args[1].hostname || args[1].host || '';
      }
      rec({ event: 'connect', addr: String(host) });
    } catch (e) {}
    return orig.apply(mod, args);
  };
}

watchHttp(require('http'));
watchHttp(require('https'));

try {
  const net = require('net');
  const origConnect = net.connect;
  net.connect = function (...args) {
    try {
      const t = args[0];
      const addr = typeof t === 'object' && t !== null
        ? (t.host || `${t.port || ''}`)
        : String(t || '');
      rec({ event: 'connect', addr: String(addr) });
    } catch (e) {}
    return origConnect.apply(net, args);
  };
  const origCreate = net.createConnection;
  net.createConnection = function (...args) {
    try {
      rec({ event: 'connect', addr: String(args[0] || '') });
    } catch (e) {}
    return origCreate.apply(net, args);
  };
} catch (e) {}

try {
  const dns = require('dns');
  ['lookup', 'resolve'].forEach((n) => {
    const orig = dns[n];
    if (typeof orig !== 'function') return;
    dns[n] = function (host, ...rest) {
      try {
        rec({ event: 'dns', host: String(host), len: String(host).length });
      } catch (e) {}
      return orig.call(dns, host, ...rest);
    };
  });
} catch (e) {}

try {
  const cp = require('child_process');
  ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync'].forEach((n) => {
    const orig = cp[n];
    if (typeof orig !== 'function') return;
    cp[n] = function (...args) {
      try {
        rec({ event: 'spawn', args: String(args[0]) });
      } catch (e) {}
      return orig.apply(cp, args);
    };
  });
} catch (e) {}

rec({ event: 'boot', probe: path.basename(__filename) });
