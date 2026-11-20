# -*- coding: utf-8 -*-
"""签发隔离层（SSAM / D7）— Ed25519 签名与验签

目的：把"AI 产出"和"人类签发"在密码学上分开。
- AI 只能生成草稿（含"草稿待人类签发"标记），**签名密钥不在 AI 手上**；
- 人类用自己的私钥签名，任何人可用公钥验签；
- 任何发布流程应只接受"验签通过"的文件。

用法：
    python sign.py init --id steven-2026            # 生成密钥对（私钥存本地，权限收紧）
    python sign.py sign <file> --id steven-2026      # 人类签发
    python sign.py verify <file> [--sig <file>]      # 任何人验签
    python sign.py list                              # 列出本机密钥
"""
import argparse
import base64
import json
import os
import sys
import time

sys.stdout.reconfigure(encoding="utf-8")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

KEYDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")
DRAFT_MARK = "草稿待人类签发"


def _paths(key_id):
    return (os.path.join(KEYDIR, key_id + ".priv"),
            os.path.join(KEYDIR, key_id + ".pub"))


def cmd_init(args):
    os.makedirs(KEYDIR, exist_ok=True)
    priv_p, pub_p = _paths(args.id)
    if os.path.exists(priv_p):
        print("已存在私钥：%s（不覆盖）" % priv_p)
        return 1
    k = Ed25519PrivateKey.generate()
    with open(priv_p, "wb") as f:
        f.write(k.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()))
    with open(pub_p, "wb") as f:
        f.write(k.public_key().public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo))
    try:
        os.chmod(priv_p, 0o600)
    except Exception:
        pass
    print("已生成密钥对 %s\n  私钥 %s（仅本机，勿外传）\n  公钥 %s（可公开分发）" % (args.id, priv_p, pub_p))
    return 0


def _sha(path):
    import hashlib
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def cmd_sign(args):
    priv_p, _ = _paths(args.id)
    if not os.path.exists(priv_p):
        print("找不到私钥 %s，请先 init 或指定 --id" % priv_p)
        return 2
    text = open(args.file, encoding="utf-8", errors="replace").read()
    if DRAFT_MARK in text and not args.human:
        print("拒绝签发：文件含「%s」标记。\n" % DRAFT_MARK
              + "AI 不得代替人类签发。若你确为人类签发者，加 --human（会在签名里记录该声明）。")
        return 3
    digest_hex = _sha(args.file)          # 纯 hex，切勿再 hex() 一次
    payload = digest_hex.encode()
    k = serialization.load_pem_private_key(open(priv_p, "rb").read(), password=None)
    sig = k.sign(payload)
    doc = {
        "alg": "ed25519",
        "key_id": args.id,
        "file": os.path.basename(args.file),
        "sha256": digest_hex,
        "signed_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "signed_by": args.signer or args.id,
        "human_attested": bool(args.human),
        "signature_b64": base64.b64encode(sig).decode(),
    }
    sig_path = args.sig or (args.file + ".sig")
    with open(sig_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    print("已签发 %s\n  签名文件 %s\n  sha256 %s…\n  human_attested=%s" % (
        args.file, sig_path, doc["sha256"][:16], doc["human_attested"]))
    return 0


def cmd_verify(args):
    sig_path = args.sig or (args.file + ".sig")
    if not os.path.exists(sig_path):
        print("MISMATCH  找不到签名文件 %s" % sig_path)
        return 1
    doc = json.load(open(sig_path, encoding="utf-8"))
    _, pub_p = _paths(doc["key_id"])
    if not os.path.exists(pub_p):
        print("MISMATCH  找不到公钥 %s" % pub_p)
        return 1
    actual = _sha(args.file)
    ok_hash = (actual == doc["sha256"])
    print("%-9s 文件哈希  %s%s" % ("MATCH" if ok_hash else "MISMATCH", actual[:16],
                                   "" if ok_hash else "  ≠ " + doc["sha256"][:16]))
    pub = serialization.load_pem_public_key(open(pub_p, "rb").read())
    ok_sig = True
    if ok_hash:
        try:
            pub.verify(base64.b64decode(doc["signature_b64"]), actual.encode())
        except Exception:
            ok_sig = False
    else:
        ok_sig = False
    print("%-9s 签名校验  %s" % ("MATCH" if ok_sig else "MISMATCH", doc.get("signed_by")))
    if doc.get("human_attested"):
        print("           human_attested=true（签发者声明为人类）")
    ok = ok_hash and ok_sig
    print("VERDICT: %s" % ("SIGNED — 可进入发布流程" if ok else "UNSIGNED/伪造 — 禁止发布"))
    return 0 if ok else 1


def cmd_list(args):
    if not os.path.isdir(KEYDIR):
        print("尚无密钥目录")
        return 0
    for fn in sorted(os.listdir(KEYDIR)):
        if fn.endswith(".pub"):
            print("  key_id=%s  公钥 %s" % (fn[:-4], os.path.join(KEYDIR, fn)))
    return 0


def main():
    ap = argparse.ArgumentParser(description="签发隔离层（Ed25519）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p1 = sub.add_parser("init"); p1.add_argument("--id", required=True); p1.set_defaults(f=cmd_init)
    p2 = sub.add_parser("sign"); p2.add_argument("file"); p2.add_argument("--id", required=True)
    p2.add_argument("--sig"); p2.add_argument("--signer"); p2.add_argument("--human", action="store_true")
    p2.set_defaults(f=cmd_sign)
    p3 = sub.add_parser("verify"); p3.add_argument("file"); p3.add_argument("--sig"); p3.set_defaults(f=cmd_verify)
    p4 = sub.add_parser("list"); p4.set_defaults(f=cmd_list)
    args = ap.parse_args()
    return args.f(args)


if __name__ == "__main__":
    sys.exit(main())
