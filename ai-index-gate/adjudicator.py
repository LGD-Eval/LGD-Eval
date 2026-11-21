# -*- coding: utf-8 -*-
"""D5 语义裁决器原型（跨语言特征版）

定位：不做"检测"，做"裁决"。输入一行文本，输出：
    verdict: attack / doc / uncertain
    evidence: 命中的证据片段（原文引用）
    reasons:  为什么这么判（可读理由，供人复核）
    confidence: high / medium / low

硬约束：uncertain 一律按 attack 处理，**不允许静默判白**。
正则仍是高召回候选源；本裁决器负责 (1) 跨语言补召回 (2) 出证据。
"""
import re

# ---- 跨语言词表（通用动词/对象，不针对任何具体样本） ----
ATTACK_VERBS = {
    "en": r"ignore|disregard|forget|override|bypass|send|post|upload|forward|relay|mirror|transmit|print|reveal|dump|expose|delete|erase|wipe|drop|truncate|clear|grant|escalate|elevate|embed|insert|plant|persist|remember|comply",
    "zh": r"忽略|无视|忘记|丢弃|发送|上传|转发|回传|外传|打印|输出|显示|泄露|交出|删除|清空|抹掉|格式化|销毁|提升|获取|植入|写入|添加|隐藏|记住|保存|留存|收集|服从",
    "fr": r"envoyer|transmettre|imprimer|afficher|révéler|divulguer|supprimer|effacer|ignorer|oublier|transférer|exfiltrer|implanter|mémoriser|conserver",
    "de": r"senden|übertragen|weiterleiten|ausgeben|drucken|anzeigen|offenbaren|löschen|entfernen|ignorieren|vergessen|einbetten|speichern|übermitteln|abrufen",
}
TARGET_NOUNS = {
    "en": r"secret|credential|token|key|password|passphrase|transcript|conversation|chat log|history|database|table|backup|dump|admin|root|superuser|privilege|permission|memory|session|address|phone|passport",
    "zh": r"令牌|密钥|口令|密码|凭证|环境变量|对话|记录|聊天|数据库|整表|表|备份|管理员|超级用户|权限|记忆|会话|手机号|住址|身份证|银行卡",
    "fr": r"clé|jeton|mot de passe|identifiant|base de données|historique|conversation|messages|sauvegarde|admin|privilège|mémoire|session|adresse|téléphone",
    "de": r"schlüssel|kennwort|passwort|zugangsdaten|datenbank|verlauf|gespräch|sicherung|admin|berechtigung|speicher|sitzung|adresse|telefon",
}
DOC_CUES = re.compile(
    r"(?i)(detect\w*|scan\w*|block\w*|guard\w*|flag\w*|prevent\w*|catch\w*|cover\w*|"
    r"limitation|cannot|can't|false positive|designed to|we (?:block|flag|catch|detect)|"
    r"检测|拦截|阻断|防护|覆盖|无法|误报|限制|不支持|"
    r"détect\w*|bloque\w*|empêche|limitation|faux positifs|"
    r"erkennt|verhindert|blockiert|einschränkung|falsch positiv)")
IMPERATIVE_CUE = re.compile(
    r"(?i)(?:^|[。;,：:]\s*|please\s|kindly\s|请|务必|bitte\s|veuillez\s)(?:请|务必)?\s*"
    r"(%s)" % "|".join("(?:%s)" % v for v in ATTACK_VERBS.values()))
EXTERNAL_URL = re.compile(r"(?i)https?://[^\s)\"'>]+")
# 硬载荷护栏（2026-11-20）：URL 查询串里带 leak/payload/exfil/data/conv 等参数，就是把数据
# 往外送的载荷本体。一旦命中直接 attack，且不允许被"我们拦截/防护"等文档用语降级下去——
# 伪装成能力说明的外泄样本（红队 R10）就卡在这条上，昨日修动词条件时被连带降成 uncertain。
PAYLOAD_URL = re.compile(
    r"(?i)https?://[^\s)\"'>]*[?&](?:leaks?|payload|exfil\w*|data|conv\w*|tokens?|secrets?)=")
# 徽章/排版标记（2026-11-21）：README 顶部的 shields / readthedocs / actions 状态图与
# <p align="center">、<img src=…> 属纯排版，不含任何指令。四份竞品 README 实测中，
# deepeval / garak / promptfoo 各有 3–6 条复核候选出自这类行，人工队列被稀释。
# 硬约束：仅在"无攻击动词、无敏感对象"时放行；PAYLOAD_URL 在其之前返回，仍不得洗白。
BADGE_MARKUP = re.compile(
    r"(?i)(img\.shields\.io|badge\.svg|badgen\.net|badge\.fury\.io|readthedocs\.org|"
    r"actions/workflows/[^\s)\"'>]*/badge|<img\s+src=|</?p\s+align=|</?a\s+href=)")
CALL_CTX = re.compile(
    r"(?i)\b(?:scanner?|scan_text|scan|detector?|detect|guard|matches|assert|expect|pytest|fixture|test)\b\s*(\w*)\s*\(")
IDENT = re.compile(r"\b[A-Za-z][A-Za-z0-9]*_[A-Za-z0-9_]+\b")
# 逗号枚举的专名列表（"MMLU, HellaSwag, DROP, BIG-Bench Hard…"）：里的 DROP 是榜单名，
# 不是攻击动词。仅当同一行出现 ≥3 个逗号分隔的"首字母大写/全大写"词时才遮蔽，避免把
# "IGNORE ALL RULES" 这类全大写攻击句当成专名。
ENUM_NAME = re.compile(
    r"(?<![A-Za-z])[A-Z][A-Za-z0-9\-]{1,}(?:,\s*[A-Z][A-Za-z0-9\-]{1,}){2,}")
QUOTE_SPAN = re.compile(r'"[^"]{0,240}"|\u201c[^\u201d]{0,240}\u201d|`[^`]{0,240}`')


def _any(pattern_map, text):
    hits = []
    for lang, pat in pattern_map.items():
        for m in re.finditer(pat, text, re.I):
            hits.append((lang, m.group(0), m.start(), m.end()))
    return hits


def adjudicate(text):
    """返回裁决结果。不抛异常，输入任意文本。"""
    reasons, evid = [], []
    # 标识符遮蔽：ignore_instructions / system_prompt 这类 snake_case 是代码里的名字，
    # 不是自然语言祈使句。不遮蔽会把"规则名清单"读成"攻击指令"（良性夹具 L22 实测误判）。
    masked = IDENT.sub(" _ID_ ", text)
    url_hits = [m.group(0) for m in EXTERNAL_URL.finditer(text)]
    # URL 遮蔽（2026-11-19）：链接里的 "…-conversation-completeness"、"…key" 过去会被
    # 当成"敏感对象/动作动词"，再叠加"含外部地址 +2 分"直接冲进 attack 分支 —— deepeval
    # README 实测 9 条 P1 误报全出自此。地址本身只作为"含外部地址"信号，不参与词表匹配。
    masked = EXTERNAL_URL.sub(" _URL_ ", masked)
    masked = ENUM_NAME.sub(" _LIST_ ", masked)
    verb_hits = _any(ATTACK_VERBS, masked)
    target_hits = _any(TARGET_NOUNS, masked)
    doc_hits = [m.group(0) for m in DOC_CUES.finditer(text)]
    imper = IMPERATIVE_CUE.search(masked)

    if verb_hits:
        reasons.append("检测到动作动词：%s" % "、".join(sorted({h[1] for h in verb_hits})[:4]))
    if target_hits:
        reasons.append("检测到敏感对象：%s" % "、".join(sorted({h[1] for h in target_hits})[:4]))
    if url_hits:
        reasons.append("含外部地址：%s" % url_hits[0][:60])
    if doc_hits:
        reasons.append("含文档/能力陈述用语：%s" % "、".join(sorted(set(doc_hits))[:4]))

    # 证据片段：含动词或对象的那一句
    for sent in re.split(r"[。！？.!?\n]", text):
        s = sent.strip()
        if not s:
            continue
        if re.search("|".join(ATTACK_VERBS.values()), s, re.I) and \
           re.search("|".join(TARGET_NOUNS.values()), s, re.I):
            evid.append(s[:160])
            break

    # 引号内的示例 —— 不能单独作为白名单，只降低置信度
    quoted_only = bool(QUOTE_SPAN.search(text)) and not url_hits
    call_ctx = bool(CALL_CTX.search(text))

    a = len(verb_hits) + len(target_hits) + (2 if url_hits else 0)
    d = len(doc_hits)

    if PAYLOAD_URL.search(text):
        return {"verdict": "attack", "confidence": "high",
                "reasons": ["URL 携带载荷参数（硬规则：不因文档用语降级）"] + reasons,
                "evidence": [PAYLOAD_URL.search(text).group(0)[:160]]}
    # 徽章/排版：无动词、无敏感对象才放行（硬载荷已在上一行返回，不受影响）
    if BADGE_MARKUP.search(text) and not verb_hits and not target_hits:
        return {"verdict": "doc", "confidence": "medium",
                "reasons": ["徽章/排版标记（无攻击动词、无敏感对象）"] + reasons,
                "evidence": [(BADGE_MARKUP.search(text).group(0) or text)[:160]]}
    if imper and a >= 2 and d == 0:
        return {"verdict": "attack", "confidence": "high",
                "reasons": reasons, "evidence": evid[:1]}
    if url_hits and verb_hits and any(t[0] in ("en", "zh") for t in target_hits) and d == 0:
        # 2026-11-19：过去这里只要求"有链接 + 有敏感名词"就 attack，导致普通文档里
        # 每条带 docs 链接、且链接文字含 conversation/key/transcript 的说明行都成 P1。
        # 现在必须同时出现攻击动词，才允许走这条中置信 attack。
        return {"verdict": "attack", "confidence": "medium",
                "reasons": reasons, "evidence": evid[:1]}
    if d >= 2 and imper is None and not url_hits:
        return {"verdict": "doc", "confidence": "medium",
                "reasons": reasons, "evidence": []}
    if a >= 2 and d == 1 and not url_hits:
        return {"verdict": "uncertain", "confidence": "low",
                "reasons": reasons + ["文档用语与动作对象同时出现，需人工裁决"],
                "evidence": evid[:1]}
    if a >= 2 and imper is None and not url_hits and not doc_hits and quoted_only:
        return {"verdict": "uncertain", "confidence": "low",
                "reasons": reasons, "evidence": evid[:1]}
    if call_ctx and imper is None and not url_hits:
        return {"verdict": "uncertain", "confidence": "low",
                "reasons": reasons + ["代码示例/API 调用形态，需人工裁决"], "evidence": evid[:1]}
    if a >= 3 and verb_hits:
        # 2026-11-19：必须真的出现动作动词。此前 URL 记 +2 分，一个名词配一个链接就够 3 分，
        # 于是"带 docs 链接的说明行"被批量判成 attack（deepeval 实测 8 条 P1）。
        return {"verdict": "attack", "confidence": "medium",
                "reasons": reasons, "evidence": evid[:1]}
    return {"verdict": "uncertain", "confidence": "low", "reasons": reasons or ["信号不足"],
            "evidence": evid[:1]}


if __name__ == "__main__":
    import json
    import sys
    sys.stdout.reconfigure(encoding="utf-8")
    for line in sys.argv[1:]:
        print(line[:60], "→", json.dumps(adjudicate(line), ensure_ascii=False))
